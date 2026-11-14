package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
)

const (
	maxFeedXMLBytes = 2 << 20
	// A fetch or parse failure is logged as an error once this many checks
	// in a row have failed, so a single blip of the site doesn't alert.
	feedCheckFailuresBeforeError = 3
)

// feedFreshnessMonitor checks that the public feed shows what threat-bot
// published. The site lists briefs by publish date, so once it has been
// rebuilt the feed's lastBuildDate reaches the publish date of the newest
// brief whose public Markdown threat-bot pushed. A quiet period, with nothing new
// to publish, leaves the feed as it is and isn't a failure.
type feedFreshnessMonitor struct {
	cfg    config.MonitoringConfig
	client *http.Client
	logger *slog.Logger
	// newestPublic reports the newest public brief threat-bot pushed: its publish
	// date and when it was pushed. Nil when nothing is published.
	newestPublic func() (published, pushed time.Time)
	nextCheck    time.Time
	failures     int
}

func newFeedFreshnessMonitor(cfg config.MonitoringConfig, newestPublic func() (published, pushed time.Time), logger *slog.Logger) *feedFreshnessMonitor {
	return &feedFreshnessMonitor{
		cfg:          cfg,
		logger:       logger,
		client:       &http.Client{Timeout: 20 * time.Second},
		newestPublic: newestPublic,
	}
}

func (m *feedFreshnessMonitor) Check(ctx context.Context) {
	if m == nil || m.cfg.PublicFeedURL == "" {
		return
	}
	now := time.Now()
	if !m.nextCheck.IsZero() && now.Before(m.nextCheck) {
		return
	}
	m.nextCheck = now.Add(m.cfg.PublicFeedCheckInterval)

	lastBuildDate, err := fetchFeedLastBuildDate(ctx, m.client, m.cfg.PublicFeedURL)
	if err != nil {
		m.failures++
		log := m.logger.Warn
		if m.failures >= feedCheckFailuresBeforeError {
			log = m.logger.Error
		}
		log("public feed freshness check failed",
			"url", m.cfg.PublicFeedURL,
			"consecutive_failures", m.failures,
			"error", err,
		)
		return
	}
	m.failures = 0

	var published, pushed time.Time
	if m.newestPublic != nil {
		published, pushed = m.newestPublic()
	}
	behind, overdue := feedBehind(lastBuildDate, published, pushed, now, m.cfg.PublicFeedPublishGrace)
	switch {
	case overdue:
		m.logger.Error("public feed stale",
			"url", m.cfg.PublicFeedURL,
			"last_build_date", lastBuildDate,
			"newest_published", published,
			"pushed_at", pushed,
			"grace", m.cfg.PublicFeedPublishGrace.String(),
		)
	case behind:
		m.logger.Info("public feed update pending",
			"url", m.cfg.PublicFeedURL,
			"last_build_date", lastBuildDate,
			"newest_published", published,
			"pushed_at", pushed,
		)
	default:
		m.logger.Info("public feed fresh",
			"url", m.cfg.PublicFeedURL,
			"last_build_date", lastBuildDate,
		)
	}
}

// feedBehind reports whether the feed lacks the newest public brief, and
// whether it has lacked it for longer than the site needs to rebuild after a
// push.
func feedBehind(lastBuildDate, published, pushed, now time.Time, grace time.Duration) (behind, overdue bool) {
	if published.IsZero() {
		return false, false
	}
	// The feed carries whole seconds.
	behind = lastBuildDate.Before(published.Truncate(time.Second))
	return behind, behind && now.Sub(pushed) > grace
}

func fetchFeedLastBuildDate(ctx context.Context, client *http.Client, feedURL string) (time.Time, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return time.Time{}, fmt.Errorf("fetching feed: HTTP %d", resp.StatusCode)
	}

	decoder := xml.NewDecoder(io.LimitReader(resp.Body, maxFeedXMLBytes))
	var newestItem time.Time
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing RSS XML: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok || (start.Name.Local != "lastBuildDate" && start.Name.Local != "pubDate") {
			continue
		}
		var raw string
		if err := decoder.DecodeElement(&raw, &start); err != nil {
			return time.Time{}, fmt.Errorf("parsing RSS XML: %w", err)
		}
		parsed, err := parseRSSDate(raw)
		if err != nil {
			continue
		}
		if start.Name.Local == "lastBuildDate" {
			return parsed, nil
		}
		if newestItem.IsZero() || parsed.After(newestItem) {
			newestItem = parsed
		}
	}
	if newestItem.IsZero() {
		return time.Time{}, fmt.Errorf("no lastBuildDate or item pubDate found")
	}
	return newestItem, nil
}

func parseRSSDate(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC1123Z, time.RFC1123} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("parsing lastBuildDate %q", raw)
}
