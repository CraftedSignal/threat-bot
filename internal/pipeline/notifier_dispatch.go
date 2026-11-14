package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// l3SourceAllowlist gates which scraper sources can promote a merge to
// the L3 ("update dispatch") tier. Anything else may still mark the
// brief as updated visually but won't email subscribers, regardless of
// what changed. The list is the set of feeds we trust to be both
// authoritative and low-false-positive on KEV / exploitation /
// severity-critical signals.
var l3SourceAllowlist = map[string]struct{}{
	"nvd":                    {},
	"cisa":                   {},
	"cisa-kev":               {},
	"msrc":                   {},
	"cisco-psirt":            {},
	"ghsa":                   {},
	"mandiant":               {},
	"talos":                  {},
	"unit42":                 {},
	"volexity":               {},
	"sophos-xops":            {},
	"crowdstrike":            {},
	"microsoft-threat-intel": {},
	"google-project-zero":    {},
}

// dispatchPayload mirrors the feed-notifier /dispatch wire format. We
// keep this tiny and string-keyed so a schema change on the receiving
// side that adds optional fields doesn't break threat-bot's send path.
type dispatchPayload struct {
	Briefs []dispatchBrief `json:"briefs"`
}

type dispatchBrief struct {
	Slug          string   `json:"slug"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	URL           string   `json:"url"`
	Type          string   `json:"type"`
	Severity      string   `json:"severity"`
	Actors        []string `json:"actors,omitempty"`
	Vendors       []string `json:"vendors,omitempty"`
	Products      []string `json:"products,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Exploited     bool     `json:"exploited,omitempty"`
	IsUpdate      bool     `json:"is_update,omitempty"`
	UpdateSummary string   `json:"update_summary,omitempty"`
}

// maybeDispatchL3Update fires the notifier dispatch path for an L3
// merge event when (a) the source is in the allowlist, (b) the per-brief
// cooldown has elapsed, and (c) the notifier endpoint is configured.
// Failures are logged and swallowed — the visual update on the site is
// the primary signal; the email is a nice-to-have.
func (p *Pipeline) maybeDispatchL3Update(ctx context.Context, draftID string, summary string, sourceName string, siteURL string) {
	if p.notifierURL == "" || p.notifierToken == "" {
		return
	}
	if _, ok := l3SourceAllowlist[strings.ToLower(strings.TrimSpace(sourceName))]; !ok {
		p.logger.Info("L3 update suppressed: source not in allowlist",
			"draft_id", draftID, "source", sourceName)
		return
	}
	draft, err := p.db.GetDraft(draftID)
	if err != nil || draft == nil {
		return
	}
	cooldown := p.notifierCooldown
	if cooldown == 0 {
		cooldown = 6 * time.Hour
	}
	if draft.LastL3Dispatch != nil && time.Since(*draft.LastL3Dispatch) < cooldown {
		p.logger.Info("L3 update suppressed: cooldown",
			"draft_id", draftID,
			"last_dispatch", draft.LastL3Dispatch,
			"cooldown", cooldown)
		return
	}

	brief, err := dispatchBriefFromDraftYAML(draft.BriefYAML, summary, siteURL)
	if err != nil {
		p.logger.Warn("L3 dispatch payload build failed", "draft_id", draftID, "error", err)
		return
	}
	var lifecycle struct {
		ClaimState string `yaml:"claim_state"`
	}
	_ = yaml.Unmarshal([]byte(draft.BriefYAML), &lifecycle)
	if lifecycle.ClaimState == "disputed" || lifecycle.ClaimState == "retracted" {
		p.logger.Info("L3 update suppressed: inactive rumour lifecycle", "draft_id", draftID, "claim_state", lifecycle.ClaimState)
		return
	}

	if err := postDispatch(ctx, p.notifierURL, p.notifierToken, dispatchPayload{Briefs: []dispatchBrief{brief}}); err != nil {
		p.logger.Warn("L3 dispatch POST failed", "draft_id", draftID, "error", err)
		return
	}
	if err := p.db.RecordL3Dispatch(draftID, time.Now().UTC()); err != nil {
		p.logger.Warn("L3 dispatch stamp failed", "draft_id", draftID, "error", err)
		return
	}
	p.logger.Info("L3 update dispatched", "draft_id", draftID, "summary", summary)
}

// dispatchBriefFromDraftYAML builds the JSON payload entry by reading
// the same fields the Site Deploy workflow's Python builder reads, so
// the notifier sees a payload of the same shape regardless of caller.
func dispatchBriefFromDraftYAML(briefYAML, summary, siteURL string) (dispatchBrief, error) {
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &fm); err != nil {
		return dispatchBrief{}, err
	}
	str := func(k string) string {
		v, _ := fm[k].(string)
		return v
	}
	strList := func(k string) []string {
		raw, _ := fm[k].([]any)
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	severity := str("severity")
	if severity == "" {
		if list := strList("severities"); len(list) > 0 {
			severity = list[0]
		} else {
			severity = "medium"
		}
	}
	exploited, _ := fm["exploited"].(bool)
	slug := str("slug")
	url := siteURL
	if url != "" && slug != "" {
		url = strings.TrimRight(url, "/") + "/briefs/" + slug + "/"
	}
	return dispatchBrief{
		Slug:          slug,
		Title:         str("title"),
		Description:   firstNonEmpty(str("description"), str("summary")),
		URL:           url,
		Type:          str("type"),
		Severity:      severity,
		Actors:        strList("actors"),
		Vendors:       strList("vendors"),
		Products:      strList("products"),
		Tags:          strList("tags"),
		Exploited:     exploited,
		IsUpdate:      true,
		UpdateSummary: summary,
	}, nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// postDispatch is the HTTP client for the /dispatch endpoint. It retries
// retryable failures (5xx, 429, network errors) with exponential backoff
// while respecting context cancellation.
func postDispatch(ctx context.Context, baseURL, token string, payload dispatchPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/dispatch"

	client := &http.Client{Timeout: 10 * time.Second}
	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

	var lastErr error
	for attempt := 0; attempt <= len(delays); attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(ctx, delays[attempt-1]); err != nil {
				return err
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("invalid notifier endpoint")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			// Request errors can include endpoint credentials or query parameters.
			lastErr = errors.New("notifier request failed")
			if errors.Is(err, context.Canceled) {
				return context.Canceled
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return context.DeadlineExceeded
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				lastErr = errors.New("notifier request timed out")
			}
			if !isRetryableNotifierError(err) {
				return lastErr
			}
			continue
		}
		// Drain a bounded amount for connection reuse; remote bodies are never errors.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		// The response status is authoritative; Close only releases resources.
		_ = resp.Body.Close()

		if resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("notifier HTTP %d", resp.StatusCode)
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return lastErr
		}
	}
	return fmt.Errorf("notifier dispatch failed after %d attempts: %w", len(delays)+1, lastErr)
}

func isRetryableNotifierError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "temporary failure") ||
		strings.Contains(msg, "no such host")
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
