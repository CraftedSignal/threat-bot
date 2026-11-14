package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/mmcdole/gofeed"
)

type MastodonTagDiscovery struct {
	cfg    config.MastodonDiscoveryConfig
	client *http.Client
}

func NewMastodonTagDiscovery(cfg config.MastodonDiscoveryConfig) Scraper {
	if len(cfg.Tags) == 0 {
		cfg.Tags = []string{"cve", "infosec", "vulnerability", "exploit", "0day", "malware"}
	}
	if cfg.CandidateCap <= 0 {
		cfg.CandidateCap = 100
	}
	return &MastodonTagDiscovery{cfg: cfg, client: &http.Client{Timeout: 30 * time.Second}}
}
func (m *MastodonTagDiscovery) Name() string { return "mastodon-discovery" }
func (m *MastodonTagDiscovery) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	seen := map[string]bool{}
	var out []RawItem
	var lastErr error
	for _, instance := range m.cfg.Instances {
		for _, tag := range m.cfg.Tags {
			feedURL := strings.TrimRight(instance, "/") + "/tags/" + url.PathEscape(tag) + ".rss"
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
			resp, err := m.client.Do(req)
			if err != nil {
				lastErr = err
				continue
			}
			if resp.StatusCode/100 != 2 {
				_ = resp.Body.Close()
				lastErr = statusErrorf(resp.StatusCode, "%s: %s", feedURL, resp.Status)
				continue
			}
			feed, err := gofeed.NewParser().Parse(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				lastErr = err
				continue
			}
			for _, entry := range feed.Items {
				published := time.Now()
				if entry.PublishedParsed != nil {
					published = *entry.PublishedParsed
				}
				if published.Before(since) || seen[entry.Link] {
					continue
				}
				seen[entry.Link] = true
				author := ""
				if u, e := url.Parse(entry.Link); e == nil {
					parts := strings.Split(strings.Trim(u.Path, "/"), "/")
					if len(parts) > 0 {
						author = parts[0]
					}
				}
				item := RawItem{SourceID: m.Name() + ":" + entry.Link, Source: m.Name(), Title: entry.Title, URL: entry.Link, Content: entry.Description + "\n\n" + entry.Content, PublishedAt: published, Discovery: &DiscoveryContext{Platform: "mastodon", OriginalURL: entry.Link, DiscoveryURL: feedURL, Author: author, ContextComplete: true}}
				if IsRelevantDiscoveryCandidate(item) {
					out = append(out, item)
				}
			}
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, fmt.Errorf("polling Mastodon tags: %w", lastErr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt.Before(out[j].PublishedAt) })
	if len(out) > m.cfg.CandidateCap {
		out = out[:m.cfg.CandidateCap]
	}
	return out, nil
}
