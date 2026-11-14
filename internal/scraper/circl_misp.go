package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	circlManifestURL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
	circlBaseURL     = "https://www.circl.lu/doc/misp/feed-osint"
	// Skip events larger than 2MB to avoid slow downloads.
	maxEventSize = 2 * 1024 * 1024
	// Process at most 20 new events per poll to stay within reasonable time.
	maxEventsPerPoll = 20
)

// CIRCLMISP scrapes the CIRCL OSINT MISP feed for threat events.
type CIRCLMISP struct {
	client *http.Client
}

func NewCIRCLMISP() *CIRCLMISP {
	return &CIRCLMISP{
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *CIRCLMISP) Name() string { return "circl-misp" }

func (c *CIRCLMISP) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	return c.pollFrom(ctx, since, circlManifestURL, circlBaseURL)
}

func (c *CIRCLMISP) pollFrom(ctx context.Context, since time.Time, manifestURL, baseURL string) ([]RawItem, error) {
	manifest, err := c.fetchManifestFrom(ctx, manifestURL)
	if err != nil {
		return nil, err
	}

	// Filter to events newer than since, sort by timestamp descending (newest first).
	type eventRef struct {
		UUID      string
		Entry     mispManifestEntry
		Timestamp int64
	}
	var candidates []eventRef
	for uuid, entry := range manifest {
		ts, _ := strconv.ParseInt(entry.Timestamp.String(), 10, 64)
		if ts == 0 {
			continue
		}
		eventTime := time.Unix(ts, 0)
		if eventTime.Before(since) {
			continue
		}
		candidates = append(candidates, eventRef{UUID: uuid, Entry: entry, Timestamp: ts})
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Timestamp > candidates[j].Timestamp
	})
	if len(candidates) > maxEventsPerPoll {
		candidates = candidates[:maxEventsPerPoll]
	}

	var items []RawItem
	for _, ref := range candidates {
		item, err := c.fetchEventFrom(ctx, ref.UUID, ref.Entry, baseURL)
		if err != nil {
			continue // skip events that fail to fetch
		}
		items = append(items, *item)
	}

	return items, nil
}

func (c *CIRCLMISP) fetchManifestFrom(ctx context.Context, url string) (map[string]mispManifestEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "threat-bot/1.0 (threat-intelligence aggregator; +https://github.com/CraftedSignal/threat-bot)")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, statusErrorf(resp.StatusCode, "CIRCL manifest: HTTP %d", resp.StatusCode)
	}

	var manifest map[string]mispManifestEntry
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decoding manifest: %w", err)
	}

	return manifest, nil
}

func (c *CIRCLMISP) fetchEventFrom(ctx context.Context, uuid string, entry mispManifestEntry, baseURL string) (*RawItem, error) {
	url := fmt.Sprintf("%s/%s.json", baseURL, uuid)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "threat-bot/1.0 (threat-intelligence aggregator; +https://github.com/CraftedSignal/threat-bot)")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, statusErrorf(resp.StatusCode, "HTTP %d for event %s", resp.StatusCode, uuid)
	}

	// Check content-length if available.
	if resp.ContentLength > maxEventSize {
		return nil, fmt.Errorf("event %s too large: %d bytes", uuid, resp.ContentLength)
	}

	var event mispEvent
	if err := json.NewDecoder(resp.Body).Decode(&event); err != nil {
		return nil, fmt.Errorf("decoding event %s: %w", uuid, err)
	}

	// Build content from event info + attributes.
	var content strings.Builder
	content.WriteString(event.Event.Info)
	content.WriteString("\n\n")

	// Extract IOC-type attributes for context.
	iocCount := 0
	for _, attr := range event.Event.Attributes {
		if iocCount >= 50 {
			fmt.Fprintf(&content, "... and %d more attributes\n", len(event.Event.Attributes)-50)
			break
		}
		if attr.Category == "Network activity" || attr.Category == "Payload delivery" ||
			attr.Category == "External analysis" || attr.Category == "Artifacts dropped" {
			fmt.Fprintf(&content, "[%s] %s: %s", attr.Category, attr.Type, attr.Value)
			if attr.Comment != "" {
				fmt.Fprintf(&content, " (%s)", attr.Comment)
			}
			content.WriteString("\n")
			iocCount++
		}
	}

	// Extract tags.
	var tags []string
	for _, tag := range entry.Tag {
		tags = append(tags, tag.Name)
	}

	ts, _ := strconv.ParseInt(entry.Timestamp.String(), 10, 64)
	published := time.Unix(ts, 0)

	return &RawItem{
		SourceID:    fmt.Sprintf("circl-misp:%s", uuid),
		Source:      "circl-misp",
		Title:       entry.Info,
		URL:         fmt.Sprintf("%s/%s.json", circlBaseURL, uuid),
		Content:     content.String(),
		PublishedAt: published,
		Metadata: map[string]string{
			"threat_level": entry.ThreatLevelID.String(),
			"tags":         strings.Join(tags, ", "),
			"org":          entry.Orgc.Name,
		},
	}, nil
}

type mispManifestEntry struct {
	Orgc          mispOrg     `json:"Orgc"`
	Tag           []mispTag   `json:"Tag"`
	Info          string      `json:"info"`
	Date          string      `json:"date"`
	Analysis      json.Number `json:"analysis"`
	ThreatLevelID json.Number `json:"threat_level_id"`
	Timestamp     json.Number `json:"timestamp"`
}

type mispOrg struct {
	Name string `json:"name"`
}

type mispTag struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

type mispEvent struct {
	Event struct {
		Info       string          `json:"info"`
		Attributes []mispAttribute `json:"Attribute"`
	} `json:"Event"`
}

type mispAttribute struct {
	Category string `json:"category"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Comment  string `json:"comment"`
}
