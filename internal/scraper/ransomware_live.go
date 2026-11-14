package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const ransomwareLiveAPI = "https://api.ransomware.live/recentvictims"

// RansomwareLive polls the ransomware.live API for recent victim postings and groups
// them by ransomware group, emitting one RawItem per active group per poll cycle.
// This produces rich, multi-victim content that clears the pipeline quality gate,
// unlike the RSS feed which only carries a victim name + 1–2 sentence description.
type RansomwareLive struct {
	client *http.Client
}

func NewRansomwareLive() *RansomwareLive {
	return &RansomwareLive{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &uaTransport{ua: userAgent, rt: http.DefaultTransport},
		},
	}
}

func (r *RansomwareLive) Name() string { return "ransomware-live" }

type rlVictim struct {
	Activity    string   `json:"activity"`
	Country     string   `json:"country"`
	DataSize    *string  `json:"data_size"`
	Description string   `json:"description"`
	Discovered  string   `json:"discovered"`
	GroupName   string   `json:"group_name"`
	PostTitle   string   `json:"post_title"`
	PostURL     string   `json:"post_url"`
	Published   string   `json:"published"`
	Ransom      *float64 `json:"ransom"`
	Website     string   `json:"website"`
}

func (v *rlVictim) publishedTime() (time.Time, error) {
	return time.Parse(time.RFC3339Nano, v.Published)
}

func (v *rlVictim) name() string {
	if v.Website != "" {
		return v.Website
	}
	// PostTitle is sometimes a bare URL — strip scheme for readability.
	name := strings.TrimPrefix(v.PostTitle, "https://")
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimSuffix(name, "/")
	return name
}

func (r *RansomwareLive) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ransomwareLiveAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode == 429 {
		return nil, statusErrorf(resp.StatusCode, "rate limited")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusErrorf(resp.StatusCode, "unexpected status %d", resp.StatusCode)
	}

	var victims []rlVictim
	if err := json.NewDecoder(resp.Body).Decode(&victims); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Group victims by ransomware group, keeping only those published after since.
	byGroup := map[string][]rlVictim{}
	for _, v := range victims {
		pub, err := v.publishedTime()
		if err != nil || pub.Before(since) {
			continue
		}
		byGroup[v.GroupName] = append(byGroup[v.GroupName], v)
	}

	var items []RawItem
	for groupName, gv := range byGroup {
		// Sort newest first so the first entry drives title and SourceID.
		sort.Slice(gv, func(i, j int) bool { return gv[i].Published > gv[j].Published })

		newestPub, _ := gv[0].publishedTime()
		if newestPub.IsZero() {
			newestPub = time.Now()
		}

		var sb strings.Builder
		fmt.Fprintf(&sb, "Ransomware group **%s** has claimed %d new victim(s):\n\n", groupName, len(gv))
		for i, v := range gv {
			fmt.Fprintf(&sb, "%d. **%s**\n", i+1, v.name())
			if v.Country != "" {
				fmt.Fprintf(&sb, "   Country: %s\n", v.Country)
			}
			if v.Activity != "" {
				fmt.Fprintf(&sb, "   Sector: %s\n", v.Activity)
			}
			if v.Description != "" {
				fmt.Fprintf(&sb, "   Data stolen: %s\n", v.Description)
			}
			if v.DataSize != nil {
				fmt.Fprintf(&sb, "   Data size: %s\n", *v.DataSize)
			}
			if v.Ransom != nil {
				fmt.Fprintf(&sb, "   Ransom demand: $%.0f\n", *v.Ransom)
			}
			if v.PostURL != "" {
				fmt.Fprintf(&sb, "   Leak site: %s\n", v.PostURL)
			}
			sb.WriteString("\n")
		}

		firstVictim := gv[0].name()
		var title string
		if len(gv) == 1 {
			title = fmt.Sprintf("%s ransomware claims new victim: %s (%s, %s)",
				groupName, firstVictim, gv[0].Country, gv[0].Activity)
		} else {
			title = fmt.Sprintf("%s ransomware claims %d new victims including %s",
				groupName, len(gv), firstVictim)
		}

		// Key by group + newest victim's published minute — unique per burst of activity,
		// avoids re-processing the same event if polled twice in the same minute.
		sourceID := fmt.Sprintf("ransomware-live:%s:%s",
			groupName, newestPub.UTC().Format("2006-01-02T15:04"))

		items = append(items, RawItem{
			SourceID:    sourceID,
			Source:      "ransomware-live",
			Title:       title,
			URL:         fmt.Sprintf("https://www.ransomware.live/group/%s", groupName),
			Content:     sb.String(),
			PublishedAt: newestPub,
		})
	}

	return items, nil
}
