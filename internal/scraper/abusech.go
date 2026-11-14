package scraper

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	threatFoxRecentURL = "https://threatfox-api.abuse.ch/api/v1/"
	// urlhausRecentLimit is the most URLs the recent endpoint returns.
	urlhausRecentLimit = 1000
	// urlhausRecentWindow is how far back the recent endpoint reaches.
	urlhausRecentWindow = 3 * 24 * time.Hour
	// threatFoxDays is how many days of indicators a poll requests. Two days
	// hold the whole previous UTC day at any time of the current one.
	threatFoxDays = 2
	// abuseCHSettle is how long a poll waits after a UTC day ends before it
	// reports the day, so entries submitted around midnight are in.
	abuseCHSettle = 15 * time.Minute
	// abuseCHMaxListed caps the entries an item lists. Its title and counts
	// still cover all of them.
	abuseCHMaxListed = 50
	// abuseCHTimeLayout is how both APIs format timestamps.
	abuseCHTimeLayout = "2006-01-02 15:04:05 UTC"
)

var urlhausRecentURL = fmt.Sprintf("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/%d/", urlhausRecentLimit)

// AbuseCH polls URLhaus and ThreatFox. Both list single indicators, about two
// thousand a day on ThreatFox alone, so a poll reports each malware family
// (ThreatFox) or tag set (URLhaus) once per UTC day: when the day is over and
// the poll fetched all of it. The source ID names the family and day, so the
// seen state keeps later polls from reporting it again.
type AbuseCH struct {
	client  *http.Client
	authKey string
	now     func() time.Time
}

func NewAbuseCH(authKey string) *AbuseCH {
	return &AbuseCH{
		client:  &http.Client{Timeout: 30 * time.Second},
		authKey: authKey,
		now:     time.Now,
	}
}

func (a *AbuseCH) Name() string { return "abuse-ch" }

// Poll reports the days a poll can report in full, whatever since says: their
// source IDs are stable, and the runner skips items it has seen.
func (a *AbuseCH) Poll(ctx context.Context, _ time.Time) ([]RawItem, error) {
	if a.authKey == "" {
		return nil, fmt.Errorf("abuse.ch Auth-Key is required")
	}
	items, err := a.pollURLhausFrom(ctx, urlhausRecentURL)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: %w", err)
	}
	tfItems, err := a.pollThreatFoxFrom(ctx, threatFoxRecentURL)
	if err != nil {
		return nil, fmt.Errorf("threatfox: %w", err)
	}
	return append(items, tfItems...), nil
}

func (a *AbuseCH) do(req *http.Request, api string, out any) error {
	req.Header.Set("Auth-Key", a.authKey)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer discardClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return statusErrorf(resp.StatusCode, "%s API: %s", api, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding %s response: %w", api, err)
	}
	return nil
}

// utcDay returns the start of t's UTC day.
func utcDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// reportableDay reports whether the UTC day starting at day is over, with time
// to settle, and lies inside a fetched window that starts at windowStart.
func reportableDay(day, windowStart, now time.Time) bool {
	return !day.Before(windowStart) && !day.Add(24*time.Hour+abuseCHSettle).After(now)
}

func parseAbuseCHTime(field, id, value string) (time.Time, error) {
	parsed, err := time.Parse(abuseCHTimeLayout, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("entry %s: %s %q: %w", id, field, value, err)
	}
	return parsed, nil
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

type urlhausEntry struct {
	ID        json.Number `json:"id"`
	Reference string      `json:"urlhaus_reference"`
	URL       string      `json:"url"`
	Status    string      `json:"url_status"`
	Host      string      `json:"host"`
	DateAdded string      `json:"date_added"`
	Threat    string      `json:"threat"`
	Reporter  string      `json:"reporter"`
	Tags      []string    `json:"tags"`
	added     time.Time
}

// reportURL returns the entry's URLhaus report page. The listed URL itself
// serves malware, so nothing may use it as an item URL.
func (e urlhausEntry) reportURL() string {
	if strings.HasPrefix(e.Reference, "https://urlhaus.abuse.ch/") {
		return e.Reference
	}
	return "https://urlhaus.abuse.ch/url/" + url.PathEscape(e.ID.String()) + "/"
}

func (a *AbuseCH) pollURLhausFrom(ctx context.Context, endpoint string) ([]RawItem, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Status string         `json:"query_status"`
		URLs   []urlhausEntry `json:"urls"`
	}
	if err := a.do(req, "urlhaus", &result); err != nil {
		return nil, err
	}
	if result.Status != "ok" && result.Status != "no_results" {
		return nil, fmt.Errorf("urlhaus API query_status %q", result.Status)
	}

	now := a.now().UTC()
	windowStart := now.Add(-urlhausRecentWindow)
	type group struct {
		tags    []string
		day     time.Time
		entries []urlhausEntry
	}
	groups := map[string]*group{}
	var oldest time.Time
	for _, entry := range result.URLs {
		added, err := parseAbuseCHTime("date_added", entry.ID.String(), entry.DateAdded)
		if err != nil {
			return nil, err
		}
		entry.added = added
		if oldest.IsZero() || added.Before(oldest) {
			oldest = added
		}
		tags := normalizedTags(entry.Tags)
		day := utcDay(added)
		key := strings.ToLower(strings.Join(tags, ",")) + "\x00" + day.Format(time.DateOnly)
		if groups[key] == nil {
			groups[key] = &group{tags: tags, day: day}
		}
		groups[key].entries = append(groups[key].entries, entry)
	}
	// A full response holds only the newest URLs, so it covers days from its
	// oldest entry on. URLhaus offers no query by date, so a day that began
	// earlier is reported with what the window holds, as a lower bound.
	covered := windowStart
	if len(result.URLs) >= urlhausRecentLimit && oldest.After(covered) {
		covered = oldest
	}

	var items []RawItem
	for _, g := range groups {
		if !reportableDay(g.day, windowStart, now) {
			continue
		}
		slices.SortFunc(g.entries, func(x, y urlhausEntry) int {
			return cmp.Or(y.added.Compare(x.added), strings.Compare(y.ID.String(), x.ID.String()))
		})
		day := g.day.Format(time.DateOnly)
		tagKey, described := "untagged", "untagged"
		if len(g.tags) > 0 {
			tagKey = strings.ToLower(strings.Join(g.tags, ","))
			described = "tagged " + strings.Join(g.tags, ", ")
		}
		subject := plural(len(g.entries), "new malware URL")
		if g.day.Before(covered) {
			subject = "at least " + subject
		}
		var content strings.Builder
		fmt.Fprintf(&content, "URLhaus listed %s %s on %s UTC.\n", subject, described, day)
		if g.day.Before(covered) {
			fmt.Fprintf(&content, "URLhaus returns its newest %d URLs, which reached back to %s.\n", urlhausRecentLimit, covered.Format(abuseCHTimeLayout))
		}
		content.WriteString("\nURLs, newest first:\n")
		for i, entry := range g.entries {
			if i == abuseCHMaxListed {
				fmt.Fprintf(&content, "... and %d more\n", len(g.entries)-abuseCHMaxListed)
				break
			}
			fmt.Fprintf(&content, "- %s (host %s, %s, %s, added %s, reported by %s, %s)\n",
				entry.URL, entry.Host, entry.Status, entry.Threat, entry.DateAdded, entry.Reporter, entry.reportURL())
		}
		items = append(items, RawItem{
			SourceID:    "abuse-ch:urlhaus:" + tagKey + ":" + day,
			Source:      "abuse-ch",
			Title:       fmt.Sprintf("URLhaus: %s %s on %s", subject, described, day),
			URL:         g.entries[0].reportURL(),
			Content:     content.String(),
			PublishedAt: g.entries[0].added,
			Metadata: map[string]string{
				"tags": strings.Join(g.tags, ","),
				"urls": fmt.Sprint(len(g.entries)),
			},
			Enriched: true,
		})
	}
	slices.SortFunc(items, func(x, y RawItem) int { return strings.Compare(x.SourceID, y.SourceID) })
	return items, nil
}

// normalizedTags returns tags sorted and without case-insensitive duplicates,
// so one set of tags in any order forms one group.
func normalizedTags(tags []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[strings.ToLower(tag)] {
			continue
		}
		seen[strings.ToLower(tag)] = true
		out = append(out, tag)
	}
	slices.SortFunc(out, func(x, y string) int { return strings.Compare(strings.ToLower(x), strings.ToLower(y)) })
	return out
}

type threatFoxEntry struct {
	ID               json.Number `json:"id"`
	IOC              string      `json:"ioc"`
	IOCType          string      `json:"ioc_type"`
	ThreatType       string      `json:"threat_type"`
	Malware          string      `json:"malware"`
	MalwarePrintable string      `json:"malware_printable"`
	Malpedia         string      `json:"malware_malpedia"`
	Confidence       json.Number `json:"confidence_level"`
	FirstSeen        string      `json:"first_seen"`
	Reporter         string      `json:"reporter"`
	Reference        string      `json:"reference"`
	Tags             []string    `json:"tags"`
	firstSeen        time.Time
}

func (a *AbuseCH) pollThreatFoxFrom(ctx context.Context, endpoint string) ([]RawItem, error) {
	body := strings.NewReader(fmt.Sprintf(`{"query":"get_iocs","days":%d}`, threatFoxDays))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	var result struct {
		Status string          `json:"query_status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := a.do(req, "threatfox", &result); err != nil {
		return nil, err
	}
	var entries []threatFoxEntry
	switch result.Status {
	case "ok":
		if err := json.Unmarshal(result.Data, &entries); err != nil {
			return nil, fmt.Errorf("decoding threatfox indicators: %w", err)
		}
	case "no_result":
		// The data field then holds a message, not indicators.
	default:
		return nil, fmt.Errorf("threatfox API query_status %q", result.Status)
	}

	now := a.now().UTC()
	windowStart := now.Add(-threatFoxDays * 24 * time.Hour)
	type group struct {
		malware string
		name    string
		day     time.Time
		entries []threatFoxEntry
	}
	groups := map[string]*group{}
	for _, entry := range entries {
		seen, err := parseAbuseCHTime("first_seen", entry.ID.String(), entry.FirstSeen)
		if err != nil {
			return nil, err
		}
		entry.firstSeen = seen
		malware := cmp.Or(strings.TrimSpace(entry.Malware), "unknown")
		day := utcDay(seen)
		key := malware + "\x00" + day.Format(time.DateOnly)
		if groups[key] == nil {
			groups[key] = &group{malware: malware, name: cmp.Or(strings.TrimSpace(entry.MalwarePrintable), malware), day: day}
		}
		groups[key].entries = append(groups[key].entries, entry)
	}

	var items []RawItem
	for _, g := range groups {
		if !reportableDay(g.day, windowStart, now) {
			continue
		}
		slices.SortFunc(g.entries, func(x, y threatFoxEntry) int {
			return cmp.Or(y.firstSeen.Compare(x.firstSeen), strings.Compare(y.ID.String(), x.ID.String()))
		})
		day := g.day.Format(time.DateOnly)
		subject := plural(len(g.entries), "new "+g.name+" indicator")
		threatTypes, iocTypes := map[string]int{}, map[string]int{}
		for _, entry := range g.entries {
			threatTypes[entry.ThreatType]++
			iocTypes[entry.IOCType]++
		}
		var content strings.Builder
		fmt.Fprintf(&content, "ThreatFox listed %s of compromise (%s) first seen on %s UTC.\n", subject, g.malware, day)
		if malpedia := g.entries[0].Malpedia; malpedia != "" {
			fmt.Fprintf(&content, "Malpedia: %s\n", malpedia)
		}
		fmt.Fprintf(&content, "Threat types: %s. Indicator types: %s.\n\nIndicators, newest first:\n", countList(threatTypes), countList(iocTypes))
		for i, entry := range g.entries {
			if i == abuseCHMaxListed {
				fmt.Fprintf(&content, "... and %d more\n", len(g.entries)-abuseCHMaxListed)
				break
			}
			fmt.Fprintf(&content, "- %s (%s, %s, confidence %s%%, first seen %s, reported by %s", entry.IOC, entry.IOCType, entry.ThreatType, entry.Confidence, entry.FirstSeen, entry.Reporter)
			if tags := normalizedTags(entry.Tags); len(tags) > 0 {
				fmt.Fprintf(&content, ", tags %s", strings.Join(tags, ", "))
			}
			if entry.Reference != "" {
				fmt.Fprintf(&content, ", reference %s", entry.Reference)
			}
			content.WriteString(")\n")
		}
		items = append(items, RawItem{
			SourceID:    "abuse-ch:threatfox:" + g.malware + ":" + day,
			Source:      "abuse-ch",
			Title:       fmt.Sprintf("ThreatFox: %s on %s", subject, day),
			URL:         "https://threatfox.abuse.ch/browse/malware/" + url.PathEscape(g.malware) + "/",
			Content:     content.String(),
			PublishedAt: g.entries[0].firstSeen,
			Metadata: map[string]string{
				"malware":    g.name,
				"malpedia":   g.malware,
				"indicators": fmt.Sprint(len(g.entries)),
			},
			Enriched: true,
		})
	}
	slices.SortFunc(items, func(x, y RawItem) int { return strings.Compare(x.SourceID, y.SourceID) })
	return items, nil
}

// countList renders counts as "a (3), b (1)", most frequent first.
func countList(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(x, y string) int { return cmp.Or(counts[y]-counts[x], strings.Compare(x, y)) })
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s (%d)", cmp.Or(key, "unknown"), counts[key]))
	}
	return strings.Join(parts, ", ")
}
