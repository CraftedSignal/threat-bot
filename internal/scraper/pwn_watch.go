package scraper

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	pwnWatchChangesURL        = "https://pwn.watch/changes.json"
	pwnWatchIncidentURL       = "https://pwn.watch/i"
	pwnWatchMaxReferenceURLs  = 12
	pwnWatchFallbackReference = 3
)

// PwnWatch consumes structured incident snapshots as corroboration. It never
// creates a brief by itself; the pipeline only lets these items enrich an
// incident already identified by another source.
type PwnWatch struct {
	client          *http.Client
	changesURL      string
	incidentBaseURL string
	validatorMu     sync.Mutex
	etag            string
	lastModified    string
}

type pwnWatchChanges struct {
	Changes []pwnWatchChange `json:"changes"`
}

type pwnWatchChange struct {
	Incident string `json:"incident"`
	Date     string `json:"date"`
}

type pwnWatchIncident struct {
	Slug             string                   `json:"slug"`
	Title            string                   `json:"title"`
	URL              string                   `json:"url"`
	Status           string                   `json:"status"`
	Severity         string                   `json:"severity"`
	PatchStatus      string                   `json:"patchStatus"`
	Product          string                   `json:"product"`
	CVEIDs           []string                 `json:"cveIds"`
	AffectedVersions []string                 `json:"affectedVersions"`
	FixedVersions    []string                 `json:"fixedVersions"`
	StartedAt        string                   `json:"startedAt"`
	UpdatedAt        string                   `json:"updatedAt"`
	Summary          string                   `json:"summary"`
	Tags             []string                 `json:"tags"`
	Sources          []pwnWatchIncidentSource `json:"sources"`
	Timeline         []pwnWatchTimelineEntry  `json:"timeline"`
}

type pwnWatchIncidentSource struct {
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	Publisher string `json:"publisher"`
	Date      string `json:"date"`
}

type pwnWatchTimelineEntry struct {
	Date      string `json:"date"`
	Title     string `json:"title"`
	SourceURL string `json:"sourceUrl"`
}

func NewPwnWatch() *PwnWatch {
	client := &http.Client{
		Timeout:   90 * time.Second,
		Transport: &uaTransport{ua: userAgent, rt: rssHTTPTransport()},
	}
	return newPwnWatch(client, pwnWatchChangesURL, pwnWatchIncidentURL)
}

func newPwnWatch(client *http.Client, changesURL, incidentBaseURL string) *PwnWatch {
	return &PwnWatch{client: client, changesURL: changesURL, incidentBaseURL: strings.TrimRight(incidentBaseURL, "/")}
}

func (p *PwnWatch) Name() string { return "pwn-watch" }

func (p *PwnWatch) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.changesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating pwn.watch changes request: %w", err)
	}
	p.validatorMu.Lock()
	etag, lastModified := p.etag, p.lastModified
	p.validatorMu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching pwn.watch changes: %w", err)
	}
	defer discardClose(resp.Body)
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if err := pwnWatchHTTPStatus(resp, "changes"); err != nil {
		return nil, err
	}
	var changes pwnWatchChanges
	if err := json.NewDecoder(resp.Body).Decode(&changes); err != nil {
		return nil, fmt.Errorf("decoding pwn.watch changes: %w", err)
	}

	slugs := changedPwnWatchIncidents(changes.Changes, since)
	items := make([]RawItem, 0, len(slugs))
	for _, slug := range slugs {
		incident, err := p.fetchIncident(ctx, slug)
		if err != nil {
			return nil, err
		}
		updatedAt, dateOnly, err := parsePwnWatchUpdatedAt(incident.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("pwn.watch incident %q has invalid updatedAt %q: %w", slug, incident.UpdatedAt, err)
		}
		if !since.IsZero() && updatedAt.Before(since) && (!dateOnly || !samePwnWatchDate(updatedAt, since)) {
			continue
		}
		items = append(items, pwnWatchRawItem(incident, updatedAt))
	}

	// Validators only advance after the changes document and every referenced
	// incident were decoded successfully. A partial outage is retried in full.
	p.validatorMu.Lock()
	p.etag = resp.Header.Get("ETag")
	p.lastModified = resp.Header.Get("Last-Modified")
	p.validatorMu.Unlock()
	return items, nil
}

func parsePwnWatchUpdatedAt(raw string) (time.Time, bool, error) {
	raw = strings.TrimSpace(raw)
	if updatedAt, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return updatedAt, false, nil
	}
	updatedAt, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, false, err
	}
	return updatedAt, true, nil
}

func samePwnWatchDate(a, b time.Time) bool {
	return a.UTC().Format("2006-01-02") == b.UTC().Format("2006-01-02")
}

func changedPwnWatchIncidents(changes []pwnWatchChange, since time.Time) []string {
	seen := make(map[string]bool)
	var slugs []string
	for _, change := range changes {
		slug := strings.TrimSpace(change.Incident)
		if slug == "" || seen[slug] || !pwnWatchDateMayBeNew(change.Date, since) {
			continue
		}
		seen[slug] = true
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs
}

func pwnWatchDateMayBeNew(raw string, since time.Time) bool {
	if since.IsZero() || strings.TrimSpace(raw) == "" {
		return true
	}
	date, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return true
	}
	sinceDate := time.Date(since.UTC().Year(), since.UTC().Month(), since.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return !date.Before(sinceDate)
}

func (p *PwnWatch) fetchIncident(ctx context.Context, slug string) (pwnWatchIncident, error) {
	endpoint := p.incidentBaseURL + "/" + url.PathEscape(slug) + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return pwnWatchIncident{}, fmt.Errorf("creating pwn.watch incident request %q: %w", slug, err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return pwnWatchIncident{}, fmt.Errorf("fetching pwn.watch incident %q: %w", slug, err)
	}
	defer discardClose(resp.Body)
	if err := pwnWatchHTTPStatus(resp, "incident "+slug); err != nil {
		return pwnWatchIncident{}, err
	}
	var incident pwnWatchIncident
	if err := json.NewDecoder(resp.Body).Decode(&incident); err != nil {
		return pwnWatchIncident{}, fmt.Errorf("decoding pwn.watch incident %q: %w", slug, err)
	}
	if strings.TrimSpace(incident.Slug) == "" {
		incident.Slug = slug
	}
	return incident, nil
}

func pwnWatchHTTPStatus(resp *http.Response, resource string) error {
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPErrorBodyBytes+1))
	truncated := len(body) > maxHTTPErrorBodyBytes
	if truncated {
		body = body[:maxHTTPErrorBodyBytes]
	}
	detail := strings.Join(strings.Fields(string(body)), " ")
	if truncated {
		detail += " … (truncated)"
	}
	return statusErrorf(resp.StatusCode, "fetching pwn.watch %s: http error: %s: %s", resource, resp.Status, detail)
}

func pwnWatchRawItem(incident pwnWatchIncident, updatedAt time.Time) RawItem {
	incidentURL := strings.TrimSpace(incident.URL)
	if incidentURL == "" {
		incidentURL = pwnWatchIncidentURL + "/" + url.PathEscape(incident.Slug)
	}
	metadata := make(map[string]string, len(incident.Sources)+len(incident.Timeline)+1)
	metadata["incident_slug"] = incident.Slug
	seenSourceURLs := make(map[string]bool)
	seenReferenceURLs := make(map[string]bool)
	sourceURLs := make([]string, 0, len(incident.Sources))
	sourceURLIndex := 0
	addSourceURL := func(raw string) {
		raw = strings.TrimSpace(raw)
		if !isHTTPURL(raw) {
			return
		}
		if seenSourceURLs[raw] {
			return
		}
		seenSourceURLs[raw] = true
		metadata[fmt.Sprintf("source_url_%03d", sourceURLIndex)] = raw
		sourceURLIndex++
	}
	referenceURLIndex := 0
	addReferenceURL := func(raw string) {
		raw = strings.TrimSpace(raw)
		if !isHTTPURL(raw) || seenReferenceURLs[raw] || referenceURLIndex >= pwnWatchMaxReferenceURLs {
			return
		}
		seenReferenceURLs[raw] = true
		metadata[fmt.Sprintf("reference_url_%03d", referenceURLIndex)] = raw
		referenceURLIndex++
	}
	for _, source := range incident.Sources {
		addSourceURL(source.URL)
		if isHTTPURL(source.URL) {
			sourceURLs = append(sourceURLs, source.URL)
		}
		if strings.EqualFold(source.Kind, "advisory") || strings.EqualFold(source.Kind, "writeup") {
			addReferenceURL(source.URL)
		}
	}
	for _, event := range incident.Timeline {
		addSourceURL(event.SourceURL)
	}
	// Some incidents contain only news links. Preserve a small fallback set so
	// corroboration still has visible provenance without flooding the brief.
	if referenceURLIndex == 0 {
		for _, sourceURL := range sourceURLs {
			if referenceURLIndex >= pwnWatchFallbackReference {
				break
			}
			addReferenceURL(sourceURL)
		}
	}

	content := formatPwnWatchIncident(incident)
	revision := updatedAt.UTC().Format(time.RFC3339Nano)
	if _, err := time.Parse("2006-01-02", strings.TrimSpace(incident.UpdatedAt)); err == nil {
		// A date-only revision can change more than once in a day. Include a
		// short content digest so a later snapshot is not hidden by seen-state.
		digest := sha256.Sum256([]byte(content))
		revision = fmt.Sprintf("%s:%x", strings.TrimSpace(incident.UpdatedAt), digest[:6])
	}

	return RawItem{
		SourceID:            fmt.Sprintf("pwn-watch:%s:%s", incident.Slug, revision),
		Source:              "pwn-watch",
		Title:               incident.Title,
		URL:                 incidentURL,
		Content:             content,
		PublishedAt:         updatedAt.UTC(),
		Metadata:            metadata,
		BodyCVEsAreSubjects: true,
		CorroborationOnly:   true,
		Enriched:            true,
	}
}

func isHTTPURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func formatPwnWatchIncident(incident pwnWatchIncident) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Incident: %s\nStatus: %s\nSeverity: %s\nPatch status: %s\n", incident.Title, incident.Status, incident.Severity, incident.PatchStatus)
	if incident.Product != "" {
		fmt.Fprintf(&out, "Product: %s\n", incident.Product)
	}
	if incident.StartedAt != "" {
		fmt.Fprintf(&out, "Started: %s\n", incident.StartedAt)
	}
	if incident.Summary != "" {
		fmt.Fprintf(&out, "\nSummary:\n%s\n", incident.Summary)
	}
	writePwnWatchList(&out, "CVE IDs", incident.CVEIDs)
	writePwnWatchList(&out, "Affected versions", incident.AffectedVersions)
	writePwnWatchList(&out, "Fixed versions", incident.FixedVersions)
	writePwnWatchList(&out, "Tags", incident.Tags)
	if len(incident.Timeline) > 0 {
		out.WriteString("\nTimeline:\n")
		for _, event := range incident.Timeline {
			fmt.Fprintf(&out, "- %s: %s", event.Date, event.Title)
			if event.SourceURL != "" {
				fmt.Fprintf(&out, " (%s)", event.SourceURL)
			}
			out.WriteByte('\n')
		}
	}
	if len(incident.Sources) > 0 {
		out.WriteString("\nUnderlying sources:\n")
		for _, source := range incident.Sources {
			fmt.Fprintf(&out, "- %s — %s", source.Publisher, source.Title)
			if source.Date != "" {
				fmt.Fprintf(&out, " (%s)", source.Date)
			}
			if source.URL != "" {
				fmt.Fprintf(&out, ": %s", source.URL)
			}
			out.WriteByte('\n')
		}
	}
	return strings.TrimSpace(out.String())
}

func writePwnWatchList(out *strings.Builder, heading string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s:\n", heading)
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			fmt.Fprintf(out, "- %s\n", value)
		}
	}
}
