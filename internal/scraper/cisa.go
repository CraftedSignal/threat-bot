package scraper

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	cisaRSSURL           = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
	cisaCSAFBaseURL      = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files"
	maxCISAChangesBytes  = 512 << 10
	maxCISAAdvisoryBytes = 2 << 20
	maxCISAItemsPerPoll  = 100
)

var cisaCSAFAreas = []string{"IT", "OT", "VA"}

// CISA consumes the agency's official CSAF distribution. The legacy RSS feed
// remains a fallback for an outage of that distribution, but it is no longer
// the primary path because CISA's Akamai policy denies public feed requests
// from cloud egress even when they carry browser-like headers.
type CISA struct {
	*RSS
	csafBaseURL string
}

func NewCISA() *CISA {
	return &CISA{
		RSS:         NewRSS("cisa", cisaRSSURL),
		csafBaseURL: cisaCSAFBaseURL,
	}
}

func (c *CISA) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	items, csafErr := c.pollCSAF(ctx, since)
	if csafErr == nil {
		return items, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	items, rssErr := c.RSS.Poll(ctx, since)
	if rssErr == nil {
		return items, nil
	}
	return nil, fmt.Errorf("CISA CSAF distribution failed: %v; RSS fallback failed: %w", csafErr, rssErr)
}

type cisaChange struct {
	area      string
	path      string
	published time.Time
}

func (c *CISA) pollCSAF(ctx context.Context, since time.Time) ([]RawItem, error) {
	changesByID := make(map[string]cisaChange)
	for _, area := range cisaCSAFAreas {
		areaChanges, err := c.fetchChanges(ctx, area, since)
		if err != nil {
			return nil, err
		}
		for _, change := range areaChanges {
			id := strings.ToUpper(strings.TrimSuffix(path.Base(change.path), ".json"))
			current, exists := changesByID[id]
			if !exists || change.published.After(current.published) {
				changesByID[id] = change
			}
		}
	}

	changes := make([]cisaChange, 0, len(changesByID))
	for _, change := range changesByID {
		changes = append(changes, change)
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].published.Equal(changes[j].published) {
			if changes[i].area == changes[j].area {
				return changes[i].path < changes[j].path
			}
			return changes[i].area < changes[j].area
		}
		return changes[i].published.Before(changes[j].published)
	})
	if len(changes) > maxCISAItemsPerPoll {
		changes = changes[:maxCISAItemsPerPoll]
	}
	items := make([]RawItem, 0, len(changes))
	for _, change := range changes {
		item, err := c.fetchAdvisory(ctx, change)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (c *CISA) fetchChanges(ctx context.Context, area string, since time.Time) ([]cisaChange, error) {
	changesURL := fmt.Sprintf("%s/%s/white/changes.csv", c.csafBaseURL, area)
	body, err := c.fetchBounded(ctx, changesURL, maxCISAChangesBytes)
	if err != nil {
		return nil, fmt.Errorf("fetching CISA CSAF %s changes: %w", area, err)
	}

	reader := csv.NewReader(strings.NewReader(string(body)))
	reader.FieldsPerRecord = 2
	var changes []cisaChange
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing CISA CSAF %s changes: %w", area, err)
		}
		relativePath := strings.TrimSpace(record[0])
		if !validCISACSAFPath(relativePath) {
			return nil, fmt.Errorf("parsing CISA CSAF %s changes: unsafe advisory path %q", area, relativePath)
		}
		published, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(record[1]))
		if err != nil {
			return nil, fmt.Errorf("parsing CISA CSAF %s change time for %s: %w", area, relativePath, err)
		}
		if published.Before(since) {
			continue
		}
		changes = append(changes, cisaChange{area: area, path: relativePath, published: published})
	}
	return changes, nil
}

func validCISACSAFPath(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && len(parts[0]) == 4 && path.Clean(value) == value &&
		!strings.Contains(parts[1], "..") && strings.HasSuffix(parts[1], ".json")
}

type cisaCSAFDocument struct {
	Document struct {
		Title      string          `json:"title"`
		Tracking   cisaTracking    `json:"tracking"`
		Notes      []cisaNote      `json:"notes"`
		References []cisaReference `json:"references"`
	} `json:"document"`
	Vulnerabilities []cisaVulnerability `json:"vulnerabilities"`
}

type cisaTracking struct {
	ID string `json:"id"`
}

type cisaNote struct {
	Category string `json:"category"`
	Title    string `json:"title"`
	Text     string `json:"text"`
}

type cisaReference struct {
	Category string `json:"category"`
	URL      string `json:"url"`
}

type cisaVulnerability struct {
	CVE          string            `json:"cve"`
	Title        string            `json:"title"`
	Notes        []cisaNote        `json:"notes"`
	Remediations []cisaRemediation `json:"remediations"`
}

type cisaRemediation struct {
	Details string `json:"details"`
	URL     string `json:"url"`
}

func (c *CISA) fetchAdvisory(ctx context.Context, change cisaChange) (RawItem, error) {
	documentURL := fmt.Sprintf("%s/%s/white/%s", c.csafBaseURL, change.area, change.path)
	body, err := c.fetchBounded(ctx, documentURL, maxCISAAdvisoryBytes)
	if err != nil {
		return RawItem{}, fmt.Errorf("fetching CISA CSAF advisory %s: %w", change.path, err)
	}

	var document cisaCSAFDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return RawItem{}, fmt.Errorf("parsing CISA CSAF advisory %s: %w", change.path, err)
	}
	if strings.TrimSpace(document.Document.Tracking.ID) == "" || strings.TrimSpace(document.Document.Title) == "" {
		return RawItem{}, fmt.Errorf("parsing CISA CSAF advisory %s: missing tracking id or title", change.path)
	}

	canonicalURL := cisaCanonicalURL(document.Document.References)
	sourceID := "cisa:" + strings.ToUpper(document.Document.Tracking.ID)
	itemURL := documentURL
	if canonicalURL != "" {
		sourceID = "cisa:" + canonicalURL
		itemURL = canonicalURL
	}

	return RawItem{
		SourceID:            sourceID,
		Source:              "cisa",
		Title:               document.Document.Title,
		URL:                 itemURL,
		Content:             cisaAdvisoryContent(document),
		PublishedAt:         change.published,
		BodyCVEsAreSubjects: true,
		Metadata: map[string]string{
			"csaf_tracking_id": strings.ToUpper(document.Document.Tracking.ID),
			"csaf_area":        change.area,
		},
	}, nil
}

func cisaCanonicalURL(references []cisaReference) string {
	for _, reference := range references {
		if reference.Category != "self" {
			continue
		}
		parsed, err := url.Parse(reference.URL)
		if err == nil && parsed.Scheme == "https" && (parsed.Hostname() == "www.cisa.gov" || parsed.Hostname() == "cisa.gov") {
			return parsed.String()
		}
	}
	return ""
}

func cisaAdvisoryContent(document cisaCSAFDocument) string {
	var sections []string
	for _, note := range document.Document.Notes {
		if note.Category == "legal_disclaimer" || strings.TrimSpace(note.Text) == "" {
			continue
		}
		sections = append(sections, strings.TrimSpace(note.Title+": "+note.Text))
	}
	for _, vulnerability := range document.Vulnerabilities {
		heading := strings.TrimSpace(vulnerability.CVE + " " + vulnerability.Title)
		if heading != "" {
			sections = append(sections, heading)
		}
		for _, note := range vulnerability.Notes {
			if strings.TrimSpace(note.Text) != "" {
				sections = append(sections, strings.TrimSpace(note.Title+": "+note.Text))
			}
		}
		for _, remediation := range vulnerability.Remediations {
			if strings.TrimSpace(remediation.Details) != "" {
				sections = append(sections, "Remediation: "+strings.TrimSpace(remediation.Details))
			}
		}
	}
	return strings.Join(sections, "\n\n")
}

func (c *CISA) fetchBounded(ctx context.Context, target string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/csv;q=0.9, text/plain;q=0.8")
	resp, err := c.parser.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPErrorBodyBytes))
		return nil, statusErrorf(resp.StatusCode, "HTTP %s: %s", resp.Status, strings.Join(strings.Fields(string(body)), " "))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, nil
}
