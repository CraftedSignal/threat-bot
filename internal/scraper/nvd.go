package scraper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/cna"
)

const (
	nvdAPIURL         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdResultsPerPage = 100
	// Critical CVEs get up to 150 slots; high CVEs fill the remaining 50.
	// This prevents a high-volume Patch Tuesday from crowding out critical CVEs.
	nvdMaxCritical = 150
	nvdMaxHigh     = 50
	nvdRateDelay   = 6 * time.Second
	// The awaiting-analysis sweep reads every CVE published in the window, so
	// it pages; 5 pages cover more than NVD publishes in a typical day.
	nvdMaxSweepPages = 5
	// Corrections can concern old publications and need their own bounded sweep.
	// Hitting this cap is an incomplete poll, so the caller retains its cursor.
	nvdMaxModifiedPages = 5
	nvdModifiedPageSize = 2000
)

// NVD scrapes NIST National Vulnerability Database for high/critical CVEs.
// Critical CVEs are fetched first and given priority within the result cap.
type NVD struct {
	client *http.Client
	logger *slog.Logger
	// pageDelay spaces out requests to stay within NVD's public rate limit;
	// zero means nvdRateDelay.
	pageDelay time.Duration
}

func NewNVD() *NVD {
	// NVD's services.nvd.nist.gov routinely exceeds 90s during busy windows.
	// 180s is the empirical p99 from prod logs; beyond that, per-page retries
	// compound latency without adding signal.
	return &NVD{
		client: &http.Client{Timeout: 180 * time.Second},
		logger: slog.Default(),
	}
}

func (n *NVD) WithLogger(logger *slog.Logger) *NVD {
	n.logger = logger
	return n
}

func (n *NVD) Name() string { return "nvd" }

func (n *NVD) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	return n.pollFrom(ctx, since, nvdAPIURL)
}

func (n *NVD) pollFrom(ctx context.Context, since time.Time, apiURL string) ([]RawItem, error) {
	pubStart := since.UTC().Format("2006-01-02T15:04:05.000")
	pubEnd := time.Now().UTC().Format("2006-01-02T15:04:05.000")

	critical, err := n.pollSeverity(ctx, apiURL, pubStart, pubEnd, "CRITICAL", nvdMaxCritical)
	if err != nil {
		return nil, err
	}

	remaining := nvdMaxHigh
	if len(critical) < nvdMaxCritical {
		// Unused critical slots can be reallocated to high.
		remaining += nvdMaxCritical - len(critical)
	}

	high, err := n.pollSeverity(ctx, apiURL, pubStart, pubEnd, "HIGH", remaining)
	if err != nil && len(critical) == 0 {
		return nil, err
	}

	// Third pass: catch entries whose primary CVSS is "Awaiting
	// Analysis" but a secondary source (Red Hat, Linux kernel CNA,
	// vendor PSIRT) has scored them ≥7.0. NVD's cvssV3Severity URL
	// filter only honors primary scoring, so without this pass we
	// miss every high-CVSS Linux kernel CVE between publication and
	// NVD-analyst review (~weeks).
	awaiting, err := n.pollAwaitingAnalysis(ctx, apiURL, pubStart, pubEnd)
	if err != nil {
		// Non-fatal: keep whatever critical+high already gave us.
		n.log("awaiting-analysis sweep failed", "error", boundedScraperError(err))
	}
	modified, modifiedErr := n.pollModified(ctx, apiURL, pubStart, pubEnd)

	// A record can appear in both date windows. Prefer its newest evidence,
	// rather than letting the publication pass hide a later correction.
	var items []RawItem
	seen := make(map[string]int)
	for _, batch := range [][]RawItem{critical, high, awaiting, modified} {
		for _, item := range batch {
			if i, ok := seen[item.SourceID]; ok {
				if item.UpdatedAt.After(items[i].UpdatedAt) {
					items[i] = item
				}
				continue
			}
			seen[item.SourceID] = len(items)
			items = append(items, item)
		}
	}
	if modifiedErr != nil {
		return items, fmt.Errorf("NVD modified-record sweep incomplete: %w", modifiedErr)
	}
	return items, nil
}

// pollModified uses modification dates without a publication-date restriction:
// a correction to a years-old CVE still belongs in this polling window. The
// same score filter as normal ingestion includes secondary-scored records.
func (n *NVD) pollModified(ctx context.Context, apiURL, start, end string) ([]RawItem, error) {
	var items []RawItem
	for page := range nvdMaxModifiedPages {
		select {
		case <-ctx.Done():
			return items, ctx.Err()
		case <-time.After(n.rateDelay()):
		}
		startIndex := page * nvdModifiedPageSize
		query := fmt.Sprintf("%s?lastModStartDate=%s&lastModEndDate=%s&resultsPerPage=%d&startIndex=%d", apiURL, start, end, nvdModifiedPageSize, startIndex)
		batch, total, err := n.fetchPageMode(ctx, query, true)
		if err != nil {
			return items, err
		}
		items = append(items, batch...)
		if startIndex+nvdModifiedPageSize >= total {
			return items, nil
		}
	}
	return items, fmt.Errorf("modified-record page limit (%d) reached", nvdMaxModifiedPages)
}

// pollAwaitingAnalysis reads every non-rejected CVE published in the
// window. NVD API 2.0 has no filter for vuln status "Awaiting Analysis", so
// the sweep relies on extractCVSS reading any source's score: entries scored
// only by a secondary source still pass the score filter inside fetchPage.
// NVD's boolean filters are presence flags, so only noRejected is sent; an
// empty hasCertAlerts= would keep just CVEs with CERT alerts, and
// isVulnerable without a cpeName is rejected with HTTP 404.
func (n *NVD) pollAwaitingAnalysis(ctx context.Context, apiURL, pubStart, pubEnd string) ([]RawItem, error) {
	var allItems []RawItem
	for page := range nvdMaxSweepPages {
		// The severity passes have just queried NVD, so every sweep page waits.
		select {
		case <-ctx.Done():
			return allItems, ctx.Err()
		case <-time.After(n.rateDelay()):
		}

		startIndex := page * nvdResultsPerPage
		url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&noRejected&resultsPerPage=%d&startIndex=%d",
			apiURL, pubStart, pubEnd, nvdResultsPerPage, startIndex)
		items, totalResults, err := n.fetchPage(ctx, url)
		if err != nil {
			if len(allItems) > 0 {
				return allItems, nil
			}
			return nil, err
		}
		allItems = append(allItems, items...)
		if startIndex+nvdResultsPerPage >= totalResults {
			break
		}
	}
	return allItems, nil
}

func (n *NVD) rateDelay() time.Duration {
	if n.pageDelay > 0 {
		return n.pageDelay
	}
	return nvdRateDelay
}

// log is a small wrapper so the scraper can emit warnings without
// requiring a *slog.Logger field on every call site.
func (n *NVD) log(msg string, args ...any) {
	if n.logger != nil {
		n.logger.Warn(msg, args...)
	}
}

func (n *NVD) pollSeverity(ctx context.Context, apiURL, pubStart, pubEnd, severity string, max int) ([]RawItem, error) {
	var allItems []RawItem
	startIndex := 0

	for len(allItems) < max {

		if startIndex > 0 {
			select {
			case <-ctx.Done():
				return allItems, ctx.Err()
			case <-time.After(n.rateDelay()):
			}
		}

		url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&cvssV3Severity=%s&resultsPerPage=%d&startIndex=%d",
			apiURL, pubStart, pubEnd, severity, nvdResultsPerPage, startIndex)

		items, totalResults, err := n.fetchPage(ctx, url)
		if err != nil {
			if len(allItems) > 0 {
				return allItems, nil
			}
			return nil, err
		}

		allItems = append(allItems, items...)
		startIndex += nvdResultsPerPage

		if startIndex >= totalResults {
			break
		}
	}

	if len(allItems) > max {
		allItems = allItems[:max]
	}
	return allItems, nil
}

// FetchItems returns the items for the given source IDs ("nvd:CVE-…"), built
// as a poll builds them, by querying each CVE. A wide poll cannot replay older
// CVEs: its result caps keep only the oldest of the window. CVEs that NVD no
// longer lists, or that no longer pass the score filter, are left out.
func (n *NVD) FetchItems(ctx context.Context, sourceIDs []string) ([]RawItem, error) {
	return n.fetchItemsFrom(ctx, nvdAPIURL, sourceIDs)
}

func (n *NVD) fetchItemsFrom(ctx context.Context, apiURL string, sourceIDs []string) ([]RawItem, error) {
	var items []RawItem
	var errs []error
	for i, sourceID := range sourceIDs {
		if i > 0 {
			select {
			case <-ctx.Done():
				return items, ctx.Err()
			case <-time.After(n.rateDelay()):
			}
		}
		cveID := strings.TrimPrefix(sourceID, "nvd:")
		page, _, err := n.fetchPage(ctx, fmt.Sprintf("%s?cveId=%s", apiURL, cveID))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sourceID, err))
			continue
		}
		items = append(items, page...)
	}
	return items, errors.Join(errs...)
}

func (n *NVD) fetchPage(ctx context.Context, url string) ([]RawItem, int, error) {
	return n.fetchPageMode(ctx, url, false)
}

func (n *NVD) fetchPageMode(ctx context.Context, url string, includeCorrections bool) ([]RawItem, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := n.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, 0, statusErrorf(resp.StatusCode, "NVD API HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("decoding NVD response: %w", err)
	}

	var items []RawItem
	for _, vuln := range result.Vulnerabilities {
		cve := vuln.CVE

		// A downgrade or retraction must still reach an already-published CVE.
		// Publication-window ingestion keeps its high/critical threshold.
		score, scoreStr := n.extractCVSS(cve)
		correctionOnly := score < 7.0 || strings.EqualFold(cve.VulnStatus, "Rejected")
		if correctionOnly && !includeCorrections {
			continue
		}

		published := parseNVDTimestamp(cve.Published)
		updated := parseNVDTimestamp(cve.LastModified)
		if updated.IsZero() {
			updated = published
		}

		description := n.extractDescription(cve)
		cpeList := n.extractCPEs(cve)

		var contentParts []string
		contentParts = append(contentParts, description)
		contentParts = append(contentParts, fmt.Sprintf("\nCVSS v3.1 Base Score: %s", scoreStr))
		if len(cpeList) > 0 {
			contentParts = append(contentParts, fmt.Sprintf("\nAffected Products:\n- %s", strings.Join(cpeList, "\n- ")))
		}

		titleDesc := description
		if len(titleDesc) > 100 {
			titleDesc = titleDesc[:100] + "..."
		}

		items = append(items, RawItem{
			SourceID:          fmt.Sprintf("nvd:%s", cve.ID),
			Source:            "nvd",
			Title:             fmt.Sprintf("%s — %s", cve.ID, titleDesc),
			URL:               fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID),
			Content:           strings.Join(contentParts, "\n"),
			PublishedAt:       published,
			UpdatedAt:         updated,
			Metadata:          nvdItemMetadata(cve, scoreStr, cpeList),
			CorroborationOnly: correctionOnly,
		})
	}

	return items, result.TotalResults, nil
}

func parseNVDTimestamp(value string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

// nvdItemMetadata records NVD's own vendor data (CNA and vulnerable CPEs) on
// the item so downstream routing can check vendor claims without another
// NVD request. CPEs are space-separated (CPE URIs never contain spaces).
func nvdItemMetadata(cve nvdCVE, scoreStr string, cpes []string) map[string]string {
	md := map[string]string{
		"cve":  cve.ID,
		"cvss": scoreStr,
	}
	if id := strings.TrimSpace(cve.SourceIdentifier); id != "" {
		md["source_identifier"] = id
	}
	if status := strings.TrimSpace(cve.VulnStatus); status != "" {
		md["vuln_status"] = status
	}
	if len(cpes) > 0 {
		md["cpes"] = strings.Join(cpes, " ")
	}
	if ranges := nvdAffectedRanges(cve); ranges != "" {
		md["affected_ranges"] = ranges
	}
	var advisoryURLs []string
	cnaDomain := nvdCNADomain(cve.SourceIdentifier)
	for _, ref := range cve.References {
		vendorTagged := false
		for _, tag := range ref.Tags {
			if strings.EqualFold(strings.TrimSpace(tag), "Vendor Advisory") && strings.TrimSpace(ref.URL) != "" {
				vendorTagged = true
				break
			}
		}
		if strings.TrimSpace(ref.URL) == "" || (!vendorTagged && !referenceMatchesCNADomain(ref.URL, cnaDomain)) {
			continue
		}
		advisoryURLs = append(advisoryURLs, strings.TrimSpace(ref.URL))
	}
	if len(advisoryURLs) > 0 {
		if encoded, err := json.Marshal(advisoryURLs); err == nil {
			md["vendor_advisory_urls"] = string(encoded)
		}
	}
	return md
}

// nvdCNADomain returns the domain from NVD's CNA/source identifier when it is
// vendor-specific. Coordinators and third-party CNAs cannot establish that an
// untagged reference is a vendor advisory.
func nvdCNADomain(sourceIdentifier string) string {
	return cna.VendorDomain(sourceIdentifier)
}

func referenceMatchesCNADomain(rawURL, cnaDomain string) bool {
	if cnaDomain == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	return host == cnaDomain || strings.HasSuffix(host, "."+cnaDomain)
}

// extractCVSS returns the highest CVSS v3.1 base score across all
// metric sources (Primary + Secondary). NVD assigns Primary only after
// analyst review; for "Awaiting Analysis" entries the only score
// present is from a downstream source like Red Hat or the Linux
// kernel CNA. Honoring those means we catch high-impact CVEs
// (CVE-2026-31431, the Linux kernel crypto fix at 7.8 HIGH) on the
// day they're published rather than waiting for primary review.
func (n *NVD) extractCVSS(cve nvdCVE) (float64, string) {
	if m := cve.Metrics; m != nil {
		var best float64
		for _, v31 := range m.CvssMetricV31 {
			if v31.CVSSData.BaseScore > best {
				best = v31.CVSSData.BaseScore
			}
		}
		if best > 0 {
			return best, fmt.Sprintf("%.1f", best)
		}
	}
	return 0, "0.0"
}

func (n *NVD) extractDescription(cve nvdCVE) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	if len(cve.Descriptions) > 0 {
		return cve.Descriptions[0].Value
	}
	return ""
}

func (n *NVD) extractCPEs(cve nvdCVE) []string {
	seen := make(map[string]bool)
	var cpes []string
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				// vulnerable:false entries are platform/context CPEs (e.g. the
				// OS an app runs on), not affected software.
				if !match.Vulnerable || match.Criteria == "" {
					continue
				}
				if !seen[match.Criteria] {
					seen[match.Criteria] = true
					cpes = append(cpes, match.Criteria)
				}
			}
		}
	}
	return cpes
}

// NVD API 2.0 response types.

type nvdResponse struct {
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	SourceIdentifier string             `json:"sourceIdentifier"`
	ID               string             `json:"id"`
	Published        string             `json:"published"`
	LastModified     string             `json:"lastModified"`
	VulnStatus       string             `json:"vulnStatus"`
	Descriptions     []nvdDescription   `json:"descriptions"`
	Metrics          *nvdMetrics        `json:"metrics"`
	Configurations   []nvdConfiguration `json:"configurations"`
	References       []nvdReference     `json:"references"`
}

type nvdReference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCvssMetric `json:"cvssMetricV31"`
}

type nvdCvssMetric struct {
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// versionRange renders the bounds of m as "<op> v, ..." (for example
// ">= 1.0, < 1.4.2"), or "" when the match carries no version bound.
func (m nvdCPEMatch) versionRange() string {
	var parts []string
	for _, b := range []struct{ op, v string }{
		{">=", m.VersionStartIncluding},
		{">", m.VersionStartExcluding},
		{"<=", m.VersionEndIncluding},
		{"<", m.VersionEndExcluding},
	} {
		if v := strings.TrimSpace(b.v); v != "" {
			parts = append(parts, b.op+" "+v)
		}
	}
	return strings.Join(parts, ", ")
}

// nvdAffectedRanges renders the vulnerable version ranges NVD lists per
// product as one "vendor product: range; range" line per product, in first-seen
// order. Matches without a version bound add nothing.
func nvdAffectedRanges(cve nvdCVE) string {
	var order []string
	ranges := map[string][]string{}
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				r := match.versionRange()
				if r == "" {
					continue
				}
				parts := strings.Split(match.Criteria, ":")
				if len(parts) < 5 {
					continue
				}
				name := strings.ReplaceAll(parts[3], "_", " ") + " " + strings.ReplaceAll(parts[4], "_", " ")
				if parts[3] == "*" || parts[3] == "-" {
					name = strings.ReplaceAll(parts[4], "_", " ")
				}
				if !slices.Contains(ranges[name], r) {
					if _, ok := ranges[name]; !ok {
						order = append(order, name)
					}
					ranges[name] = append(ranges[name], r)
				}
			}
		}
	}
	lines := make([]string, 0, len(order))
	for _, name := range order {
		lines = append(lines, name+": "+strings.Join(ranges[name], "; "))
	}
	return strings.Join(lines, "\n")
}
