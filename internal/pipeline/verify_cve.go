package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// CVEMeta holds the full enriched metadata for a verified CVE.
type CVEMeta struct {
	Exists         bool
	CVSS           float64
	CVSSVector     string
	EPSS           float64
	EPSSPercentile float64
	CPEs           []string // vulnerable CPE URIs from NVD configurations
	Description    string   // English NVD description, used for deterministic scope enrichment
	// SourceIdentifier is NVD's sourceIdentifier (the CNA / submitter, e.g.
	// security@android.com).
	SourceIdentifier string
	CachedAt         time.Time
}

const cveCacheTTL = 24 * time.Hour
const cveCacheMaxSize = 10000

// maxNVDRecordBytes bounds one NVD API response for a single CVE.
const maxNVDRecordBytes = 8 << 20

// CVEVerifier checks CVE IDs against the NVD API to detect hallucinated CVEs,
// and enriches them with CVSS, EPSS, and KEV data.
type CVEVerifier struct {
	client    *http.Client
	cache     map[string]*CVEMeta
	mu        sync.Mutex
	epssCache *scraper.EPSSCache
	kev       *scraper.KEVCatalog
}

// NewCVEVerifier creates a new CVEVerifier. epssCache may be nil, which skips
// EPSS enrichment. kev is the catalog the CISA KEV source fills; nil, like a
// catalog that has not loaded yet, leaves KEV membership unknown.
func NewCVEVerifier(epssCache *scraper.EPSSCache, kev *scraper.KEVCatalog) *CVEVerifier {
	return &CVEVerifier{
		client:    &http.Client{Timeout: 10 * time.Second},
		cache:     make(map[string]*CVEMeta),
		epssCache: epssCache,
		kev:       kev,
	}
}

// KEV reports whether cveID is in the CISA KEV catalog as currently loaded.
// It is read at enrichment time rather than cached with the NVD record, so a
// CVE CISA lists after its record was cached is still marked. known is false
// while the catalog has not loaded.
func (v *CVEVerifier) KEV(cveID string) (listed, known bool) {
	if v == nil {
		return false, false
	}
	return v.kev.Lookup(cveID)
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// nvdDetailResponse is the full NVD API response with vulnerability details.
type nvdDetailResponse struct {
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVEDetail `json:"cve"`
}

type nvdCVEDetail struct {
	SourceIdentifier string           `json:"sourceIdentifier"`
	Descriptions     []nvdDescription `json:"descriptions"`
	Metrics          nvdMetrics       `json:"metrics"`
	Configurations   []nvdConfig      `json:"configurations"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssV31 []nvdCVSSV31 `json:"cvssMetricV31"`
	CvssV30 []nvdCVSSV31 `json:"cvssMetricV30"`
}

type nvdCVSSV31 struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

type nvdConfig struct {
	Nodes []nvdConfigNode `json:"nodes"`
}

type nvdConfigNode struct {
	CpeMatch []nvdCpeMatch `json:"cpeMatch"`
}

type nvdCpeMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
}

const maxCPEsPerCVE = 20

// cpesFromNVD extracts unique vulnerable CPE URIs from an NVD detail response,
// capped at maxCPEsPerCVE to keep brief frontmatter compact. Builds of one
// product version are collapsed (see CleanCPEList) before the cap so they
// can't crowd other products and versions out of the list.
func cpesFromNVD(resp *nvdDetailResponse) []string {
	if resp == nil || len(resp.Vulnerabilities) == 0 {
		return nil
	}
	var criteria []string
	for _, cfg := range resp.Vulnerabilities[0].CVE.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CpeMatch {
				if m.Vulnerable && m.Criteria != "" {
					criteria = append(criteria, m.Criteria)
				}
			}
		}
	}
	cpes := CleanCPEList(criteria)
	if len(cpes) > maxCPEsPerCVE {
		cpes = cpes[:maxCPEsPerCVE]
	}
	return cpes
}

func sourceIdentifierFromNVD(resp *nvdDetailResponse) string {
	if resp == nil || len(resp.Vulnerabilities) == 0 {
		return ""
	}
	return strings.TrimSpace(resp.Vulnerabilities[0].CVE.SourceIdentifier)
}

func descriptionFromNVD(resp *nvdDetailResponse) string {
	if resp == nil || len(resp.Vulnerabilities) == 0 {
		return ""
	}
	descriptions := resp.Vulnerabilities[0].CVE.Descriptions
	for _, d := range descriptions {
		if strings.EqualFold(d.Lang, "en") && strings.TrimSpace(d.Value) != "" {
			return strings.TrimSpace(d.Value)
		}
	}
	for _, d := range descriptions {
		if strings.TrimSpace(d.Value) != "" {
			return strings.TrimSpace(d.Value)
		}
	}
	return ""
}

// cvssFromNVD extracts the base CVSS score from an NVD detail response.
// Prefers CVSS v3.1 over v3.0; returns 0 if no metrics are available.
func cvssFromNVD(resp *nvdDetailResponse) float64 {
	score, _ := cvssScoreVectorFromNVD(resp)
	return score
}

// cvssScoreVectorFromNVD extracts base CVSS score and vector from NVD detail
// response. Prefers CVSS v3.1 over v3.0; returns zero values if unavailable.
func cvssScoreVectorFromNVD(resp *nvdDetailResponse) (float64, string) {
	if resp == nil || len(resp.Vulnerabilities) == 0 {
		return 0, ""
	}
	metrics := resp.Vulnerabilities[0].CVE.Metrics
	if len(metrics.CvssV31) > 0 {
		data := metrics.CvssV31[0].CVSSData
		return data.BaseScore, data.VectorString
	}
	if len(metrics.CvssV30) > 0 {
		data := metrics.CvssV30[0].CVSSData
		return data.BaseScore, data.VectorString
	}
	return 0, ""
}

// GetMeta returns the cached metadata for a CVE ID, or nil if not cached.
func (v *CVEVerifier) GetMeta(cveID string) *CVEMeta {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.cache[strings.ToUpper(cveID)]
}

// Verify parses the brief YAML, extracts CVE IDs, checks them against NVD,
// removes invalid ones from IOCs, and returns the (possibly modified) YAML
// along with validation notes.
func (v *CVEVerifier) Verify(ctx context.Context, briefStr string) (string, []string) {
	cves := cveRe.FindAllString(briefStr, -1)
	if len(cves) == 0 {
		return briefStr, nil
	}

	// Deduplicate.
	unique := make(map[string]bool)
	for _, cve := range cves {
		unique[strings.ToUpper(cve)] = true
	}

	// Check each CVE against NVD.
	invalid := make(map[string]bool)
	var notes []string
	count := 0
	for cve := range unique {
		exists, err := v.checkCVE(ctx, cve)
		if err != nil {
			// NVD unreachable — skip verification gracefully.
			continue
		}
		if !exists {
			invalid[cve] = true
			notes = append(notes, fmt.Sprintf("CVE %s not found in NVD — possible hallucination", cve))
		}
		count++
		// Cap at 5 CVEs per brief to avoid blocking the pipeline.
		if count >= 5 {
			break
		}
	}

	if len(invalid) == 0 {
		return briefStr, notes
	}

	// Remove invalid CVEs from IOCs.
	var brief briefYAML
	if err := yaml.Unmarshal([]byte(briefStr), &brief); err != nil {
		return briefStr, notes
	}

	modified := false
	if len(brief.IOCs) > 0 {
		var clean []briefIOC
		for _, ioc := range brief.IOCs {
			cveID := strings.ToUpper(strings.TrimSpace(ioc.Value))
			if invalid[cveID] {
				notes = append(notes, fmt.Sprintf("removed IOC with hallucinated CVE: %s", cveID))
				modified = true
				continue
			}
			clean = append(clean, ioc)
		}
		if modified {
			if len(clean) == 0 {
				brief.IOCs = nil
			} else {
				brief.IOCs = clean
			}
		}
	}

	if !modified {
		return briefStr, notes
	}

	out, err := yaml.Marshal(&brief)
	if err != nil {
		return briefStr, notes
	}
	return string(out), notes
}

// checkCVE queries the NVD API for a single CVE ID, enriches with EPSS data,
// caches the result, and returns whether the CVE exists.
func (v *CVEVerifier) checkCVE(ctx context.Context, cveID string) (bool, error) {
	v.mu.Lock()
	if entry, cached := v.cache[cveID]; cached && time.Since(entry.CachedAt) < cveCacheTTL {
		v.mu.Unlock()
		return entry.Exists, nil
	}
	v.mu.Unlock()

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("NVD API request failed: %w", err)
	}
	// Closing a response body only releases the connection after its result is handled.
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 500 {
		return false, fmt.Errorf("NVD API returned %d", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		// 403/429 — treat as unreachable, skip gracefully.
		return false, fmt.Errorf("NVD API returned %d", resp.StatusCode)
	}

	// A single CVE record: the largest seen (CVE-2017-5753, thousands of CPE
	// matches) is ~230KB. An oversized record skips verification like any
	// other NVD failure.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxNVDRecordBytes+1))
	if err != nil {
		return false, err
	}
	if len(body) > maxNVDRecordBytes {
		return false, fmt.Errorf("NVD record for %s exceeds %d bytes", cveID, maxNVDRecordBytes)
	}

	var nvdDetail nvdDetailResponse
	if err := json.Unmarshal(body, &nvdDetail); err != nil {
		return false, fmt.Errorf("parsing NVD response: %w", err)
	}

	exists := len(nvdDetail.Vulnerabilities) > 0
	cvss, cvssVector := cvssScoreVectorFromNVD(&nvdDetail)
	cpes := cpesFromNVD(&nvdDetail)
	description := descriptionFromNVD(&nvdDetail)

	// Look up EPSS scores.
	var epss, epssPercentile float64
	if v.epssCache != nil {
		if score, ok := v.epssCache.Lookup(cveID); ok {
			epss = score.EPSS
			epssPercentile = score.Percentile
		}
	}

	meta := &CVEMeta{
		Exists:           exists,
		CVSS:             cvss,
		CVSSVector:       cvssVector,
		EPSS:             epss,
		EPSSPercentile:   epssPercentile,
		CPEs:             cpes,
		Description:      description,
		SourceIdentifier: sourceIdentifierFromNVD(&nvdDetail),
		CachedAt:         time.Now(),
	}

	v.mu.Lock()
	// Evict oldest entries if cache exceeds max size.
	if len(v.cache) >= cveCacheMaxSize {
		cutoff := time.Now().Add(-cveCacheTTL)
		for k, entry := range v.cache {
			if entry.CachedAt.Before(cutoff) {
				delete(v.cache, k)
			}
		}
		// If still too large after TTL eviction, clear the oldest half.
		if len(v.cache) >= cveCacheMaxSize {
			count := 0
			for k := range v.cache {
				delete(v.cache, k)
				count++
				if count >= cveCacheMaxSize/2 {
					break
				}
			}
		}
	}
	v.cache[cveID] = meta
	v.mu.Unlock()

	return exists, nil
}
