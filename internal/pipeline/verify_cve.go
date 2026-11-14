package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// CVEMeta holds the full enriched metadata for a verified CVE.
type CVEVerification struct {
	Status    string    `json:"status" yaml:"status"`
	Source    string    `json:"source" yaml:"source"`
	CheckedAt time.Time `json:"checked_at" yaml:"checked_at"`
}

type CVEMeta struct {
	Verification   CVEVerification
	Exists         bool
	CVSS           float64
	CVSSVector     string
	EPSS           float64
	EPSSPercentile float64
	CPEs           []string // vulnerable CPE URIs from NVD configurations
	Description    string   // English NVD description, used for deterministic scope enrichment
	CNAFacts       []cnaSourceFact
	CNAGap         string // Explicit coverage uncertainty, never evidence that no fix exists.
	CNAChecked     bool
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
	client      *http.Client
	cache       map[string]*CVEMeta
	mu          sync.Mutex
	cnaInFlight map[string]chan struct{}
	epssCache   *scraper.EPSSCache
	kev         *scraper.KEVCatalog
}

// NewCVEVerifier creates a new CVEVerifier. epssCache may be nil, which skips
// EPSS enrichment. kev is the catalog the CISA KEV source fills; nil, like a
// catalog that has not loaded yet, leaves KEV membership unknown.
func NewCVEVerifier(epssCache *scraper.EPSSCache, kev *scraper.KEVCatalog) *CVEVerifier {
	return &CVEVerifier{
		client:      &http.Client{Timeout: 10 * time.Second},
		cache:       make(map[string]*CVEMeta),
		cnaInFlight: make(map[string]chan struct{}),
		epssCache:   epssCache,
		kev:         kev,
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
	ID               string           `json:"id"`
	VulnStatus       string           `json:"vulnStatus"`
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

// Verify checks sorted identities against NVD and the CVE Program and records
// every outcome in cve_verification. Absence and outages are not invalidity.
func (v *CVEVerifier) Verify(ctx context.Context, briefStr string) (string, []string) {
	var doc map[string]any
	if yaml.Unmarshal([]byte(briefStr), &doc) != nil || doc == nil {
		return briefStr, nil
	}
	unique := map[string]bool{}
	for _, id := range sourceCVEPattern.FindAllString(briefStr, -1) {
		unique[strings.ToUpper(id)] = true
	}
	if len(unique) == 0 {
		return briefStr, nil
	}
	ids := make([]string, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	verification := map[string]CVEVerification{}
	var notes []string
	for _, id := range ids {
		_, err := v.checkCVE(ctx, id)
		meta := v.GetMeta(id)
		status := CVEVerification{Status: "unavailable", Source: "nvd+cve_program", CheckedAt: time.Now().UTC()}
		if meta != nil {
			status = meta.Verification
			if status.Status == "" {
				status.Status = "unavailable"
			}
		}
		verification[id] = status
		if status.Status != "verified" {
			notes = append(notes, fmt.Sprintf("CVE %s verification %s via %s", id, status.Status, status.Source))
		}
		_ = err // Failure is persisted as explicit status, never confused with absence.
	}
	doc["cve_verification"] = verification
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefStr, notes
	}
	return string(out), notes
}

// checkCVE queries the NVD API for a single CVE ID, enriches with EPSS data,
// caches the result, and returns whether the CVE exists.
func (v *CVEVerifier) checkNVD(ctx context.Context, cveID string) (bool, error) {
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
	if exists && (len(nvdDetail.Vulnerabilities) != 1 || !strings.EqualFold(nvdDetail.Vulnerabilities[0].CVE.ID, cveID)) {
		return false, fmt.Errorf("NVD identity mismatch for %s", cveID)
	}
	if exists && strings.EqualFold(nvdDetail.Vulnerabilities[0].CVE.VulnStatus, "Rejected") {
		v.cacheMeta(cveID, &CVEMeta{Verification: CVEVerification{Status: "rejected", Source: "nvd", CheckedAt: time.Now().UTC()}, CachedAt: time.Now()})
		return false, nil
	}
	cvss, cvssVector := cvssScoreVectorFromNVD(&nvdDetail)
	if cvss < 0 || cvss > 10 {
		cvss, cvssVector = 0, ""
	}
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
		Verification:     CVEVerification{Status: "verified", Source: "nvd", CheckedAt: time.Now().UTC()},
		CVSS:             cvss,
		CVSSVector:       cvssVector,
		EPSS:             epss,
		EPSSPercentile:   epssPercentile,
		CPEs:             cpes,
		Description:      description,
		SourceIdentifier: sourceIdentifierFromNVD(&nvdDetail),
		CachedAt:         time.Now(),
	}

	if !exists {
		return false, nil
	}
	v.cacheMeta(cveID, meta)

	return exists, nil
}

// checkCVE checks every requested identity and records uncertainty. Negative
// results expire quickly because newly assigned IDs propagate asynchronously.
func (v *CVEVerifier) checkCVE(ctx context.Context, id string) (bool, error) {
	id = strings.ToUpper(id)
	v.mu.Lock()
	cached := v.cache[id]
	if cached != nil {
		ttl := cveCacheTTL
		if !cached.Exists {
			ttl = 5 * time.Minute
		}
		if time.Since(cached.CachedAt) < ttl {
			v.mu.Unlock()
			meta, err := v.supplementCNA(ctx, id)
			if err != nil {
				return false, err
			}
			return meta.Exists, nil
		}
		delete(v.cache, id)
	}
	v.mu.Unlock()
	exists, nvdErr := v.checkNVD(ctx, id)
	if exists && nvdErr == nil {
		meta, err := v.supplementCNA(ctx, id)
		if err != nil {
			return false, err
		}
		return meta.Exists, nil
	}
	if meta := v.GetMeta(id); meta != nil && meta.Verification.Status == "rejected" {
		return false, nil
	}
	meta, err := v.checkCVEProgram(ctx, id)
	if err != nil {
		meta = &CVEMeta{Verification: CVEVerification{Status: "unavailable", Source: "nvd+cve_program", CheckedAt: time.Now().UTC()}, CachedAt: time.Now()}
	} else if meta.Verification.Status == "not_found" && nvdErr != nil {
		meta.Verification.Status = "unavailable"
	}
	v.cacheMeta(id, meta)
	return meta.Exists, err
}

func (v *CVEVerifier) checkCVEProgram(ctx context.Context, id string) (*CVEMeta, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cveawg.mitre.org/api/cve/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	meta := &CVEMeta{Verification: CVEVerification{Status: "not_found", Source: "cve_program", CheckedAt: time.Now().UTC()}, CachedAt: time.Now()}
	if resp.StatusCode == http.StatusNotFound {
		return meta, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CVE Program returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxNVDRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxNVDRecordBytes {
		return nil, fmt.Errorf("CVE Program response exceeds limit")
	}
	var record struct {
		Metadata struct {
			ID    string `json:"cveId"`
			State string `json:"state"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA cnaSourceRecord `json:"cna"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, err
	}
	if !strings.EqualFold(record.Metadata.ID, id) {
		return nil, fmt.Errorf("CVE Program identity mismatch")
	}
	switch strings.ToUpper(record.Metadata.State) {
	case "PUBLISHED":
		meta.Exists = true
		meta.Verification.Status = "verified"
	case "REJECTED":
		meta.Verification.Status = "rejected"
	case "RESERVED":
		meta.Verification.Status = "reserved"
	default:
		return nil, fmt.Errorf("CVE Program unknown record state")
	}
	for _, d := range record.Containers.CNA.Descriptions {
		if d.Lang == "en" {
			meta.Description = d.Value
			break
		}
	}
	meta.CNAChecked = true
	if meta.Exists {
		meta.CNAFacts, meta.CNAGap = record.Containers.CNA.sourceFacts(id)
	}
	return meta, nil
}

// Supplement a verified NVD identity with the CNA fields NVD's metadata model
// does not retain. The optional request is singleflight, bounded and cached
// with this record. It cannot turn an outage or mismatched response into an
// unverified identity, a fixed version, or a claim that no fixed release exists.
func (v *CVEVerifier) supplementCNA(ctx context.Context, id string) (*CVEMeta, error) {
	for {
		v.mu.Lock()
		meta := v.cache[id]
		if meta == nil {
			v.mu.Unlock()
			return nil, fmt.Errorf("CVE metadata expired during supplemental evidence lookup for %s", id)
		}
		if !meta.Exists || meta.Verification.Status != "verified" || meta.Verification.Source != "nvd" || meta.CNAChecked {
			v.mu.Unlock()
			return meta, nil
		}
		if pending := v.cnaInFlight[id]; pending != nil {
			v.mu.Unlock()
			select {
			case <-ctx.Done():
				return meta, ctx.Err()
			case <-pending:
				continue
			}
		}
		if v.cnaInFlight == nil {
			v.cnaInFlight = make(map[string]chan struct{})
		}
		pending := make(chan struct{})
		v.cnaInFlight[id] = pending
		v.mu.Unlock()

		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		primary, err := v.checkCVEProgram(lookupCtx, id)
		cancel()
		updated := *meta // Cached records are immutable to concurrent GetMeta readers.
		updated.CNAChecked = true
		switch {
		case err != nil:
			// This status is included in model evidence. Keep transport details
			// out of it while retaining explicit uncertainty about coverage.
			updated.CNAGap = "unknown: CNA affected, remediation and prerequisite coverage unavailable"
		case primary.Exists:
			updated.CNAFacts, updated.CNAGap = primary.CNAFacts, primary.CNAGap
		case primary.Verification.Status == "rejected" || primary.Verification.Status == "reserved":
			// An explicit primary identity contradiction is not an outage.
			updated.Exists = false
			updated.Verification = primary.Verification
			updated.Verification.Source = "nvd+cve_program"
			updated.CNAGap = "CVE Program identity state conflicts with the cached NVD listing"
		default:
			updated.CNAGap = "unknown: CNA record is not available; affected, remediation and prerequisite coverage is incomplete"
		}
		v.mu.Lock()
		if current := v.cache[id]; ctx.Err() == nil && current != nil && current.Exists && current.Verification.Status == "verified" && current.Verification.Source == "nvd" {
			// A concurrent NVD response may have replaced the metadata while
			// this primary request ran. Keep its NVD fields and attach the one
			// completed primary result instead of discarding the fetched evidence.
			merged := *current
			copyCNAEvidence(&merged, &updated)
			v.cache[id] = &merged
		}
		delete(v.cnaInFlight, id)
		close(pending)
		current := v.cache[id]
		v.mu.Unlock()
		if ctx.Err() != nil {
			return current, ctx.Err()
		}
		if current == nil {
			// Cache eviction must not panic or turn a positive verified lookup
			// into a negative identity. Verify records unavailable if the entry
			// was evicted before it can persist the verification metadata.
			return &updated, nil
		}
		return current, nil
	}
}

func copyCNAEvidence(target, source *CVEMeta) {
	target.CNAFacts, target.CNAGap, target.CNAChecked = source.CNAFacts, source.CNAGap, source.CNAChecked
	if !source.Exists && (source.Verification.Status == "rejected" || source.Verification.Status == "reserved") {
		target.Exists, target.Verification = false, source.Verification
	}
}

// cnaSourceFact retains source fields rather than inferred fixes or privilege
// roles. Product-scoped fields stay attached to the product that supplied them.
type cnaSourceFact struct {
	CVEID   string `json:"cve_id"`
	Product string `json:"product,omitempty"`
	Kind    string `json:"kind"`
	Text    string `json:"text"`
}

type cnaSourceRecord struct {
	Descriptions []nvdDescription `json:"descriptions"`
	Affected     []struct {
		Vendor        string          `json:"vendor"`
		Product       string          `json:"product"`
		PackageName   string          `json:"packageName,omitempty"`
		DefaultStatus string          `json:"defaultStatus,omitempty"`
		Platforms     []string        `json:"platforms,omitempty"`
		Versions      json.RawMessage `json:"versions,omitempty"`
	} `json:"affected"`
	Solutions   []nvdDescription  `json:"solutions"`
	Workarounds []nvdDescription  `json:"workarounds"`
	Metrics     []json.RawMessage `json:"metrics"`
}

const maxCNAEvidenceBytes = 12000

func (record cnaSourceRecord) sourceFacts(id string) ([]cnaSourceFact, string) {
	var facts []cnaSourceFact
	size, truncated := 0, false
	add := func(product, kind, text string) {
		if strings.TrimSpace(text) == "" {
			return
		}
		fact := cnaSourceFact{CVEID: id, Product: product, Kind: kind, Text: text}
		raw, _ := json.Marshal(fact)
		if size+len(raw) > maxCNAEvidenceBytes || len(facts) >= 80 {
			truncated = true
			return
		}
		size += len(raw)
		facts = append(facts, fact)
	}
	// A record-wide solution is only product-scoped when the source contains
	// exactly one product. A multi-product record never transfers one product's
	// fixed version to a neighboring product.
	product := ""
	if len(record.Affected) == 1 {
		product = record.Affected[0].Product
	}
	for _, solution := range record.Solutions {
		if strings.EqualFold(solution.Lang, "en") {
			add(product, "solution", solution.Value)
		}
	}
	for _, workaround := range record.Workarounds {
		if strings.EqualFold(workaround.Lang, "en") {
			add(product, "workaround", workaround.Value)
		}
	}
	for _, metric := range record.Metrics {
		if json.Valid(metric) {
			var compact strings.Builder
			// Re-encoding removes only JSON whitespace, retaining metric meaning.
			var value any
			if json.Unmarshal(metric, &value) == nil {
				raw, _ := json.Marshal(value)
				compact.Write(raw)
				add(product, "metric", compact.String())
			}
		}
	}
	for _, affected := range record.Affected {
		raw, _ := json.Marshal(affected)
		add(affected.Product, "affected", string(raw))
	}
	for _, description := range record.Descriptions {
		if strings.EqualFold(description.Lang, "en") {
			add(product, "description", description.Value)
		}
	}
	gap := ""
	hasRemediation := false
	for _, fact := range facts {
		if fact.Kind == "solution" || fact.Kind == "workaround" {
			hasRemediation = true
		}
	}
	if !hasRemediation {
		gap = "unknown: usable remediation is not present in retained CNA evidence; this does not establish the absence of a fixed release"
	}
	if truncated {
		gap += "; CNA evidence size limit omitted additional fields; completeness requires confirmation"
	}
	return facts, strings.TrimPrefix(gap, "; ")
}

func (v *CVEVerifier) cacheMeta(id string, meta *CVEMeta) {
	v.mu.Lock()
	if existing := v.cache[id]; existing != nil && existing.CNAChecked && meta.Exists && meta.Verification.Source == "nvd" {
		ttl := cveCacheTTL
		if !existing.Exists {
			ttl = 5 * time.Minute
		}
		if time.Since(existing.CachedAt) < ttl {
			// A late response from an overlapping NVD request must not erase a
			// still-fresh CNA supplement and start another identical lookup.
			merged := *meta
			copyCNAEvidence(&merged, existing)
			meta = &merged
		}
	}
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
	v.cache[id] = meta
	v.mu.Unlock()

}
