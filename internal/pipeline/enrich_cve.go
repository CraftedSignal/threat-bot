package pipeline

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// CVEEnricher enriches briefs with EPSS, CVSS, and KEV data per CVE.
type CVEEnricher struct {
	cveVerifier *CVEVerifier
}

func NewCVEEnricher(cveVerifier *CVEVerifier) *CVEEnricher {
	return &CVEEnricher{cveVerifier: cveVerifier}
}

// Enrich extracts CVE IDs from the brief YAML, looks up their metadata,
// and adds a cves array and deduplicated cpes list to the brief. keep holds
// the CVEs the brief listed before this update; scope filtering and NVD
// verification never remove them. A brief with no prior listing passes nil.
func (e *CVEEnricher) Enrich(briefYAML string, keep map[string]bool) (string, []BundleCVE) {
	return e.enrich(briefYAML, nil, keep, false)
}

// EnrichRoundup is Enrich for vendor roundups and campaign umbrellas. They
// collect many CVEs by design and NVD often has no CPEs for fresh ones, so the
// brief-scope filter must not remove any CVE routed into them. Like
// EnrichListedCVEs it enriches only the CVEs the front matter lists, not every
// ID mentioned in body text or related links.
func (e *CVEEnricher) EnrichRoundup(briefYAML string, keep map[string]bool) (string, []BundleCVE) {
	return e.enrich(briefYAML, listedCVEs(briefYAML), keep, true)
}

// EnrichListedCVEs enriches only the CVEs the brief already lists. A merged
// brief mentions other CVEs in references and IOCs it took from its sources;
// enriching every mention would add those vulnerabilities to the brief
// (cve_identity.go). A brief that lists no CVE is enriched like Enrich.
func (e *CVEEnricher) EnrichListedCVEs(briefYAML string, keep map[string]bool) (string, []BundleCVE) {
	return e.enrich(briefYAML, listedCVEs(briefYAML), keep, false)
}

// listedCVEs returns the CVEs the front matter lists, or nil when it lists none.
func listedCVEs(briefYAML string) map[string]bool {
	listed := briefCVEIDs(parseBriefFrontmatter(briefYAML))
	if len(listed) == 0 {
		return nil
	}
	return listed
}

func (e *CVEEnricher) enrich(briefYAML string, only, keep map[string]bool, exemptScope bool) (string, []BundleCVE) {
	existingStructured := structuredCVEsFromBrief(briefYAML)
	cveIDs := cveRe.FindAllString(briefYAML, -1)
	seen := make(map[string]bool)
	var cves []BundleCVE
	var metas []*CVEMeta
	for _, id := range cveIDs {
		id = strings.ToUpper(id)
		if seen[id] || (only != nil && !only[id]) {
			continue
		}
		seen[id] = true
		meta := e.cveVerifier.GetMeta(id)
		if meta == nil || !meta.Exists {
			continue
		}
		metas = append(metas, meta)
		cves = append(cves, BundleCVE{
			ID:             id,
			EPSS:           meta.EPSS,
			EPSSPercentile: meta.EPSSPercentile,
			CVSS:           meta.CVSS,
			CVSSVector:     meta.CVSSVector,
		})
	}
	scope := detectBriefCVEScope(briefYAML)
	if exemptScope {
		scope = briefCVEScope{}
	}
	verifiedIDs := cveIDSet(cves)
	allCVEs := cves
	cves, metas, excludedMetas := filterCVEsToBriefScope(scope, cves, metas)
	excludedIDs := verifiedIDs
	for id := range cveIDSet(cves) {
		delete(excludedIDs, id)
	}
	// Scope keeps unrelated CVEs from being added, never removes one the brief
	// listed before this update: that is an editorial correction, and a
	// replacement set sharing none with the published one is rejected.
	for _, cve := range allCVEs {
		id := strings.ToUpper(strings.TrimSpace(cve.ID))
		if excludedIDs[id] && keep[id] {
			delete(excludedIDs, id)
			cves = append(cves, cve)
		}
	}
	// A kept CVE the authorities could not verify must
	// not vanish when EnrichBriefWithCVEs rebuilds the cves list.
	have := cveIDSet(cves)
	for _, cve := range existingStructured {
		have[strings.ToUpper(strings.TrimSpace(cve.ID))] = true
	}
	var unverified []string
	for id := range keep {
		if !have[id] {
			unverified = append(unverified, id)
		}
	}
	sort.Strings(unverified)
	for _, id := range unverified {
		cves = append(cves, BundleCVE{ID: id})
	}
	cves = mergeStructuredCVEs(existingStructured, cves, excludedIDs)
	e.applyKEV(cves, existingStructured)
	cpes := cpesFromCVEMetas(metas)
	enriched := EnrichBriefWithCVEs(briefYAML, cves)
	enriched = scrubAffectedFieldsToScope(enriched, scope, metas, excludedMetas)
	enriched = enrichCVEScope(enriched, cpes, metas)
	return enriched, cves
}

// applyKEV sets each CVE's KEV fields from the CISA catalog. Membership does
// not depend on NVD, so CVEs NVD could not verify are marked too. While the
// catalog has not loaded, a CVE keeps the KEV fields the brief already had, so
// an outage cannot erase an earlier listing.
func (e *CVEEnricher) applyKEV(cves, existing []BundleCVE) {
	prior := make(map[string]BundleCVE, len(existing))
	for _, cve := range existing {
		prior[strings.ToUpper(strings.TrimSpace(cve.ID))] = cve
	}
	for i := range cves {
		id := strings.ToUpper(strings.TrimSpace(cves[i].ID))
		if listed, known := e.cveVerifier.KEV(id); known {
			cves[i].KEV, cves[i].KEVStatus = listed, kevStatus(listed, true)
		} else if before, ok := prior[id]; ok {
			cves[i].KEV, cves[i].KEVStatus = before.KEV, before.KEVStatus
		}
	}
}

func structuredCVEsFromBrief(briefYAML string) []BundleCVE {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return nil
	}
	var cves []BundleCVE
	for _, item := range yamlAnyList(doc["cves"]) {
		if scalar, ok := item.(string); ok {
			id := strings.ToUpper(strings.TrimSpace(scalar))
			if match := sourceCVEPattern.FindString(id); id != "" && match == id {
				cves = append(cves, BundleCVE{ID: id})
			}
			continue
		}
		entry, ok := asStringMap(item)
		if !ok {
			continue
		}
		raw, err := yaml.Marshal(entry)
		if err != nil {
			continue
		}
		var cve BundleCVE
		if err := yaml.Unmarshal(raw, &cve); err != nil || strings.TrimSpace(cve.ID) == "" {
			continue
		}
		cve.ID = strings.ToUpper(strings.TrimSpace(cve.ID))
		cves = append(cves, cve)
	}
	return cves
}

func cveIDSet(cves []BundleCVE) map[string]bool {
	ids := make(map[string]bool, len(cves))
	for _, cve := range cves {
		if id := strings.ToUpper(strings.TrimSpace(cve.ID)); id != "" {
			ids[id] = true
		}
	}
	return ids
}

func mergeStructuredCVEs(existing, verified []BundleCVE, excluded map[string]bool) []BundleCVE {
	verifiedByID := make(map[string]BundleCVE, len(verified))
	for _, cve := range verified {
		id := strings.ToUpper(strings.TrimSpace(cve.ID))
		if id == "" {
			continue
		}
		cve.ID = id
		if prior, ok := verifiedByID[id]; ok {
			cve = mergeBundleCVEFields(cve, prior)
		}
		verifiedByID[id] = cve
	}

	merged := make([]BundleCVE, 0, len(existing))
	indices := make(map[string]int, len(existing))
	for _, cve := range existing {
		id := strings.ToUpper(strings.TrimSpace(cve.ID))
		if id == "" || excluded[id] {
			continue
		}
		cve.ID = id
		if idx, ok := indices[id]; ok {
			merged[idx] = mergeBundleCVEFields(merged[idx], cve)
			continue
		}
		indices[id] = len(merged)
		merged = append(merged, cve)
	}
	for i := range merged {
		if enriched, ok := verifiedByID[merged[i].ID]; ok {
			// Verified metadata is authoritative where present, while fields
			// carried only by an existing row (for example product scope) survive.
			merged[i] = mergeBundleCVEFields(enriched, merged[i])
			delete(verifiedByID, merged[i].ID)
		}
	}
	for _, cve := range verified {
		id := strings.ToUpper(strings.TrimSpace(cve.ID))
		if id == "" || excluded[id] {
			continue
		}
		if _, ok := verifiedByID[id]; !ok {
			continue
		}
		cve.ID = id
		cve = mergeBundleCVEFields(cve, verifiedByID[id])
		merged = append(merged, cve)
		delete(verifiedByID, id)
	}
	return merged
}

// mergeBundleCVEFields prefers non-empty values from preferred and fills gaps
// from fallback. KEV membership is monotonic until the catalog is reapplied.
func mergeBundleCVEFields(preferred, fallback BundleCVE) BundleCVE {
	if preferred.ID == "" {
		preferred.ID = fallback.ID
	}
	if preferred.Product == "" {
		preferred.Product = fallback.Product
	}
	if preferred.EPSS == 0 {
		preferred.EPSS = fallback.EPSS
	}
	if preferred.EPSSPercentile == 0 {
		preferred.EPSSPercentile = fallback.EPSSPercentile
	}
	if preferred.CVSS == 0 {
		preferred.CVSS = fallback.CVSS
	}
	if preferred.CVSSVector == "" {
		preferred.CVSSVector = fallback.CVSSVector
	}
	preferred.KEV = preferred.KEV || fallback.KEV
	if preferred.KEVStatus == "" || strings.EqualFold(preferred.KEVStatus, "unknown") ||
		(strings.EqualFold(preferred.KEVStatus, "false") && strings.EqualFold(fallback.KEVStatus, "true")) {
		preferred.KEVStatus = fallback.KEVStatus
	}
	return preferred
}

type briefCVEScope struct {
	active   bool
	vendors  map[string]bool
	products map[string]bool
}

func detectBriefCVEScope(briefYAML string) briefCVEScope {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefCVEScope{}
	}
	title, _ := doc["title"].(string)
	summary, _ := doc["summary"].(string)

	scope := briefCVEScope{
		vendors:  map[string]bool{},
		products: map[string]bool{},
	}
	titleVendorScope := collectScopeMatches(scope.vendors, yamlStringList(doc["affected_vendors"]), title, false)
	titleProductScope := collectScopeMatches(scope.products, yamlStringList(doc["affected_products"]), title, true)
	if titleVendorScope || titleProductScope {
		scope.active = true
		return scope
	}

	fallbackText := strings.TrimSpace(title + "\n" + summary)
	if fallbackText == "" {
		return briefCVEScope{}
	}
	fallbackVendorScope := collectScopeMatches(scope.vendors, yamlStringList(doc["affected_vendors"]), fallbackText, false)
	fallbackProductScope := collectScopeMatches(scope.products, yamlStringList(doc["affected_products"]), fallbackText, true)
	scope.active = fallbackVendorScope || fallbackProductScope
	if !scope.active {
		return briefCVEScope{}
	}
	return scope
}

func collectScopeMatches(out map[string]bool, candidates []string, text string, product bool) bool {
	normalizedText := normalizeScopeText(text)
	if normalizedText == "" {
		return false
	}
	changed := false
	for _, candidate := range candidates {
		term := normalizedScopeCandidate(candidate, product)
		if term == "" || out[term] {
			continue
		}
		if normalizedScopeContains(normalizedText, term) {
			out[term] = true
			changed = true
		}
	}
	return changed
}

func normalizedScopeCandidate(value string, product bool) string {
	value = strings.TrimSpace(value)
	if value == "" || isPlaceholder(value) {
		return ""
	}
	if product {
		value = bareProductName(value)
		if !isSpecificProduct(value) {
			return ""
		}
		return normalizeProductName(value)
	}
	return normalizeVendorName(value)
}

func normalizeScopeText(text string) string {
	return nonAlphaNumRe.ReplaceAllString(strings.ToLower(text), "")
}

func normalizedScopeContains(text, term string) bool {
	return term != "" && len(term) >= 3 && strings.Contains(text, term)
}

func filterCVEsToBriefScope(scope briefCVEScope, cves []BundleCVE, metas []*CVEMeta) ([]BundleCVE, []*CVEMeta, []*CVEMeta) {
	if !scope.active || len(cves) < 2 || len(cves) != len(metas) {
		return cves, metas, nil
	}
	filteredCVEs := make([]BundleCVE, 0, len(cves))
	filteredMetas := make([]*CVEMeta, 0, len(metas))
	excludedMetas := make([]*CVEMeta, 0, len(metas))
	for i, meta := range metas {
		if cveMetaMatchesScope(meta, scope) {
			filteredCVEs = append(filteredCVEs, cves[i])
			filteredMetas = append(filteredMetas, meta)
			continue
		}
		excludedMetas = append(excludedMetas, meta)
	}
	if len(filteredCVEs) == 0 || len(excludedMetas) == 0 {
		return cves, metas, nil
	}
	return filteredCVEs, filteredMetas, excludedMetas
}

func cpesFromCVEMetas(metas []*CVEMeta) []string {
	seen := map[string]bool{}
	var cpes []string
	for _, meta := range metas {
		if meta == nil {
			continue
		}
		for _, cpe := range meta.CPEs {
			cpe = strings.TrimSpace(cpe)
			if cpe == "" || seen[cpe] {
				continue
			}
			seen[cpe] = true
			cpes = append(cpes, cpe)
		}
	}
	return cpes
}

func scrubAffectedFieldsToScope(briefYAML string, scope briefCVEScope, keptMetas, excludedMetas []*CVEMeta) string {
	if !scope.active || len(excludedMetas) == 0 {
		return briefYAML
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML
	}
	changed := false
	if values, ok := scrubScopedValues(yamlStringList(doc["affected_vendors"]), scope, keptMetas, excludedMetas, false); ok {
		doc["affected_vendors"] = values
		changed = true
	}
	if values, ok := scrubScopedValues(yamlStringList(doc["affected_products"]), scope, keptMetas, excludedMetas, true); ok {
		doc["affected_products"] = values
		changed = true
	}
	if values, ok := scrubScopedCPEs(yamlStringList(doc["cpes"]), keptMetas, excludedMetas); ok {
		doc["cpes"] = values
		changed = true
	}
	if !changed {
		return briefYAML
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

func scrubScopedValues(values []string, scope briefCVEScope, keptMetas, excludedMetas []*CVEMeta, product bool) ([]string, bool) {
	if len(values) == 0 {
		return values, false
	}
	out := make([]string, 0, len(values))
	changed := false
	for _, value := range values {
		if shouldDropScopedValue(value, scope, keptMetas, excludedMetas, product) {
			changed = true
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return values, false
	}
	return out, changed
}

func shouldDropScopedValue(value string, scope briefCVEScope, keptMetas, excludedMetas []*CVEMeta, product bool) bool {
	term := normalizedScopeCandidate(value, product)
	if term == "" {
		return false
	}
	if product {
		if scope.products[term] {
			return false
		}
	} else if scope.vendors[term] {
		return false
	}
	if cveMetasMatchTerm(keptMetas, term, product) {
		return false
	}
	return cveMetasMatchTerm(excludedMetas, term, product)
}

func scrubScopedCPEs(cpes []string, keptMetas, excludedMetas []*CVEMeta) ([]string, bool) {
	if len(cpes) == 0 {
		return cpes, false
	}
	out := make([]string, 0, len(cpes))
	changed := false
	for _, cpe := range cpes {
		if cveMetaCPEsContain(keptMetas, cpe) || !cveMetaCPEsContain(excludedMetas, cpe) {
			out = append(out, cpe)
			continue
		}
		changed = true
	}
	return out, changed
}

func cveMetaMatchesScope(meta *CVEMeta, scope briefCVEScope) bool {
	if meta == nil {
		return false
	}
	for vendor := range scope.vendors {
		if cveMetaMatchesTerm(meta, vendor, false) {
			return true
		}
	}
	for product := range scope.products {
		if cveMetaMatchesTerm(meta, product, true) {
			return true
		}
	}
	return false
}

func cveMetasMatchTerm(metas []*CVEMeta, term string, product bool) bool {
	for _, meta := range metas {
		if cveMetaMatchesTerm(meta, term, product) {
			return true
		}
	}
	return false
}

func cveMetaMatchesTerm(meta *CVEMeta, term string, product bool) bool {
	if meta == nil || term == "" {
		return false
	}
	for _, cpe := range meta.CPEs {
		vendor, cpeProduct := cpeVendorProduct(cpe)
		if !product && scopeTermsMatch(term, normalizeVendorName(vendor)) {
			return true
		}
		if product && scopeTermsMatch(term, normalizeProductName(cpeProduct)) {
			return true
		}
	}
	description := normalizeScopeText(meta.Description)
	return normalizedScopeContains(description, term)
}

func cveMetaCPEsContain(metas []*CVEMeta, cpe string) bool {
	cpe = strings.TrimSpace(cpe)
	if cpe == "" {
		return false
	}
	for _, meta := range metas {
		if meta == nil {
			continue
		}
		for _, candidate := range meta.CPEs {
			if strings.TrimSpace(candidate) == cpe {
				return true
			}
		}
	}
	return false
}

func cpeVendorProduct(cpe string) (string, string) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", ""
	}
	return cpeComponentToName(parts[3]), cpeComponentToName(parts[4])
}

func cpeComponentToName(value string) string {
	value = strings.Trim(value, `"'`)
	value = strings.ReplaceAll(value, `\`, "")
	value = strings.ReplaceAll(value, "_", " ")
	return strings.TrimSpace(value)
}

func scopeTermsMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return (len(a) >= 5 && strings.Contains(b, a)) || (len(b) >= 5 && strings.Contains(a, b))
}

type patchVersionHint struct {
	VulnerableRange string
	FixedVersion    string
	// BeforeVersions lists every version named by a "before X, Y and Z" phrase,
	// in source order. FixedVersion records only an explicitly stated fix, so
	// deterministic scope never resolves conflicting clauses on its own; the
	// model applies releaseBoundRemediationRule to bounds such as these.
	BeforeVersions []string
}

var (
	beforeVersionRe = regexp.MustCompile(`(?i)\b(?:before|prior to|earlier than|below)\s+(?:version\s+)?([0-9][A-Za-z0-9._+-]*(?:\.[A-Za-z0-9._+-]+)+)`)
	patchedInRe     = regexp.MustCompile(`(?i)\b(?:patched|fixed|resolved|addressed)\s+in\s+(?:version\s+)?([0-9][A-Za-z0-9._+-]*(?:\.[A-Za-z0-9._+-]+)+)`)
	updateToRe      = regexp.MustCompile(`(?i)\b(?:upgrade|upgrading|update|updating|patch|patching)\b[^.\n]{0,120}?\bto\s+(?:[A-Za-z][A-Za-z0-9._+-]*\s+){0,6}(?:version\s+)?([0-9][A-Za-z0-9._+-]*(?:\.[A-Za-z0-9._+-]+)+)\s+(?:or\s+later|and\s+later|or\s+newer|or\s+higher)`)
	rangeThroughRe  = regexp.MustCompile(`(?i)\bversions?\s+([0-9][A-Za-z0-9._+-]*(?:\.[A-Za-z0-9._+-]+)+)\s+(?:through|to|-)\s+([0-9][A-Za-z0-9._+-]*(?:\.[A-Za-z0-9._+-]+)+)`)
	upToRe          = regexp.MustCompile(`(?i)\bversions?\s+(?:up\s+to(?:\s*,?\s*and\s+including\s*,?)?|through)\s+([0-9][A-Za-z0-9._+-]*(?:\.[A-Za-z0-9._+-]+)+)`)
	earlierRe       = regexp.MustCompile(`(?i)\bversions?\s+([0-9][A-Za-z0-9._+-]*(?:\.[A-Za-z0-9._+-]+)+)\s+(?:and\s+)?(?:earlier|below|or\s+earlier)`)
	versionLikeRe   = regexp.MustCompile(`(?i)\b(?:version\s+)?\d+(?:\.\d+)+(?:[-+._a-z0-9]*)\b`)
	cpeComponentRe  = regexp.MustCompile(`[^a-z0-9]+`)
	// beforeContinuationRe matches the separator and next version of a list
	// such as "before 7.3.2 and 7.4.1" or "before 1.2.3, 1.3.4 and 2.0.1".
	beforeContinuationRe = regexp.MustCompile(`(?i)^\s*(?:,\s*(?:(?:and|or)\s+)?|\s+(?:and|or)\s+|\s*&\s*)(?:version\s+)?([0-9][A-Za-z0-9._+-]*(?:\.[A-Za-z0-9._+-]+)+)`)
)

// extractBeforeVersions returns every version named by "before X" phrases,
// including the whole list in "before X, Y and Z", without duplicates.
func extractBeforeVersions(text string) []string {
	var out []string
	add := func(raw string) {
		if v := cleanVersionToken(raw); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	for _, loc := range beforeVersionRe.FindAllStringSubmatchIndex(text, -1) {
		add(text[loc[2]:loc[3]])
		rest := text[loc[1]:]
		for {
			m := beforeContinuationRe.FindStringSubmatchIndex(rest)
			if m == nil {
				break
			}
			add(rest[m[2]:m[3]])
			rest = rest[m[1]:]
		}
	}
	return out
}

func enrichCVEScope(briefYAML string, cpes []string, metas []*CVEMeta) string {
	if len(cpes) == 0 && len(metas) == 0 {
		return briefYAML
	}

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML
	}

	// A repaired scope dispute also excludes automatic machine-scope
	// expansion. CPEs may cover more products/branches than this article.
	scopeDisputed := len(yamlStringList(doc["grounding_rejected_scope"])) > 0
	changed := false
	if !scopeDisputed {
		changed = mergeStringListField(doc, "cpes", cpes)
	}

	// Only authoritative descriptions are source facts; generated/repaired
	// prose cannot corroborate itself during later enrichment.
	scopeText := cveScopeText(doc, metas)
	hints := supportedProductScope(yamlStringList(doc["affected_products"]), scopeText)
	if applySupportedProductScope(doc, hints) {
		changed = true
	}

	// Some fresh NVD records have CVSS and an English description but no
	// configurations block yet. Emit a conservative CPE 2.3 URI from a clear
	// vendor+product pair so API consumers still get a machine-readable product
	// key instead of an empty _cs_cpes array.
	if !scopeDisputed && len(yamlStringList(doc["cpes"])) == 0 && len(metas) > 0 {
		if inferred := synthesizeCPEs(yamlStringList(doc["affected_vendors"]), yamlStringList(doc["affected_products"]), yamlStringList(doc["affected_os"])); len(inferred) > 0 {
			if mergeStringListField(doc, "cpes", inferred) {
				changed = true
			}
		}
	}

	// Apply a fixed version only when the source names it for this product.
	for _, product := range yamlStringList(doc["affected_products"]) {
		hint := hints[scopeProductKey(product)]
		if hint.FixedVersion != "" && !scopeRepairBlocked(doc, product) && len(yamlStringList(doc["affected_products"])) == 1 {
			if enrichActionPlanPatchVersion(doc, []string{product}, hint.FixedVersion) {
				changed = true
			}
		}
	}

	if !changed {
		return briefYAML
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

func mergeStringListField(doc map[string]any, key string, incoming []string) bool {
	if len(incoming) == 0 {
		return false
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range yamlStringList(doc[key]) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		k := strings.ToLower(value)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, value)
	}
	changed := false
	for _, value := range incoming {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		k := strings.ToLower(value)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, value)
		changed = true
	}
	if changed {
		doc[key] = out
	}
	return changed
}

func cveScopeText(doc map[string]any, metas []*CVEMeta) string {
	var parts []string
	for _, meta := range metas {
		if meta != nil && strings.TrimSpace(meta.Description) != "" {
			parts = append(parts, meta.Description)
		}
	}

	return strings.Join(parts, "\n")
}

func extractPatchVersionHint(text string) patchVersionHint {
	var hint patchVersionHint
	if m := rangeThroughRe.FindStringSubmatch(text); len(m) == 3 {
		from := cleanVersionToken(m[1])
		to := cleanVersionToken(m[2])
		if from != "" && to != "" {
			hint.VulnerableRange = from + "-" + to
		}
	}
	if hint.VulnerableRange == "" {
		if m := upToRe.FindStringSubmatch(text); len(m) == 2 {
			if v := cleanVersionToken(m[1]); v != "" {
				hint.VulnerableRange = "<= " + v
			}
		}
	}
	if hint.VulnerableRange == "" {
		if m := earlierRe.FindStringSubmatch(text); len(m) == 2 {
			if v := cleanVersionToken(m[1]); v != "" {
				hint.VulnerableRange = "<= " + v
			}
		}
	}
	if before := extractBeforeVersions(text); len(before) > 0 {
		hint.BeforeVersions = before
		if hint.VulnerableRange == "" {
			bounds := make([]string, len(before))
			for i, v := range before {
				bounds[i] = "< " + v
			}
			hint.VulnerableRange = strings.Join(bounds, ", ")
		}
	}
	if hint.FixedVersion == "" {
		for _, re := range []*regexp.Regexp{patchedInRe, updateToRe} {
			if m := re.FindStringSubmatch(text); len(m) == 2 {
				if v := cleanVersionToken(m[1]); v != "" {
					hint.FixedVersion = v
					break
				}
			}
		}
	}
	return hint
}

func cleanVersionToken(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, " \t\r\n.,;:)]}\"'")
	if strings.EqualFold(v, "version") {
		return ""
	}
	return v
}

func synthesizeCPEs(vendors, products, oses []string) []string {
	vendors = uniqueNonPlaceholderStrings(vendors, false)
	products = uniqueNonPlaceholderStrings(products, true)
	oses = uniqueNonPlaceholderStrings(oses, true)
	if len(vendors) != 1 {
		return nil
	}
	vendor := vendors[0]
	vendorComponent := cpeComponent(vendor)
	if vendorComponent == "" {
		return nil
	}

	if len(products) == 1 {
		product := trimLeadingVendor(products[0], vendor)
		if productComponent := cpeComponent(product); productComponent != "" {
			return []string{fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", vendorComponent, productComponent)}
		}
	}
	if len(products) == 0 && len(oses) == 1 {
		if osComponent := cpeComponent(oses[0]); osComponent != "" {
			return []string{fmt.Sprintf("cpe:2.3:o:%s:%s:*:*:*:*:*:*:*:*", vendorComponent, osComponent)}
		}
	}
	return nil
}

func uniqueNonPlaceholderStrings(items []string, stripVersionQualifier bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range items {
		value := strings.TrimSpace(raw)
		if stripVersionQualifier {
			value = bareProductName(value)
		}
		if value == "" || isPlaceholder(value) {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func bareProductName(product string) string {
	product = strings.TrimSpace(product)
	if i := strings.Index(product, "("); i >= 0 {
		product = strings.TrimSpace(product[:i])
	}
	return product
}

func trimLeadingVendor(product, vendor string) string {
	product = strings.TrimSpace(product)
	vendor = strings.TrimSpace(vendor)
	if product == "" || vendor == "" {
		return product
	}
	lowerProduct := strings.ToLower(product)
	lowerVendor := strings.ToLower(vendor)
	if lowerProduct == lowerVendor {
		return product
	}
	if strings.HasPrefix(lowerProduct, lowerVendor+" ") {
		return strings.TrimSpace(product[len(vendor):])
	}
	return product
}

func cpeComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = corporateSuffixRe.ReplaceAllString(value, "")
	value = cpeComponentRe.ReplaceAllString(value, "_")
	value = strings.Trim(value, "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return value
}

func enrichActionPlanPatchVersion(doc map[string]any, products []string, fixedVersion string) bool {
	if fixedVersion == "" || len(products) == 0 {
		return false
	}
	product := firstNonPlaceholder(products)
	product = bareProductName(product)
	if product == "" {
		return false
	}
	plan, ok := asStringMap(doc["action_plan"])
	if !ok {
		return false
	}
	changed := false
	for _, key := range []string{"immediate_actions", "mitigation_plan"} {
		items := yamlAnyList(plan[key])
		if len(items) == 0 {
			continue
		}
		for i, item := range items {
			m, ok := asStringMap(item)
			if !ok {
				continue
			}
			action, ok := m["action"].(string)
			if !ok || !shouldRewritePatchAction(action, product, fixedVersion) {
				continue
			}
			m["action"] = patchActionWithVersion(action, product, fixedVersion)
			items[i] = m
			changed = true
		}
		if changed {
			plan[key] = items
		}
	}
	if changed {
		doc["action_plan"] = plan
	}
	return changed
}

func shouldRewritePatchAction(action, product, fixedVersion string) bool {
	action = strings.TrimSpace(action)
	if action == "" || strings.Contains(action, fixedVersion) || versionLikeRe.MatchString(action) {
		return false
	}
	lower := strings.ToLower(action)
	if !containsAny(lower, []string{"patch", "upgrade", "update", "remediate", "mitigat"}) {
		return false
	}
	return strings.Contains(normalizeProductName(action), normalizeProductName(product)) ||
		strings.Contains(lower, "software") ||
		strings.Contains(lower, "vendor")
}

func patchActionWithVersion(action, product, fixedVersion string) string {
	lower := strings.ToLower(action)
	verb := "Update"
	switch {
	case strings.Contains(lower, "upgrade"):
		verb = "Upgrade"
	case strings.Contains(lower, "patch"):
		verb = "Patch"
	case strings.Contains(lower, "mitigat"):
		verb = "Mitigate"
	}
	if verb == "Mitigate" {
		return fmt.Sprintf("Mitigate %s by upgrading to %s or later", product, fixedVersion)
	}
	return fmt.Sprintf("%s %s to %s or later", verb, product, fixedVersion)
}

// EnrichBriefWithCVEs adds a cves array to the brief YAML.
func EnrichBriefWithCVEs(briefYAML string, cves []BundleCVE) string {
	if len(cves) == 0 {
		return briefYAML
	}

	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML
	}
	existingExtras := existingCVEExtraFields(doc["cves"])

	cveList := make([]map[string]interface{}, len(cves))
	anyKEV := false
	for i, c := range cves {
		entry := map[string]interface{}{
			"id":              c.ID,
			"epss":            c.EPSS,
			"epss_percentile": c.EPSSPercentile,
		}
		if extras := existingExtras[strings.ToUpper(c.ID)]; len(extras) > 0 {
			for k, v := range extras {
				entry[k] = v
			}
		}
		if strings.TrimSpace(c.Product) != "" {
			entry["product"] = strings.TrimSpace(c.Product)
		}
		if c.CVSS > 0 {
			entry["cvss"] = c.CVSS
		}
		if c.CVSSVector != "" {
			entry["cvss_vector"] = c.CVSSVector
		}
		if c.KEV {
			entry["kev"] = true
			anyKEV = true
		}
		entry["kev_status"] = firstNonBlank(c.KEVStatus, kevStatus(c.KEV, false))
		cveList[i] = entry
	}
	doc["cves"] = cveList
	// CISA-confirmed exploited-in-the-wild — bubble up to the brief level
	// so the public emitter's `exploited:true` flag is set, the
	// classifier returns "threat" instead of "coverage", and the dispatch
	// fan-out matches subscribers who filter on `exploited`.
	if anyKEV {
		doc["exploited"] = true
		evidence := map[string]interface{}{
			"status":     "confirmed_active",
			"source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			"confidence": "high",
		}
		if publishedAt := strings.TrimSpace(fmt.Sprint(doc["published_at"])); publishedAt != "" && publishedAt != "<nil>" {
			evidence["observed_at"] = publishedAt
		}
		doc["exploitation_evidence"] = evidence
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

var cveEnrichmentOwnedFields = map[string]bool{
	"id":              true,
	"epss":            true,
	"epss_percentile": true,
	"cvss":            true,
	"cvss_vector":     true,
	"kev":             true,
	"kev_status":      true,
}

func kevStatus(kev, known bool) string {
	if kev {
		return "true"
	}
	if known {
		return "false"
	}
	return "unknown"
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func existingCVEExtraFields(v any) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	for _, item := range yamlAnyList(v) {
		m, ok := asStringMap(item)
		if !ok {
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(fmt.Sprint(m["id"])))
		if id == "" || id == "<NIL>" {
			continue
		}
		fields := map[string]interface{}{}
		for k, value := range m {
			if cveEnrichmentOwnedFields[k] || emptyCVEExtraField(value) {
				continue
			}
			fields[k] = value
		}
		if len(fields) > 0 {
			out[id] = fields
		}
	}
	return out
}

func emptyCVEExtraField(v any) bool {
	if v == nil {
		return true
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	return s == "" || s == "<nil>"
}
