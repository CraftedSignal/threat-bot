package pipeline

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// injectAffectedRanges renders product-specific, unambiguous source scope into
// affected_products before grounding. The checker then judges the exact ranges
// its evidence states, instead of a model's transcription of them that it can
// dispute in both directions (range missing, range unsupported). Every stated
// range becomes its own "Product (range)" entry, which the public projection
// splits back into the product and its version scope.
//
// Structured ranges, from NVD configurations and from the CVE records the
// checker receives as primary evidence, are exact and take precedence over
// bounds extracted from prose. Structured sources that disagree leave the
// product unscoped, as does any uninterpretable scope; scope removed by a
// grounding repair is never reintroduced automatically.
func injectAffectedRanges(briefYAML string, item scraper.RawItem, primary primaryRecordFacts) string {
	var doc map[string]any
	if yaml.Unmarshal([]byte(briefYAML), &doc) != nil {
		return briefYAML
	}
	products := nonEmptyTrimmed(yamlStringList(doc["affected_products"]))
	scopes := map[string][]string{}
	for key, hint := range supportedProductScope(products, item.Content) {
		if hint.VulnerableRange != "" {
			scopes[key] = []string{hint.VulnerableRange}
		}
	}
	structured := map[string][]string{}
	conflicting := map[string]bool{}
	if item.Source == "nvd" || item.Source == "ghsa" {
		for _, mr := range parseAffectedRangeLines(item.Metadata["affected_ranges"]) {
			var matches []string
			for _, product := range products {
				if productMatchesRangeName(product, mr.name) {
					matches = append(matches, product)
				}
			}
			if len(matches) == 1 {
				key := scopeProductKey(matches[0])
				if prior, ok := structured[key]; ok && !sameRanges(prior, mr.ranges) {
					conflicting[key] = true
				} else {
					structured[key] = mr.ranges
				}
			}
		}
	}
	// CVE Program/CNA facts are the vendor's primary affected-version record.
	// NVD's normalized ranges can omit precision (for example, .8 versus .8.1)
	// or flatten custom release streams. Use complete primary-record ranges for
	// products they cover, while retaining NVD metadata for other products.
	for key, ranges := range primaryRecordRanges(products, primary) {
		structured[key] = ranges
		delete(conflicting, key)
	}
	for key, ranges := range structured {
		scopes[key] = ranges
	}
	for key := range conflicting {
		delete(scopes, key)
	}
	if !applyProductRanges(doc, scopes) {
		return briefYAML
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

// primaryRecordFacts are the structured CVE record facts of a brief's grounding
// evidence. Included facts reached the checker intact. Incomplete facts were
// kept out of the evidence by cross-record references or its size limit.
// Truncated reports that a record lost affected entries before any fact was
// retained, so the names of the products it covered are unknown.
type primaryRecordFacts struct {
	Included   []cnaSourceFact
	Incomplete []cnaSourceFact
	Truncated  bool
}

// cnaAffectedEntry is one retained CVE JSON 5 "affected" entry.
type cnaAffectedEntry struct {
	Vendor        string               `json:"vendor"`
	Product       string               `json:"product"`
	DefaultStatus string               `json:"defaultStatus"`
	Versions      []cnaAffectedVersion `json:"versions"`
}

type cnaAffectedVersion struct {
	Version         string          `json:"version"`
	Status          string          `json:"status"`
	LessThan        string          `json:"lessThan"`
	LessThanOrEqual string          `json:"lessThanOrEqual"`
	VersionType     string          `json:"versionType"`
	Changes         json.RawMessage `json:"changes"`
}

var exactProductVersion = regexp.MustCompile(`(?i)^` + productVersionToken + `$`)

// primaryRecordRanges returns the affected ranges the primary CVE records state
// for each brief product. A record names a product only by its exact name,
// optionally vendor-qualified, so "FortiAnalyzer" never takes the ranges of
// "FortiAnalyzer Cloud". A product gets record ranges only when every affected
// entry naming it reached the checker, renders literally and agrees: several
// packages or CVEs with different ranges need editorial branch mapping, and a
// partial rendering would omit affected versions.
func primaryRecordRanges(products []string, primary primaryRecordFacts) map[string][]string {
	if primary.Truncated {
		return nil
	}
	keys := map[string]bool{}
	for _, product := range products {
		keys[scopeProductKey(product)] = true
	}
	match := func(names ...string) string {
		for _, name := range names {
			if key := scopeProductKey(name); key != "" && keys[key] {
				return key
			}
		}
		return ""
	}
	entryKey := func(fact cnaSourceFact) (string, cnaAffectedEntry, bool) {
		var entry cnaAffectedEntry
		parsed := json.Unmarshal([]byte(fact.Text), &entry) == nil
		key := match(fact.Product)
		if key == "" && parsed {
			key = match(entry.Product, entry.Vendor+" "+entry.Product)
		}
		return key, entry, parsed
	}
	blocked := map[string]bool{}
	for _, fact := range primary.Incomplete {
		if fact.Kind != "affected" {
			continue
		}
		if key, _, _ := entryKey(fact); key != "" {
			blocked[key] = true
		}
	}
	out := map[string][]string{}
	for _, fact := range primary.Included {
		if fact.Kind != "affected" {
			continue
		}
		key, entry, parsed := entryKey(fact)
		if key == "" {
			continue
		}
		ranges, ok := entry.ranges()
		if !parsed || !ok {
			blocked[key] = true
			continue
		}
		if prior, seen := out[key]; seen && !sameRanges(prior, ranges) {
			blocked[key] = true
			continue
		}
		out[key] = ranges
	}
	for key := range blocked {
		delete(out, key)
	}
	return out
}

// ranges renders the entry's affected versions literally. It refuses entries
// whose affected set needs interpretation: versions affected by default,
// unaffected or unknown entries, status changes inside a range, commit ranges,
// and bounds that are not plain version tokens, such as wildcards or URLs.
func (e cnaAffectedEntry) ranges() ([]string, bool) {
	switch strings.ToLower(strings.TrimSpace(e.DefaultStatus)) {
	case "", "unaffected", "unknown":
	default:
		return nil, false
	}
	if len(e.Versions) == 0 {
		return nil, false
	}
	var out []string
	for _, version := range e.Versions {
		r, ok := version.render()
		if !ok {
			return nil, false
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out, true
}

func (v cnaAffectedVersion) render() (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(v.Status), "affected") || strings.EqualFold(strings.TrimSpace(v.VersionType), "git") {
		return "", false
	}
	if changes := strings.TrimSpace(string(v.Changes)); changes != "" && changes != "null" && changes != "[]" {
		return "", false
	}
	from := strings.TrimSpace(v.Version)
	below, through := strings.TrimSpace(v.LessThan), strings.TrimSpace(v.LessThanOrEqual)
	open := from == "0"
	if !open && !exactProductVersion.MatchString(from) {
		return "", false
	}
	// CVE JSON 5 defines an upper limit of "*" as unbounded: "all versions
	// starting at" the lower one. F5 states every NGINX record that way, so
	// refusing it left NGINX2Shell CVE-2026-123633 unscoped and the grounding
	// checker demanded the range until the brief was quarantined. Only the
	// bare "*" is unbounded; "2.*" is a branch pattern and still refused.
	if below == "*" && through == "" || through == "*" && below == "" {
		if open {
			return "", false
		}
		return ">= " + from, true
	}
	var op, bound string
	switch {
	case below != "" && through != "":
		return "", false
	case below != "":
		op, bound = "< ", below
	case through != "":
		op, bound = "<= ", through
	case open:
		return "", false
	default:
		return "= " + from, true
	}
	if !exactProductVersion.MatchString(bound) {
		return "", false
	}
	if open {
		return op + bound, true
	}
	return ">= " + from + ", " + op + bound, true
}

func sameRanges(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		if !slices.Contains(b, r) {
			return false
		}
	}
	return true
}

// applyProductRanges replaces each unscoped product entry with one
// "Product (range)" entry per range. A product the brief already scopes, or
// whose scope a grounding repair removed, keeps the brief's wording. Every
// rendered entry must split back into the original name and its range;
// otherwise the public projection would publish the range as a product name.
func applyProductRanges(doc map[string]any, scopes map[string][]string) bool {
	products := yamlStringList(doc["affected_products"])
	scoped := map[string]bool{}
	for _, product := range products {
		if productScopeSuffix.MatchString(product) {
			scoped[scopeProductKey(product)] = true
		}
	}
	out := make([]string, 0, len(products))
	changed := false
	for _, product := range products {
		key := scopeProductKey(product)
		rendered, ok := renderProductRanges(product, scopes[key])
		if !ok || scoped[key] || scopeRepairBlocked(doc, product) {
			out = append(out, product)
			continue
		}
		out = append(out, rendered...)
		changed = true
	}
	if changed {
		doc["affected_products"] = out
	}
	return changed
}

func renderProductRanges(product string, ranges []string) ([]string, bool) {
	name := strings.TrimSpace(product)
	if name == "" || len(ranges) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		entry := name + " (" + r + ")"
		if gotName, gotScope := SplitProductVersionScope(entry); gotName != name || gotScope != r {
			return nil, false
		}
		out = append(out, entry)
	}
	return out, true
}

func nonEmptyTrimmed(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

type affectedRangeLine struct {
	name   string
	ranges []string
}

// parseAffectedRangeLines parses the "product: range; range" lines of
// Metadata["affected_ranges"].
func parseAffectedRangeLines(raw string) []affectedRangeLine {
	var out []affectedRangeLine
	for _, line := range strings.Split(raw, "\n") {
		name, ranges, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		var rs []string
		for _, r := range strings.Split(ranges, ";") {
			if r = strings.TrimSpace(r); r != "" {
				rs = append(rs, r)
			}
		}
		if name = strings.TrimSpace(name); name != "" && len(rs) > 0 {
			out = append(out, affectedRangeLine{name: name, ranges: rs})
		}
	}
	return out
}

// productMatchesRangeName reports whether a brief product entry names the NVD
// "vendor product" of a range line ("diskstation manager" matches both
// "Synology DiskStation Manager" and "DiskStation Manager (DSM)").
func productMatchesRangeName(product, name string) bool {
	if i := strings.Index(product, "("); i > 0 {
		product = product[:i]
	}
	return productNameLocation(name, product) != nil || productNameLocation(product, name) != nil
}

// withRanges appends each range in add that the entry does not already carry:
// "Product" becomes "Product (r1, r2)" and "Product (r1)" becomes
// "Product (r1, r2)".
func withRanges(entry string, add []string) string {
	var missing []string
	lower := strings.ToLower(entry)
	for _, r := range add {
		if r = strings.TrimSpace(r); r != "" && !strings.Contains(lower, strings.ToLower(r)) {
			if !containsString(missing, r) {
				missing = append(missing, r)
			}
		}
	}
	if len(missing) == 0 {
		return entry
	}
	joined := strings.Join(missing, ", ")
	if strings.HasSuffix(entry, ")") {
		return strings.TrimSuffix(entry, ")") + ", " + joined + ")"
	}
	return entry + " (" + joined + ")"
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
