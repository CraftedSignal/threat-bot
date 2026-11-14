package pipeline

import (
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// injectAffectedRanges adds only product-specific, unambiguous source scope.
// Removed scope from a grounding repair is never reintroduced automatically.
func injectAffectedRanges(briefYAML string, item scraper.RawItem) string {
	var doc map[string]any
	if yaml.Unmarshal([]byte(briefYAML), &doc) != nil {
		return briefYAML
	}
	products := nonEmptyTrimmed(yamlStringList(doc["affected_products"]))
	hints := supportedProductScope(products, item.Content)
	ambiguous := map[string]bool{}
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
				if len(mr.ranges) != 1 {
					ambiguous[key] = true
					continue
				}
				if prior := hints[key]; prior.VulnerableRange != "" && prior.VulnerableRange != mr.ranges[0] {
					ambiguous[key] = true
					continue
				}
				hints[key] = patchVersionHint{VulnerableRange: mr.ranges[0]}
			}
		}
	}
	for key := range ambiguous {
		delete(hints, key)
	}
	changed := applySupportedProductScope(doc, hints)
	if !changed {
		return briefYAML
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
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
