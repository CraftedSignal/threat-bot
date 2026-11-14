package pipeline

import (
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// injectAffectedRanges renders the version ranges the source states into the
// brief's affected_products, so they never depend on the LLM copying them. Two
// deterministic inputs are merged: every version of a "before X and Y" phrase
// in the item content, and the per-product ranges the NVD scraper stored in
// Metadata["affected_ranges"]. Versions already present in a product entry are
// not added again, so the injection is idempotent.
func injectAffectedRanges(briefYAML string, item scraper.RawItem) string {
	products := nonEmptyTrimmed(yamlStringListFromBrief(briefYAML, "affected_products"))
	if len(products) == 0 {
		return briefYAML
	}
	before := extractBeforeVersions(item.Content)
	metaRanges := parseAffectedRangeLines(item.Metadata["affected_ranges"])
	if len(before) == 0 && len(metaRanges) == 0 {
		return briefYAML
	}

	out := append([]string(nil), products...)
	changed := false
	for i, product := range out {
		var add []string
		for _, v := range before {
			if len(out) > 1 && !productVersionHintApplies(product, v, item.Content) {
				continue
			}
			if strings.Contains(strings.ToLower(product), strings.ToLower(v)) {
				continue
			}
			add = append(add, "< "+v)
		}
		for _, mr := range metaRanges {
			if productMatchesRangeName(product, mr.name) {
				add = append(add, mr.ranges...)
			}
		}
		if updated := withRanges(product, add); updated != product {
			out[i] = updated
			changed = true
		}
	}
	if !changed {
		return briefYAML
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML
	}
	doc["affected_products"] = out
	rendered, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(rendered)
}

func yamlStringListFromBrief(briefYAML, key string) []string {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return nil
	}
	return yamlStringList(doc[key])
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
	p, n := normalizeProductName(product), normalizeProductName(name)
	return p != "" && n != "" && (strings.Contains(n, p) || strings.Contains(p, n))
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
