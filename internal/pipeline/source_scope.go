package pipeline

import (
	"regexp"
	"strings"
)

// Sentences and list rows are attribution boundaries; a byte-distance window
// cannot distinguish a dependency's versions from the affected product's.
var sourceClauseBreak = regexp.MustCompile(`[.!?](?:\s+|$)|[\n;]`)
var productScopeSuffix = regexp.MustCompile(`\s*\([^)]*(?:[<>=]|\d+\.\d+)[^)]*\)\s*$`)
var productNameSeparator = regexp.MustCompile(`[^\pL\pN]+`)
var scopeIntroducer = regexp.MustCompile(`(?i)\b(?:before|prior to|earlier than|below|versions?|patched|fixed|resolved|addressed|upgrade|upgrading|update|updating)\b`)
var otherProductConnector = regexp.MustCompile(`(?i)\b(?:uses|includes|depends on|bundles|alongside|and)\b|,`)

func productNameLocation(text, product string) []int {
	name := strings.TrimSpace(productScopeSuffix.ReplaceAllString(product, ""))
	parts := productNameSeparator.Split(name, -1)
	var quoted []string
	for _, part := range parts {
		if part != "" {
			quoted = append(quoted, regexp.QuoteMeta(part))
		}
	}
	if len(quoted) == 0 {
		return nil
	}
	return regexp.MustCompile(`(?i)\b` + strings.Join(quoted, `[^\pL\pN]+`) + `\b`).FindStringIndex(text)
}

func scopeProductKey(product string) string {
	return normalizeScopeText(productScopeSuffix.ReplaceAllString(product, ""))
}

func supportedProductScope(products []string, text string) map[string]patchVersionHint {
	out := map[string]patchVersionHint{}
	ambiguous := map[string]bool{}
	for _, clause := range sourceClauseBreak.Split(text, -1) {
		var matched []string
		ends := map[string]int{}
		for _, product := range products {
			key := scopeProductKey(product)
			loc := productNameLocation(clause, product)
			if key != "" && loc != nil && !containsString(matched, key) {
				matched = append(matched, key)
				ends[key] = loc[1]
			}
		}
		if len(matched) != 1 {
			continue
		}
		key := matched[0]
		attributed := clause[ends[key]:]
		if loc := scopeIntroducer.FindStringIndex(attributed); loc != nil && otherProductConnector.MatchString(attributed[:loc[0]]) {
			continue
		}
		hint := extractPatchVersionHint(attributed)
		bounds := 0
		for _, pattern := range []*regexp.Regexp{beforeVersionRe, rangeThroughRe, upToRe, earlierRe} {
			bounds += len(pattern.FindAllStringIndex(attributed, -1))
		}
		if bounds > 1 {
			ambiguous[key] = true
			continue
		}
		// "update to Product version X" binds X to Product even though the
		// update verb precedes the product name. Require the name inside that
		// exact update phrase, before its captured version.
		if hint.FixedVersion == "" {
			if match := updateToRe.FindStringSubmatchIndex(clause); len(match) == 4 && match[0] < ends[key] && match[2] >= ends[key] {
				hint.FixedVersion = cleanVersionToken(clause[match[2]:match[3]])
			}
		}
		// Multiple release branches need explicit branch mapping; flattening
		// "before X and Y" into an intersection manufactures a version range.
		if len(hint.BeforeVersions) > 1 {
			ambiguous[key] = true
			continue
		}
		if hint.VulnerableRange == "" && hint.FixedVersion == "" {
			continue
		}
		prior := out[key]
		if prior.VulnerableRange != "" && hint.VulnerableRange != "" && prior.VulnerableRange != hint.VulnerableRange {
			ambiguous[key] = true
			continue
		}
		if prior.FixedVersion != "" && hint.FixedVersion != "" && prior.FixedVersion != hint.FixedVersion {
			ambiguous[key] = true
			continue
		}
		if hint.VulnerableRange != "" {
			prior.VulnerableRange = hint.VulnerableRange
		}
		if hint.FixedVersion != "" {
			prior.FixedVersion = hint.FixedVersion
		}
		out[key] = prior
	}
	for key := range ambiguous {
		delete(out, key)
	}
	return out
}

func scopeRepairBlocked(doc map[string]any, product string) bool {
	key := scopeProductKey(product)
	for _, blocked := range yamlStringList(doc["grounding_rejected_scope"]) {
		if scopeProductKey(blocked) == key {
			return true
		}
	}
	return false
}

func applySupportedProductScope(doc map[string]any, hints map[string]patchVersionHint) bool {
	products := yamlStringList(doc["affected_products"])
	changed := false
	for i, product := range products {
		hint := hints[scopeProductKey(product)]
		if hint.VulnerableRange == "" || productScopeSuffix.MatchString(product) || scopeRepairBlocked(doc, product) {
			continue
		}
		products[i] = withRanges(product, []string{hint.VulnerableRange})
		changed = true
	}
	if changed {
		doc["affected_products"] = products
	}
	return changed
}
