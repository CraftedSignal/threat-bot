package pipeline

import (
	"regexp"
	"strings"
)

const productVersionToken = `v?\d[0-9A-Za-z.+:_-]*`
const qualifiedProductVersionToken = `v?\d+(?:[._+-][A-Za-z0-9]+)+`

var productVersionInParens = regexp.MustCompile(`(?i)^(.+?)\s*\(\s*((?:versions?\s+)?(?:<=|>=|<|>|=|~|\^)\s*` + productVersionToken + `(?:\s*,\s*(?:<=|>=|<|>|=|~|\^)\s*` + productVersionToken + `)*|(?:before|after|through)\s+` + productVersionToken + `|(?:n/?a|` + productVersionToken + `)\s+(?:to|through)\s+` + productVersionToken + `|` + productVersionToken + `(?:\s*,\s*` + productVersionToken + `)+|` + qualifiedProductVersionToken + `)\s*\)$`)
var productVersionAfterName = regexp.MustCompile(`(?i)^(.+?)\s+(before|after|through)\s+(` + productVersionToken + `)$`)

// SplitProductVersionScope separates the supported version scope before any
// name truncation. Both internal cleaning and public projection use this parser.
func SplitProductVersionScope(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if m := productVersionInParens.FindStringSubmatch(value); m != nil {
		return strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
	}
	if m := productVersionAfterName.FindStringSubmatch(value); m != nil {
		return strings.TrimSpace(m[1]), strings.TrimSpace(m[2] + " " + m[3])
	}
	return value, ""
}

// CleanProductList keeps source version scope intact while cleaning product
// identity. Taxonomy byte limits apply to the name, never to its version data.
func CleanProductList(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		name, scope := SplitProductVersionScope(strings.Join(strings.Fields(raw), " "))
		// Marketplace feature lists are display copy, not a product family.
		// Only remove an unambiguous multi-feature suffix after a separator;
		// leave unfamiliar ambiguous names for the publication review gate.
		if strings.Count(name, "|") >= 2 {
			for _, sep := range []string{" – ", " — ", " - "} {
				if prefix, _, ok := strings.Cut(name, sep); ok && strings.TrimSpace(prefix) != "" {
					name = strings.TrimSpace(prefix)
					break
				}
			}
		}
		name = affectedName(name)
		if name == "" || isPlaceholder(name) {
			continue
		}
		if scope != "" {
			name += " (" + scope + ")"
		}
		key := strings.ToLower(name)
		if !seen[key] {
			seen[key] = true
			out = append(out, name)
		}
	}
	return out
}
