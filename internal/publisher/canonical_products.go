package publisher

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"gopkg.in/yaml.v3"
)

var canonicalVendorAliases = map[string]string{"nginx": "NGINX"}

// CanonicalVendorName applies only explicit, unambiguous vendor display
// aliases; unknown names retain their supplied spelling.
func CanonicalVendorName(raw string) string {
	name := strings.TrimSpace(raw)
	if canonical, ok := canonicalVendorAliases[strings.ToLower(name)]; ok {
		return canonical
	}
	return name
}

func productNameAndRange(raw string) (string, string) {
	return pipeline.SplitProductVersionScope(raw)
}

// CanonicalProductNameAndRange splits a product's exact version scope, when
// present, without guessing at non-version parenthetical model lists.
func CanonicalProductNameAndRange(raw string) (string, string) { return productNameAndRange(raw) }

func canonicalProductProjection(raw []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, item := range pipeline.CleanProductList(raw) {
		name, _ := productNameAndRange(item)
		cleaned := pipeline.CleanAffectedList([]string{name})
		if len(cleaned) == 0 {
			continue
		}
		name = cleaned[0]
		key := strings.ToLower(name)
		if name == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, name)
	}
	sort.SliceStable(result, func(i, j int) bool { return strings.ToLower(result[i]) < strings.ToLower(result[j]) })
	return result
}

func productVersionProjection(raw []string) []publicProductVersion {
	seen := map[string]bool{}
	var result []publicProductVersion
	for _, item := range pipeline.CleanProductList(raw) {
		name, scope := productNameAndRange(item)
		name, scope = strings.TrimSpace(name), strings.TrimSpace(scope)
		key := strings.ToLower(name) + "\x00" + strings.ToLower(scope)
		if name == "" || scope == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, publicProductVersion{Product: name, Range: scope})
	}
	sort.SliceStable(result, func(i, j int) bool {
		if strings.EqualFold(result[i].Product, result[j].Product) {
			return result[i].Range < result[j].Range
		}
		return strings.ToLower(result[i].Product) < strings.ToLower(result[j].Product)
	})
	return result
}

// CanonicalizeProductsMarkdown updates only product taxonomy fields in one
// public brief and preserves the entire Markdown body byte-for-byte.
func CanonicalizeProductsMarkdown(content []byte) ([]byte, []TermRedirect, error) {
	parts := strings.SplitN(string(content), "---\n", 3)
	if len(parts) != 3 || strings.TrimSpace(parts[0]) != "" {
		return nil, nil, fmt.Errorf("markdown has no delimited YAML frontmatter")
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(parts[1]), &fm); err != nil {
		return nil, nil, fmt.Errorf("decode frontmatter: %w", err)
	}
	var versionFields struct {
		ProductVersions []publicProductVersion `yaml:"product_versions"`
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &versionFields); err != nil {
		return nil, nil, fmt.Errorf("decode product version fields: %w", err)
	}
	oldVendors := stringSlice(fm["vendors"])
	oldProducts := stringSlice(fm["products"])
	legacyProducts := stringSlice(fm["affected_products"])
	// Legacy briefs may still store the full affected product with its scope.
	if len(oldProducts) == 0 && len(legacyProducts) > 0 {
		oldProducts = legacyProducts
	}
	newVendors := canonicalTextList(oldVendors)
	newProducts := canonicalProductProjection(oldProducts)
	versions := productVersionProjection(oldProducts)
	versions = mergeProductVersions(versions, versionFields.ProductVersions)
	if sameStringSet(oldVendors, newVendors) && sameStringSet(oldProducts, newProducts) &&
		sameProductVersionSet(versionFields.ProductVersions, versions) && len(legacyProducts) == 0 {
		return content, nil, nil
	}
	if len(newVendors) == 0 {
		delete(fm, "vendors")
	} else {
		fm["vendors"] = newVendors
	}
	if len(newProducts) == 0 {
		delete(fm, "products")
	} else {
		fm["products"] = newProducts
	}
	delete(fm, "affected_products")
	if len(versions) == 0 {
		delete(fm, "product_versions")
	} else {
		fm["product_versions"] = versions
	}
	encoded, err := yaml.Marshal(fm)
	if err != nil {
		return nil, nil, fmt.Errorf("encode frontmatter: %w", err)
	}
	redirects := termRedirects(oldVendors, newVendors, oldProducts, newProducts)
	return []byte("---\n" + string(encoded) + "---\n" + parts[2]), redirects, nil
}

func sameStringSet(a, b []string) bool {
	set := make(map[string]int, len(a))
	for _, s := range a {
		set[strings.TrimSpace(s)]++
	}
	for _, s := range b {
		key := strings.TrimSpace(s)
		if set[key] == 0 {
			return false
		}
		set[key]--
	}
	for _, count := range set {
		if count != 0 {
			return false
		}
	}
	return true
}

func sameProductVersionSet(a, b []publicProductVersion) bool {
	key := func(v publicProductVersion) string {
		return strings.ToLower(strings.TrimSpace(v.Product)) + "\x00" + strings.TrimSpace(v.Range)
	}
	set := make(map[string]int, len(a))
	for _, v := range a {
		set[key(v)]++
	}
	for _, v := range b {
		k := key(v)
		if set[k] == 0 {
			return false
		}
		set[k]--
	}
	for _, count := range set {
		if count != 0 {
			return false
		}
	}
	return true
}

func mergeProductVersions(groups ...[]publicProductVersion) []publicProductVersion {
	seen := map[string]bool{}
	var result []publicProductVersion
	for _, group := range groups {
		for _, v := range group {
			key := strings.ToLower(strings.TrimSpace(v.Product)) + "\x00" + strings.ToLower(strings.TrimSpace(v.Range))
			if v.Product != "" && v.Range != "" && !seen[key] {
				seen[key] = true
				result = append(result, v)
			}
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if strings.EqualFold(result[i].Product, result[j].Product) {
			return result[i].Range < result[j].Range
		}
		return strings.ToLower(result[i].Product) < strings.ToLower(result[j].Product)
	})
	return result
}

type TermRedirect struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

func canonicalTextList(raw []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, s := range raw {
		s = CanonicalVendorName(s)
		k := strings.ToLower(s)
		if s != "" && !seen[k] {
			seen[k] = true
			result = append(result, s)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return strings.ToLower(result[i]) < strings.ToLower(result[j]) })
	return result
}

func stringSlice(value any) []string {
	switch values := value.(type) {
	case []any:
		out := []string{}
		for _, v := range values {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return values
	default:
		return nil
	}
}

func termRedirects(oldVendors, newVendors, oldProducts, newProducts []string) []TermRedirect {
	redirects := map[string]TermRedirect{}
	add := func(kind string, old, canonical string) {
		from, to := "/"+kind+"/"+termSlug(old)+"/", "/"+kind+"/"+termSlug(canonical)+"/"
		if old != "" && canonical != "" && from != to {
			redirects[from] = TermRedirect{From: from, To: to, Kind: strings.TrimSuffix(kind, "s")}
		}
	}
	for _, old := range oldVendors {
		for _, canonical := range newVendors {
			if strings.EqualFold(strings.TrimSpace(old), canonical) {
				add("vendors", old, canonical)
				break
			}
		}
	}
	for _, old := range oldProducts {
		name, _ := productNameAndRange(old)
		for _, canonical := range newProducts {
			if strings.EqualFold(strings.TrimSpace(name), canonical) {
				add("products", old, canonical)
				break
			}
		}
	}
	out := make([]TermRedirect, 0, len(redirects))
	for _, r := range redirects {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From < out[j].From })
	return out
}

func termSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			if r <= unicode.MaxASCII {
				b.WriteRune(r)
			} else {
				for _, value := range []byte(string(r)) {
					fmt.Fprintf(&b, "%%%02X", value)
				}
			}
			dash = false
		} else if r == '-' || r == '_' || r == '.' || r == '/' || r == '+' || r == '@' || r == '~' {
			b.WriteRune(r)
			dash = false
		} else if unicode.IsSpace(r) && !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
