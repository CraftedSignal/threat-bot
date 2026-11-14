package sigma

import "strings"

// modifierAliases maps modifier spellings an LLM tends to write to the Sigma
// modifier they mean.
var modifierAliases = map[string]string{
	"regex":     "re",
	"regexp":    "re",
	"startwith": "startswith",
	"endwith":   "endswith",
	"contain":   "contains",
}

// NormalizeModifierKey rewrites alias modifier tokens in a Sigma field key
// (Field|mod1|mod2). Only whole modifier tokens after the field name change;
// the field name is never touched.
func NormalizeModifierKey(key string) string {
	parts := strings.Split(key, "|")
	if len(parts) < 2 {
		return key
	}
	for i := 1; i < len(parts); i++ {
		if canonical, ok := modifierAliases[strings.ToLower(strings.TrimSpace(parts[i]))]; ok {
			parts[i] = canonical
		}
	}
	return strings.Join(parts, "|")
}

// NormalizeModifierAliases rewrites alias modifiers in the field keys of a
// detection block in place and reports whether anything changed. Values are
// never modified. A key is left alone when its normalized form already
// exists in the same selection.
func NormalizeModifierAliases(detection map[string]any) bool {
	changed := false
	for _, v := range detection {
		if normalizeValue(v) {
			changed = true
		}
	}
	return changed
}

func normalizeValue(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for key, val := range t {
			if normalizeValue(val) {
				changed = true
			}
			norm := NormalizeModifierKey(key)
			if norm == key {
				continue
			}
			if _, exists := t[norm]; exists {
				continue
			}
			t[norm] = val
			delete(t, key)
			changed = true
		}
	case []any:
		for _, item := range t {
			if normalizeValue(item) {
				changed = true
			}
		}
	}
	return changed
}
