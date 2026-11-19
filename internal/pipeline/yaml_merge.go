package pipeline

import (
	"fmt"
	"strings"
)

func yamlStringList(v any) []string {
	var out []string
	for _, item := range yamlAnyList(v) {
		if s := strings.TrimSpace(fmt.Sprint(item)); s != "" && s != "<nil>" {
			out = append(out, s)
		}
	}
	return out
}

func yamlAnyList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, 0, len(t))
		for _, s := range t {
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}

func asStringMap(v any) (map[string]any, bool) {
	if m, ok := v.(map[string]any); ok {
		return m, true
	}
	if m, ok := v.(map[any]any); ok {
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[fmt.Sprint(k)] = v
		}
		return out, true
	}
	return nil, false
}

// mergeMapListByIdentityComplete unions structured entries and enriches an
// existing entry when a later source supplies fields that were previously
// absent. Positive booleans are monotonic so later corroboration can promote
// KEV/confirmed flags but cannot erase them.
func mergeMapListByIdentityComplete(fm map[string]any, key string, incoming any, identityKeys []string) bool {
	existing := yamlAnyList(fm[key])
	indices := make(map[string]int, len(existing))
	for i, item := range existing {
		if id := mapListIdentity(item, identityKeys); id != "" {
			indices[id] = i
		}
	}
	changed := false
	for _, item := range yamlAnyList(incoming) {
		id := mapListIdentity(item, identityKeys)
		if id == "" {
			continue
		}
		if idx, found := indices[id]; found {
			baseMap, baseOK := asStringMap(existing[idx])
			incomingMap, incomingOK := asStringMap(item)
			if baseOK && incomingOK && mergeMissingMapValues(baseMap, incomingMap) {
				existing[idx] = baseMap
				changed = true
			}
			continue
		}
		existing = append(existing, item)
		indices[id] = len(existing) - 1
		changed = true
	}
	if changed {
		fm[key] = existing
	}
	return changed
}

func mergeMissingMapValues(base, incoming map[string]any) bool {
	changed := false
	for key, next := range incoming {
		current, exists := base[key]
		if !exists || yamlValueEmpty(current) {
			if !yamlValueEmpty(next) {
				base[key] = next
				changed = true
			}
			continue
		}
		if currentBool, ok := current.(bool); ok {
			if nextBool, ok := next.(bool); ok && nextBool && !currentBool {
				base[key] = true
				changed = true
			}
			continue
		}
		currentMap, currentOK := asStringMap(current)
		nextMap, nextOK := asStringMap(next)
		if currentOK && nextOK && mergeMissingMapValues(currentMap, nextMap) {
			base[key] = currentMap
			changed = true
		}
		if key == "kev_status" && strings.EqualFold(strings.TrimSpace(fmt.Sprint(current)), "unknown") &&
			!strings.EqualFold(strings.TrimSpace(fmt.Sprint(next)), "unknown") && !yamlValueEmpty(next) {
			base[key] = next
			changed = true
		}
	}
	return changed
}

func yamlValueEmpty(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		s := strings.TrimSpace(v)
		return s == "" || s == "<nil>"
	case []any:
		return len(v) == 0
	case []string:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	case map[any]any:
		return len(v) == 0
	}
	return false
}

func mergeScalarIfMissing(base, incoming map[string]any, key string) bool {
	if !yamlValueEmpty(base[key]) || yamlValueEmpty(incoming[key]) {
		return false
	}
	base[key] = incoming[key]
	return true
}

func mergeMapIfMissing(base, incoming map[string]any, key string) bool {
	if !yamlValueEmpty(base[key]) || yamlValueEmpty(incoming[key]) {
		return false
	}
	if _, ok := asStringMap(incoming[key]); !ok {
		return false
	}
	base[key] = incoming[key]
	return true
}

func mergeMonotonicBool(base, incoming map[string]any, key string) bool {
	next, _ := incoming[key].(bool)
	current, _ := base[key].(bool)
	if !next || current {
		return false
	}
	base[key] = true
	return true
}

func mergeExploitationState(base, incoming map[string]any) bool {
	changed := mergeMonotonicBool(base, incoming, "exploited")
	next, nextOK := asStringMap(incoming["exploitation_evidence"])
	if !nextOK {
		return changed
	}
	current, currentOK := asStringMap(base["exploitation_evidence"])
	if !currentOK {
		base["exploitation_evidence"] = next
		current = next
		changed = true
	} else {
		currentRank := exploitationStateRank(current)
		nextRank := exploitationStateRank(next)
		if nextRank > currentRank {
			base["exploitation_evidence"] = next
			current = next
			changed = true
		} else if nextRank == currentRank && mergeMissingMapValues(current, next) {
			base["exploitation_evidence"] = current
			changed = true
		}
	}
	if exploitationStateRank(current) == exploitationEvidenceRank("confirmed_active") {
		if exploited, _ := base["exploited"].(bool); !exploited {
			base["exploited"] = true
			changed = true
		}
	}
	return changed
}

// exploitationStateRank ranks an evidence state. A confirmed state whose only
// evidence is an exploit-code listing asserts nothing, so attributed evidence
// from a later source replaces it instead of keeping the listing URL.
func exploitationStateRank(evidence map[string]any) int {
	rank := exploitationEvidenceRank(fmt.Sprint(evidence["status"]))
	if rank == exploitationEvidenceRank("confirmed_active") && ExploitCodeListingURL(fmt.Sprint(evidence["source_url"])) {
		return 0
	}
	return rank
}

func exploitationEvidenceRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "confirmed_active":
		return 2
	case "not_observed":
		return 1
	default:
		return 0
	}
}

func mergeHigherPriority(base, incoming map[string]any) bool {
	changed := false
	current := strings.ToLower(strings.TrimSpace(fmt.Sprint(base["priority"])))
	next := strings.ToLower(strings.TrimSpace(fmt.Sprint(incoming["priority"])))
	if severityRank(next) > severityRank(current) {
		base["priority"] = next
		changed = true
	}
	currentScore, currentOK := numericValue(base["priority_score"])
	nextScore, nextOK := numericValue(incoming["priority_score"])
	if nextOK && (!currentOK || nextScore > currentScore) {
		base["priority_score"] = incoming["priority_score"]
		changed = true
	}
	return changed
}

func numericValue(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	case float32:
		return float64(v), true
	default:
		return 0, false
	}
}

func mergeActionPlan(base, incoming map[string]any) bool {
	next, nextOK := asStringMap(incoming["action_plan"])
	if !nextOK {
		return false
	}
	current, currentOK := asStringMap(base["action_plan"])
	if !currentOK {
		base["action_plan"] = next
		return true
	}
	changed := mergeStringList(current, "owners", yamlStringList(next["owners"]))
	changed = mergeStringList(current, "gaps", yamlStringList(next["gaps"])) || changed
	changed = mergeMapListByIdentityComplete(current, "immediate_actions", next["immediate_actions"], []string{"action", "owner"}) || changed
	changed = mergeMapListByIdentityComplete(current, "enrichment_needed", next["enrichment_needed"], []string{"item", "owner"}) || changed
	changed = mergeMapListByIdentityComplete(current, "hunt_leads", next["hunt_leads"], []string{"lead", "technique_id"}) || changed
	changed = mergeMapListByIdentityComplete(current, "mitigation_plan", next["mitigation_plan"], []string{"action", "owner"}) || changed
	currentPriority := strings.ToLower(strings.TrimSpace(fmt.Sprint(current["priority"])))
	nextPriority := strings.ToLower(strings.TrimSpace(fmt.Sprint(next["priority"])))
	if severityRank(nextPriority) > severityRank(currentPriority) {
		current["priority"] = nextPriority
		changed = true
	}
	if changed {
		base["action_plan"] = current
	}
	return changed
}

func mapListIdentity(item any, keys []string) string {
	if m, ok := asStringMap(item); ok {
		var parts []string
		for _, key := range keys {
			if s := strings.TrimSpace(fmt.Sprint(m[key])); s != "" && s != "<nil>" {
				parts = append(parts, strings.ToLower(s))
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\x00")
		}
	}
	if s := strings.TrimSpace(fmt.Sprint(item)); s != "" && s != "<nil>" {
		return strings.ToLower(s)
	}
	return ""
}

func mergeHigherSeverity(base, incoming map[string]any) bool {
	current := strings.ToLower(strings.TrimSpace(fmt.Sprint(base["severity"])))
	next := strings.ToLower(strings.TrimSpace(fmt.Sprint(incoming["severity"])))
	if severityRank(next) > severityRank(current) {
		base["severity"] = next
		return true
	}
	return false
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func assembledUpdateSummary(incoming map[string]any) string {
	// Detection rule added.
	for _, item := range yamlAnyList(incoming["rules"]) {
		if m, ok := asStringMap(item); ok {
			if title := strings.TrimSpace(fmt.Sprint(m["title"])); title != "" && title != "<nil>" {
				return "added detection rule: " + title
			}
		}
	}
	// New product coverage is the most useful signal for product merges.
	if products := yamlStringList(incoming["affected_products"]); len(products) > 0 {
		product := products[0]
		if len(products) > 1 {
			return fmt.Sprintf("added coverage for %s +%d products", product, len(products)-1)
		}
		return "added coverage for " + product
	}
	// New vendor.
	if vendors := yamlStringList(incoming["affected_vendors"]); len(vendors) > 0 {
		return "added vendor: " + vendors[0]
	}
	// New IOCs.
	if iocs := yamlAnyList(incoming["iocs"]); len(iocs) > 0 {
		return fmt.Sprintf("added %d IOCs", len(iocs))
	}
	// Fallback to the incoming brief title, but avoid the repetitive
	// "merged source coverage" prefix that was making every update line identical.
	if title := strings.TrimSpace(fmt.Sprint(incoming["title"])); title != "" && title != "<nil>" {
		return "merged coverage from " + title
	}
	return "merged additional coverage"
}

// mergeStringList unions newVals into fm[key] (a list of strings),
// case-insensitive dedup, preserving the existing order. Returns true
// if any new value was added.
func mergeStringList(fm map[string]any, key string, newVals []string) bool {
	if len(newVals) == 0 {
		return false
	}
	var existing []any
	if v, ok := fm[key].([]any); ok {
		existing = v
	}
	seen := make(map[string]struct{}, len(existing))
	for _, e := range existing {
		if s, ok := e.(string); ok {
			seen[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
		} else if m, ok := asStringMap(e); ok {
			// Enriched CVEs are entries with an id. Re-appending one as a bare
			// string created duplicate CVE entries in published briefs.
			if id, ok := m["id"].(string); ok {
				seen[strings.ToLower(strings.TrimSpace(id))] = struct{}{}
			}
		}
	}
	added := false
	for _, v := range newVals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		k := strings.ToLower(v)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		existing = append(existing, v)
		added = true
	}
	if added {
		fm[key] = existing
	}
	return added
}

// mergeIOCList unions IOCs (type+value pairs) into fm["iocs"]. Returns
// true if any entry was added.
func mergeIOCList(fm map[string]any, newIOCs []ExtractedIOC) bool {
	if len(newIOCs) == 0 {
		return false
	}
	var existing []any
	if v, ok := fm["iocs"].([]any); ok {
		existing = v
	}
	seen := make(map[string]struct{}, len(existing))
	keyFor := func(t, val string) string {
		return strings.ToLower(strings.TrimSpace(t)) + "|" + strings.TrimSpace(val)
	}
	for _, e := range existing {
		m, _ := e.(map[string]any)
		t, _ := m["type"].(string)
		val, _ := m["value"].(string)
		seen[keyFor(t, val)] = struct{}{}
	}
	added := false
	for _, ioc := range newIOCs {
		val := strings.TrimSpace(ioc.Value)
		if val == "" || strings.TrimSpace(ioc.Type) == "" {
			continue
		}
		k := keyFor(ioc.Type, val)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		entry := map[string]any{"type": ioc.Type, "value": val}
		if c := strings.TrimSpace(ioc.Context); c != "" {
			entry["context"] = c
		}
		existing = append(existing, entry)
		added = true
	}
	if added {
		fm["iocs"] = existing
	}
	return added
}
