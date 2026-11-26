package pipeline

import (
	"encoding/json"
	"slices"
	"strings"
)

// releaseBoundRemediationRule is the one remediation policy shared by brief
// assembly, grounding, claim checks, repair and the machine-derived evidence
// below. When those stages disagreed, assembly wrote "upgrade to X" from
// "affected before X", the checker rejected it as unsupported, and after repair
// demanded the same fixed release again: most first-pass grounding failures on
// new CVE briefs were this oscillation. Keep every stage on this exact text.
const releaseBoundRemediationRule = `RELEASE-BOUND REMEDIATION: When a source bounds a product's affected releases with an exclusive upper release (for example "before X", "prior to X", "earlier than X", "< X", versionEndExcluding X, or a CVE record range with lessThan X), X is that product's fixed release for that range: "upgrade to X or later" and "fixed in X" are source-supported. A list such as "before X and Y" names one fixed release per release branch; keep each with its branch. This does not apply to inclusive bounds ("through X", "up to and including X", "X and earlier", "<= X", versionEndIncluding, lessThanOrEqual), to Git commit or original_commit_for_fix bounds, or when the source states that no fix is available; there, report remediation as unknown unless the source states it.`

// releaseBoundFix is the fixed release that releaseBoundRemediationRule derives
// from one exclusive affected range.
type releaseBoundFix struct {
	Fixed, Range string
}

// exclusiveReleaseBounds returns the fixed release of each exclusive, literal
// release range in a CVE record's affected entry. A scope the range renderer
// cannot express (commit bounds, version changes, default-affected exceptions)
// derives nothing and keeps its applicability gap.
func (e cnaAffectedEntry) exclusiveReleaseBounds() []releaseBoundFix {
	if _, ok := e.ranges(); !ok {
		return nil
	}
	var out []releaseBoundFix
	for _, version := range e.Versions {
		below := strings.TrimSpace(version.LessThan)
		if below == "" || below == "*" || strings.TrimSpace(version.LessThanOrEqual) != "" {
			continue
		}
		rendered, ok := version.render()
		if !ok {
			continue
		}
		fix := releaseBoundFix{Fixed: below, Range: rendered}
		if !slices.Contains(out, fix) {
			out = append(out, fix)
		}
	}
	return out
}

// releaseBoundRemediationGuidance states, for each CVE and product, the fixed
// releases the rule derives from the record's exclusive bounds. Assembly and
// grounding then read the same fact instead of each interpreting the bound.
func releaseBoundRemediationGuidance(primary primaryRecordFacts) string {
	if primary.Truncated {
		return ""
	}
	var lines []string
	for _, fact := range primary.Included {
		if fact.Kind != "affected" || strings.TrimSpace(fact.CVEID) == "" {
			continue
		}
		var entry cnaAffectedEntry
		if json.Unmarshal([]byte(fact.Text), &entry) != nil {
			continue
		}
		product := strings.TrimSpace(fact.Product)
		if product == "" {
			product = strings.TrimSpace(entry.Product)
		}
		fixes := entry.exclusiveReleaseBounds()
		if product == "" || len(fixes) == 0 {
			continue
		}
		parts := make([]string, len(fixes))
		for i, fix := range fixes {
			parts[i] = fix.Fixed + " (affected " + fix.Range + ")"
		}
		line := "- " + fact.CVEID + " / " + product + ": fixed release " + strings.Join(parts, "; ")
		if !slices.Contains(lines, line) {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	slices.Sort(lines)
	return "Release-bound remediation (machine-derived from the exclusive affected bounds above under RELEASE-BOUND REMEDIATION; upgrading to a listed fixed release or later is source-supported). Apply each line only to its CVE and product:\n" + strings.Join(lines, "\n") + "\n"
}

// recordHasReleaseBoundFix reports whether any affected entry of a CVE record
// derives a fixed release, so its coverage note must not call remediation
// absent.
func recordHasReleaseBoundFix(facts []cnaSourceFact) bool {
	for _, fact := range facts {
		if fact.Kind != "affected" {
			continue
		}
		var entry cnaAffectedEntry
		if json.Unmarshal([]byte(fact.Text), &entry) == nil && len(entry.exclusiveReleaseBounds()) > 0 {
			return true
		}
	}
	return false
}
