package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

var sourceCVEPattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// CheckMergeDelta checks only claims arriving with this source. Previously
// accepted claims are deliberately not checked against an unrelated new item.
// Call before any draft mutation or rumour transition. Provenance is issued
// only after both deterministic identities and semantic grounding pass.
func (g *GroundingChecker) CheckMergeDelta(ctx context.Context, item scraper.RawItem, extraction *ExtractionResult) (*GroundingResult, error) {
	if extraction == nil {
		return &GroundingResult{Grounded: true}, nil
	}
	if extraction.ClaimAssessment != nil {
		for i := range extraction.ClaimAssessment.Evidence {
			extraction.ClaimAssessment.Evidence[i].Provenance = nil
		}
	}
	// JSON intentionally excludes pipeline-owned provenance.
	encoded, err := json.Marshal(extraction)
	if err != nil {
		return nil, err
	}
	var delta map[string]any
	if err := json.Unmarshal(encoded, &delta); err != nil {
		return nil, err
	}
	// An empty field asserts nothing. Sent anyway, the checker reports it as
	// the brief omitting a source fact, which an incoming merge never claims.
	pruneEmptyDelta(delta)
	if len(delta) == 0 {
		return &GroundingResult{Grounded: true}, nil
	}
	rendered, err := yaml.Marshal(delta)
	if err != nil {
		return nil, err
	}
	result, err := g.checkClaims(ctx, item.Title, groundingSource(item), string(rendered))
	if err != nil || !result.Grounded {
		return result, err
	}
	if assessment := extraction.ClaimAssessment; assessment != nil {
		source := normalizeForQuote(item.Title + "\n" + item.Content)
		for i := range assessment.Evidence {
			e := &assessment.Evidence[i]
			if strings.TrimSpace(e.SourceURL) != strings.TrimSpace(item.URL) || claimEvidenceLineage(*e) == "" {
				continue
			}
			// Promotion requires an exact source excerpt, beyond the model's verdict.
			if len(strings.Fields(e.Detail)) < 4 || !strings.Contains(source, normalizeForQuote(e.Detail)) {
				continue
			}
			primary := trustedClaimPrimary(item, extraction.AffectedVendors)
			e.Provenance = &ClaimEvidenceProvenance{
				SourceURL: item.URL, SourceID: item.SourceID, Source: item.Source,
				EvidenceHash: claimEvidenceHash(*e), TrustedPrimary: primary,
				// Unknown publisher ownership cannot prove independence merely
				// by repeating a claim on two domains. Hold for review instead.
				Independent: primary && (strings.Contains(normalizeForQuote(e.Detail), "we independently reproduced") || strings.Contains(normalizeForQuote(e.Detail), "we independently confirmed")),
			}
		}
	}
	return result, nil
}

// mergeAppliedDelta returns the part of an extraction a merge can write to its
// target, for CheckMergeDelta. unionIntoDraft never writes summary, platforms,
// tactics, techniques, vuln_class or chained CVEs, so grounding them only held
// merges for claims nobody would publish: from 2026-11-17 to 11-19, 3,518 of
// 4,327 merge holds cited nothing else. Actor and exploitation use the same
// predicates unionIntoDraft applies, and a claim assessment only feeds a rumour
// lifecycle the target already has. The claim assessment stays shared with the
// extraction, so provenance granted by the check still reaches the lifecycle.
func mergeAppliedDelta(item scraper.RawItem, extraction *ExtractionResult, liveLifecycle bool) *ExtractionResult {
	delta := cloneExtraction(extraction)
	delta.Tactics, delta.Techniques, delta.Platforms, delta.ChainedCVEs = nil, nil, nil, nil
	delta.Summary, delta.VulnClass = "", ""
	if !mergeAppliesActor(item, extraction) {
		delta.ThreatActor = ""
	}
	if !mergeAppliesExploitation(item, extraction) {
		delta.ActiveExploitation, delta.ExploitationEvidence = false, ""
	}
	if !liveLifecycle {
		delta.ClaimAssessment = nil
	}
	return delta
}

// mergeAppliesActor reports whether a merge records the extraction's actor:
// only a named actor the source itself mentions.
func mergeAppliesActor(item scraper.RawItem, extraction *ExtractionResult) bool {
	actor := strings.ToLower(strings.TrimSpace(extraction.ThreatActor))
	return !item.CorroborationOnly && actor != "" && strings.Contains(strings.ToLower(item.Title+" "+item.Content), actor)
}

// mergeAppliesExploitation reports whether a merge records exploitation: only
// when the source asserts it with a quoted excerpt at a citable URL. An exploit
// tracker lists code, which is never exploitation evidence.
func mergeAppliesExploitation(item scraper.RawItem, extraction *ExtractionResult) bool {
	evidence := strings.ToLower(strings.TrimSpace(extraction.ExploitationEvidence))
	return !item.CorroborationOnly && extraction.ActiveExploitation && evidence != "" && validSourceURL(item.URL) &&
		!isExploitTracker(item.Source) && !ExploitCodeListingURL(item.URL) &&
		strings.Contains(strings.ToLower(item.Title+" "+item.Content), evidence)
}

// pruneEmptyDelta deletes fields that assert nothing, recursively.
func pruneEmptyDelta(fields map[string]any) {
	for key, value := range fields {
		if emptyDeltaValue(value) {
			delete(fields, key)
		}
	}
}

func emptyDeltaValue(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case bool:
		return !v
	case string:
		return strings.TrimSpace(v) == ""
	case []any:
		return len(v) == 0
	case map[string]any:
		pruneEmptyDelta(v)
		return len(v) == 0
	}
	return false
}

func normalizeIndicator(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("hxxps://", "https://", "hxxp://", "http://", "[.]", ".", "(.)", ".", "[:]", ":").Replace(s)
}

func sourceContainsIndicator(source, value string) bool {
	source, value = normalizeIndicator(source), normalizeIndicator(value)
	if value == "" {
		return false
	}
	// Token boundaries prevent an allowed domain/hash from legitimising a
	// different indicator whose value merely includes it as a substring.
	for offset := 0; offset <= len(source); {
		i := strings.Index(source[offset:], value)
		if i < 0 {
			return false
		}
		i += offset
		end := i + len(value)
		token := func(b byte) bool {
			return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.ContainsRune("._-@/", rune(b))
		}
		endBoundary := end == len(source) || !token(source[end])
		if end < len(source) && source[end] == '.' && (end+1 == len(source) || !token(source[end+1])) {
			endBoundary = true
		}
		if (i == 0 || !token(source[i-1])) && endBoundary {
			return true
		}
		offset = i + 1
	}
	return false
}

func identityGroundingIssues(source, brief string) []string {
	var doc map[string]any
	if yaml.Unmarshal([]byte(brief), &doc) != nil {
		return []string{"claims: invalid YAML cannot be grounded"}
	}
	allowed := map[string]bool{}
	for _, id := range sourceCVEPattern.FindAllString(source, -1) {
		allowed[strings.ToUpper(id)] = true
	}
	claims := map[string]any{}
	for _, field := range []string{"title", "summary", "content", "cves", "chained_cves", "claim_assessment", "action_plan", "affected_products", "affected_os", "ttps", "rules", "exploitation_evidence"} {
		claims[field] = doc[field]
	}
	b, _ := yaml.Marshal(claims)
	var issues []string
	seen := map[string]bool{}
	for _, id := range sourceCVEPattern.FindAllString(string(b), -1) {
		id = strings.ToUpper(id)
		if !allowed[id] && !seen[id] {
			issues = append(issues, "cves: identity absent from source: "+id)
			seen[id] = true
		}
	}
	if iocs, ok := doc["iocs"].([]any); ok {
		for _, raw := range iocs {
			ioc, ok := asStringMap(raw)
			if !ok {
				continue
			}
			value, _ := ioc["value"].(string)
			if value != "" && !sourceContainsIndicator(source, value) {
				issues = append(issues, fmt.Sprintf("iocs: identity absent from source: %s", value))
			}
		}
	}
	var checkAttribution func(any)
	checkAttribution = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, nested := range value {
				if key == "source_url" {
					if raw, ok := nested.(string); ok && raw != "" && !sourceContainsIndicator(source, raw) {
						issues = append(issues, "source_url: attribution absent from source: "+raw)
					}
				} else {
					checkAttribution(nested)
				}
			}
		case []any:
			for _, nested := range value {
				checkAttribution(nested)
			}
		}
	}
	for _, field := range []string{"claim_assessment", "exploitation_evidence", "action_plan"} {
		checkAttribution(doc[field])
	}
	return issues
}
