package pipeline

import (
	"fmt"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"

	"gopkg.in/yaml.v3"
)

// BundleCVE represents a CVE with enrichment data used in priority scoring.
// SYNC: keep in sync with publisher.BundleCVE (duplicate to avoid circular imports).
type BundleCVE struct {
	ID             string  `json:"id" yaml:"id"`
	Product        string  `json:"product,omitempty" yaml:"product,omitempty"`
	EPSS           float64 `json:"epss" yaml:"epss"`
	EPSSPercentile float64 `json:"epss_percentile" yaml:"epss_percentile"`
	CVSS           float64 `json:"cvss" yaml:"cvss"`
	CVSSVector     string  `json:"cvss_vector,omitempty" yaml:"cvss_vector,omitempty"`
	KEV            bool    `json:"kev,omitempty" yaml:"kev"`
	KEVStatus      string  `json:"kev_status,omitempty" yaml:"kev_status,omitempty"`
}

// UnmarshalYAML accepts a bare scalar ("CVE-2026-1234") as shorthand for a
// CVE entry with only its ID set, alongside the full mapping form.
func (c *BundleCVE) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*c = BundleCVE{ID: strings.TrimSpace(node.Value)}
		return nil
	}
	type plain BundleCVE
	return node.Decode((*plain)(c))
}

// PriorityInput holds all signals used to compute priority.
type PriorityInput struct {
	CVEs               []BundleCVE
	ActiveExploitation bool
	SourceConfidence   float64
	Corroborated       bool
	WatchlistMatch     bool
	HasRules           bool
	HasIOCs            bool
}

// PriorityResult holds the computed priority tier and contributing signals.
type PriorityResult struct {
	Tier    string // "critical", "high", "medium", "low"
	Score   int
	Signals []string
}

// ComputePriority calculates a priority tier from available signals.
func ComputePriority(input PriorityInput) PriorityResult {
	var score int
	var signals []string

	// CVE-specific signals: use the highest-scoring CVE
	var maxEPSS, maxCVSS float64
	hasKEV := false
	for _, cve := range input.CVEs {
		if cve.EPSS > maxEPSS {
			maxEPSS = cve.EPSS
		}
		if cve.CVSS > maxCVSS {
			maxCVSS = cve.CVSS
		}
		if cve.KEV {
			hasKEV = true
		}
	}

	// EPSS (mutually exclusive)
	if maxEPSS >= 0.7 {
		score += 4
		signals = append(signals, "epss_high")
	} else if maxEPSS >= 0.4 {
		score += 2
		signals = append(signals, "epss_medium")
	}

	// CISA KEV
	if hasKEV {
		score += 4
		signals = append(signals, "kev")
	}

	// CVSS (mutually exclusive)
	if maxCVSS >= 9.0 {
		score += 3
		signals = append(signals, "cvss_critical")
	} else if maxCVSS >= 7.0 {
		score += 1
		signals = append(signals, "cvss_high")
	}

	// Active exploitation (content-based, distinct from KEV)
	if input.ActiveExploitation {
		score += 3
		signals = append(signals, "active_exploitation")
	}

	// Multi-source corroboration
	if input.Corroborated {
		score += 2
		signals = append(signals, "corroborated")
	}

	// Global watchlist match
	if input.WatchlistMatch {
		score += 2
		signals = append(signals, "watchlist_match")
	}

	// Actionability indicators
	if input.HasRules {
		score += 1
		signals = append(signals, "has_rules")
	}
	if input.HasIOCs {
		score += 1
		signals = append(signals, "has_iocs")
	}

	// Source confidence is trust, not urgency. It can boost an item that
	// already has an impact/exploitation/actionability signal, but must not
	// promote a low-impact advisory by itself.
	if input.SourceConfidence >= 0.9 {
		if score > 0 {
			score += 1
		}
		signals = append(signals, "high_confidence_source")
	} else if input.SourceConfidence >= 0.7 {
		if score > 0 {
			score += 1
		}
		signals = append(signals, "medium_confidence_source")
	}

	tier := "low"
	if score >= 7 {
		tier = "critical"
	} else if score >= 4 {
		tier = "high"
	} else if score >= 2 {
		tier = "medium"
	}

	return capPriorityForLowUrgency(input, PriorityResult{Tier: tier, Score: score, Signals: signals})
}

// EnrichBriefWithPriority adds priority tier, score, and signals to the brief YAML.
func EnrichBriefWithPriority(briefYAML string, result PriorityResult) string {
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML
	}
	doc["priority"] = result.Tier
	doc["priority_score"] = result.Score
	if len(result.Signals) > 0 {
		doc["priority_signals"] = result.Signals
	} else {
		delete(doc, "priority_signals")
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

// EnrichBriefWithExploitationEvidence records a sourced active-exploitation
// state without treating a priority signal as evidence by itself.
func EnrichBriefWithExploitationEvidence(briefYAML, sourceURL, observedAt, confidence string) string {
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML
	}
	evidence := map[string]interface{}{
		"status":     "confirmed_active",
		"source_url": sourceURL,
	}
	if strings.TrimSpace(observedAt) != "" {
		evidence["observed_at"] = observedAt
	} else if publishedAt := strings.TrimSpace(fmt.Sprint(doc["published_at"])); publishedAt != "" && publishedAt != "<nil>" {
		evidence["observed_at"] = publishedAt
	}
	if strings.TrimSpace(confidence) != "" {
		evidence["confidence"] = confidence
	}
	doc["exploitation_evidence"] = evidence
	doc["exploited"] = true
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

type SourceAssessmentInput struct {
	Source             string
	SourceConfidence   float64
	Corroborated       bool
	ActiveExploitation bool
}

func EnrichBriefWithSourceAssessment(briefYAML string, input SourceAssessmentInput) string {
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML
	}
	if _, exists := doc["source_assessment"]; exists {
		return briefYAML
	}

	reliability := sourceReliabilityCode(input.SourceConfidence)
	credibility := sourceCredibilityCode(input)
	confidence := sourceConfidenceBand(input.SourceConfidence, input.Corroborated)

	corroboration := "Single-source reporting in the current feed; confirm independently before high-impact operational action."
	if input.Corroborated {
		corroboration = "Corroborated by at least two distinct sources observed by the pipeline."
	}
	if input.ActiveExploitation {
		corroboration += " Active exploitation language is present in the source-derived brief."
	}

	flags := []map[string]any{}
	if !input.Corroborated {
		flags = append(flags, map[string]any{
			"type":   "single_source",
			"detail": "Pipeline did not observe independent corroboration for the key claim before publication.",
			"impact": "Treat operational decisions as provisional until a second source or environment evidence confirms it.",
		})
	}
	if strings.Contains(strings.ToLower(input.Source), "reddit") {
		flags = append(flags, map[string]any{
			"type":   "anonymous",
			"detail": "Source is community or social reporting with limited originator verification.",
			"impact": "Use for monitoring or enrichment until corroborated by a primary source.",
		})
	}

	assessment := map[string]any{
		"reliability":   reliability,
		"credibility":   credibility,
		"rating":        reliability + credibility,
		"confidence":    confidence,
		"corroboration": corroboration,
	}
	if input.ActiveExploitation || input.Corroborated {
		assessment["likelihood"] = "likely"
	} else {
		assessment["likelihood"] = "roughly even chance"
	}
	if len(flags) > 0 {
		assessment["flags"] = flags
		assessment["gaps"] = []string{"Confirm the key operational claim with an independent primary source or local telemetry before broad response action."}
	}
	doc["source_assessment"] = assessment

	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

func sourceReliabilityCode(conf float64) string {
	switch {
	case conf >= 0.9:
		return "A"
	case conf >= 0.8:
		return "B"
	case conf >= 0.65:
		return "C"
	case conf >= 0.45:
		return "D"
	case conf > 0:
		return "E"
	default:
		return "F"
	}
}

func sourceCredibilityCode(input SourceAssessmentInput) string {
	switch {
	case input.Corroborated:
		return "1"
	case input.ActiveExploitation || input.SourceConfidence >= 0.8:
		return "2"
	case input.SourceConfidence >= 0.5:
		return "3"
	default:
		return "6"
	}
}

func sourceConfidenceBand(conf float64, corroborated bool) string {
	switch {
	case corroborated && conf >= 0.8:
		return "high"
	case conf >= 0.65:
		return "moderate"
	default:
		return "low"
	}
}

// RumourInput holds the signals used to decide whether a brief is unconfirmed
// chatter rather than a verified threat. It mirrors the same inputs as
// PriorityInput plus a flag for Sigma-rule briefs (which are always concrete).
type RumourInput struct {
	SourceConfidence   float64
	CVEs               []BundleCVE
	Corroborated       bool
	ActiveExploitation bool
	WatchlistMatch     bool
	HasSigmaRule       bool
}

// IsRumour returns true when a brief has none of the signals that promote it
// to a verified threat: low source confidence (forum / social), no CVE
// references, no cross-source corroboration, no active-exploitation language,
// not on the watchlist, and not derived from a Sigma rule. Any single positive
// signal disqualifies — we want to be conservative about labelling content as
// "rumour" because it tells consumers to discount it.
func IsRumour(in RumourInput) bool {
	if in.HasSigmaRule {
		return false
	}
	if in.WatchlistMatch || in.ActiveExploitation || in.Corroborated {
		return false
	}
	if len(in.CVEs) > 0 {
		return false
	}
	// Threshold: anything below 0.5 is forum/social tier in the
	// defaultSourceConfidence map (reddit-* < 0.4, risky-biz and
	// risky-biz-bulletin at 0.80 sit above this; bleepingcomputer at 0.70
	// also). We pick 0.5 as a clean "credentialed source ⇕ chatter" boundary.
	return in.SourceConfidence < 0.5
}

func PublishableRumour(item scraper.RawItem, assessment *ClaimAssessment) (bool, string) {
	if item.Discovery == nil || strings.TrimSpace(item.Discovery.OriginalURL) == "" {
		return false, "missing discovery provenance"
	}
	if !item.Discovery.ContextComplete {
		return false, "incomplete social context"
	}
	if _, _, ok := scraper.ParseXStatusURL(item.Discovery.OriginalURL); !ok && !strings.HasPrefix(item.Discovery.OriginalURL, "http") {
		return false, "missing attributed public URL"
	}
	if assessment == nil || strings.TrimSpace(assessment.Claim) == "" {
		return false, "missing claim assessment"
	}
	if assessment.Likelihood != "likely" {
		return false, "likelihood is not likely"
	}
	if len(assessment.EstablishedFacts) == 0 {
		return false, "missing established facts"
	}
	if len(assessment.Gaps) == 0 {
		return false, "missing uncertainty gaps"
	}
	allowed := map[string]bool{"first_party_observation": true, "mechanism": true, "artifact": true, "corroboration": true}
	firstParty, concrete, corroborated := false, false, false
	for _, e := range assessment.Evidence {
		if !allowed[e.Type] || strings.TrimSpace(e.Detail) == "" || strings.TrimSpace(e.SourceURL) == "" {
			continue
		}
		if e.Type == "first_party_observation" {
			firstParty = true
		}
		if e.Type == "mechanism" || e.Type == "artifact" {
			concrete = true
		}
		if e.Type == "corroboration" {
			corroborated = true
		}
	}
	if !concrete || (!corroborated && !firstParty) {
		return false, "likely requires concrete mechanism/artifact evidence plus corroboration or first-party observation"
	}
	return true, ""
}

func EnrichBriefWithRumourAssessment(briefYAML string, a *ClaimAssessment) string {
	var doc map[string]any
	if yaml.Unmarshal([]byte(briefYAML), &doc) != nil {
		return briefYAML
	}
	doc["severity"] = "rumour"
	doc["type"] = "rumour"
	doc["claim_state"] = string(NextClaimState(ClaimReported, *a))
	doc["established_facts"] = a.EstablishedFacts
	doc["reported_claims"] = []string{a.Claim}
	doc["evidence"] = a.Evidence
	doc["gaps"] = a.Gaps
	doc["unverified_notice"] = "This evidence-backed report remains unverified; treat recommendations as provisional pending independent confirmation."
	if content, ok := doc["content"].(string); ok && !strings.Contains(strings.ToLower(content), "provisional") {
		doc["content"] = content + "\n\n> Unverified: all recommendations are provisional pending independent confirmation.\n"
	}
	sa, _ := doc["source_assessment"].(map[string]any)
	if sa == nil {
		sa = map[string]any{}
	}
	sa["likelihood"] = "likely"
	sa["gaps"] = a.Gaps
	doc["source_assessment"] = sa
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}
