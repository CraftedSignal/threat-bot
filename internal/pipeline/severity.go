package pipeline

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// SeverityContext carries post-enrichment signals used to normalize the public
// feed severity label. Feed severity is operational urgency, not raw CVSS.
type SeverityContext struct {
	CVEs               []BundleCVE
	ActiveExploitation bool
	WatchlistMatch     bool
}

// SeverityBasis records who assigned a label and which deterministic rule
// produced it. Operational urgency and detector priority are not source CVSS.
type SeverityBasisKind string

const (
	SeverityOperationalPolicy SeverityBasisKind = "operational_policy"
	SeveritySourceCVSS        SeverityBasisKind = "source_cvss"
	SeveritySourceRating      SeverityBasisKind = "source_severity"
	SeverityModelInference    SeverityBasisKind = "model_inference"
)

type SeverityBasis struct {
	Kind      SeverityBasisKind `yaml:"kind" json:"kind"`
	Value     string            `yaml:"value" json:"value"`
	Rule      string            `yaml:"rule,omitempty" json:"rule,omitempty"`
	Source    string            `yaml:"source,omitempty" json:"source,omitempty"`
	SourceURL string            `yaml:"source_url,omitempty" json:"source_url,omitempty"`
}

func setSeverityBasis(raw string, basis SeverityBasis) string {
	var doc map[string]any
	if yaml.Unmarshal([]byte(raw), &doc) != nil || doc == nil {
		return raw
	}
	basis.Value = stringFromAny(doc["severity"])
	if basis.Value == "" {
		return raw
	}
	doc["severity_basis"] = basis
	out, err := yaml.Marshal(doc)
	if err != nil {
		return raw
	}
	return string(out)
}

// NormalizeOperationalSeverity caps low-urgency CVE advisories after CVE
// enrichment. Source authority is intentionally not an input: it establishes
// trust, but it should not promote low-impact issues.
func NormalizeOperationalSeverity(briefYAML string, ctx SeverityContext) (string, []string) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML, nil
	}

	current := strings.ToLower(strings.TrimSpace(stringFromAny(doc["severity"])))
	if severityRank(current) <= severityRank("low") {
		return briefYAML, nil
	}

	if low, reason := isLowUrgencyCVE(ctx); low {
		doc["severity"] = "low"
		doc["severity_basis"] = SeverityBasis{Kind: SeverityOperationalPolicy, Value: "low", Rule: "low-urgency-cve/v1"}
		out, err := yaml.Marshal(doc)
		if err != nil {
			return briefYAML, nil
		}
		return string(out), []string{fmt.Sprintf("downgraded severity %s->low: %s", current, reason)}
	}

	return briefYAML, nil
}

// capPriorityForLowUrgency prevents low-impact CVEs from sorting above low just
// because the source is trusted or the item is cross-posted.
func capPriorityForLowUrgency(input PriorityInput, result PriorityResult) PriorityResult {
	if low, _ := isLowUrgencyCVE(SeverityContext{
		CVEs:               input.CVEs,
		ActiveExploitation: input.ActiveExploitation,
		WatchlistMatch:     input.WatchlistMatch,
	}); low && severityRank(result.Tier) > severityRank("low") {
		result.Tier = "low"
		if result.Score > 1 {
			result.Score = 1
		}
		result.Signals = append(result.Signals, "low_operational_urgency")
	}
	return result
}

func isLowUrgencyCVE(ctx SeverityContext) (bool, string) {
	if len(ctx.CVEs) == 0 || hasUrgencyBoost(ctx) {
		return false, ""
	}

	seenClassified := false
	for _, cve := range ctx.CVEs {
		low, reason := isLowUrgencySingleCVE(cve)
		if !low {
			return false, ""
		}
		if reason != "" {
			seenClassified = true
		}
	}
	if !seenClassified {
		return false, ""
	}
	return true, "all CVEs are low-impact and have no exploitation/KEV/EPSS/watchlist boost"
}

func hasUrgencyBoost(ctx SeverityContext) bool {
	if ctx.ActiveExploitation || ctx.WatchlistMatch {
		return true
	}
	for _, cve := range ctx.CVEs {
		if cve.KEV || cve.EPSS >= 0.4 {
			return true
		}
	}
	return false
}

func isLowUrgencySingleCVE(cve BundleCVE) (bool, string) {
	if cve.CVSS > 0 && cve.CVSS < 5.0 {
		return true, "cvss_below_5"
	}

	vector := parseCVSSVector(cve.CVSSVector)
	if len(vector) == 0 {
		return false, ""
	}

	if isAvailabilityOnly(vector) {
		return true, "availability_only"
	}
	if cve.CVSS > 0 && cve.CVSS < 7.0 && privilegesRequired(vector) {
		return true, "authenticated_low_or_medium_cvss"
	}
	if cve.CVSS > 0 && cve.CVSS < 7.0 && userInteractionRequired(vector) && !hasHighConfidentialityOrIntegrity(vector) {
		return true, "user_interaction_low_or_medium_cvss"
	}

	return false, ""
}

func parseCVSSVector(vector string) map[string]string {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	out := make(map[string]string, len(parts))
	for _, part := range parts {
		if strings.HasPrefix(part, "CVSS:") {
			continue
		}
		key, value, ok := strings.Cut(part, ":")
		if !ok || key == "" || value == "" {
			continue
		}
		out[strings.ToUpper(key)] = strings.ToUpper(value)
	}
	return out
}

func isAvailabilityOnly(vector map[string]string) bool {
	return vector["C"] == "N" && vector["I"] == "N" && vector["A"] != "" && vector["A"] != "N"
}

func privilegesRequired(vector map[string]string) bool {
	return vector["PR"] == "L" || vector["PR"] == "H"
}

func userInteractionRequired(vector map[string]string) bool {
	return vector["UI"] == "R"
}

func hasHighConfidentialityOrIntegrity(vector map[string]string) bool {
	return vector["C"] == "H" || vector["I"] == "H"
}

func stringFromAny(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}
