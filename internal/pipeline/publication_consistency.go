package pipeline

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ValidatePublicationConsistency catches contradictions that are sufficiently
// clear to require editorial review before a brief is published. It runs on
// the final YAML, including later merges, so a draft cannot bypass it by
// passing the initial LLM validation.
func ValidatePublicationConsistency(rawYAML string) []string {
	var brief map[string]any
	if err := yaml.Unmarshal([]byte(rawYAML), &brief); err != nil {
		return []string{fmt.Sprintf("invalid brief YAML: %v", err)}
	}
	if brief == nil {
		return []string{"brief YAML is empty"}
	}

	var issues []string
	title := publicationString(brief["title"])
	summary := publicationString(brief["summary"])
	content := publicationString(brief["content"])
	published, dateErr := time.Parse(time.RFC3339, publicationString(brief["published_at"]))
	if dateErr == nil {
		latestChange := published
		if t, err := time.Parse(time.RFC3339, publicationString(brief["lastmod"])); err == nil && t.After(latestChange) {
			latestChange = t
		}
		for _, cve := range publicationCVEs(brief["cves"], title) {
			year, err := strconv.Atoi(cve[4:8])
			if err == nil && latestChange.Year() < year {
				issues = append(issues, fmt.Sprintf("published_at and lastmod predate %s", cve))
				break
			}
		}
	}

	// Product-specific briefs with a single named product should not absorb
	// unrelated CVEs, vendors, or CPE families during a later source merge.
	// Broad campaign/roundup briefs deliberately cover multiple products.
	if publicationNarrowProduct(title, yamlStringList(brief["affected_products"])) {
		vendors := publicationUnique(yamlStringList(brief["affected_vendors"]))
		cpeVendors := publicationCPEVendors(yamlStringList(brief["cpes"]))
		cvEs := publicationCVEs(brief["cves"], "")
		titleCVEs := publicationCVEs(nil, title)
		if len(vendors) >= 3 || len(cpeVendors) >= 3 || (len(titleCVEs) == 1 && len(cvEs) >= 3) {
			issues = append(issues, fmt.Sprintf("product-specific brief has inconsistent scope (%d CVEs, %d vendors, %d CPE vendors)", len(cvEs), len(vendors), len(cpeVendors)))
		}
	}

	// The assembler is instructed to emit TTPs only for source-supported
	// behavior. If that behavior cannot ground a portable Sigma rule, it still
	// needs an operational hunt lead; otherwise the brief tells defenders what
	// happened without giving them a way to look for it.
	ttps := briefTTPs(brief)
	if lacksDetectionCoverage(brief) {
		issues = append(issues, "source-supported TTPs require at least one grounded detection rule or hunt lead")
	}

	for _, entry := range ttps {
		ttp, ok := asStringMap(entry)
		if !ok || publicationString(ttp["technique_id"]) != "T1203" {
			continue
		}
		evidence := publicationString(ttp["evidence"])
		context := strings.ToLower(strings.Join([]string{title, summary, content, evidence}, " "))
		if publicationServerEvidence(evidence, context) && !publicationClientEvidence(evidence, context) {
			issues = append(issues, "T1203 describes client exploitation but the evidence describes a server-side web application")
		}
	}
	return issues
}

func publicationString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

var publicationCVERe = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

func publicationCVEs(field any, title string) []string {
	var values []string
	for _, entry := range yamlAnyList(field) {
		values = append(values, fmt.Sprint(entry))
	}
	values = append(values, title)
	var ids []string
	seen := make(map[string]bool)
	for _, id := range publicationCVERe.FindAllString(strings.Join(values, " "), -1) {
		id = strings.ToUpper(id)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

func publicationNarrowProduct(title string, products []string) bool {
	if len(publicationUnique(products)) != 1 {
		return false
	}
	lower := strings.ToLower(title)
	for _, term := range []string{"roundup", "multiple products", "multiple vendors", "supply chain", "campaign across", "patch tuesday"} {
		if strings.Contains(lower, term) {
			return false
		}
	}
	return true
}

func publicationUnique(values []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func publicationCPEVendors(cpes []string) []string {
	var vendors []string
	for _, cpe := range cpes {
		parts := strings.Split(cpe, ":")
		if len(parts) >= 5 && parts[0] == "cpe" && parts[1] == "2.3" {
			vendors = append(vendors, parts[3])
		}
	}
	return publicationUnique(vendors)
}

func publicationServerEvidence(evidence, context string) bool {
	text := strings.ToLower(evidence)
	if text == "" {
		text = context
	}
	for _, term := range []string{"server-side", "web application", "web server", "file upload", "http post", "web shell", "public-facing application"} {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func publicationClientEvidence(evidence, context string) bool {
	for _, term := range []string{"client application", "browser", "document", "victim opens", "user opens", "user interaction"} {
		if strings.Contains(strings.ToLower(evidence), term) || strings.Contains(context, term) {
			return true
		}
	}
	return false
}

// briefTTPs returns the brief's TTP entries under either field name.
func briefTTPs(brief map[string]any) []any {
	ttps := yamlAnyList(brief["ttps"])
	if len(ttps) == 0 {
		ttps = yamlAnyList(brief["mitre_ttps"])
	}
	return ttps
}

// lacksDetectionCoverage reports whether a brief names TTPs but offers neither
// a rule nor a hunt lead to look for them.
func lacksDetectionCoverage(brief map[string]any) bool {
	actionPlan, _ := asStringMap(brief["action_plan"])
	return len(briefTTPs(brief)) > 0 && len(yamlAnyList(brief["rules"])) == 0 && len(yamlAnyList(actionPlan["hunt_leads"])) == 0
}
