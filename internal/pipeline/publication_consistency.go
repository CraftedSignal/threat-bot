package pipeline

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/sigma"
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
	// A catalog-backed exploitation withdrawal is a narrow safety correction to
	// an already-published brief. It must not be held because that legacy brief
	// lacks unrelated content-quality fields (such as a recommendation or hunt
	// lead). Structural validation, source-reference checks, and rendering still
	// run in the normal publication path.
	if safeExploitationWithdrawalUpdate(brief) {
		return nil
	}

	var issues []string
	title := publicationString(brief["title"])
	summary := publicationString(brief["summary"])
	content := publicationString(brief["content"])
	issues = append(issues, publicationRoundupIdentityIssues(brief, title)...)
	if verification, ok := asStringMap(brief["cve_verification"]); ok {
		for _, id := range publicationCVEs(brief["cves"], title+"\n"+summary+"\n"+content) {
			entry, ok := asStringMap(verification[id])
			if !ok {
				continue
			}
			status := strings.ToLower(publicationString(entry["status"]))
			if status == "rejected" || status == "reserved" {
				issues = append(issues, fmt.Sprintf("CVE identity %s has authoritative status %s and requires editorial correction", id, status))
			}
		}
	}
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
	return append(issues, publicationQualityIssues(brief)...)
}

// A roundup with dozens of CVEs cannot be titled as though it were a single
// vulnerability. This guards against a product-specific source narrative
// replacing the aggregate identity while the full roundup CVE inventory stays
// attached. Smaller vulnerability chains and aggregate titles are unaffected.
func publicationRoundupIdentityIssues(brief map[string]any, title string) []string {
	tags := publicationUnique(yamlStringList(brief["tags"]))
	roundup := false
	for _, tag := range tags {
		if tag == "roundup" {
			roundup = true
			break
		}
	}
	if !roundup {
		return nil
	}
	cves := publicationCVEs(brief["cves"], "")
	titleCVEs := publicationCVEs(nil, title)
	if len(cves) < 50 || len(titleCVEs) != 1 {
		return nil
	}
	return []string{fmt.Sprintf("roundup lists %d CVEs but its title identifies only %s; use an aggregate title", len(cves), titleCVEs[0])}
}

func safeExploitationWithdrawalUpdate(brief map[string]any) bool {
	if exploited, ok := brief["exploited"].(bool); ok && exploited {
		return false
	}
	if value := brief["exploited"]; value != nil {
		if _, ok := value.(bool); !ok {
			return false
		}
	}
	evidence, ok := asStringMap(brief["exploitation_evidence"])
	if !ok || strings.ToLower(publicationString(evidence["status"])) != "unknown" || publicationString(evidence["source_url"]) != "" {
		return false
	}
	if briefTextClaimsExploitation(brief) {
		return false
	}
	// A KEV-listed CVE must remain exploited even if another source's listing
	// was the previous evidence. Reconciliation records those with CISA as the
	// source, so no true KEV flag may be present on this downgrade path.
	cves := yamlAnyList(brief["cves"])
	if len(cves) == 0 {
		return false
	}
	for _, raw := range cves {
		entry, ok := asStringMap(raw)
		if !ok {
			continue
		}
		if kev, _ := entry["kev"].(bool); kev || strings.EqualFold(publicationString(entry["kev_status"]), "true") {
			return false
		}
	}
	updates := yamlAnyList(brief["updates"])
	if len(updates) == 0 {
		return false
	}
	last, ok := asStringMap(updates[len(updates)-1])
	if !ok || publicationString(last["level"]) != "L1" || publicationString(last["summary"]) != "exploitation evidence corrected: an exploit-code listing is not exploitation" {
		return false
	}
	sources := yamlStringList(last["sources"])
	if len(sources) != 1 || sources[0] != "threat-bot" || len(yamlAnyList(last["source_urls"])) != 0 {
		return false
	}
	return true
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
	// One product can carry several "Product (range)" entries, one per
	// affected version range; they still name a single product.
	names := make([]string, 0, len(products))
	for _, product := range products {
		name, _ := SplitProductVersionScope(product)
		names = append(names, name)
	}
	if len(publicationUnique(names)) != 1 {
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
	if len(briefTTPs(brief)) == 0 {
		return false
	}
	for _, item := range yamlAnyList(brief["rules"]) {
		var rule briefRule
		raw, err := yaml.Marshal(item)
		if err == nil && yaml.Unmarshal(raw, &rule) == nil && len(sigma.Problems(rule.Title, sigma.LogSource(rule.LogSource), rule.Detection)) == 0 {
			return false
		}
	}
	for _, item := range yamlAnyList(actionPlan["hunt_leads"]) {
		lead, ok := asStringMap(item)
		if ok && meaningfulPublicationText(lead["lead"]) && meaningfulPublicationText(lead["evidence"]) && hasPublicationTelemetry(lead["data_needed"]) {
			return false
		}
	}
	return true
}
