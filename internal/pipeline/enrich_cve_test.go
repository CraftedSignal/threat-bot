package pipeline

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestEnrichBriefWithCVEs(t *testing.T) {
	briefYAML := `id: brief-2026-03-30-test
title: Test Brief
severity: high
published_at: "2026-03-30T00:00:00Z"
iocs:
  - type: hash_sha256
    value: abc123
    context: "test"
`
	cves := []BundleCVE{
		{ID: "CVE-2026-1234", EPSS: 0.87, EPSSPercentile: 0.99, CVSS: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", KEV: true},
		{ID: "CVE-2026-5678", EPSS: 0.02, EPSSPercentile: 0.15, CVSS: 5.4, KEV: false},
	}

	result := EnrichBriefWithCVEs(briefYAML, cves)

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	cvesField, ok := parsed["cves"].([]interface{})
	if !ok || len(cvesField) != 2 {
		t.Fatalf("expected 2 cves, got %v", parsed["cves"])
	}
	first := cvesField[0].(map[string]interface{})
	if first["id"] != "CVE-2026-1234" {
		t.Errorf("expected CVE-2026-1234, got %v", first["id"])
	}
	if first["cvss_vector"] != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("expected cvss_vector to be preserved, got %v", first["cvss_vector"])
	}
	if first["kev_status"] != "true" {
		t.Fatalf("expected true kev_status, got %v", first["kev_status"])
	}
	second := cvesField[1].(map[string]interface{})
	if second["kev_status"] != "unknown" {
		t.Fatalf("expected unknown kev_status, got %v", second["kev_status"])
	}
	evidence, ok := parsed["exploitation_evidence"].(map[string]interface{})
	if !ok || evidence["status"] != "confirmed_active" || evidence["source_url"] == "" {
		t.Fatalf("expected attributed KEV exploitation evidence, got %v", parsed["exploitation_evidence"])
	}
}

func TestEnrichBriefWithCVEs_Empty(t *testing.T) {
	briefYAML := `id: brief-2026-03-30-test
title: No CVEs
severity: low
`
	result := EnrichBriefWithCVEs(briefYAML, nil)
	if result != briefYAML {
		t.Error("expected unchanged YAML when no CVEs")
	}
}

func TestEnrichBriefWithCVEs_OmitsUnknownCVSS(t *testing.T) {
	briefYAML := `id: brief-2026-03-30-test
title: Unknown CVSS
severity: medium
`
	cves := []BundleCVE{{ID: "CVE-2026-9999", EPSS: 0.01, EPSSPercentile: 0.25, CVSS: 0}}

	result := EnrichBriefWithCVEs(briefYAML, cves)

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	cvesField, ok := parsed["cves"].([]interface{})
	if !ok || len(cvesField) != 1 {
		t.Fatalf("expected 1 cve, got %v", parsed["cves"])
	}
	first := cvesField[0].(map[string]interface{})
	if _, ok := first["cvss"]; ok {
		t.Fatalf("expected unknown CVSS to be omitted, got %v", first["cvss"])
	}
}

func TestEnrichBriefWithCVEs_PreservesPerCVEProduct(t *testing.T) {
	briefYAML := `id: brief-2026-03-30-test
title: Product Metadata
severity: high
cves:
  - id: CVE-2026-1234
    product: Microsoft Teams
`
	cves := []BundleCVE{{ID: "CVE-2026-1234", EPSS: 0.01, EPSSPercentile: 0.25, CVSS: 8.8}}

	result := EnrichBriefWithCVEs(briefYAML, cves)

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	cvesField, ok := parsed["cves"].([]interface{})
	if !ok || len(cvesField) != 1 {
		t.Fatalf("expected 1 cve, got %v", parsed["cves"])
	}
	first := cvesField[0].(map[string]interface{})
	if first["product"] != "Microsoft Teams" {
		t.Fatalf("expected product to be preserved, got %v", first["product"])
	}
}

func TestCVEEnricherPreservesStructuredCVEsWhenVerificationIsPartial(t *testing.T) {
	verifier := NewCVEVerifier(nil, nil)
	verifier.cache["CVE-2026-101356"] = &CVEMeta{
		Exists:      true,
		CVSS:        8.8,
		Description: "Apache Tomcat contains a vulnerability affecting multiple supported releases.",
	}
	enricher := NewCVEEnricher(verifier)
	briefYAML := `id: brief-2026-10-20-apache-tomcat-buffer-under-read
title: Apache Tomcat Buffer Under-Read (CVE-2026-103119)
summary: CVE-2026-103119 affects Apache Tomcat.
affected_vendors:
  - Apache
affected_products:
  - Tomcat
cves:
  - id: CVE-2026-103119
    cvss: 9.1
    kev_status: "false"
  - CVE-2026-101356
`

	result, _ := enricher.Enrich(briefYAML, nil)

	var parsed struct {
		CVEs []BundleCVE `yaml:"cves"`
	}
	if err := yaml.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.CVEs) != 2 {
		t.Fatalf("structured CVEs = %#v, want the published and newly verified CVEs", parsed.CVEs)
	}
	if parsed.CVEs[0].ID != "CVE-2026-103119" || parsed.CVEs[0].CVSS != 9.1 {
		t.Fatalf("published CVE changed or disappeared: %#v", parsed.CVEs[0])
	}
	if parsed.CVEs[1].ID != "CVE-2026-101356" || parsed.CVEs[1].CVSS != 8.8 {
		t.Fatalf("new CVE was not enriched: %#v", parsed.CVEs[1])
	}
}

func TestCVEEnricherAddsFallbackCPEVersionScopeAndPatchActions(t *testing.T) {
	verifier := NewCVEVerifier(nil, nil)
	verifier.cache["CVE-2026-40541"] = &CVEMeta{
		Exists:      true,
		CVSS:        9.0,
		Description: "An improper neutralization of input during web page generation vulnerability in extract domain in Synology Chat Server before 2.4.5-22148 allows remote authenticated users to read or write arbitrary files and conduct denial-of-service attacks in DSM.",
	}
	enricher := NewCVEEnricher(verifier)
	briefYAML := `id: brief-2026-08-synology-chat-xss
title: Critical XSS Vulnerability in Synology Chat Server
summary: CVE-2026-40541 affects Synology Chat Server.
severity: high
published_at: "2026-08-28T09:13:01Z"
content: |
  Synology Chat Server is affected by CVE-2026-40541.
tags:
  - xss
affected_vendors:
  - Synology
affected_products:
  - Chat Server
cves:
  - CVE-2026-40541
action_plan:
  priority: immediate_escalation
  immediate_actions:
    - action: Patch Synology Chat Server
      owner: IT Operations
      due: 24h
  mitigation_plan:
    - priority: immediate
      action: Upgrade Chat Server software
      owner: IT Operations
      addresses: CVE-2026-40541
`

	result, cves := enricher.Enrich(briefYAML, nil)
	if len(cves) != 1 || cves[0].ID != "CVE-2026-40541" || cves[0].CVSS != 9.0 {
		t.Fatalf("unexpected cves: %#v", cves)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	if got := yamlStringList(parsed["cpes"]); len(got) != 1 || got[0] != "cpe:2.3:a:synology:chat_server:*:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected cpes: %#v\n%s", got, result)
	}
	if got := yamlStringList(parsed["affected_products"]); len(got) != 1 || got[0] != "Chat Server (< 2.4.5-22148)" {
		t.Fatalf("unexpected affected_products: %#v\n%s", got, result)
	}

	plan, ok := asStringMap(parsed["action_plan"])
	if !ok {
		t.Fatalf("missing action_plan in:\n%s", result)
	}
	immediate := yamlAnyList(plan["immediate_actions"])
	if len(immediate) != 1 {
		t.Fatalf("unexpected immediate_actions: %#v", immediate)
	}
	immediateAction, _ := asStringMap(immediate[0])
	if got := fmt.Sprint(immediateAction["action"]); got != "Patch Chat Server to 2.4.5-22148 or later" {
		t.Fatalf("immediate action = %q", got)
	}
	mitigations := yamlAnyList(plan["mitigation_plan"])
	if len(mitigations) != 1 {
		t.Fatalf("unexpected mitigation_plan: %#v", mitigations)
	}
	mitigation, _ := asStringMap(mitigations[0])
	if got := fmt.Sprint(mitigation["action"]); got != "Upgrade Chat Server to 2.4.5-22148 or later" {
		t.Fatalf("mitigation action = %q", got)
	}
}

func TestExtractPatchVersionHintCombinesAffectedRangeAndFixedVersion(t *testing.T) {
	text := "SvelteKit versions 2.49.0 through 2.53.2 are affected. Defenders should prioritize updating to SvelteKit version 2.53.3 or later."

	got := extractPatchVersionHint(text)
	if got.VulnerableRange != "2.49.0-2.53.2" {
		t.Fatalf("vulnerable range = %q", got.VulnerableRange)
	}
	if got.FixedVersion != "2.53.3" {
		t.Fatalf("fixed version = %q", got.FixedVersion)
	}
}

func TestAddVersionRangeUsesVersionWindowForMultiProductBrief(t *testing.T) {
	products := []string{"SvelteKit", "Other Product"}
	text := "SvelteKit versions 2.49.0 through 2.53.2 are affected. Defenders should prioritize updating to SvelteKit version 2.53.3 or later."

	got, changed := addVersionRangeToAffectedProducts(products, "2.49.0-2.53.2", "2.53.3", text)
	if !changed {
		t.Fatal("expected affected product to be scoped")
	}
	if got[0] != "SvelteKit (2.49.0-2.53.2)" {
		t.Fatalf("first product = %q", got[0])
	}
	if got[1] != "Other Product" {
		t.Fatalf("second product = %q", got[1])
	}
}

func TestSynthesizeCPEsRequiresSingleClearProduct(t *testing.T) {
	if got := synthesizeCPEs([]string{"Google"}, []string{"Chrome", "Edge"}, nil); len(got) != 0 {
		t.Fatalf("expected no inferred CPE for ambiguous product scope, got %#v", got)
	}
	if got := synthesizeCPEs([]string{"Synology"}, []string{"Chat Server (< 2.4.5-22148)"}, nil); len(got) != 1 || got[0] != "cpe:2.3:a:synology:chat_server:*:*:*:*:*:*:*:*" {
		t.Fatalf("expected one inferred Synology CPE, got %#v", got)
	}
}

func TestCVEEnricherDropsOffScopeCVELeakageFromFocusedBrief(t *testing.T) {
	verifier := NewCVEVerifier(nil, loadedKEVCatalog(t, "CVE-2026-16232", "CVE-2026-50522"))
	verifier.cache["CVE-2026-16232"] = &CVEMeta{
		Exists:      true,
		CVSS:        9.8,
		CPEs:        []string{"cpe:2.3:a:check_point:smartconsole:*:*:*:*:*:*:*:*"},
		Description: "Check Point SmartConsole contains an authentication bypass vulnerability.",
	}
	verifier.cache["CVE-2026-62144"] = &CVEMeta{
		Exists:      true,
		CVSS:        8.8,
		CPEs:        []string{"cpe:2.3:a:check_point:security_management:*:*:*:*:*:*:*:*"},
		Description: "Check Point Security Management contains a management server vulnerability.",
	}
	verifier.cache["CVE-2026-62145"] = &CVEMeta{
		Exists:      true,
		CVSS:        8.8,
		CPEs:        []string{"cpe:2.3:a:check_point:multi-domain_management:*:*:*:*:*:*:*:*"},
		Description: "Check Point Multi-Domain Management contains a management server vulnerability.",
	}
	verifier.cache["CVE-2026-50522"] = &CVEMeta{
		Exists:      true,
		CVSS:        9.8,
		CPEs:        []string{"cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*"},
		Description: "Microsoft SharePoint Server contains a deserialization vulnerability.",
	}
	enricher := NewCVEEnricher(verifier)
	briefYAML := `id: brief-2026-07-check-point-smartconsole
title: Check Point SmartConsole Authentication Bypass (CVE-2026-16232) Actively Exploited
summary: CVE-2026-16232 affects Check Point SmartConsole and related management products.
severity: critical
content: |
  CISA added CVE-2026-16232 and CVE-2026-50522 to the Known Exploited Vulnerabilities catalog.
affected_vendors:
  - Check Point
  - Microsoft
affected_products:
  - SmartConsole
  - Security Management
  - Multi-Domain Management
  - Firewall
  - SharePoint
cpes:
  - cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*
cves:
  - CVE-2026-16232
  - CVE-2026-62144
  - CVE-2026-62145
  - CVE-2026-50522
`

	result, cves := enricher.Enrich(briefYAML, nil)
	if len(cves) != 3 {
		t.Fatalf("expected 3 scoped CVEs, got %#v\n%s", cves, result)
	}
	for _, cve := range cves {
		if cve.ID == "CVE-2026-50522" {
			t.Fatalf("off-scope Microsoft CVE survived: %#v\n%s", cves, result)
		}
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	if got := yamlStringList(parsed["affected_vendors"]); stringListContainsFold(got, "Microsoft") || !stringListContainsFold(got, "Check Point") {
		t.Fatalf("unexpected affected_vendors: %#v\n%s", got, result)
	}
	if got := yamlStringList(parsed["affected_products"]); stringListContainsFold(got, "SharePoint") || !stringListContainsFold(got, "SmartConsole") {
		t.Fatalf("unexpected affected_products: %#v\n%s", got, result)
	}
	for _, cpe := range yamlStringList(parsed["cpes"]) {
		if strings.Contains(strings.ToLower(cpe), "microsoft") || strings.Contains(strings.ToLower(cpe), "sharepoint") {
			t.Fatalf("off-scope CPE survived: %#v\n%s", yamlStringList(parsed["cpes"]), result)
		}
	}
	for _, item := range yamlAnyList(parsed["cves"]) {
		cve, ok := asStringMap(item)
		if !ok {
			t.Fatalf("unexpected cve item: %#v", item)
		}
		if fmt.Sprint(cve["id"]) == "CVE-2026-50522" {
			t.Fatalf("off-scope CVE entry survived: %#v\n%s", cve, result)
		}
	}
}

func TestCVEEnricherPreservesUnfocusedMultiVendorBrief(t *testing.T) {
	verifier := NewCVEVerifier(nil, nil)
	verifier.cache["CVE-2026-16232"] = &CVEMeta{
		Exists:      true,
		CPEs:        []string{"cpe:2.3:a:check_point:smartconsole:*:*:*:*:*:*:*:*"},
		Description: "Check Point SmartConsole contains an authentication bypass vulnerability.",
	}
	verifier.cache["CVE-2026-50522"] = &CVEMeta{
		Exists:      true,
		CPEs:        []string{"cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*"},
		Description: "Microsoft SharePoint Server contains a deserialization vulnerability.",
	}
	enricher := NewCVEEnricher(verifier)
	briefYAML := `id: brief-2026-07-cisa-kev-update
title: CISA Adds Two Known Exploited Vulnerabilities to Catalog
summary: The update covers multiple products and vendors.
severity: high
affected_vendors:
  - Check Point
  - Microsoft
affected_products:
  - SmartConsole
  - SharePoint
cves:
  - CVE-2026-16232
  - CVE-2026-50522
`

	result, cves := enricher.Enrich(briefYAML, nil)
	if len(cves) != 2 {
		t.Fatalf("expected both CVEs to remain for unfocused brief, got %#v\n%s", cves, result)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	if got := yamlStringList(parsed["affected_vendors"]); !stringListContainsFold(got, "Microsoft") || !stringListContainsFold(got, "Check Point") {
		t.Fatalf("unexpected affected_vendors: %#v\n%s", got, result)
	}
	if got := yamlStringList(parsed["affected_products"]); !stringListContainsFold(got, "SharePoint") || !stringListContainsFold(got, "SmartConsole") {
		t.Fatalf("unexpected affected_products: %#v\n%s", got, result)
	}
	if got := yamlStringList(parsed["cpes"]); len(got) != 2 {
		t.Fatalf("expected both CPEs, got %#v\n%s", got, result)
	}
}

// An update that unions an off-scope CVE into a published focused brief keeps
// the CVEs the brief listed before the update and drops the newcomer.
func TestCVEEnricherUpdateKeepsPreFoldCVEsAndDropsOffScopeNewcomer(t *testing.T) {
	verifier := NewCVEVerifier(nil, nil)
	now := time.Now()
	verifier.cache["CVE-2026-16232"] = &CVEMeta{Exists: true, CachedAt: now, CVSS: 9.8,
		CPEs:        []string{"cpe:2.3:a:check_point:smartconsole:*:*:*:*:*:*:*:*"},
		Description: "Check Point SmartConsole contains an authentication bypass vulnerability."}
	verifier.cache["CVE-2026-62144"] = &CVEMeta{Exists: true, CachedAt: now, CVSS: 8.8,
		Description: "A flaw."} // no CPEs: does not match scope
	verifier.cache["CVE-2026-50522"] = &CVEMeta{Exists: true, CachedAt: now, CVSS: 9.8,
		CPEs:        []string{"cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*"},
		Description: "Microsoft SharePoint Server contains a deserialization vulnerability."}
	enricher := NewCVEEnricher(verifier)
	// X = CVE-2026-62144 was listed before the update; Y = CVE-2026-50522 was unioned in.
	briefYAML := `id: brief-2026-07-check-point-smartconsole
title: Check Point SmartConsole Authentication Bypass (CVE-2026-16232)
summary: CVE-2026-16232 affects Check Point SmartConsole.
affected_vendors:
  - Check Point
affected_products:
  - SmartConsole
cves:
  - id: CVE-2026-16232
  - id: CVE-2026-62144
  - CVE-2026-50522
`
	keep := map[string]bool{"CVE-2026-16232": true, "CVE-2026-62144": true}
	_, cves := enricher.Enrich(briefYAML, keep)
	got := cveIDSet(cves)
	if !got["CVE-2026-62144"] || !got["CVE-2026-16232"] {
		t.Fatalf("pre-fold CVEs must be kept, got %v", got)
	}
	if got["CVE-2026-50522"] {
		t.Fatalf("off-scope newcomer must be removed, got %v", got)
	}
}

// A kept plain-string CVE that NVD has no record of must not vanish.
func TestCVEEnricherKeepSetRetainsUnverifiedPlainString(t *testing.T) {
	verifier := NewCVEVerifier(nil, nil)
	verifier.cache["CVE-2026-16232"] = &CVEMeta{Exists: true, CachedAt: time.Now(), CVSS: 9.8,
		Description: "Check Point SmartConsole bypass."}
	enricher := NewCVEEnricher(verifier)
	briefYAML := `id: brief-x
title: Check Point SmartConsole bypass (CVE-2026-16232)
cves:
  - CVE-2026-16232
  - CVE-2026-77777
`
	_, cves := enricher.Enrich(briefYAML, map[string]bool{"CVE-2026-77777": true})
	if !cveIDSet(cves)["CVE-2026-77777"] {
		t.Fatalf("kept unverified plain-string CVE dropped: %#v", cves)
	}
	_, cves = enricher.Enrich(briefYAML, nil)
	if cveIDSet(cves)["CVE-2026-77777"] {
		t.Fatalf("empty keep-set must keep today's behaviour: %#v", cves)
	}
}
