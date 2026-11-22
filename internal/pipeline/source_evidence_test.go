package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestGroundingEvidenceRetainsSyntheticTargetFactsBeforeLongArticle(t *testing.T) {
	var record struct {
		Containers struct {
			CNA cnaSourceRecord `json:"cna"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(syntheticCompletenessCNA(t), &record); err != nil {
		t.Fatal(err)
	}
	facts, gap := record.Containers.CNA.sourceFacts("CVE-2099-4001")
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CNAFacts: facts, CNAGap: gap}
	p := &Pipeline{cveVerifier: v}
	item := scraper.RawItem{Title: "Example Harbor CVE-2099-4001", Content: strings.Repeat("Article background. ", 3000)}
	source := p.groundingEvidence(item, syntheticIncompleteBrief)
	visible := truncateUTF8(item.Title+"\n\n"+source, maxSourceLen)
	for _, fact := range []string{"2.3", "2.4", "PR:L", "cveawg.mitre.org/api/cve/CVE-2099-4001"} {
		if !strings.Contains(visible, fact) {
			t.Errorf("grounding truncation lost primary fact %q", fact)
		}
	}
	if !strings.Contains(visible, "Article background.") {
		t.Fatal("primary supplement displaced all original source evidence")
	}
}

func TestGroundingEvidenceSupportsGeneratedBriefBeforeCVEEnrichment(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CNAFacts: []cnaSourceFact{{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: "solution", Text: "Update Example Harbor to 2.4."}}}
	// generatedBrief excludes pipeline-owned cves; enrichment adds them later.
	brief := strings.Replace(syntheticIncompleteBrief, "cves: [CVE-2099-4001]\n", "", 1)
	p := &Pipeline{cveVerifier: v}
	source := p.groundingEvidence(scraper.RawItem{Title: "Example Harbor CVE-2099-4001", Content: "Example Harbor permits object injection."}, brief)
	if !strings.Contains(source, "2.4") {
		t.Fatal("new generated brief lost primary evidence before cves were enriched")
	}
}

func TestGroundingEvidenceCannotLegitimizeAnUnassertedCVE(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4002"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CNAFacts: []cnaSourceFact{{CVEID: "CVE-2099-4002", Product: "ExampleBridge", Kind: "solution", Text: "ExampleBridge is fixed in 9.9.9."}}}
	p := &Pipeline{cveVerifier: v}
	item := scraper.RawItem{Title: "Example Harbor CVE-2099-4001", Content: syntheticCompletenessSource}
	source := p.groundingEvidence(item, syntheticIncompleteBrief+"references: [https://example.com/CVE-2099-4002]\n")
	if strings.Contains(source, "9.9.9") || strings.Contains(source, "CVE-2099-4002") {
		t.Fatalf("unasserted cached identity leaked into source: %s", source)
	}
}

func TestGroundingEvidenceKeepsMissingAndCrossRecordCoverageExplicit(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, CNAGap: "unknown: optional CNA request unavailable", CNAFacts: []cnaSourceFact{{CVEID: "CVE-2099-4002", Kind: "solution", Text: "ExampleBridge fixed in 9.9.9."}, {CVEID: "CVE-2099-4001", Kind: "description", Text: "Compare CVE-2099-4002, fixed in 9.9.9."}}}
	p := &Pipeline{cveVerifier: v}
	source := p.groundingEvidence(scraper.RawItem{Title: "Example Harbor CVE-2099-4001", Content: syntheticCompletenessSource}, syntheticIncompleteBrief)
	if !strings.Contains(source, "unknown") || strings.Contains(source, "9.9.9") {
		t.Fatalf("missing or cross-record evidence became a fact: %s", source)
	}
}

func TestUnrenderableScopeGuidanceStaysInsideThePrimaryEvidenceBudget(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	var facts []cnaSourceFact
	for i := 0; i < 24; i++ {
		product := "Linux product " + strings.Repeat("x", 700) + string(rune('a'+i))
		facts = append(facts, affectedFact("CVE-2026-99462", product, `{"product":"`+product+`","versions":[{"version":"abcdef0123456789abcdef0123456789abcdef01","lessThan":"0123456789abcdef0123456789abcdef01234567","status":"affected","versionType":"git"}]}`))
	}
	v.cache["CVE-2026-99462"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CNAFacts: facts}
	evidence := (&Pipeline{cveVerifier: v}).verifiedPrimaryEvidence([]string{"CVE-2026-99462"})
	if len(evidence) > maxCNAEvidenceBytes {
		t.Fatalf("primary evidence including machine guidance exceeds budget: %d > %d", len(evidence), maxCNAEvidenceBytes)
	}
}

func TestCNASourceFactsKeepMultiProductRemediationUnassignedAndBounded(t *testing.T) {
	var record cnaSourceRecord
	if err := json.Unmarshal([]byte(`{"affected":[{"vendor":"Acme","product":"Widget A","versions":[{"version":"1","status":"affected","lessThan":"2"}]},{"vendor":"Acme","product":"Widget B","versions":[{"version":"3","status":"affected","lessThan":"4"}]}],"solutions":[{"lang":"en","value":"Upgrade Widget A to version 2."}]}`), &record); err != nil {
		t.Fatal(err)
	}
	facts, _ := record.sourceFacts("CVE-2026-9999")
	for _, fact := range facts {
		if fact.Kind == "solution" && fact.Product != "" {
			t.Fatalf("record-wide remediation assigned across products: %+v", fact)
		}
		if fact.Product == "Widget B" && strings.Contains(fact.Text, "version 2") {
			t.Fatal("Widget A fix leaked to Widget B")
		}
	}
	record.Solutions = []nvdDescription{{Lang: "en", Value: strings.Repeat("large source. ", maxCNAEvidenceBytes)}}
	facts, gap := record.sourceFacts("CVE-2026-9999")
	encoded, _ := json.Marshal(facts)
	if len(encoded) > maxCNAEvidenceBytes+100 || !strings.Contains(gap, "size limit") {
		t.Fatalf("unbounded or silently incomplete primary evidence: bytes=%d gap=%s", len(encoded), gap)
	}
}
