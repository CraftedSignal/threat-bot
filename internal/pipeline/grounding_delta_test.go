package pipeline

import (
	"context"
	"encoding/json"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestGroundingSuccessCannotAdmitInventedIdentities(t *testing.T) {
	checker := NewGroundingChecker(scriptedGroundingLLM{})
	for _, brief := range []string{"cves: [CVE-2026-99999]\n", "iocs:\n - type: domain\n   value: unrelated.example\n", "exploitation_evidence:\n  status: confirmed_active\n  source_url: https://invented.example/report\n"} {
		result, err := checker.Check(context.Background(), "notice", "CVE-2026-12345 describes bad[.]example", brief)
		if err != nil || result.Grounded {
			t.Fatalf("invented identity accepted: %#v %v", result, err)
		}
	}
	result, err := checker.Check(context.Background(), "notice", "CVE-2026-12345 describes bad[.]example", "cves: [CVE-2026-12345]\niocs:\n - type: domain\n   value: bad.example\n")
	if err != nil || !result.Grounded {
		t.Fatalf("source identities rejected: %#v %v", result, err)
	}
}

func TestGroundingUsesOptionalRepairClientOnlyForRepair(t *testing.T) {
	repair := &briefScriptedLLM{replies: []briefLLMReply{{text: `{"title":"A verified notice","summary":"Source-supported summary","severity":"low","content":"Source-supported content"}`}}}
	checker := NewGroundingChecker(scriptedGroundingLLM{}).WithRepairClient(repair)
	result, err := checker.Check(context.Background(), "notice", "Source-supported content", "title: A verified notice\n")
	if err != nil || !result.Grounded || len(repair.prompts) != 0 {
		t.Fatal(result, err, len(repair.prompts))
	}
	if _, err := checker.Repair(context.Background(), "notice", "Source-supported content", "title: A verified notice\n", []string{"unsupported detail"}); err != nil {
		t.Fatal(err)
	}
	if len(repair.prompts) != 1 {
		t.Fatalf("repair calls=%d", len(repair.prompts))
	}
}

func TestIndicatorSourcePunctuationDoesNotChangeIdentity(t *testing.T) {
	for _, source := range []string{"It uses evil.example. The article continues.", "It uses evil[.]example.", "Indicator: evil.example,"} {
		if !sourceContainsIndicator(source, "evil.example") {
			t.Fatalf("sentence punctuation rejected: %s", source)
		}
	}
	for _, source := range []string{"evil.example.attacker.test", "prefixevil.example", "evil.example/longer-path"} {
		if sourceContainsIndicator(source, "evil.example") {
			t.Fatalf("different identity accepted: %s", source)
		}
	}
}

func TestCheckMergeDeltaAttestsOnlyFetchedPrimaryEvidence(t *testing.T) {
	checker := NewGroundingChecker(scriptedGroundingLLM{})
	for _, rawURL := range []string{"https://unrelated.example/advisory", "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"} {
		item := scraper.RawItem{Source: "nvd", URL: rawURL, Content: "The vendor confirms this reported vulnerability."}
		extraction := &ExtractionResult{ClaimAssessment: &ClaimAssessment{Evidence: []ClaimEvidence{{Type: "authoritative_primary", SourceURL: rawURL, Detail: item.Content}}}}
		result, err := checker.CheckMergeDelta(context.Background(), item, extraction)
		if err != nil || !result.Grounded {
			t.Fatal(result, err)
		}
		want := ClaimReported
		if strings.Contains(rawURL, "nvd.nist.gov") {
			want = ClaimVerified
		}
		if got := NextClaimState(ClaimReported, *extraction.ClaimAssessment); got != want {
			t.Fatalf("%s: %s != %s", rawURL, got, want)
		}
	}
}

func TestEvidenceProvenanceIsNotModelWritableAndPersistsYAML(t *testing.T) {
	var e ClaimEvidence
	if err := json.Unmarshal([]byte(`{"type":"authoritative_primary","detail":"vendor confirms","source_url":"https://vendor.example/","provenance":{"trusted_primary":true}}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Provenance != nil {
		t.Fatal("model minted provenance")
	}
	e.Provenance = &ClaimEvidenceProvenance{SourceURL: e.SourceURL, EvidenceHash: claimEvidenceHash(e), TrustedPrimary: true}
	b, _ := yaml.Marshal(e)
	var restored ClaimEvidence
	_ = yaml.Unmarshal(b, &restored)
	if !attestedClaimEvidence(restored) {
		t.Fatal("YAML lost provenance")
	}
	restored.Detail = "altered claim"
	if attestedClaimEvidence(restored) {
		t.Fatal("provenance not bound to evidence")
	}
}

func TestGroundingRatingsIgnoreAbsenceButRejectFactualOverstatement(t *testing.T) {
	checker := NewGroundingChecker(scriptedGroundingLLM{report: groundingReport{Issues: []groundingIssue{
		{Kind: groundingKindUnsupported, Field: "severity", Reason: "Source does not specify a severity rating"},
		{Kind: groundingKindUnsupported, Field: "rules[0].level", Reason: "No rating is stated"},
	}}})
	result, err := checker.Check(context.Background(), "notice", "A local crash.", "severity: low\n")
	if err != nil || !result.Grounded {
		t.Fatal(result, err)
	}
	if nonFactualRatingIssue(groundingIssue{Field: "severity", Reason: "The impact is overstated; exploitation is not stated"}, "") {
		t.Fatal("factual overstatement suppressed")
	}
}
