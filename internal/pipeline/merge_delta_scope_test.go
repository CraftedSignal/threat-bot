package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// The merge delta checker must judge only claims a merge can write. Before
// this, it judged summary, platforms, tactics, techniques, vuln class, a false
// exploitation flag and empty fields too. A finding on any of them held the
// merge for review although unionIntoDraft discards them all: 3,518 of 4,327
// merge holds on 2026-11-17..19, Java4Shell's news coverage among them.
func TestMergeDeltaGroundsOnlyAppliedFields(t *testing.T) {
	var prompts []string
	checker := NewGroundingChecker(referenceTestLLM{respond: func(_ context.Context, prompt, _ string, _ *llm.Schema, out any) error {
		prompts = append(prompts, prompt)
		*out.(*groundingReport) = groundingReport{}
		return nil
	}}).WithLogger(quietLogger())
	item := scraper.RawItem{SourceID: "news:java4shell", Source: "the-hacker-news", URL: "https://news.example/java4shell", Title: "Java4Shell enables pre-auth RCE", Content: "OpenJDK CVE-2026-114938 lets unauthenticated attackers run code."}
	extraction := &ExtractionResult{
		CVEs:                 []string{"CVE-2026-114938"},
		AffectedVendors:      []string{"Oracle"},
		AffectedProducts:     []string{"OpenJDK"},
		Platforms:            []string{"windows", "linux", "macos"},
		Tactics:              []string{"TA0001"},
		Techniques:           []string{"T1059.003"},
		Summary:              "Java4Shell is a critical pre-auth RCE.",
		VulnClass:            "buffer-overflow",
		ChainedCVEs:          [][]string{{"CVE-2026-114938", "CVE-2026-1"}},
		ActiveExploitation:   false,
		ExploitationEvidence: "researchers expect attacks",
		ClaimAssessment:      &ClaimAssessment{Claim: "pre-auth RCE", Status: "unverified", Likelihood: "likely"},
	}

	result, err := checker.CheckMergeDelta(context.Background(), item, mergeAppliedDelta(item, extraction, false))
	if err != nil || !result.Grounded {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(prompts) != 1 {
		t.Fatalf("checker calls=%d", len(prompts))
	}
	brief := strings.SplitN(prompts[0], "## Generated Brief (YAML)\n", 2)[1]
	var checked map[string]any
	if err := yaml.Unmarshal([]byte(strings.SplitN(brief, "\n\nAssess", 2)[0]), &checked); err != nil {
		t.Fatal(err)
	}
	for _, unused := range []string{"platforms", "tactics", "techniques", "summary", "vuln_class", "chained_cves", "active_exploitation", "exploitation_evidence", "claim_assessment", "iocs", "affected_os", "threat_actor"} {
		if _, ok := checked[unused]; ok {
			t.Errorf("checker was asked to ground %s, which the merge does not write: %v", unused, checked)
		}
	}
	for _, applied := range []string{"cves", "affected_vendors", "affected_products"} {
		if _, ok := checked[applied]; !ok {
			t.Errorf("checker no longer grounds applied field %s: %v", applied, checked)
		}
	}
	if extraction.ClaimAssessment == nil || len(extraction.Platforms) != 3 || extraction.Summary == "" {
		t.Fatalf("scoping the check mutated the caller's extraction: %+v", extraction)
	}

	// A source that asserts exploitation keeps that claim under review, and a
	// live rumour lifecycle keeps its claim assessment.
	extraction.ActiveExploitation = true
	item.Content += " Researchers expect attacks soon."
	prompts = nil
	if _, err := checker.CheckMergeDelta(context.Background(), item, mergeAppliedDelta(item, extraction, true)); err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{"active_exploitation: true", "exploitation_evidence: researchers expect attacks", "claim_assessment:"} {
		if !strings.Contains(prompts[0], kept) {
			t.Errorf("checker lost %q:\n%s", kept, prompts[0])
		}
	}

	// Nothing to apply means nothing to pay for.
	prompts = nil
	result, err = checker.CheckMergeDelta(context.Background(), item, mergeAppliedDelta(item, &ExtractionResult{Summary: "context only", Platforms: []string{"linux"}}, false))
	if err != nil || !result.Grounded || len(prompts) != 0 {
		t.Fatalf("empty delta: result=%+v err=%v calls=%d", result, err, len(prompts))
	}
}

// Provenance granted while checking a lifecycle claim must reach the rumour
// lifecycle merge, which reads the caller's extraction.
func TestMergeAppliedDeltaSharesClaimAssessment(t *testing.T) {
	extraction := &ExtractionResult{ClaimAssessment: &ClaimAssessment{Claim: "x"}}
	if got := mergeAppliedDelta(scraper.RawItem{}, extraction, true); got.ClaimAssessment != extraction.ClaimAssessment {
		t.Fatal("claim assessment copied: granted provenance would be lost")
	}
}
