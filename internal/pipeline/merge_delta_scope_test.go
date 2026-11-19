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
		ChainedCVEs:          [][]string{{"CVE-2026-99999", "CVE-2026-1"}},
		ActiveExploitation:   false,
		ExploitationEvidence: "researchers expect attacks",
		ClaimAssessment:      &ClaimAssessment{Claim: "pre-auth RCE", Status: "unverified", Likelihood: "likely"},
	}

	result, err := checker.CheckMergeDelta(context.Background(), item, mergeAppliedDelta(item, extraction, map[string]any{}, nil))
	if err != nil || !result.Grounded {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(prompts) != 1 {
		t.Fatalf("checker calls=%d", len(prompts))
	}
	checked := checkedDeltaFields(t, prompts[0])
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

	// Nothing to apply means nothing to pay for.
	prompts = nil
	result, err = checker.CheckMergeDelta(context.Background(), item, mergeAppliedDelta(item, &ExtractionResult{Summary: "context only", Platforms: []string{"linux"}}, map[string]any{}, nil))
	if err != nil || !result.Grounded || len(prompts) != 0 {
		t.Fatalf("empty delta: result=%+v err=%v calls=%d", result, err, len(prompts))
	}
}

func checkedDeltaFields(t *testing.T, prompt string) map[string]any {
	t.Helper()
	brief := strings.SplitN(prompt, "## Generated Brief (YAML)\n", 2)[1]
	var checked map[string]any
	if err := yaml.Unmarshal([]byte(strings.SplitN(brief, "\n\nAssess", 2)[0]), &checked); err != nil {
		t.Fatal(err)
	}
	return checked
}

// Provenance granted while checking a lifecycle claim must reach the rumour
// lifecycle merge, which reads the caller's extraction.
func TestMergeAppliedDeltaSharesClaimAssessment(t *testing.T) {
	extraction := &ExtractionResult{ClaimAssessment: &ClaimAssessment{Claim: "x"}}
	if got := mergeAppliedDelta(scraper.RawItem{}, extraction, map[string]any{"claim_state": "reported"}, nil); got.ClaimAssessment != extraction.ClaimAssessment {
		t.Fatal("claim assessment copied: granted provenance would be lost")
	}
	if got := mergeAppliedDelta(scraper.RawItem{}, extraction, map[string]any{}, nil); got.ClaimAssessment != nil {
		t.Fatal("claim assessment graded for a brief without a lifecycle")
	}
}

// A value the target already holds is not written again, so it is not graded.
// Talos's Java4Shell merge was held for questioning the Oracle vendor the
// brief already listed, which also blocked everything else the source added.
// The comparison is the merge writers' own: CVE entries stored as maps, bare
// IDs, case differences and IOC type case all count as held.
func TestMergeDeltaGradesExactlyWhatTheMergeWrites(t *testing.T) {
	item := scraper.RawItem{URL: "https://news.example/a", Title: "Java4Shell attacks", Content: "Attackers are exploiting CVE-2026-114938. Storm-1 is behind it."}
	extraction := &ExtractionResult{
		CVEs:                 []string{"cve-2026-114938", "CVE-2026-1", "CVE-2026-2"},
		AffectedVendors:      []string{" oracle ", "Red Hat"},
		AffectedProducts:     []string{"OpenJDK"},
		IOCs:                 []ExtractedIOC{{Type: "ip", Value: "198.51.100.7"}, {Type: "IP", Value: "203.0.113.9"}},
		ThreatActor:          "Storm-1",
		ActiveExploitation:   true,
		ExploitationEvidence: "Attackers are exploiting CVE-2026-114938.",
	}
	target := map[string]any{
		"cves":             []any{map[string]any{"id": "CVE-2026-114938", "kev": false}, "CVE-2026-2"},
		"affected_vendors": []any{"Oracle"},
		"iocs":             []any{map[string]any{"type": "ip", "value": "203.0.113.9"}},
	}
	incoming := (&Pipeline{}).incomingExploitation(item)
	delta := mergeAppliedDelta(item, extraction, target, incoming)
	if strings.Join(delta.CVEs, ",") != "CVE-2026-1" || strings.Join(delta.AffectedVendors, ",") != "Red Hat" || strings.Join(delta.AffectedProducts, ",") != "OpenJDK" {
		t.Fatalf("held values not dropped: %+v", delta)
	}
	if len(delta.IOCs) != 1 || delta.IOCs[0].Value != "198.51.100.7" {
		t.Fatalf("held IOC not dropped: %+v", delta.IOCs)
	}
	if delta.ThreatActor != "Storm-1" || !delta.ActiveExploitation {
		t.Fatalf("new actor or exploitation dropped: %+v", delta)
	}
	if len(target["cves"].([]any)) != 2 || target["threat_actor"] != nil || target["exploitation_evidence"] != nil {
		t.Fatalf("computing the delta mutated the target: %v", target)
	}

	// An actor already set and complete attributed exploitation are not
	// rewritten. (Confirmed evidence without exploited: true would be: the
	// merge flips the flag, which is a write and is graded.)
	target["threat_actor"] = "Storm-2"
	target["exploited"] = true
	target["exploitation_evidence"] = map[string]any{"status": "confirmed_active", "source_url": "https://cisa.example/kev", "observed_at": "2026-11-18T00:00:00Z", "confidence": "high"}
	delta = mergeAppliedDelta(item, extraction, target, incoming)
	if delta.ThreatActor != "" || delta.ActiveExploitation || delta.ExploitationEvidence != "" {
		t.Fatalf("claims the merge cannot write were kept: %+v", delta)
	}
}

// A confirmed state resting only on an exploit-code listing yields to a later
// source, so that source's exploitation claim is written and must be graded.
// Without this, "Researchers expect attacks" from a news item replaced the
// listing and published the brief as exploited unchecked.
func TestMergeDeltaGradesExploitationReplacingListingOnlyEvidence(t *testing.T) {
	item := scraper.RawItem{URL: "https://news.example/b", Title: "CVE-2024-0582", Content: "Researchers expect attacks on CVE-2024-0582 soon."}
	extraction := &ExtractionResult{ActiveExploitation: true, ExploitationEvidence: "Researchers expect attacks on CVE-2024-0582 soon."}
	target := map[string]any{"exploited": true, "exploitation_evidence": map[string]any{"status": "confirmed_active", "source_url": "https://sploitus.com/exploit?id=X"}}
	delta := mergeAppliedDelta(item, extraction, target, (&Pipeline{}).incomingExploitation(item))
	if !delta.ActiveExploitation || delta.ExploitationEvidence == "" {
		t.Fatalf("exploitation replacing listing-only evidence was not graded: %+v", delta)
	}
	// Filling missing details of an attributed state is a write too.
	target["exploitation_evidence"] = map[string]any{"status": "confirmed_active", "source_url": "https://cisa.example/kev"}
	if delta := mergeAppliedDelta(item, extraction, target, (&Pipeline{}).incomingExploitation(item)); !delta.ActiveExploitation {
		t.Fatalf("evidence details written ungraded: %+v", delta)
	}
}

// A chain is the claim that admits a CVE a single-vulnerability brief does not
// list (cvesAccepted); grading only the admitted CVE let a made-up chain add an
// unrelated CVE unchecked. Admission follows connected chain groups, so every
// group connected to the added CVE is graded and an unrelated one is not.
func TestMergeDeltaGradesTheChainThatAdmitsANewCVE(t *testing.T) {
	chains := [][]string{{"CVE-2026-1001", "CVE-2026-1007"}, {"CVE-2026-1001", "CVE-2026-1008"}, {"CVE-2026-2001", "CVE-2026-2002"}}
	extraction := &ExtractionResult{CVEs: []string{"CVE-2026-1001", "CVE-2026-1007"}, ChainedCVEs: chains}
	target := map[string]any{"cves": []any{map[string]any{"id": "CVE-2026-1001"}}}
	delta := mergeAppliedDelta(scraper.RawItem{}, extraction, target, nil)
	if strings.Join(delta.CVEs, ",") != "CVE-2026-1007" || len(delta.ChainedCVEs) != 2 {
		t.Fatalf("admitting chain groups not graded: %+v", delta)
	}
	for _, chain := range delta.ChainedCVEs {
		if chain[0] == "CVE-2026-2001" {
			t.Fatalf("unrelated chain graded: %v", delta.ChainedCVEs)
		}
	}
	if delta := mergeAppliedDelta(scraper.RawItem{}, &ExtractionResult{CVEs: []string{"CVE-2026-1001"}, ChainedCVEs: chains}, target, nil); len(delta.ChainedCVEs) != 0 {
		t.Fatalf("chains graded although no CVE is added: %+v", delta)
	}
}

// mergeStringList skipped CVE entries stored as maps, so a CVE the brief
// already listed was re-appended as a bare ID and enrichment turned it into a
// second entry (9 published briefs list a CVE twice).
func TestMergeStringListTreatsCVEEntriesAsPresent(t *testing.T) {
	fm := map[string]any{"cves": []any{map[string]any{"id": "CVE-2026-1", "kev": true}}}
	if mergeStringList(fm, "cves", []string{"cve-2026-1"}) {
		t.Fatalf("held CVE entry re-appended: %v", fm["cves"])
	}
	if !mergeStringList(fm, "cves", []string{"CVE-2026-2"}) || len(fm["cves"].([]any)) != 2 {
		t.Fatalf("new CVE not appended: %v", fm["cves"])
	}
}

// Admission follows chains transitively across groups, so a made-up group
// that connects an added CVE to the brief's CVE must be graded even when it
// does not name the added CVE itself.
func TestMergeDeltaGradesTransitiveChains(t *testing.T) {
	extraction := &ExtractionResult{
		CVEs:        []string{"CVE-2026-98432"},
		ChainedCVEs: [][]string{{"CVE-2026-98432", "CVE-2026-11111"}, {"CVE-2026-11111", "CVE-2024-0582"}, {"CVE-2026-5", "CVE-2026-6"}},
	}
	target := map[string]any{"cves": []any{map[string]any{"id": "CVE-2024-0582"}}}
	delta := mergeAppliedDelta(scraper.RawItem{}, extraction, target, nil)
	if len(delta.ChainedCVEs) != 2 {
		t.Fatalf("connecting chain groups not graded: %v", delta.ChainedCVEs)
	}
	for _, chain := range delta.ChainedCVEs {
		if strings.Join(chain, ",") == "CVE-2026-5,CVE-2026-6" {
			t.Fatalf("unrelated chain graded: %v", delta.ChainedCVEs)
		}
	}
}

// A scoped delta leaves out vendors the target already lists. Provenance must
// still judge the source's ownership against them: an Oracle advisory on a
// brief listing Oracle is the vendor's own primary evidence.
func TestMergeDeltaProvenanceUsesTheTargetVendors(t *testing.T) {
	item := scraper.RawItem{SourceID: "oracle:advisory", Source: "oracle", URL: "https://www.oracle.com/security-alerts/alert-cve-2026-1.html",
		Title: "Oracle Security Alert CVE-2026-1", Content: "Oracle confirms the flaw affects Java SE 21 and 25."}
	checker := NewGroundingChecker(referenceTestLLM{respond: func(_ context.Context, _, _ string, _ *llm.Schema, out any) error {
		*out.(*groundingReport) = groundingReport{}
		return nil
	}}).WithLogger(quietLogger())
	grade := func(vendors ...string) *ClaimEvidenceProvenance {
		extraction := &ExtractionResult{AffectedProducts: []string{"Java SE"}, ClaimAssessment: &ClaimAssessment{Claim: "affects Java SE", Status: "unverified",
			Evidence: []ClaimEvidence{{Type: "authoritative_primary", Detail: "Oracle confirms the flaw affects Java SE 21 and 25.", SourceURL: item.URL}}}}
		if _, err := checker.CheckMergeDelta(context.Background(), item, extraction, vendors...); err != nil {
			t.Fatal(err)
		}
		return extraction.ClaimAssessment.Evidence[0].Provenance
	}
	if p := grade(); p == nil || p.TrustedPrimary {
		t.Fatalf("without the target's vendors the source must not be trusted primary: %+v", p)
	}
	if p := grade("Oracle"); p == nil || !p.TrustedPrimary {
		t.Fatalf("the vendor's own advisory lost trusted-primary status: %+v", p)
	}
}
