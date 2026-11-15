package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
)

func integrityPrimarySource(facts []cnaSourceFact, article string) string {
	verifier := NewCVEVerifier(nil, nil)
	verifier.cache["CVE-2099-4001"] = &CVEMeta{
		Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"},
		CNAFacts: facts,
		CNAGap:   "unknown: usable remediation is not present in retained CNA evidence; this does not establish the absence of a fixed release",
	}
	return (&Pipeline{cveVerifier: verifier}).verifiedPrimaryEvidence([]string{"CVE-2099-4001"}) + "\nOriginal source:\n" + article
}

func TestGroundingMetadataCannotSupportMaterialOmission(t *testing.T) {
	source := integrityPrimarySource(nil, "Example Harbor permits a configuration change.")
	for _, quote := range []string{
		"CVE Program source for CVE-2099-4001: https://cveawg.mitre.org/api/cve/CVE-2099-4001",
		"https://cveawg.mitre.org/api/cve/CVE-2099-4001",
		"CVE-2099-4001 coverage: unknown: usable remediation is not present in retained CNA evidence; this does not establish the absence of a fixed release",
		"CVE-2099-4001 coverage: unknown: usable remediation is not present in retained CNA evidence",
	} {
		t.Run(quote, func(t *testing.T) {
			issue := groundingIssue{Kind: groundingKindMaterialOmission, Subject: "CVE-2099-4001", Field: "fixed_version", SourceQuote: quote, Reason: "Missing the fixed release."}
			if err := validateMaterialOmission(issue, source, syntheticIncompleteBrief); err == nil {
				t.Fatal("generated provenance or coverage bookkeeping became positive evidence for a fixed release")
			}
			for _, ref := range scopedOmissionEvidence(source, syntheticIncompleteBrief) {
				if strings.Contains(ref.Quote, quote) {
					t.Fatalf("generated bookkeeping entered the evidence catalogue: %+v", ref)
				}
			}
		})
	}
}

func TestGroundingMetadataFindingStaysHeldAfterBoundedCorrection(t *testing.T) {
	quote := "CVE-2099-4001 coverage: unknown: usable remediation is not present in retained CNA evidence; this does not establish the absence of a fixed release"
	answer, err := json.Marshal(materialOmissionEvidenceReport{Evidence: []materialOmissionEvidence{{Subject: "CVE-2099-4001", SourceQuote: quote}}})
	if err != nil {
		t.Fatal(err)
	}
	client := &evidenceRepairLLM{
		report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "fixed_version", Subject: "CVE-2099-4001", SourceQuote: quote, Reason: "Missing the fixed release."}}},
		answer: string(answer),
	}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", integrityPrimarySource(nil, "Example Harbor permits a configuration change."), syntheticIncompleteBrief)
	var failure *omissionEvidenceContractError
	if result != nil || !errors.As(err, &failure) || failure.FailureKind() != "omission_evidence_contract" || len(failure.RequestDigest()) != 64 || client.calls != 2 {
		t.Fatalf("invalid omission must remain a typed hold after exactly one correction: result=%+v err=%v calls=%d", result, err, client.calls)
	}
}

func TestGroundingPreservesRealUncertaintyAndNoFixEvidence(t *testing.T) {
	for _, text := range []string{
		"CVE-2099-4001: Example Harbor has no fixed release available.",
		"CVE-2099-4001: Example Harbor's fixed release is unknown pending vendor confirmation.",
		"CVE-2099-4001 coverage: Example Harbor's vendor has not established remediation.",
	} {
		t.Run(text, func(t *testing.T) {
			issue := groundingIssue{Subject: "CVE-2099-4001", SourceQuote: text}
			for _, source := range []string{
				integrityPrimarySource(nil, text),
				integrityPrimarySource([]cnaSourceFact{{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: "description", Text: text}}, "Example Harbor permits a configuration change."),
			} {
				if err := validateMaterialOmission(issue, source, syntheticIncompleteBrief); err != nil {
					t.Fatalf("actual source uncertainty was discarded with generated bookkeeping: %v", err)
				}
				found := false
				for _, ref := range scopedOmissionEvidence(source, syntheticIncompleteBrief) {
					var fact cnaSourceFact
					if ref.Quote == text || json.Unmarshal([]byte(ref.Quote), &fact) == nil && fact.Text == text {
						found = true
					}
				}
				if !found {
					t.Fatal("actual source uncertainty disappeared from the evidence catalogue")
				}
			}
		})
	}
}

func TestGroundingStructuredReferencesRetainSeparateCVEScopes(t *testing.T) {
	text := `{"product":"Example Harbor","versions":[{"version":"2.3","status":"affected"}]}`
	var lines []string
	for _, id := range []string{"CVE-2099-4001", "CVE-2099-4002"} {
		raw, _ := json.Marshal(cnaSourceFact{CVEID: id, Product: "Example Harbor", Kind: "affected", Text: text})
		lines = append(lines, string(raw))
	}
	brief := syntheticIncompleteBrief + "summary: Covers CVE-2099-4001 and CVE-2099-4002.\n"
	source := strings.Join(lines, "\n")
	refs := scopedOmissionEvidence(source, brief)
	if len(refs) != 2 || refs[0].ID == refs[1].ID {
		t.Fatalf("identical product facts from distinct CVEs lost their separate identities: %+v", refs)
	}
	for _, ref := range refs {
		var fact cnaSourceFact
		if err := json.Unmarshal([]byte(ref.Quote), &fact); err != nil || fact.CVEID == "" || fact.Product != "Example Harbor" || fact.Kind != "affected" || fact.Text != text {
			t.Fatalf("reference lost its full primary source record: %+v err=%v", ref, err)
		}
		neighbor := "CVE-2099-4002"
		if fact.CVEID == neighbor {
			neighbor = "CVE-2099-4001"
		}
		if !containsString(ref.Subjects, fact.CVEID) || containsString(ref.Subjects, neighbor) {
			t.Fatalf("full primary source record escaped its CVE scope: %+v", ref)
		}
	}
}

func TestGroundingStructuredFactsKeepIdentityThroughRepairBlocker(t *testing.T) {
	for _, kind := range []string{"affected", "solution", "description"} {
		t.Run(kind, func(t *testing.T) {
			fact := cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: kind, Text: "Example Harbor through 2.3 is affected; update to 2.4."}
			raw, _ := json.Marshal(fact)
			client := referenceTestLLM{respond: func(_ context.Context, prompt, _ string, _ *llm.Schema, out any) error {
				for _, ref := range readReferenceFixture(t, prompt) {
					var selected cnaSourceFact
					if json.Unmarshal([]byte(ref.Quote), &selected) == nil && selected.CVEID == "CVE-2099-4001" && selected.Kind == kind {
						return llm.DecodeStructured(fmt.Sprintf(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_evidence_id":%q,"reason":"Missing affected scope and remediation."}]}`, ref.ID), out)
					}
				}
				return errors.New("scoped primary source record missing")
			}}
			result, err := NewGroundingChecker(client).Check(context.Background(), "Example Harbor", string(raw), syntheticIncompleteBrief)
			if err != nil || result == nil || result.Grounded || len(result.Issues) != 1 || !strings.Contains(result.Issues[0], string(raw)) {
				t.Fatalf("repair blocker lost primary CVE/product/kind identity: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestGroundingDecodedPrimaryQuoteKeepsRecordIdentity(t *testing.T) {
	text := `Update Example Harbor to 2.4 and retain the "safe mode" default.`
	raw, _ := json.Marshal(cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: "solution", Text: text})
	neighbor, _ := json.Marshal(cnaSourceFact{CVEID: "CVE-2099-4002", Product: "Example Harbor", Kind: "solution", Text: text})
	for _, subject := range []string{"Example Harbor", "CVE-2099-4001"} {
		t.Run(subject, func(t *testing.T) {
			// Repeated copies are one record; the neighboring CVE is outside
			// the brief's scope and cannot make the target record ambiguous.
			source := string(raw) + "\n" + string(raw) + "\n" + string(neighbor)
			client := scriptedGroundingLLM{report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: subject, SourceQuote: text, Reason: "Missing remediation."}}}}
			result, err := NewGroundingChecker(client).Check(context.Background(), "Example Harbor", source, syntheticIncompleteBrief)
			if err != nil || result == nil || result.Grounded || len(result.Issues) != 1 || !strings.Contains(result.Issues[0], string(raw)) {
				t.Fatalf("decoded primary quote lost its only eligible record identity: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestGroundingAmbiguousDecodedPrimaryQuoteStaysHeld(t *testing.T) {
	text := "Example Harbor is fixed in 2.4."
	var lines []string
	for _, id := range []string{"CVE-2099-4001", "CVE-2099-4002"} {
		raw, _ := json.Marshal(cnaSourceFact{CVEID: id, Product: "Example Harbor", Kind: "solution", Text: text})
		lines = append(lines, string(raw))
	}
	brief := syntheticIncompleteBrief + "summary: Covers CVE-2099-4001 and CVE-2099-4002.\n"
	answer, _ := json.Marshal(materialOmissionEvidenceReport{Evidence: []materialOmissionEvidence{{Subject: "Example Harbor", SourceQuote: text}}})
	client := &evidenceRepairLLM{
		report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", SourceQuote: text, Reason: "Missing remediation."}}},
		answer: string(answer),
	}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", strings.Join(lines, "\n"), brief)
	var failure *omissionEvidenceContractError
	if result != nil || !errors.As(err, &failure) || client.calls != 2 {
		t.Fatalf("ambiguous decoded quote must stay held after one correction: result=%+v err=%v calls=%d", result, err, client.calls)
	}
}

func TestGroundingAmbiguousDecodedQuoteCanSelectScopedReference(t *testing.T) {
	text := "Example Harbor is fixed in 2.4."
	var lines []string
	for _, id := range []string{"CVE-2099-4001", "CVE-2099-4002"} {
		raw, _ := json.Marshal(cnaSourceFact{CVEID: id, Product: "Example Harbor", Kind: "solution", Text: text})
		lines = append(lines, string(raw))
	}
	brief := syntheticIncompleteBrief + "summary: Covers CVE-2099-4001 and CVE-2099-4002.\n"
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, system string, _ *llm.Schema, out any) error {
		calls++
		if system != materialOmissionEvidenceSystem {
			return llm.DecodeStructured(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_quote":"Example Harbor is fixed in 2.4.","reason":"Missing remediation."}]}`, out)
		}
		for _, ref := range readReferenceFixture(t, prompt) {
			var fact cnaSourceFact
			if json.Unmarshal([]byte(ref.Quote), &fact) == nil && fact.CVEID == "CVE-2099-4002" {
				return llm.DecodeStructured(fmt.Sprintf(`{"evidence":[{"subject":"Example Harbor","source_evidence_id":%q,"source_quote":""}]}`, ref.ID), out)
			}
		}
		return errors.New("second CVE scoped reference missing")
	}}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", strings.Join(lines, "\n"), brief)
	if err != nil || result == nil || result.Grounded || len(result.Issues) != 1 || !strings.Contains(result.Issues[0], lines[1]) || calls != 2 {
		t.Fatalf("evidence correction did not preserve the selected CVE record: result=%+v err=%v calls=%d", result, err, calls)
	}
}

func TestGroundingExplicitAndProseEvidenceQuotesStayUnchanged(t *testing.T) {
	text := "Example Harbor is fixed in 2.4."
	first, _ := json.Marshal(cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: "solution", Text: text})
	second, _ := json.Marshal(cnaSourceFact{CVEID: "CVE-2099-4002", Product: "Example Harbor", Kind: "solution", Text: text})
	brief := syntheticIncompleteBrief + "summary: Covers CVE-2099-4001 and CVE-2099-4002.\n"
	source := string(first) + "\n" + string(second)
	for _, tc := range []struct {
		name, source, quote, referenceID string
		refs                             []scopedGroundingEvidence
	}{
		{name: "original prose", source: text, quote: text},
		{name: "full primary record", source: source, quote: string(second)},
		{name: "scoped reference", source: source, quote: string(second), referenceID: "selected", refs: []scopedGroundingEvidence{{ID: "selected", Subjects: []string{"Example Harbor"}, Quote: string(second)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := resolveMaterialOmission(groundingIssue{Subject: "Example Harbor", SourceQuote: tc.quote, SourceEvidenceID: tc.referenceID}, tc.source, brief, tc.refs)
			if err != nil || resolved.SourceQuote != tc.quote {
				t.Fatalf("explicit or original prose evidence changed: resolved=%+v err=%v", resolved, err)
			}
		})
	}
}

func TestGroundingDecodedPrimaryQuoteCannotLoseOversizedRecordIdentity(t *testing.T) {
	text := "Example Harbor " + strings.Repeat("x", 3940)
	raw, _ := json.Marshal(cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: "description", Text: text})
	if len(text) > 4000 || len(raw) <= 4000 {
		t.Fatal("fixture must fit the decoded quote limit but exceed it as a complete record")
	}
	resolved, err := resolveMaterialOmission(groundingIssue{Subject: "Example Harbor", SourceQuote: text}, string(raw), syntheticIncompleteBrief, nil)
	if err == nil {
		t.Fatalf("oversized scoped record must defer rather than fall back to identity-free text: quote bytes=%d", len(resolved.SourceQuote))
	}
}

func TestGroundingStructuredTextRequiresEligibleCompleteField(t *testing.T) {
	for _, tc := range []struct {
		name, text, quote, brief string
		ids                      []string
	}{
		{
			name: "partial field in eligible records", text: "Example Harbor is fixed in 2.4. Keep safe mode enabled.", quote: "Example Harbor is fixed in 2.4.",
			brief: syntheticIncompleteBrief + "summary: Covers CVE-2099-4001 and CVE-2099-4002.\n", ids: []string{"CVE-2099-4001", "CVE-2099-4002"},
		},
		{
			name: "complete field in neighboring CVE", text: "Update Example Harbor to at least 9.9.", quote: "Update Example Harbor to at least 9.9.",
			brief: syntheticIncompleteBrief, ids: []string{"CVE-2099-4002"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			for _, id := range tc.ids {
				raw, _ := json.Marshal(cnaSourceFact{CVEID: id, Product: "Example Harbor", Kind: "solution", Text: tc.text})
				lines = append(lines, string(raw))
			}
			answer, _ := json.Marshal(materialOmissionEvidenceReport{Evidence: []materialOmissionEvidence{{Subject: "Example Harbor", SourceQuote: tc.quote}}})
			client := &evidenceRepairLLM{
				report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", SourceQuote: tc.quote, Reason: "Missing remediation."}}},
				answer: string(answer),
			}
			result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", strings.Join(lines, "\n"), tc.brief)
			var failure *omissionEvidenceContractError
			if result != nil || !errors.As(err, &failure) || client.calls != 2 {
				t.Fatalf("ineligible or partial structured text became prose evidence: result=%+v err=%v calls=%d", result, err, client.calls)
			}
		})
	}
}

func TestGroundingIndependentProsePrecedesAmbiguousPrimaryFields(t *testing.T) {
	text := "Example Harbor is fixed in 2.4."
	var lines []string
	for _, id := range []string{"CVE-2099-4001", "CVE-2099-4002"} {
		raw, _ := json.Marshal(cnaSourceFact{CVEID: id, Product: "Example Harbor", Kind: "solution", Text: text})
		lines = append(lines, string(raw))
	}
	brief := syntheticIncompleteBrief + "summary: Covers CVE-2099-4001 and CVE-2099-4002.\n"
	source := strings.Join(lines, "\n") + "\nOriginal source:\n" + text
	client := scriptedGroundingLLM{report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", SourceQuote: text, Reason: "Missing remediation."}}}}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", source, brief)
	if err != nil || result == nil || result.Grounded || len(result.Issues) != 1 || !strings.HasSuffix(result.Issues[0], "(source: "+text+")") {
		t.Fatalf("independent article evidence was replaced by ambiguous primary record scope: result=%+v err=%v", result, err)
	}
}

func TestGroundingProseCannotSpliceAcrossPrimaryRecord(t *testing.T) {
	raw, _ := json.Marshal(cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: "description", Text: "Example Harbor permits a configuration change."})
	quote := "Example Harbor is fixed in 2.4."
	issue := groundingIssue{Subject: "Example Harbor", SourceQuote: quote}
	if err := validateMaterialOmission(issue, "Example Harbor\n"+string(raw)+"\nis fixed in 2.4.", syntheticIncompleteBrief); err == nil {
		t.Fatal("removing a structured record joined disconnected prose into new evidence")
	}
	resolved, err := resolveMaterialOmission(issue, "Example Harbor\nis fixed in 2.4.", syntheticIncompleteBrief, nil)
	if err != nil || resolved.SourceQuote != quote {
		t.Fatalf("ordinary wrapped article prose changed: resolved=%+v err=%v", resolved, err)
	}
}
