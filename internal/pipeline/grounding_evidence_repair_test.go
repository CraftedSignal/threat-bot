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

// Only the external provider is scripted: the real checker must validate each
// corrected quote and retain every original factual blocker.
type evidenceRepairLLM struct {
	noopLLM
	report       groundingReport
	answer       string
	err          error
	calls        int
	checkSchema  *llm.Schema
	repairSchema *llm.Schema
}

func (c *evidenceRepairLLM) GenerateStructured(_ context.Context, _, _ string, schema *llm.Schema, out any) error {
	c.calls++
	if c.calls == 1 {
		c.checkSchema = schema
		*out.(*groundingReport) = c.report
		return nil
	}
	c.repairSchema = schema
	if c.err != nil {
		return c.err
	}
	return llm.DecodeStructured(c.answer, out)
}

func TestGroundingEvidenceRepairUsesVertexCompatibleSubjectSchema(t *testing.T) {
	client := &evidenceRepairLLM{
		report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", Reason: "Missing the fixed release."}}},
		answer: `{"evidence":[{"subject":"Example Harbor","source_quote":"Example Harbor is fixed in 2.4."}]}`,
	}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
	if err != nil || result == nil || result.Grounded || client.repairSchema == nil {
		t.Fatalf("evidence repair must reach normal blocking validation: result=%+v err=%v", result, err)
	}
	// The first response mixes omission and unsupported-claim findings; empty
	// subjects and IDs must remain representable without empty enum members.
	initial := client.checkSchema.Properties["issues"].Items
	for _, field := range []string{"subject", "source_evidence_id"} {
		if got := initial.Properties[field].Enum; len(got) != 0 {
			t.Errorf("mixed-kind checker field %s must allow an honest empty value without enums: %q", field, got)
		}
	}
	if got := client.repairSchema.Properties["evidence"].Items.Properties["source_evidence_id"].Enum; len(got) != 0 {
		t.Errorf("repair reference must allow an empty unsupported value without enums: %q", got)
	}
	bindings := client.repairSchema.Properties["evidence"].Items.Properties["binding"].Enum
	if !containsString(bindings, omissionQuoteBinding) {
		t.Errorf("repair schema must allow the verified quote path: %q", bindings)
	}
	for _, binding := range bindings {
		if binding == "" {
			t.Fatal("repair binding enum contains an empty value")
		}
	}
	// Vertex rejects empty enum members with HTTP 400 before generating an
	// answer. Unsupported evidence can instead leave source_quote empty.
	subject := client.repairSchema.Properties["evidence"].Items.Properties["subject"]
	eligible := materialOmissionSubjects(syntheticIncompleteBrief)
	if len(subject.Enum) != len(eligible) {
		t.Fatalf("repair schema must constrain subjects to eligible brief targets: got %q want %q", subject.Enum, eligible)
	}
	for i, value := range subject.Enum {
		if value == "" || value != eligible[i] {
			t.Fatalf("repair schema contains an invalid subject enum member: %q", subject.Enum)
		}
	}
}

func TestGroundingEvidenceCorrectionRejectsBindingForAnotherEligibleTarget(t *testing.T) {
	brief := strings.Replace(syntheticIncompleteBrief, "affected_products: [Example Harbor]", "affected_products: [Example Harbor, OtherPlugin]", 1)
	source := syntheticCompletenessSource + "\nOtherPlugin is fixed in 2.0."
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, system string, schema *llm.Schema, out any) error {
		calls++
		refs := readReferenceFixture(t, prompt)
		if system != materialOmissionEvidenceSystem {
			return llm.DecodeStructured(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_quote":"invented","reason":"Missing the fixed release."}]}`, out)
		}
		for _, ref := range refs {
			if containsString(ref.Subjects, "OtherPlugin") && !containsString(ref.Subjects, "Example Harbor") {
				encoded, _ := json.Marshal([]string{"OtherPlugin", ref.ID})
				wrongBinding := string(encoded)
				answer, _ := json.Marshal(map[string]any{"evidence": []map[string]string{{"subject": "OtherPlugin", "binding": wrongBinding}}})
				return llm.DecodeStructured(string(answer), out)
			}
		}
		return errors.New("other-target reference is not actually scoped to that target")
	}}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", source, brief)
	var contract *omissionEvidenceContractError
	if result != nil || !errors.As(err, &contract) || !strings.Contains(err.Error(), "invalid target/reference selection") || calls != 2 {
		t.Fatalf("correction must remain held if it switches an existing target: result=%+v err=%v calls=%d", result, err, calls)
	}
}

func TestGroundingEvidenceCorrectionRejectsLegacyTargetSwitch(t *testing.T) {
	brief := strings.Replace(syntheticIncompleteBrief, "affected_products: [Example Harbor]", "affected_products: [Example Harbor, OtherPlugin]", 1)
	client := &evidenceRepairLLM{
		report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", Reason: "Missing the fixed release."}}},
		answer: `{"evidence":[{"subject":"OtherPlugin","source_quote":"OtherPlugin is fixed in 2.0."}]}`,
	}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", syntheticCompletenessSource+"\nOtherPlugin is fixed in 2.0.", brief)
	var contract *omissionEvidenceContractError
	if result != nil || !errors.As(err, &contract) || !strings.Contains(err.Error(), "changed its eligible target") || client.calls != 2 {
		t.Fatalf("legacy correction must not switch an existing target: result=%+v err=%v calls=%d", result, err, client.calls)
	}
}

func TestGroundingRepairsMalformedOmissionEvidenceWithoutDroppingBlockers(t *testing.T) {
	for _, issue := range []groundingIssue{
		{Subject: "Example Harbor", SourceQuote: "fixed in 2.4"},
		{Subject: "Example Harbor plugin", SourceQuote: "Example Harbor is fixed in 2.4."},
		{},
	} {
		t.Run(issue.Subject+issue.SourceQuote, func(t *testing.T) {
			issue.Kind, issue.Field, issue.Reason = groundingKindMaterialOmission, "content", "Missing the fixed release."
			client := &evidenceRepairLLM{
				report: groundingReport{Issues: []groundingIssue{
					{Kind: groundingKindUnsupported, Field: "summary", BriefQuote: "grants root access", Reason: "The source does not establish root access."},
					issue,
				}},
				answer: `{"evidence":[{"subject":"Example Harbor","source_quote":"Example Harbor is fixed in 2.4."}]}`,
			}
			result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief+"summary: grants root access\n")
			if err != nil {
				t.Fatalf("correctable evidence must reach the normal blocking repair path: %v", err)
			}
			if result.Grounded || len(result.Issues) != 2 || !strings.Contains(result.Issues[0], "root access") || !strings.Contains(result.Issues[1], "content: missing source-supported fact for Example Harbor: Missing the fixed release.") || !strings.Contains(result.Issues[1], "Example Harbor is fixed in 2.4.") {
				t.Fatalf("correcting evidence lost or changed factual blockers: %+v", result)
			}
			if client.calls != 2 {
				t.Fatalf("expected exactly one evidence correction, got %d model calls", client.calls)
			}
		})
	}
}

func TestGroundingEvidenceCorrectionRemainsBoundedAndFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		err          error
	}{
		{name: "missing correction", answer: `{"evidence":[]}`},
		{name: "empty reference and quote", answer: `{"evidence":[{"subject":"Example Harbor","source_evidence_id":"","source_quote":""}]}`},
		{name: "unknown reference", answer: `{"evidence":[{"subject":"Example Harbor","source_evidence_id":"unknown","source_quote":"Example Harbor is fixed in 2.4."}]}`},
		{name: "missing quote", answer: `{"evidence":[{"subject":"Example Harbor","source_quote":""}]}`},
		{name: "detached quote", answer: `{"evidence":[{"subject":"Example Harbor","source_quote":"fixed in 2.4"}]}`},
		{name: "invented quote", answer: `{"evidence":[{"subject":"Example Harbor","source_quote":"Example Harbor is fixed in 9.9."}]}`},
		{name: "neighbor product", answer: `{"evidence":[{"subject":"Example Bridge","source_quote":"Example Bridge is fixed in 2.0."}]}`},
		{name: "neighbor CVE", answer: `{"evidence":[{"subject":"Example Harbor","source_quote":"Example Harbor CVE-2099-4002 is fixed in 2.4."}]}`},
		{name: "neighbor product structured record", answer: `{"evidence":[{"subject":"CVE-2099-4001","source_quote":"{\"cve_id\":\"CVE-2099-4001\",\"kind\":\"solution\",\"product\":\"Example Bridge\",\"text\":\"Upgrade to 2.0.\"}"}]}`},
		{name: "provider unavailable", err: errors.New("provider unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &evidenceRepairLLM{
				report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", Reason: "Missing the fixed release."}}},
				answer: tc.answer,
				err:    tc.err,
			}
			source := syntheticCompletenessSource + " Example Bridge is fixed in 2.0. Example Harbor CVE-2099-4002 is fixed in 2.4.\n" + `{"cve_id":"CVE-2099-4001","kind":"solution","product":"Example Bridge","text":"Upgrade to 2.0."}`
			result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", source, syntheticIncompleteBrief)
			if err == nil || result != nil {
				t.Fatalf("invalid corrected evidence must keep the candidate held: %+v %v", result, err)
			}
			if client.calls != 2 {
				t.Fatalf("evidence correction must stop after one attempt, got %d model calls", client.calls)
			}
		})
	}
}

func TestGroundingValidEvidenceNeedsNoCorrection(t *testing.T) {
	client := &evidenceRepairLLM{report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", SourceQuote: "Example Harbor is fixed in 2.4.", Reason: "Missing the fixed release."}}}}
	result, err := NewGroundingChecker(client).Check(context.Background(), "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
	if err != nil || result.Grounded || len(result.Issues) != 1 || client.calls != 1 {
		t.Fatalf("valid material evidence should use the existing single check: %+v %v calls=%d", result, err, client.calls)
	}
}

func TestGroundingEvidenceCorrectionRetainsStructuredPrimaryScope(t *testing.T) {
	text := `Upgrade to 2.4 and keep the "safe mode" default.`
	fact, _ := json.Marshal(cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: "solution", Text: text})
	answer, _ := json.Marshal(map[string]any{"evidence": []map[string]string{{"subject": "CVE-2099-4001", "source_quote": text}}})
	client := &evidenceRepairLLM{
		report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: "CVE-2099-4001", SourceQuote: "2.4", Reason: "Missing the fixed release."}}},
		answer: string(answer),
	}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", string(fact), syntheticIncompleteBrief)
	if err != nil || result.Grounded || len(result.Issues) != 1 || !strings.Contains(result.Issues[0], string(fact)) {
		t.Fatalf("complete decoded CNA field must keep its explicit record scope: %+v %v", result, err)
	}
}

func TestGroundingEvidenceCorrectionBatchesOnlyInvalidFindings(t *testing.T) {
	client := &evidenceRepairLLM{
		report: groundingReport{Issues: []groundingIssue{
			{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", Reason: "Missing the fixed release."},
			{Kind: groundingKindMaterialOmission, Field: "content", Subject: "Example Harbor", SourceQuote: "Example Harbor through 2.3 is affected.", Reason: "Missing the affected range."},
			{Kind: groundingKindMaterialOmission, Field: "action_plan", Subject: "Example Harbor plugin", SourceQuote: "low privileges", Reason: "Missing the privilege requirement."},
		}},
		answer: `{"evidence":[{"subject":"Example Harbor","source_quote":"Example Harbor is fixed in 2.4."},{"subject":"Example Harbor","source_quote":"Example Harbor requires low privileges and no user interaction."}]}`,
	}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
	if err != nil || result.Grounded || len(result.Issues) != 3 || client.calls != 2 {
		t.Fatalf("invalid omissions must share one bounded correction and preserve valid findings: %+v %v calls=%d", result, err, client.calls)
	}
	for i, want := range []string{"Missing the fixed release.", "Missing the affected range.", "action_plan: missing source-supported fact for Example Harbor: Missing the privilege requirement."} {
		if !strings.Contains(result.Issues[i], want) {
			t.Fatalf("correction changed finding order or meaning: %+v", result.Issues)
		}
	}
}

func TestGroundingEvidenceCorrectionBindsReferenceToItsTargetInSchema(t *testing.T) {
	brief := strings.Replace(syntheticIncompleteBrief, "affected_products: [Example Harbor]", "affected_products: [Example Harbor, OtherPlugin]", 1)
	source := syntheticCompletenessSource + "\nOtherPlugin is fixed in 2.0."
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, system string, schema *llm.Schema, out any) error {
		calls++
		refs := readReferenceFixture(t, prompt)
		if system != materialOmissionEvidenceSystem {
			var unrelated string
			for _, ref := range refs {
				if ref.Quote == "OtherPlugin is fixed in 2.0." {
					unrelated = ref.ID
				}
			}
			if unrelated == "" {
				return errors.New("unrelated product reference missing")
			}
			answer := fmt.Sprintf(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_evidence_id":%q,"reason":"Missing the fixed release."}]}`, unrelated)
			return llm.DecodeStructured(answer, out)
		}

		binding := ""
		items := schema.Properties["evidence"].Items
		if items == nil || items.Properties["binding"] == nil {
			return errors.New("target-bound repair selection missing from schema")
		}
		for _, choice := range items.Properties["binding"].Enum {
			var pair []string
			if json.Unmarshal([]byte(choice), &pair) != nil || len(pair) != 2 || pair[0] != "Example Harbor" {
				continue
			}
			for _, ref := range refs {
				if ref.ID == pair[1] && containsString(ref.Subjects, "Example Harbor") && ref.Quote == "Example Harbor is fixed in 2.4." {
					binding = choice
				}
			}
		}
		if binding == "" {
			return errors.New("target-bound repair selection missing from schema")
		}
		answer, _ := json.Marshal(map[string]any{"evidence": []map[string]string{{
			"subject": "Example Harbor", "binding": binding, "source_quote": "",
		}}})
		return llm.DecodeStructured(string(answer), out)
	}}
	result, err := NewGroundingChecker(client).WithLogger(quietLogger()).Check(context.Background(), "Example Harbor", source, brief)
	if err != nil || result == nil || result.Grounded || len(result.Issues) != 1 || !strings.Contains(result.Issues[0], "Example Harbor is fixed in 2.4.") || calls != 2 {
		t.Fatalf("target-bound correction must repair an unrelated initial reference without dropping the blocker: result=%+v err=%v calls=%d", result, err, calls)
	}
}
