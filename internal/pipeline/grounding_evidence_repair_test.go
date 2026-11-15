package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
)

// Only the external provider is scripted: the real checker must validate each
// corrected quote and retain every original factual blocker.
type evidenceRepairLLM struct {
	noopLLM
	report groundingReport
	answer string
	err    error
	calls  int
}

func (c *evidenceRepairLLM) GenerateStructured(_ context.Context, _, _ string, _ *llm.Schema, out any) error {
	c.calls++
	if c.calls == 1 {
		*out.(*groundingReport) = c.report
		return nil
	}
	if c.err != nil {
		return c.err
	}
	return llm.DecodeStructured(c.answer, out)
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
	if err != nil || result.Grounded || len(result.Issues) != 1 || !strings.Contains(result.Issues[0], text) {
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
