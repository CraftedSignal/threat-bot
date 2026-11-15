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

type referenceTestLLM struct {
	noopLLM
	respond func(context.Context, string, string, *llm.Schema, any) error
}

func (c referenceTestLLM) GenerateStructured(ctx context.Context, prompt, system string, schema *llm.Schema, out any) error {
	return c.respond(ctx, prompt, system, schema, out)
}

type referenceFixture struct {
	ID       string   `json:"id"`
	Subjects []string `json:"subjects"`
	Quote    string   `json:"quote"`
}

func readReferenceFixture(t *testing.T, prompt string) []referenceFixture {
	t.Helper()
	_, tail, ok := strings.Cut(prompt, "## Scoped source evidence (JSON)\n")
	if !ok {
		t.Errorf("checker did not provide locally bound evidence references")
		return nil
	}
	var refs []referenceFixture
	if err := json.Unmarshal([]byte(strings.SplitN(tail, "\n\n", 2)[0]), &refs); err != nil {
		t.Fatal(err)
	}
	return refs
}

// Without local resolution a provider can invent or truncate the quote of an
// otherwise correctly selected source field. Reference identity owns the text.
func TestGroundingResolvesScopedEvidenceLocally(t *testing.T) {
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, system string, schema *llm.Schema, out any) error {
		calls++
		refs := readReferenceFixture(t, prompt)
		for _, ref := range refs {
			if ref.Quote != "Example Harbor is fixed in 2.4." {
				continue
			}
			if !containsString(ref.Subjects, "Example Harbor") {
				t.Fatal("source reference lost its product scope")
			}
			subject := schema.Properties["issues"].Items.Properties["subject"]
			if len(subject.Enum) != 0 {
				t.Fatalf("mixed-kind findings require an honest empty subject without empty enums: %+v", subject)
			}
			answer := fmt.Sprintf(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_evidence_id":%q,"source_quote":"","reason":"Missing fixed release."}]}`, ref.ID)
			return llm.DecodeStructured(answer, out)
		}
		return errors.New("fixed-release source evidence missing")
	}}
	result, err := NewGroundingChecker(client).Check(context.Background(), "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
	if err != nil || result == nil || result.Grounded || len(result.Issues) != 1 || !strings.Contains(result.Issues[0], "Example Harbor is fixed in 2.4.") || calls != 1 {
		t.Fatalf("locally quoted blocker must survive: %+v %v calls=%d", result, err, calls)
	}
}

func TestGroundingReferenceCannotBorrowUnrelatedCVEEvidence(t *testing.T) {
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, system string, _ *llm.Schema, out any) error {
		calls++
		if system == materialOmissionEvidenceSystem {
			return llm.DecodeStructured(`{"evidence":[]}`, out)
		}
		for _, ref := range readReferenceFixture(t, prompt) {
			if strings.Contains(ref.Quote, "CVE-2099-4002") {
				t.Errorf("neighbor CVE became eligible evidence: %+v", ref)
			}
		}
		return llm.DecodeStructured(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_evidence_id":"unknown","source_quote":"Example Harbor is fixed in 2.4.","reason":"Missing fixed release."}]}`, out)
	}}
	result, err := NewGroundingChecker(client).Check(context.Background(), "Example Harbor", syntheticCompletenessSource+"\nExample Harbor CVE-2099-4002 is fixed in 2.0.", syntheticIncompleteBrief)
	var failure interface {
		FailureKind() string
		RequestDigest() string
	}
	if result != nil || !errors.As(err, &failure) || failure.FailureKind() != "omission_evidence_contract" || len(failure.RequestDigest()) != 64 || calls != 2 {
		t.Fatalf("invalid reference must remain a typed held failure after one correction: %+v %v calls=%d", result, err, calls)
	}
}

func TestGroundingContractDigestIncludesWholeCheckerInput(t *testing.T) {
	digest := func(title, source, brief string) string {
		client := &evidenceRepairLLM{report: groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Subject: "Example Harbor", Reason: "Missing fixed release."}}}, answer: `{"evidence":[]}`}
		_, err := NewGroundingChecker(client).Check(context.Background(), title, source, brief)
		var failure interface{ RequestDigest() string }
		if !errors.As(err, &failure) {
			t.Fatalf("untyped contract failure: %v", err)
		}
		return failure.RequestDigest()
	}
	base := digest("Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
	if base != digest("Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief) {
		t.Fatal("same input generated unstable failure identity")
	}
	for _, got := range []string{digest("corrected title", syntheticCompletenessSource, syntheticIncompleteBrief), digest("Example Harbor", syntheticCompletenessSource+" corrected advisory", syntheticIncompleteBrief), digest("Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief+"summary: Corrected\n")} {
		if got == base {
			t.Fatal("changed full checker input reused stale failure digest")
		}
	}
}

func TestGroundingCancellationDoesNotBecomeContractHold(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, _, _ string, _ *llm.Schema, out any) error {
		calls++
		cancel()
		return llm.DecodeStructured(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_quote":"invented","reason":"Missing fix."}]}`, out)
	}}
	_, err := NewGroundingChecker(client).Check(ctx, "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
	var failure interface{ FailureKind() string }
	if !errors.Is(err, context.Canceled) || errors.As(err, &failure) || calls != 1 {
		t.Fatalf("cancellation must remain retryable: %v calls=%d", err, calls)
	}
}

func TestGroundingCancellationDuringCorrectionDoesNotPersistContractFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, _, system string, _ *llm.Schema, out any) error {
		calls++
		if system == materialOmissionEvidenceSystem {
			cancel()
			return llm.DecodeStructured(`{"evidence":[]}`, out)
		}
		return llm.DecodeStructured(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_quote":"invented","reason":"Missing fix."}]}`, out)
	}}
	_, err := NewGroundingChecker(client).Check(ctx, "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
	var failure interface{ FailureKind() string }
	if !errors.Is(err, context.Canceled) || errors.As(err, &failure) || calls != 2 {
		t.Fatalf("cancellation during correction became permanent contract failure: %v calls=%d", err, calls)
	}
}

func TestGroundingReferenceCannotSwitchEligibleProductTargets(t *testing.T) {
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, system string, _ *llm.Schema, out any) error {
		calls++
		if system == materialOmissionEvidenceSystem {
			return llm.DecodeStructured(`{"evidence":[]}`, out)
		}
		for _, ref := range readReferenceFixture(t, prompt) {
			if ref.Quote == "OtherPlugin is fixed in 2.0." {
				answer := fmt.Sprintf(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_evidence_id":%q,"source_quote":"Example Harbor is fixed in 2.4.","reason":"Missing fix."}]}`, ref.ID)
				return llm.DecodeStructured(answer, out)
			}
		}
		return errors.New("second product source reference missing")
	}}
	brief := strings.Replace(syntheticIncompleteBrief, "affected_products: [Example Harbor]", "affected_products: [Example Harbor, OtherPlugin]", 1)
	result, err := NewGroundingChecker(client).Check(context.Background(), "Example Harbor", syntheticCompletenessSource+"\nOtherPlugin is fixed in 2.0.", brief)
	var failure interface{ FailureKind() string }
	if result != nil || !errors.As(err, &failure) || calls != 2 {
		t.Fatalf("reference for a different eligible product bypassed target gate: %+v %v calls=%d", result, err, calls)
	}
}

func TestGroundingEvidenceCatalogueBoundsAddedPromptCost(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 250; i++ {
		fmt.Fprintf(&source, "Example Harbor release branch %d requires authenticated administration and an independently confirmed fixed release.\n", i)
	}
	client := referenceTestLLM{respond: func(_ context.Context, prompt, _ string, _ *llm.Schema, out any) error {
		_, tail, ok := strings.Cut(prompt, "## Scoped source evidence (JSON)\n")
		if !ok {
			t.Fatal("source catalogue absent")
		}
		if len(tail) > 6000 {
			t.Fatalf("evidence metadata duplicated too much source material: %d bytes", len(tail))
		}
		return llm.DecodeStructured(`{"issues":[]}`, out)
	}}
	result, err := NewGroundingChecker(client).Check(context.Background(), "Example Harbor CVE-2099-4001", source.String(), syntheticIncompleteBrief)
	if err != nil || !result.Grounded {
		t.Fatalf("bounded catalogue changed a supported empty finding set: %+v %v", result, err)
	}
}

func TestGroundingCorrectionSelectsLocallyResolvedReference(t *testing.T) {
	calls := 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, system string, _ *llm.Schema, out any) error {
		calls++
		if system != materialOmissionEvidenceSystem {
			return llm.DecodeStructured(`{"issues":[{"kind":"material_omission","field":"content","subject":"wrong target","source_quote":"invented","reason":"Missing fixed release."}]}`, out)
		}
		for _, ref := range readReferenceFixture(t, prompt) {
			if ref.Quote == "Example Harbor is fixed in 2.4." {
				return llm.DecodeStructured(fmt.Sprintf(`{"evidence":[{"subject":"Example Harbor","source_evidence_id":%q,"source_quote":""}]}`, ref.ID), out)
			}
		}
		return errors.New("correction lacks scoped remediation evidence")
	}}
	result, err := NewGroundingChecker(client).Check(context.Background(), "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
	if err != nil || result == nil || result.Grounded || len(result.Issues) != 1 || !strings.Contains(result.Issues[0], "Example Harbor is fixed in 2.4.") || calls != 2 {
		t.Fatalf("finding-only correction did not resolve local evidence: %+v %v calls=%d", result, err, calls)
	}
}
