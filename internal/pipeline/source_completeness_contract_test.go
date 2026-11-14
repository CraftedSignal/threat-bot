package pipeline

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

const syntheticCompletenessSource = "CVE-2099-4001: Example Harbor through 2.3 is affected. Example Harbor is fixed in 2.4. Example Harbor requires low privileges and no user interaction."
const syntheticIncompleteBrief = "title: Example Harbor (CVE-2099-4001)\naffected_products: [Example Harbor]\ncves: [CVE-2099-4001]\ncontent: Example Harbor permits a configuration change.\n"

// Decode the wire report so this regression also exercises model response fields.
func syntheticOmissionReport(t *testing.T, subject, quote string) groundingReport {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"grounded": true, "issues": []map[string]string{{"kind": "material_omission", "field": "content", "subject": subject, "source_quote": quote, "reason": "The brief omits this explicit applicability or remediation fact."}}})
	if err != nil {
		t.Fatal(err)
	}
	var report groundingReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestMaterialOmissionRetainsVerifiedRepairEvidence(t *testing.T) {
	for _, quote := range []string{"Example Harbor through 2.3 is affected.", "Example Harbor is fixed in 2.4.", "Example Harbor requires low privileges and no user interaction."} {
		checker := NewGroundingChecker(scriptedGroundingLLM{report: syntheticOmissionReport(t, "Example Harbor", quote)})
		got, err := checker.Check(context.Background(), "Example Harbor", syntheticCompletenessSource, syntheticIncompleteBrief)
		if err != nil {
			t.Fatal(err)
		}
		if got.Grounded || len(got.Issues) != 1 || !strings.Contains(got.Issues[0], quote) {
			t.Fatalf("material repair instruction lost its source evidence: %+v", got)
		}
	}
}

func TestMaterialOmissionRejectsUntrustedRepairEvidence(t *testing.T) {
	for _, tc := range []struct{ name, subject, quote, source string }{
		{"missing quote", "Example Harbor", "", syntheticCompletenessSource},
		{"invented quote", "Example Harbor", "Example Harbor is fixed in 9.9.", syntheticCompletenessSource},
		{"neighbor product", "Example Bridge", "Example Bridge is fixed in 2.4.", syntheticCompletenessSource + " Example Bridge is fixed in 2.4."},
		{"neighbor CVE", "Example Harbor", "Example Harbor CVE-2099-4002 is fixed in 2.4.", syntheticCompletenessSource + " Example Harbor CVE-2099-4002 is fixed in 2.4."},
		{"bare version", "Example Harbor", "fixed in 2.4", syntheticCompletenessSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewGroundingChecker(scriptedGroundingLLM{report: syntheticOmissionReport(t, tc.subject, tc.quote)})
			if got, err := checker.Check(context.Background(), "Example Harbor", tc.source, syntheticIncompleteBrief); err == nil {
				t.Fatalf("untrusted completeness instruction must defer: %+v", got)
			}
		})
	}
}

func TestPartialClaimCheckRejectsWholeBriefCompletenessVerdict(t *testing.T) {
	checker := NewGroundingChecker(scriptedGroundingLLM{report: syntheticOmissionReport(t, "Example Harbor", "Example Harbor is fixed in 2.4.")})
	item := scraper.RawItem{Title: "Example Harbor CVE-2099-4001", Content: syntheticCompletenessSource}
	got, err := checker.CheckMergeDelta(context.Background(), item, &ExtractionResult{CVEs: []string{"CVE-2099-4001"}, AffectedProducts: []string{"Example Harbor"}})
	if err == nil {
		t.Fatalf("partial claims accepted a whole-brief completeness verdict: %+v", got)
	}
}

func TestMaterialOmissionStructuredEvidenceKeepsProductAndCVEScope(t *testing.T) {
	const text = "Update Example Harbor to at least 2.4."
	for _, tc := range []struct {
		name, id, product, quote string
		valid                    bool
	}{
		{"complete scoped fact", "CVE-2099-4001", "Example Harbor", text, true},
		{"different CVE", "CVE-2099-4002", "Example Harbor", text, false},
		{"different product", "CVE-2099-4001", "Example Bridge", text, false},
		{"detached version", "CVE-2099-4001", "Example Harbor", "2.4", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fact, err := json.Marshal(cnaSourceFact{CVEID: tc.id, Product: tc.product, Kind: "solution", Text: text})
			if err != nil {
				t.Fatal(err)
			}
			checker := NewGroundingChecker(scriptedGroundingLLM{report: syntheticOmissionReport(t, "CVE-2099-4001", tc.quote)})
			got, err := checker.Check(context.Background(), "Example Harbor CVE-2099-4001", string(fact), syntheticIncompleteBrief)
			if tc.valid {
				if err != nil || got.Grounded {
					t.Fatalf("complete scoped fact not retained: %+v %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("detached or cross-target evidence trusted: %+v", got)
			}
		})
	}
}
