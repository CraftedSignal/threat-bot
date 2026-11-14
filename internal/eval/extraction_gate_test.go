package eval

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testSyntheticExtractionReplayGate exercises the real extractor and scoring path with manually
// authored synthetic responses. This is a deterministic contract regression,
// not a live-model quality measurement. Missing fixtures fail the gate.
func testSyntheticExtractionReplayGate(t *testing.T) {
	fixB, err := os.ReadFile(filepath.Join("testdata", "fixtures.json"))
	if err != nil {
		t.Fatalf("read required synthetic fixtures: %v", err)
	}
	var fixtures map[string]string
	if err := json.Unmarshal(fixB, &fixtures); err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	baseB, err := os.ReadFile(filepath.Join("testdata", "baseline.json"))
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	var baseline struct {
		BaseMacroF1  float64 `json:"base_macro_f1"`
		BaseMicroF1  float64 `json:"base_micro_f1"`
		ExactMacroF1 float64 `json:"exact_macro_f1"`
		ExactMicroF1 float64 `json:"exact_micro_f1"`
	}
	if err := json.Unmarshal(baseB, &baseline); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	recs, err := LoadDataset(filepath.Join("testdata", "single_label.json"))
	if err != nil {
		t.Fatalf("dataset: %v", err)
	}
	docs := GroupByDoc(recs)
	client := NewReplayClient(fixtures)
	rep := Run(context.Background(), docs, ExtractorPredict(client), BaseTechniqueID)

	if rep.MacroF1 < baseline.BaseMacroF1 {
		t.Errorf("macro F1 regressed: got %.3f, baseline %.3f", rep.MacroF1, baseline.BaseMacroF1)
	}
	if rep.MicroF1 < baseline.BaseMicroF1 {
		t.Errorf("micro F1 regressed: got %.3f, baseline %.3f", rep.MicroF1, baseline.BaseMicroF1)
	}
	exact := Run(context.Background(), docs, ExtractorPredict(client), func(s string) string { return s })
	if exact.MacroF1 < baseline.ExactMacroF1 || exact.MicroF1 < baseline.ExactMicroF1 {
		t.Errorf("exact F1 regressed: macro %.3f micro %.3f, baseline %.3f %.3f", exact.MacroF1, exact.MicroF1, baseline.ExactMacroF1, baseline.ExactMicroF1)
	}
}
