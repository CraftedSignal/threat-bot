package eval

import (
	"context"
	"testing"
)

func TestRunScoresAgainstGold(t *testing.T) {
	docs := []EvalDoc{
		{Title: "D1", Text: "x", GoldTechniques: []string{"T1566"}},
		{Title: "D2", Text: "y", GoldTechniques: []string{"T1059"}},
	}
	// Perfect predictor: echoes each doc's gold set.
	predict := func(ctx context.Context, d EvalDoc) ([]string, error) {
		return d.GoldTechniques, nil
	}
	rep := Run(context.Background(), docs, predict, BaseTechniqueID)
	if rep.MicroF1 != 1.0 {
		t.Errorf("MicroF1 = %v, want 1.0", rep.MicroF1)
	}
	if rep.Docs != 2 {
		t.Errorf("Docs = %d, want 2", rep.Docs)
	}
}

func TestRunPredictErrorCountsAsMiss(t *testing.T) {
	docs := []EvalDoc{{Title: "D1", Text: "x", GoldTechniques: []string{"T1566"}}}
	predict := func(ctx context.Context, d EvalDoc) ([]string, error) {
		return nil, context.DeadlineExceeded // error -> empty prediction
	}
	rep := Run(context.Background(), docs, predict, BaseTechniqueID)
	if rep.MicroRecall != 0 {
		t.Errorf("recall = %v, want 0 (error treated as empty prediction)", rep.MicroRecall)
	}
}
