package eval

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Regression: scoring another granularity must not repeat extraction, and a
// failed prediction must not contribute partially returned techniques.
func TestCollectPredictionsScoresBothGranularities(t *testing.T) {
	docs := []EvalDoc{
		{Title: "second", GoldTechniques: []string{"T1059.001"}},
		{Title: "first", GoldTechniques: []string{"T1566.001"}},
	}
	var titles []string
	results := CollectPredictions(context.Background(), docs, func(_ context.Context, d EvalDoc) ([]string, error) {
		titles = append(titles, d.Title)
		if d.Title == "second" {
			return []string{"T1059.003"}, nil
		}
		return []string{"T1566.001"}, errors.New("failed extraction")
	})
	if !reflect.DeepEqual(titles, []string{"second", "first"}) {
		t.Fatalf("prediction order/calls = %v", titles)
	}
	want := []DocResult{
		{Gold: []string{"T1059.001"}, Pred: []string{"T1059.003"}},
		{Gold: []string{"T1566.001"}},
	}
	if !reflect.DeepEqual(results, want) {
		t.Fatalf("results = %#v, want %#v", results, want)
	}
	base := Score(results, BaseTechniqueID)
	exact := Score(results, func(s string) string { return s })
	if base.Docs != 2 || base.MicroPrecision != 1 || base.MicroRecall != .5 || base.MacroF1 != .5 {
		t.Fatalf("base = %+v", base)
	}
	if exact.Docs != 2 || exact.MicroF1 != 0 || exact.MacroF1 != 0 || len(exact.PerTechnique) != 3 {
		t.Fatalf("exact = %+v", exact)
	}
	// Scoring is repeatable and leaves the reusable predictions unchanged.
	if !reflect.DeepEqual(results, want) || len(titles) != 2 {
		t.Fatalf("scoring changed predictions or repeated extraction")
	}
}

// Run historically delegates cancellation to the predictor for every document;
// keep that contract while reusing the failed results across both scores.
func TestCollectPredictionsPreservesCancellationAndDocumentCount(t *testing.T) {
	for _, preCanceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "during", true: "before"}[preCanceled], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if preCanceled {
				cancel()
			}
			docs := []EvalDoc{
				{Title: "one", GoldTechniques: []string{"T1059.001"}},
				{Title: "two", GoldTechniques: []string{"T1566.001"}},
				{Title: "three", GoldTechniques: []string{"T1003.001"}},
			}
			calls := 0
			results := CollectPredictions(ctx, docs, func(got context.Context, d EvalDoc) ([]string, error) {
				if got != ctx {
					t.Fatal("predictor did not receive original context")
				}
				calls++
				if calls == 1 && !preCanceled {
					cancel()
					return d.GoldTechniques, nil
				}
				return d.GoldTechniques, got.Err()
			})
			if calls != 3 || len(results) != 3 {
				t.Fatalf("calls=%d results=%d, want 3 each", calls, len(results))
			}
			wantRecall := 0.0
			if !preCanceled {
				wantRecall = 1.0 / 3
			}
			for _, norm := range []func(string) string{BaseTechniqueID, func(s string) string { return s }} {
				report := Score(results, norm)
				if report.Docs != 3 || report.MicroRecall != wantRecall || len(report.PerTechnique) != 3 {
					t.Fatalf("report = %+v", report)
				}
			}
		})
	}
}

func TestCollectPredictionsEmptyDoesNotPredict(t *testing.T) {
	results := CollectPredictions(context.Background(), nil, func(context.Context, EvalDoc) ([]string, error) {
		t.Fatal("empty dataset invoked predictor")
		return nil, nil
	})
	if len(results) != 0 || Score(results, BaseTechniqueID).Docs != 0 {
		t.Fatal("empty dataset produced results")
	}
}
