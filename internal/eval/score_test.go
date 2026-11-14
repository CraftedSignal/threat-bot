package eval

import (
	"math"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestBaseTechniqueID(t *testing.T) {
	if BaseTechniqueID("T1566.001") != "T1566" {
		t.Error("subtechnique not reduced to base")
	}
	if BaseTechniqueID("T1059") != "T1059" {
		t.Error("base technique should be unchanged")
	}
}

func TestScoreExact(t *testing.T) {
	results := []DocResult{
		{Gold: []string{"T1566", "T1059"}, Pred: []string{"T1566", "T1486"}},
	}
	r := Score(results, func(s string) string { return s })
	if !approx(r.MicroPrecision, 0.5) || !approx(r.MicroRecall, 0.5) || !approx(r.MicroF1, 0.5) {
		t.Errorf("micro = %+v, want P/R/F1 = 0.5", r)
	}
	if r.Docs != 1 {
		t.Errorf("docs = %d, want 1", r.Docs)
	}
}

func TestScoreBaseNormalisationCreditsSubtechnique(t *testing.T) {
	results := []DocResult{{Gold: []string{"T1566.001"}, Pred: []string{"T1566"}}}
	exact := Score(results, func(s string) string { return s })
	if exact.MicroF1 != 0 {
		t.Errorf("exact F1 = %v, want 0", exact.MicroF1)
	}
	base := Score(results, BaseTechniqueID)
	if !approx(base.MicroF1, 1.0) {
		t.Errorf("base F1 = %v, want 1.0", base.MicroF1)
	}
}
