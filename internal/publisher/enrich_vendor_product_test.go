package publisher

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
)

type enrichMockLLM struct{ resp string }

func (m *enrichMockLLM) Generate(context.Context, string, string) (string, error) {
	return m.resp, nil
}
func (m *enrichMockLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	return json.Unmarshal([]byte(m.resp), out)
}

func TestEnrichBriefsInSegment(t *testing.T) {
	briefs := []BundleBrief{
		{Slug: "foxit", Title: "CVE-2026-3779 Foxit UAF", Content: "pdf form objects"},
		{Slug: "other", Title: "X", AffectedVendors: []string{"Microsoft"}},
		{Slug: "not-wanted", Title: "CVE-2026-1 thing", Content: "c"},
	}
	m := &enrichMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader"]}`}

	changed := enrichBriefsInSegment(context.Background(), m, briefs, map[string]bool{"foxit": true}, slog.Default())

	if len(changed) != 1 {
		t.Fatalf("len(changed) = %d, want 1", len(changed))
	}
	if changed[0].Slug != "foxit" {
		t.Errorf("changed[0].Slug = %q, want %q", changed[0].Slug, "foxit")
	}
	if len(changed[0].AffectedProducts) != 1 || changed[0].AffectedProducts[0] != "Foxit PDF Reader" {
		t.Errorf("changed[0].AffectedProducts = %v, want [Foxit PDF Reader]", changed[0].AffectedProducts)
	}
	if len(briefs[0].AffectedProducts) != 1 || briefs[0].AffectedProducts[0] != "Foxit PDF Reader" {
		t.Errorf("foxit not enriched in place: %v", briefs[0].AffectedProducts)
	}
	if briefs[1].AffectedVendors[0] != "Microsoft" {
		t.Error("populated brief must be untouched")
	}
	if len(briefs[2].AffectedProducts) != 0 {
		t.Error("brief not in want-set must be skipped")
	}
}

func (m *enrichMockLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return nil
}
