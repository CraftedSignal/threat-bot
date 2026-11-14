package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

type inferMockLLM struct {
	resp string
	err  error
	// gotPrompt captures the last prompt passed to GenerateJSON, so tests
	// can assert on prompt content (e.g. that reference URLs were included).
	gotPrompt string
}

func (m *inferMockLLM) Generate(context.Context, string, string) (string, error) {
	return m.resp, m.err
}

func (m *inferMockLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	m.gotPrompt = prompt
	if m.err != nil {
		return m.err
	}
	return json.Unmarshal([]byte(m.resp), out)
}

func TestInferVendorProduct_Foxit(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader","Foxit PDF Editor"]}`}
	v, p, err := InferVendorProduct(context.Background(), m,
		"Foxit Application Use-After-Free (CVE-2026-3779)", "use-after-free in PDF page/form objects",
		[]string{"https://www.foxit.com/support/security-bulletins.html"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v[0] != "Foxit" {
		t.Errorf("vendors = %v, want [Foxit]", v)
	}
	if len(p) != 2 {
		t.Errorf("products = %v, want 2", p)
	}
}

func TestInferVendorProduct_DropsJunk(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit","unknown",""],"affected_products":["unspecified"]}`}
	v, p, _ := InferVendorProduct(context.Background(), m, "t", "c", nil)
	if len(v) != 1 || v[0] != "Foxit" {
		t.Errorf("vendors = %v, want [Foxit]", v)
	}
	if len(p) != 0 {
		t.Errorf("products = %v, want empty ('unspecified' dropped)", p)
	}
}

func TestReferencesSection(t *testing.T) {
	if got := referencesSection(nil); got != "" {
		t.Errorf("nil references: got %q, want empty", got)
	}
	if got := referencesSection([]string{"", ""}); got != "" {
		t.Errorf("all-empty references: got %q, want empty", got)
	}
	got := referencesSection([]string{"https://www.foxit.com/a", "", "https://example.com/b"})
	want := "\n\nReference URLs:\n- https://www.foxit.com/a\n- https://example.com/b\n"
	if got != want {
		t.Errorf("referencesSection = %q, want %q", got, want)
	}
}

func TestInferVendorProduct_IncludesReferencesInPrompt(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":[]}`}
	_, _, err := InferVendorProduct(context.Background(), m, "t", "c", []string{"https://www.foxit.com/x"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.gotPrompt, "Reference URLs:") || !strings.Contains(m.gotPrompt, "https://www.foxit.com/x") {
		t.Errorf("prompt missing reference URL section: %q", m.gotPrompt)
	}
}

func TestInferVendorProduct_OmitsReferenceSectionWhenEmpty(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":[],"affected_products":[]}`}
	_, _, err := InferVendorProduct(context.Background(), m, "t", "c", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(m.gotPrompt, "Reference URLs:") {
		t.Errorf("prompt should not include reference section when references is empty: %q", m.gotPrompt)
	}
}

func TestApplyFallback_PassesItemURLAsReference(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader"]}`}
	ex := &ExtractionResult{}
	item := scraper.RawItem{
		Title:   "CVE-2026-3779 Foxit UAF",
		Content: "pdf form objects",
		URL:     "https://www.foxit.com/support/security-bulletins.html",
	}
	if !applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Fatal("expected fallback to fire")
	}
	if !strings.Contains(m.gotPrompt, "https://www.foxit.com/support/security-bulletins.html") {
		t.Errorf("prompt missing item URL as reference: %q", m.gotPrompt)
	}
}

func TestApplyFallback_FiresForGenericCVE(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader"]}`}
	ex := &ExtractionResult{}
	item := scraper.RawItem{SourceID: "x", Title: "CVE-2026-3779 Foxit UAF", Content: "pdf form objects"}
	if !applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Fatal("expected fallback to fire")
	}
	if len(ex.AffectedVendors) != 1 || ex.AffectedVendors[0] != "Foxit" {
		t.Errorf("vendors = %v", ex.AffectedVendors)
	}
	if len(ex.AffectedProducts) != 1 {
		t.Errorf("products = %v", ex.AffectedProducts)
	}
}

func TestApplyFallback_SkipsNoCVE(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader"]}`}
	ex := &ExtractionResult{}
	item := scraper.RawItem{Title: "Some malware campaign", Content: "no cve identifier here"}
	if applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Error("should not fire without a CVE")
	}
}

func TestApplyFallback_SkipsWhenPopulated(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Wrong"],"affected_products":["Wrong"]}`}
	ex := &ExtractionResult{AffectedVendors: []string{"Microsoft"}}
	item := scraper.RawItem{Title: "CVE-2026-0001 thing", Content: "c"}
	if applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Error("should not fire when vendor already present")
	}
	if ex.AffectedVendors[0] != "Microsoft" {
		t.Error("must not overwrite existing vendor")
	}
}

func TestApplyFallback_LLMErrorIsSafe(t *testing.T) {
	m := &inferMockLLM{err: errors.New("llm down")}
	ex := &ExtractionResult{}
	item := scraper.RawItem{Title: "CVE-2026-0002 thing", Content: "c"}
	if applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Error("must return false on LLM error")
	}
}

func TestApplyFallback_UsesNVDCPEsWithoutLLM(t *testing.T) {
	m := &inferMockLLM{err: errors.New("must not be called")}
	ex := &ExtractionResult{}
	item := scraper.RawItem{SourceID: "CVE-2026-0003", Title: "CVE-2026-0003", Content: "c",
		Metadata: map[string]string{"cve": "CVE-2026-0003", "cpes": "cpe:2.3:a:acme:widget_pro:1.0:*:*:*:*:*:*:* cpe:2.3:a:acme:widget_pro:2.0:*:*:*:*:*:*:*"}}
	if !applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Fatal("expected CPE fallback to fire")
	}
	if len(ex.AffectedVendors) != 1 || ex.AffectedVendors[0] != "acme" || len(ex.AffectedProducts) != 1 || ex.AffectedProducts[0] != "widget pro" {
		t.Errorf("vendors=%v products=%v", ex.AffectedVendors, ex.AffectedProducts)
	}
}

func TestIsGenericCVEBriefSigmaDetectionIsActionable(t *testing.T) {
	y := "title: CVE-2026-0004 exploitation detection\nsummary: Detects exploitation of CVE-2026-0004\n"
	if !isGenericCVEBrief(y) {
		t.Fatal("precondition: brief is generic")
	}
	if rejectGenericCVEBrief(scraper.RawItem{SigmaRule: &scraper.SigmaRule{}}, y) {
		t.Error("sigma-sourced detection brief must not be rejected")
	}
	if !rejectGenericCVEBrief(scraper.RawItem{}, y) {
		t.Error("non-sigma generic CVE brief should still be rejected")
	}
}

const genericCVEBriefYAML = "title: Folder permission bypass (CVE-2026-111000)\nsummary: A permission flaw affects folders.\naffected_vendors: []\naffected_products: []\n"

func TestBackfillAffectedFromExtraction(t *testing.T) {
	item := scraper.RawItem{SourceID: "x", Title: "CVE-2026-111000"}
	if !rejectGenericCVEBrief(item, genericCVEBriefYAML) {
		t.Fatal("fixture must start as a rejected generic brief")
	}
	got, stages := backfillAffectedFromSources(item, &ExtractionResult{AffectedProducts: []string{"Grafana"}}, genericCVEBriefYAML)
	if rejectGenericCVEBrief(item, got) || len(stages) != 1 || stages[0] != "extraction" {
		t.Fatalf("stages=%v rejected=%v\n%s", stages, rejectGenericCVEBrief(item, got), got)
	}
}

func TestBackfillAffectedFromCPEsAndCNA(t *testing.T) {
	item := scraper.RawItem{SourceID: "nvd:CVE-2026-111000", Title: "CVE-2026-111000", Metadata: map[string]string{"source_identifier": "security@grafana.com"}}
	got, stages := backfillAffectedFromSources(item, &ExtractionResult{}, genericCVEBriefYAML)
	if rejectGenericCVEBrief(item, got) || len(stages) != 1 || stages[0] != "nvd_cna" || !strings.Contains(got, "Grafana") {
		t.Fatalf("stages=%v\n%s", stages, got)
	}

	item.Metadata = map[string]string{"cpes": "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*", "source_identifier": "security@grafana.com"}
	got, stages = backfillAffectedFromSources(item, nil, genericCVEBriefYAML)
	if len(stages) == 0 || stages[0] != "nvd_cpes" || rejectGenericCVEBrief(item, got) {
		t.Fatalf("CPEs must come before the CNA: stages=%v\n%s", stages, got)
	}
}

func TestBackfillAffectedKeepsRejectionWhenAllSourcesEmpty(t *testing.T) {
	for _, id := range []string{"", "cve@mitre.org", "security-advisories@github.com", "psirt@"} {
		item := scraper.RawItem{Title: "CVE-2026-111000", Metadata: map[string]string{"source_identifier": id}}
		got, stages := backfillAffectedFromSources(item, &ExtractionResult{}, genericCVEBriefYAML)
		if len(stages) != 0 || !rejectGenericCVEBrief(item, got) {
			t.Errorf("id %q: stages=%v; want the generic rejection kept", id, stages)
		}
	}
}
