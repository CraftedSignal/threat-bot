package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// noopLLM satisfies llm.Client for test paths that never call the model.
type noopLLM struct{}

func (noopLLM) Generate(ctx context.Context, prompt, system string) (string, error) {
	return "", nil
}
func (noopLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	return nil
}

// dedupRelevanceLLM explicitly accepts the submitted candidates for integration
// tests of successful merging. Relevance/refusal tests install their own client.
// Other model stages retain the no-op behavior needed by these fixtures.
type dedupRelevanceLLM struct{ noopLLM }

func (dedupRelevanceLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	switch system {
	case mergeRelevanceSystemPrompt:
		_, candidates, ok := strings.Cut(prompt, "\nCandidate extracted fields:\n")
		if !ok {
			return fmt.Errorf("merge test fixture: missing candidate extraction")
		}
		var extraction ExtractionResult
		if err := json.Unmarshal([]byte(candidates), &extraction); err != nil {
			return err
		}
		return (mergeRelevanceMockLLM{
			merge: true, referenceRelevant: true, pocRelevant: true,
			cves: extraction.CVEs, vendors: extraction.AffectedVendors,
			products: extraction.AffectedProducts, oses: extraction.AffectedOS, iocs: extraction.IOCs,
			reason: "test fixture explicitly accepts the submitted candidates",
		}).GenerateJSON(ctx, prompt, system, out)
	case roundupContentRelevanceSystemPrompt:
		resp, ok := out.(*roundupContentRelevanceResponse)
		if !ok {
			return fmt.Errorf("roundup test fixture: unexpected output %T", out)
		}
		_, candidates, ok := strings.Cut(prompt, "\nCandidate affected products: ")
		if !ok {
			return fmt.Errorf("roundup test fixture: missing candidate products")
		}
		products, oses, ok := strings.Cut(candidates, "\nCandidate affected OS: ")
		if !ok {
			return fmt.Errorf("roundup test fixture: missing candidate OS")
		}
		resp.Relevant = boolPtr(true)
		if strings.TrimSpace(products) != "" {
			resp.AffectedProducts = strings.Split(products, ", ")
		}
		if strings.TrimSpace(oses) != "" {
			resp.AffectedOS = strings.Split(oses, ", ")
		}
		resp.Reason = "test fixture explicitly accepts the submitted candidates"
	}
	return nil
}

// newDedupTestPipeline builds a real Pipeline with relevance acceptance and an NVD stub
// that reports every CVE as existing, so mergeIntoDraft's verifier runs offline.
func newDedupTestPipeline(t *testing.T, db *storage.DB) *Pipeline {
	t.Helper()
	p := New(Config{DB: db, LLMClient: dedupRelevanceLLM{}, FastLLMClient: noopLLM{}, Logger: slog.Default()})
	p.cveVerifier.client = &http.Client{Transport: &mockNVDTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			_ = json.NewEncoder(rec).Encode(nvdDetailResponse{Vulnerabilities: []nvdVulnerability{{CVE: nvdCVEDetail{ID: req.URL.Query().Get("cveId")}}}})
			return rec.Result(), nil
		},
	}}
	return p
}

// A DedupUpdate discovered only after LLM extraction (regex pre-check missed the
// CVE) must merge into the existing brief in place — NOT assemble a parallel one.
func TestHandlePostExtractionDedup_UpdateMergesInPlace(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)

	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-existing", Status: storage.StatusApproved, Source: "nvd",
		BriefYAML: "id: brief-existing\nslug: 2026-07-existing\ntitle: Existing CVE-2026-9999\n" +
			"summary: x\nseverity: high\npublished_at: \"2026-07-01T00:00:00Z\"\n" +
			"content: about CVE-2026-9999\ncves:\n  - CVE-2026-9999\naffected_products:\n  - WidgetServer\n",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2026-9999", DraftID: "draft-existing", SourceID: "nvd:9999", Source: "nvd",
		CVEContext: `{"has_exploit":false,"has_patch":false,"active_exploitation":false}`,
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("index: %v", err)
	}

	// New item from a DIFFERENT source with exploit signal; the CVE is surfaced
	// by extraction and supported by the raw source, reproducing the post-extraction
	// DedupUpdate that the pipeline previously dropped.
	item := scraper.RawItem{
		SourceID: "exploit-db:5", Source: "exploit-db",
		Title:   "New PoC for the WidgetServer flaw",
		Content: "A working exploit code / proof-of-concept for CVE-2026-9999 was released this week.",
	}
	extraction := &ExtractionResult{CVEs: []string{"CVE-2026-9999"}, AffectedProducts: []string{"WidgetServer"}}

	handled := p.handlePostExtractionDedup(context.Background(), item, extraction, nil)
	if !handled {
		t.Fatal("want post-extraction DedupUpdate handled (merged in place), got fall-through to a new brief")
	}
	drafts := 0
	for _, err := range db.ApprovedDraftsSince(time.Now().AddDate(-1, 0, 0)) {
		if err != nil {
			t.Fatal(err)
		}
		drafts++
	}
	if drafts != 1 {
		t.Fatalf("want no new draft (1 total), got %d", drafts)
	}
	seen, err := db.HasSeen("exploit-db:5")
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("item should be marked seen after in-place merge")
	}
}

func TestMergeIntoThinDraftPromotesGroundedCampaignSignalsAndProvenance(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	base := `id: brief-connectwise
slug: 2026-10-connectwise
title: ConnectWise Cloud Backup compromise
summary: Compromised credentials enabled tenant access.
severity: high
published_at: "2026-10-17T00:00:00Z"
content: Initial disclosure.
affected_vendors: [ConnectWise, Microsoft]
affected_products: [Microsoft 365]
references: [https://status.example.test/connectwise]
action_plan:
  hunt_leads:
    - lead: Review ConnectWise service principal use
      evidence: Compromised credentials enabled tenant access
`
	if err := db.CreateDraft(&storage.Draft{
		ID: "connectwise", Status: storage.StatusApproved, Source: "news", SourceIDs: `["news:connectwise"]`,
		BriefYAML: base, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	evidence := "Microsoft observed Storm-0940 actively exploiting compromised ConnectWise credentials."
	item := scraper.RawItem{
		SourceID: "microsoft:storm-0940", Source: "microsoft-threat-intel",
		Title:   "Storm-0940 exploitation of ConnectWise Cloud Backup",
		Content: evidence + " The actor used ARTEX against Microsoft 365 tenants.",
		URL:     "https://www.microsoft.com/security/blog/storm-0940", PublishedAt: time.Date(2026, 10, 21, 19, 54, 0, 0, time.UTC),
	}
	err := p.mergeIntoDraft(context.Background(), "connectwise", &ExtractionResult{
		AffectedVendors: []string{"ConnectWise", "Microsoft"}, AffectedProducts: []string{"ConnectWise Cloud Backup"},
		ThreatActor: "Storm-0940", ActiveExploitation: true, ExploitationEvidence: evidence,
	}, item)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft("connectwise")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"threat_actor: Storm-0940", "exploited: true", "status: confirmed_active",
		"https://www.microsoft.com/security/blog/storm-0940", "microsoft:storm-0940",
	} {
		if !strings.Contains(draft.BriefYAML+draft.SourceIDs, want) {
			t.Fatalf("merged draft missing %q:\n%s\nsource IDs: %s", want, draft.BriefYAML, draft.SourceIDs)
		}
	}
	if !strings.Contains(draft.UpdateLog, `"level":"L3"`) || !strings.Contains(draft.UpdateLog, "exploited:true") {
		t.Fatalf("exploitation promotion was not classified L3: %s", draft.UpdateLog)
	}
}

// Break caught: a corroboration-only aggregator may contribute the primary
// sources it collected, but its own synthesis must not independently assert
// actor attribution or confirmed exploitation.
func TestMergeIntoDraftPreservesCorroborationSourcesWithoutPromotingClaims(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	base := `id: brief-connectwise
slug: 2026-10-connectwise
title: ConnectWise Cloud Backup compromise
summary: Compromised credentials enabled tenant access.
severity: high
published_at: "2026-10-17T00:00:00Z"
content: Initial disclosure.
affected_vendors: [ConnectWise, Microsoft]
affected_products: [Microsoft 365]
references: [https://status.example.test/connectwise]
action_plan:
  hunt_leads:
    - lead: Review ConnectWise service principal use
      evidence: Compromised credentials enabled tenant access
`
	if err := db.CreateDraft(&storage.Draft{
		ID: "connectwise-corroboration", Status: storage.StatusApproved, Source: "news", SourceIDs: `["news:connectwise"]`,
		BriefYAML: base, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	evidence := "Microsoft observed Storm-0940 actively exploiting compromised ConnectWise credentials."
	item := scraper.RawItem{
		SourceID: "pwn-watch:connectwise:2026-10-23T08:00:00Z", Source: "pwn-watch",
		Title:   "Storm-0940 exploitation of ConnectWise Cloud Backup",
		Content: evidence + " The actor used ARTEX against Microsoft 365 tenants.",
		URL:     "https://pwn.watch/i/connectwise", PublishedAt: time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC),
		Metadata: map[string]string{
			"incident_slug":     "connectwise",
			"source_url_000":    "https://www.microsoft.com/security/connectwise",
			"source_url_001":    "https://www.huntress.com/blog/connectwise",
			"reference_url_000": "https://www.microsoft.com/security/connectwise",
			"reference_url_001": "https://www.huntress.com/blog/connectwise",
		},
		CorroborationOnly: true,
	}
	err := p.mergeIntoDraft(context.Background(), "connectwise-corroboration", &ExtractionResult{
		AffectedVendors: []string{"ConnectWise", "Microsoft"}, AffectedProducts: []string{"ConnectWise Cloud Backup"},
		ThreatActor: "Storm-0940", ActiveExploitation: true, ExploitationEvidence: evidence,
	}, item)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft("connectwise-corroboration")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://pwn.watch/i/connectwise",
		"https://www.microsoft.com/security/connectwise",
		"https://www.huntress.com/blog/connectwise",
	} {
		if !strings.Contains(draft.BriefYAML, want) {
			t.Errorf("merged draft missing reference %q:\n%s", want, draft.BriefYAML)
		}
	}
	for _, forbidden := range []string{"threat_actor: Storm-0940", "exploited: true", "status: confirmed_active"} {
		if strings.Contains(draft.BriefYAML, forbidden) {
			t.Errorf("corroboration-only source promoted %q:\n%s", forbidden, draft.BriefYAML)
		}
	}
}
