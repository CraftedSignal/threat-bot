package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

type mergeRelevanceMockLLM struct {
	merge             bool
	referenceRelevant bool
	pocRelevant       bool
	cves              []string
	vendors           []string
	products          []string
	oses              []string
	iocs              []ExtractedIOC
	reason            string
}

func (mergeRelevanceMockLLM) Generate(context.Context, string, string) (string, error) {
	return "", nil
}

func (m mergeRelevanceMockLLM) GenerateJSON(_ context.Context, _ string, _ string, out any) error {
	resp, ok := out.(*mergeRelevanceLLMResponse)
	if !ok {
		return nil
	}
	resp.Merge = boolPtr(m.merge)
	resp.ReferenceRelevant = boolPtr(m.referenceRelevant)
	resp.POCRelevant = boolPtr(m.pocRelevant)
	resp.CVEs = append([]string(nil), m.cves...)
	resp.AffectedVendors = append([]string(nil), m.vendors...)
	resp.AffectedProducts = append([]string(nil), m.products...)
	resp.AffectedOS = append([]string(nil), m.oses...)
	resp.IOCs = append([]ExtractedIOC(nil), m.iocs...)
	resp.Reason = m.reason
	return nil
}

func boolPtr(v bool) *bool {
	return &v
}

// Only the external model call is scripted; the merge and its persisted state
// remain real so a permissive fallback cannot silently update the draft.
func TestMergeIntoDraftDefersWhenRelevanceUnavailable(t *testing.T) {
	checkerErr := errors.New("relevance provider unavailable")
	tests := []struct {
		name     string
		noClient bool
		response string
		callErr  error
	}{
		{name: "no client", noClient: true},
		{name: "provider error", callErr: checkerErr},
		{name: "empty response", response: `{}`},
		{name: "missing merge", response: `{"reference_relevant":true,"poc_relevant":true,"cves":["CVE-2026-4242"],"iocs":[{"type":"domain","value":"unrelated.example"}]}`},
		{name: "missing reference decision", response: `{"merge":true,"poc_relevant":true,"cves":["CVE-2026-4242"],"iocs":[{"type":"domain","value":"unrelated.example"}]}`},
		{name: "missing poc decision", response: `{"merge":true,"reference_relevant":true,"cves":["CVE-2026-4242"],"iocs":[{"type":"domain","value":"unrelated.example"}]}`},
		{name: "null decision", response: `{"merge":null,"reference_relevant":true,"poc_relevant":true}`},
		{name: "malformed decision", response: `{"merge":"yes","reference_relevant":true,"poc_relevant":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			p := newDedupTestPipeline(t, db)
			p.llmClient = nil
			if !tt.noClient {
				p.llmClient = shutdownStageLLM{generateJSON: func(_ context.Context, _, system string, out any) error {
					if system != mergeRelevanceSystemPrompt {
						return fmt.Errorf("unexpected system prompt %q", system)
					}
					if tt.callErr != nil {
						return tt.callErr
					}
					return json.Unmarshal([]byte(tt.response), out)
				}}
			}
			if err := db.CreateDraft(&storage.Draft{
				ID: "draft-unchanged", Status: storage.StatusApproved, Source: "original", SourceIDs: `["original:1"]`,
				BriefYAML: "id: original\nslug: original\ntitle: Existing report\nsummary: Existing report\nseverity: high\ncontent: Existing report.\n",
				CreatedAt: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}
			before, err := db.GetDraft("draft-unchanged")
			if err != nil {
				t.Fatal(err)
			}
			item := scraper.RawItem{
				SourceID: "exploit-db:unsupported", Source: "exploit-db", URL: "https://unrelated.example/exploit",
				Title: "Public proof-of-concept for CVE-2026-4242", Content: "Public exploit code is available for CVE-2026-4242.",
			}
			mergeErr := p.mergeIntoDraft(context.Background(), "draft-unchanged", &ExtractionResult{
				CVEs: []string{"CVE-2026-4242"}, IOCs: []ExtractedIOC{{Type: "domain", Value: "unrelated.example"}},
			}, item)
			if mergeErr == nil {
				t.Error("unavailable or incomplete relevance check accepted a merge")
			} else if !errors.Is(mergeErr, errMergeRelevanceUnavailable) || errors.Is(mergeErr, errMergeNotRelevant) {
				t.Errorf("merge error = %v, want an informative checker failure rather than a story rejection", mergeErr)
			}
			if tt.callErr != nil && !errors.Is(mergeErr, tt.callErr) {
				t.Errorf("merge error = %v, want wrapped provider error %v", mergeErr, tt.callErr)
			}
			after, err := db.GetDraft("draft-unchanged")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("failed relevance check changed persisted draft:\nbefore: %+v\nafter: %+v", before, after)
			}
		})
	}
}

func TestAssessDraftMergeRelevanceRequiresExtraction(t *testing.T) {
	p := &Pipeline{llmClient: mergeRelevanceMockLLM{merge: true, referenceRelevant: true, pocRelevant: true}}
	got, decision, err := p.assessDraftMergeRelevance(context.Background(), nil, nil, scraper.RawItem{})
	if !errors.Is(err, errMergeRelevanceUnavailable) || got != nil || decision.Merge || decision.ReferenceRelevant || decision.POCRelevant {
		t.Fatalf("missing extraction accepted: extraction=%+v decision=%+v err=%v", got, decision, err)
	}
}

func TestAssessDraftMergeRelevanceHonorsContextCancellation(t *testing.T) {
	for _, when := range []string{"before check", "after accepted response", "during provider failure"} {
		t.Run(when, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &Pipeline{}
			if when == "before check" {
				cancel()
			} else {
				p.llmClient = shutdownStageLLM{generateJSON: func(_ context.Context, _, _ string, out any) error {
					cancel()
					if when == "during provider failure" {
						return errors.New("provider disconnected")
					}
					return json.Unmarshal([]byte(`{"merge":true,"reference_relevant":true,"poc_relevant":true}`), out)
				}}
			}
			got, decision, err := p.assessDraftMergeRelevance(ctx, nil, &ExtractionResult{}, scraper.RawItem{})
			if !errors.Is(err, context.Canceled) || got != nil || decision.Merge || decision.ReferenceRelevant || decision.POCRelevant {
				t.Fatalf("canceled relevance check accepted: extraction=%+v decision=%+v err=%v", got, decision, err)
			}
		})
	}
}

func TestAssessDraftMergeRelevanceUsesExplicitDecisions(t *testing.T) {
	tests := []struct {
		name, response string
		want           mergeRelevanceDecision
	}{
		{name: "explicit positive signals", response: `{"merge":true,"reference_relevant":true,"poc_relevant":true,"cves":["CVE-2026-4242"]}`, want: mergeRelevanceDecision{Merge: true, ReferenceRelevant: true, POCRelevant: true}},
		{name: "explicit negative signals", response: `{"merge":true,"reference_relevant":false,"poc_relevant":false,"cves":["CVE-2026-4242"]}`, want: mergeRelevanceDecision{Merge: true}},
		{name: "explicit refusal needs no acceptance flags", response: `{"merge":false}`, want: mergeRelevanceDecision{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Pipeline{llmClient: shutdownStageLLM{generateJSON: func(_ context.Context, _, _ string, out any) error {
				return json.Unmarshal([]byte(tt.response), out)
			}}}
			got, decision, err := p.assessDraftMergeRelevance(context.Background(), nil, &ExtractionResult{CVEs: []string{"CVE-2026-4242"}}, scraper.RawItem{})
			if err != nil || decision != tt.want || got == nil {
				t.Fatalf("explicit response: extraction=%+v decision=%+v err=%v; want %+v", got, decision, err, tt.want)
			}
			if tt.want.Merge && (len(got.CVEs) != 1 || got.CVEs[0] != "CVE-2026-4242") {
				t.Fatalf("explicit acceptance dropped selected CVE: %+v", got)
			}
		})
	}
}

func TestFilterRoundupContentExtractionDefersWhenRelevanceUnavailable(t *testing.T) {
	for _, mode := range []string{"no client", "provider error", "missing decision"} {
		t.Run(mode, func(t *testing.T) {
			p := &Pipeline{}
			if mode != "no client" {
				p.llmClient = shutdownStageLLM{generateJSON: func(context.Context, string, string, any) error {
					if mode == "provider error" {
						return errors.New("provider unavailable")
					}
					return nil
				}}
			}
			extraction := &ExtractionResult{CVEs: []string{"CVE-2026-4242"}, AffectedProducts: []string{"Unrelated product"}, AffectedOS: []string{"Unrelated OS"}}
			got, err := p.filterRoundupContentExtraction(context.Background(), "Microsoft", extraction, scraper.RawItem{})
			if !errors.Is(err, errMergeRelevanceUnavailable) || got != nil {
				t.Fatalf("unavailable roundup checker returned unfiltered scope: extraction=%+v err=%v", got, err)
			}
			if extraction.AffectedProducts[0] != "Unrelated product" || extraction.AffectedOS[0] != "Unrelated OS" {
				t.Fatal("failed roundup check modified candidate extraction")
			}
		})
	}
}

func TestConstrainMergeKeepsSingleCVETitleScoped(t *testing.T) {
	t.Parallel()
	target := map[string]any{
		"title":             "DD-WRT: UPnP buffer overflow (CVE-2021-27137)",
		"summary":           "DD-WRT UPnP vulnerability",
		"cves":              []any{"CVE-2021-27137"},
		"affected_products": []any{"DD-WRT"},
	}
	incoming := &ExtractionResult{
		CVEs:             []string{"CVE-2021-27137", "CVE-2026-63030"},
		AffectedProducts: []string{"DD-WRT", "WordPress Core"},
	}
	got := constrainMergeToTargetScope(target, incoming)
	if len(got.CVEs) != 1 || got.CVEs[0] != "CVE-2021-27137" {
		t.Fatalf("cross-product CVE reached narrow brief: %v", got.CVEs)
	}
	if len(got.AffectedProducts) != 1 || got.AffectedProducts[0] != "DD-WRT" {
		t.Fatalf("cross-product software reached narrow brief: %v", got.AffectedProducts)
	}
}

func TestMergeIntoDraftUsesLLMRelevanceFilter(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.llmClient = mergeRelevanceMockLLM{
		merge:             true,
		referenceRelevant: true,
		pocRelevant:       false,
		cves:              []string{"CVE-2026-4242"},
		vendors:           []string{"Acme"},
		products:          []string{"WidgetServer"},
		iocs:              []ExtractedIOC{{Type: "domain", Value: "evil.example"}},
		reason:            "WidgetServer and evil.example are about the existing brief",
	}

	if err := db.CreateDraft(&storage.Draft{
		ID:     "draft-widget",
		Status: storage.StatusApproved,
		Source: "nvd",
		BriefYAML: `id: brief-widget
slug: 2026-08-widget
title: WidgetServer CVE-2026-4242
summary: WidgetServer vulnerability
severity: high
published_at: "2026-08-11T00:00:00Z"
content: WidgetServer vulnerability CVE-2026-4242.
cves:
  - CVE-2026-4242
affected_vendors:
  - Acme
affected_products:
  - WidgetServer
`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}

	item := scraper.RawItem{
		SourceID: "research:1",
		Source:   "research",
		Title:    "WidgetServer exploit writeup also mentions Roblox and Discord",
		URL:      "https://research.example/widgetserver",
		Content:  "A proof-of-concept exists for WidgetServer CVE-2026-4242 and uses evil.example. The article also mentions Roblox, Discord, and https://solthere.net/api/v1/redeem as unrelated context.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-4242"},
		AffectedVendors:  []string{"Acme", "Discord"},
		AffectedProducts: []string{"WidgetServer", "Roblox", "Discord"},
		IOCs: []ExtractedIOC{
			{Type: "domain", Value: "evil.example"},
			{Type: "url", Value: "https://solthere.net/api/v1/redeem"},
		},
	}
	if err := p.mergeIntoDraft(context.Background(), "draft-widget", extraction, item); err != nil {
		t.Fatalf("merge: %v", err)
	}

	d, err := db.GetDraft("draft-widget")
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}
	for _, want := range []string{"WidgetServer", "evil.example", "https://research.example/widgetserver"} {
		if !strings.Contains(d.BriefYAML, want) {
			t.Fatalf("merged draft missing %q:\n%s", want, d.BriefYAML)
		}
	}
	for _, bad := range []string{"Roblox", "Discord", "solthere.net", "has_poc:", "poc_references:"} {
		if strings.Contains(d.BriefYAML, bad) {
			t.Fatalf("merge retained irrelevant value %q:\n%s", bad, d.BriefYAML)
		}
	}
}

func TestMergeIntoDraftRejectsLLMSeparateStory(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.llmClient = mergeRelevanceMockLLM{
		merge:             false,
		referenceRelevant: false,
		pocRelevant:       false,
		reason:            "same CVE string appears in a separate malware story",
	}

	if err := db.CreateDraft(&storage.Draft{
		ID:     "draft-ms",
		Status: storage.StatusApproved,
		Source: "msrc",
		BriefYAML: `id: brief-ms
slug: 2026-08-ms
title: Microsoft CVE-2026-5000
summary: Microsoft vulnerability
severity: high
published_at: "2026-08-11T00:00:00Z"
content: Microsoft vulnerability CVE-2026-5000.
cves:
  - CVE-2026-5000
affected_vendors:
  - Microsoft
affected_products:
  - Windows
`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}

	item := scraper.RawItem{
		SourceID: "blog:1",
		Source:   "blog",
		Title:    "Fake Xeno Roblox/Discord executor PoC for CVE-2026-5000",
		URL:      "https://blog.example/fake-xeno",
		Content:  "The malware story mentions CVE-2026-5000 and https://solthere.net/api/v1/redeem.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-5000"},
		AffectedVendors:  []string{"Microsoft"},
		AffectedProducts: []string{"Roblox", "Discord"},
		IOCs:             []ExtractedIOC{{Type: "url", Value: "https://solthere.net/api/v1/redeem"}},
	}
	if err := p.mergeIntoDraft(context.Background(), "draft-ms", extraction, item); err == nil {
		t.Fatal("expected merge rejection for separate story")
	}

	d, err := db.GetDraft("draft-ms")
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}
	for _, bad := range []string{"Roblox", "Discord", "solthere.net", "blog.example", "has_poc:", "iocs:"} {
		if strings.Contains(d.BriefYAML, bad) {
			t.Fatalf("rejected merge polluted draft with %q:\n%s", bad, d.BriefYAML)
		}
	}
}

func TestProcessItemRefusedMerge(t *testing.T) {
	tests := []struct {
		name              string
		corroborationOnly bool
		wantDrafts        int
	}{
		{name: "separate story gets its own brief", wantDrafts: 1},
		// A corroboration-only item may never be the sole source of a brief.
		{name: "corroboration-only item is dropped", corroborationOnly: true, wantDrafts: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()

			const existingYAML = `id: brief-existing
slug: 2026-10-existing
title: Existing threat brief
summary: Existing brief
severity: high
published_at: "2026-10-19T08:00:00Z"
content: Existing detection context.
`
			if err := db.CreateDraft(&storage.Draft{
				ID: "draft-existing", Status: storage.StatusApproved, Source: "original", BriefYAML: existingYAML, CreatedAt: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}
			item := scraper.RawItem{
				SourceID:          "kev:separate-story",
				Source:            "cisa-kev",
				URL:               "https://research.example/shared-report",
				Title:             "Credential theft campaign persistence",
				Content:           strings.Repeat("Observed credential theft persistence concrete detection evidence. ", 20),
				SigmaRule:         &scraper.SigmaRule{Title: "Rule"},
				CorroborationOnly: tt.corroborationOnly,
			}
			// The shared source URL makes pre-extraction dedup pick a merge.
			if err := db.IndexContent(&storage.ContentIndexEntry{
				DraftID: "draft-existing", SourceID: "original:1", Source: "original", SourceURLHash: SourceURLHash(item.URL), CreatedAt: time.Now(),
			}); err != nil {
				t.Fatal(err)
			}

			brief := strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1)
			client := shutdownStageLLM{
				generate: func(context.Context, string, string) (string, error) {
					return brief, nil
				},
				generateJSON: func(_ context.Context, _, system string, out any) error {
					switch system {
					case extractionSystemPrompt:
						out.(*ExtractionResult).AffectedProducts = []string{"WidgetServer"}
					case mergeRelevanceSystemPrompt:
						resp := out.(*mergeRelevanceLLMResponse)
						resp.Merge = boolPtr(false)
						resp.Reason = "a different vulnerability in the same product"
					case groundingSystem:
						out.(*GroundingResult).Grounded = true
					default:
						return fmt.Errorf("unexpected JSON generation system %q", system)
					}
					return nil
				},
			}
			pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

			if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
				t.Fatal(err)
			}
			seen, err := db.HasSeen(item.SourceID)
			if err != nil {
				t.Fatal(err)
			}
			existing, err := db.GetDraft("draft-existing")
			if err != nil {
				t.Fatal(err)
			}
			if drafts := pipe.Decisions(time.Hour).Drafts; !seen || drafts != tt.wantDrafts {
				t.Fatalf("seen=%v drafts=%d, want seen with %d new draft(s)", seen, drafts, tt.wantDrafts)
			}
			if existing == nil || existing.BriefYAML != existingYAML {
				t.Fatal("refused merge changed the existing draft")
			}
		})
	}
}

func TestHandlePostExtractionDedupRefusedMerge(t *testing.T) {
	tests := []struct {
		name              string
		corroborationOnly bool
		wantConsumed      bool
	}{
		{name: "separate story is left for its own brief", wantConsumed: false},
		{name: "corroboration-only item is dropped", corroborationOnly: true, wantConsumed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			p := newDedupTestPipeline(t, db)
			p.llmClient = mergeRelevanceMockLLM{merge: false, reason: "a different PAN-OS vulnerability"}

			// A thin no-CVE PAN-OS brief that a new PAN-OS CVE matches by product.
			if err := db.IndexContent(&storage.ContentIndexEntry{
				ProductFingerprintHash: ProductFingerprint([]string{"Palo Alto Networks"}, []string{"PAN-OS"}),
				TitleNorm:              normalizeTitleTokens("Palo Alto Networks PAN-OS: Remote Code Execution Vulnerability"),
				DraftID:                "draft-rce",
				SourceID:               "cert-bund:wid-sec-2026-1366",
				Source:                 "cert-bund",
				CreatedAt:              time.Now().Add(-90 * time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.CreateDraft(&storage.Draft{
				ID:        "draft-rce",
				Status:    storage.StatusApproved,
				Source:    "cert-bund",
				BriefYAML: "title: PAN-OS RCE\nseverity: critical\nttps:\n  - tactic_id: TA0002\n",
				CreatedAt: time.Now().Add(-90 * time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			item := scraper.RawItem{
				SourceID:          "cisa-kev:cve-2026-0300",
				Source:            "cisa-kev",
				Title:             "Palo Alto Networks PAN-OS Out-of-bounds Write Vulnerability Added to CISA KEV Catalog",
				Content:           "CVE-2026-0300 is actively exploited in the wild.",
				CorroborationOnly: tt.corroborationOnly,
			}
			extraction := &ExtractionResult{
				CVEs:             []string{"CVE-2026-0300"},
				AffectedVendors:  []string{"Palo Alto Networks"},
				AffectedProducts: []string{"PAN-OS"},
			}

			handled := p.handlePostExtractionDedup(context.Background(), item, extraction, nil)
			seen, err := db.HasSeen(item.SourceID)
			if err != nil {
				t.Fatal(err)
			}
			if handled != tt.wantConsumed || seen != tt.wantConsumed {
				t.Fatalf("handled=%v seen=%v, want both %v", handled, seen, tt.wantConsumed)
			}
		})
	}
}

func TestMergeIntoDraftConstrainsBroadSurveyProducts(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.llmClient = mergeRelevanceMockLLM{
		merge:             true,
		referenceRelevant: true,
		pocRelevant:       false,
		cves: []string{
			"CVE-2026-12957",
			"CVE-2026-12958",
			"CVE-2025-59536",
			"CVE-2025-54136",
			"CVE-2026-30615",
			"CVE-2024-21626",
		},
		vendors: []string{"Amazon Web Services", "Amazon", "Anthropic", "Cursor", "Google", "Augment"},
		products: []string{
			"Amazon Q Developer",
			"VS Code plugin for Amazon Q (< 2.20)",
			"Claude Code",
			"Cursor",
			"Windsurf",
			"Google Antigravity (1.19.6)",
			"Augment (0.754.3)",
			"runc",
		},
		oses:   []string{"Linux", "macOS"},
		reason: "broad AI coding assistant article mentions Amazon Q alongside other assistants",
	}

	if err := db.CreateDraft(&storage.Draft{
		ID:     "draft-amazon-q",
		Status: storage.StatusApproved,
		Source: "wiz",
		BriefYAML: `id: brief-amazon-q
slug: 2026-06-amazon-q-rce
title: "CVE-2026-12957: Amazon Q VS Code Extension Arbitrary Code Execution"
summary: Amazon Q Developer Extension for Visual Studio Code allowed arbitrary code execution.
severity: high
published_at: "2026-06-26T00:00:00Z"
content: Amazon Q Developer Extension for Visual Studio Code CVE-2026-12957.
cves:
  - CVE-2026-12957
affected_vendors:
  - Amazon Web Services
  - Amazon
affected_products:
  - Amazon Q Developer Extension for Visual Studio Code
`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}

	item := scraper.RawItem{
		SourceID: "wiz:ghostapproval",
		Source:   "wiz",
		Title:    "GhostApproval: a trust-boundary gap in AI coding assistants",
		URL:      "https://www.wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants",
		Content:  "CVE-2026-12957 GhostApproval affects several AI coding assistants including Amazon Q Developer, Claude Code, Cursor, Windsurf, Google Antigravity, and Augment. It lists adjacent CVEs CVE-2026-12958, CVE-2025-59536, CVE-2025-54136, CVE-2026-30615, and discusses runc CVE-2024-21626 as background.",
	}
	extraction := &ExtractionResult{
		CVEs: []string{
			"CVE-2026-12957",
			"CVE-2026-12958",
			"CVE-2025-59536",
			"CVE-2025-54136",
			"CVE-2026-30615",
			"CVE-2024-21626",
		},
		AffectedVendors: []string{"Amazon Web Services", "Amazon", "Anthropic", "Cursor", "Google", "Augment"},
		AffectedProducts: []string{
			"Amazon Q Developer",
			"VS Code plugin for Amazon Q (< 2.20)",
			"Claude Code",
			"Cursor",
			"Windsurf",
			"Google Antigravity (1.19.6)",
			"Augment (0.754.3)",
			"runc",
		},
		AffectedOS: []string{"Linux", "macOS"},
	}
	if err := p.mergeIntoDraft(context.Background(), "draft-amazon-q", extraction, item); err != nil {
		t.Fatalf("merge: %v", err)
	}

	d, err := db.GetDraft("draft-amazon-q")
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}
	for _, want := range []string{
		"Amazon Q Developer",
		"VS Code plugin for Amazon Q (< 2.20)",
		"CVE-2026-12957",
		item.URL,
	} {
		if !strings.Contains(d.BriefYAML, want) {
			t.Fatalf("merged draft missing scoped value %q:\n%s", want, d.BriefYAML)
		}
	}
	for _, bad := range []string{
		"Anthropic",
		"Claude Code",
		"Cursor",
		"Windsurf",
		"Google Antigravity",
		"Augment",
		"runc",
		"CVE-2026-12958",
		"CVE-2025-59536",
		"CVE-2025-54136",
		"CVE-2026-30615",
		"CVE-2024-21626",
	} {
		if strings.Contains(d.BriefYAML, bad) {
			t.Fatalf("broad survey polluted draft with %q:\n%s", bad, d.BriefYAML)
		}
	}
}
