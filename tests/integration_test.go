package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// mockScraper implements scraper.Scraper for testing.
type mockScraper struct {
	items []scraper.RawItem
}

func (m *mockScraper) Name() string { return "test-source" }

func (m *mockScraper) Poll(ctx context.Context, since time.Time) ([]scraper.RawItem, error) {
	return m.items, nil
}

func TestIntegrationEndToEnd(t *testing.T) {
	// Mock LLM server that handles quality, extraction, and brief assembly.
	// The llm.Client POSTs to {endpoint}/api/generate with:
	//   {"model":"...", "prompt":"...", "system":"...", "format":"json"|"", "stream":false}
	// and expects: {"response": "..."}
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody struct {
			Prompt string          `json:"prompt"`
			Model  string          `json:"model"`
			System string          `json:"system"`
			Format json.RawMessage `json:"format"`
			Stream bool            `json:"stream"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		var response string
		if isJSONFormat(reqBody.Format) {
			// Distinguish between JSON calls based on the system prompt.
			if strings.Contains(reqBody.System, "fact-checking") || strings.Contains(reqBody.System, "grounding") {
				// Grounding check
				response = `{"issues": []}`
			} else if strings.Contains(reqBody.System, "Score each item") || strings.Contains(reqBody.System, "threat intelligence analyst evaluating") {
				// Quality gate
				response = `{"credibility": 4.5, "actionability": 4.0, "novelty": 4.5, "summary": "High-quality advisory with concrete IOCs"}`
			} else {
				// Extraction or other JSON calls
				response = `{"tactics": ["Initial Access"], "techniques": ["T1566"], "iocs": [], "cves": ["CVE-2026-1234"], "platforms": ["windows"], "summary": "Test extraction"}`
			}
		} else {
			// Non-JSON response = brief assembly (must be valid YAML)
			response = structuredBriefJSON(map[string]any{
				"id": "brief-test-integration", "slug": "test-integration-brief", "title": "Integration Test Threat Brief",
				"summary": "A test threat brief for integration testing", "content": "## Overview\nThis is a test brief.\n", "severity": "high",
				"tags": []any{"test"},
				"rules": []any{map[string]any{
					"title": "Test Rule", "description": "Detects malware.exe",
					"logsource": map[string]any{"category": "process_creation", "product": "windows"},
					"detection": map[string]any{
						"selections": []any{map[string]any{"name": "selection", "fields": []any{map[string]any{"field": "Image", "modifier": "endswith", "values": []any{"\\malware.exe"}}}}},
						"condition":  "selection",
					},
					"level": "high",
					"tags":  []any{"attack.initial_access", "attack.t1566.001"},
				}},
				"ttps": []any{map[string]any{"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing"}, map[string]any{"tactic_id": "TA0099", "tactic_name": "Fake", "technique_id": "T9999", "technique_name": "Nonexistent"}},
			})
		}
		callCount++

		json.NewEncoder(w).Encode(map[string]interface{}{
			"response": response,
		})
	}))
	defer server.Close()

	// Open in-memory database
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create LLM client pointed at mock server
	llmClient := llm.NewOllamaClient(server.URL, "test-model")

	// Create pipeline with low quality threshold so our mock passes
	pipe := pipeline.New(pipeline.Config{
		DB:               db,
		LLMClient:        llmClient,
		QualityThreshold: 3.0,
		Logger:           logger,
	})

	// Create test scraper with a mock item
	testItem := scraper.RawItem{
		SourceID:    "test-source:integration-001",
		Source:      "test-source",
		Title:       "Critical Vulnerability in Example Software",
		URL:         "https://example.com/advisory/2026-001",
		Content:     "A critical remote code execution vulnerability has been discovered in Example Software v4.2. Attackers are actively exploiting CVE-2026-1234 via phishing emails with malicious PDF attachments.",
		PublishedAt: time.Now(),
		Metadata:    map[string]string{"cve": "CVE-2026-1234"},
	}

	// Create scraper runner and register mock scraper
	runner := scraper.NewRunner(db, logger, 0)
	runner.RegisterWithInterval(&mockScraper{items: []scraper.RawItem{testItem}}, time.Minute)

	ctx := context.Background()

	// Step 1: Poll for items
	items, err := runner.PollAll(ctx)
	if err != nil {
		t.Fatalf("PollAll failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	// Step 2: Process through pipeline (quality gate -> extraction -> brief assembly)
	if err := pipe.Process(ctx, items); err != nil {
		t.Fatalf("pipeline.Process failed: %v", err)
	}

	// Step 3: Verify a draft was created
	drafts := draftsWithStatus(t, db, "pending")
	if len(drafts) != 1 {
		t.Fatalf("expected 1 pending draft, got %d", len(drafts))
	}

	if got, want := pipe.Decisions(time.Hour), (pipeline.DecisionCounts{Processed: 1, PassedQuality: 1, Drafts: 1}); got != want {
		t.Errorf("decisions = %+v, want %+v", got, want)
	}

	draft := drafts[0]
	if draft.Source != "test-source" {
		t.Errorf("expected source 'test-source', got %q", draft.Source)
	}
	if draft.Score < 3.0 {
		t.Errorf("expected score >= 3.0, got %.1f", draft.Score)
	}

	// Step 4: Verify brief YAML contains expected fields
	if !strings.Contains(draft.BriefYAML, "Integration Test Threat Brief") {
		t.Errorf("brief YAML missing expected title")
	}
	if !strings.Contains(draft.BriefYAML, "logsource") {
		t.Errorf("brief YAML missing expected logsource in rules")
	}

	// Step 4b: Verify validation cleaned the brief
	if strings.Contains(draft.BriefYAML, "TA0099") {
		t.Error("expected validator to remove invalid tactic TA0099")
	}
	if strings.Contains(draft.BriefYAML, "T9999") {
		t.Error("expected validator to remove invalid technique T9999")
	}
	if !strings.Contains(draft.BriefYAML, "T1566") {
		t.Error("expected valid technique T1566 to remain")
	}

	// Step 4c: Verify validation notes were stored
	if draft.ValidationNotes == "" {
		t.Error("expected validation notes to be populated")
	}
	if !strings.Contains(draft.ValidationNotes, "TA0099") {
		t.Errorf("expected validation notes to mention TA0099, got: %s", draft.ValidationNotes)
	}

	// Step 5: Approve the draft
	if err := db.UpdateDraftStatus(draft.ID, "approved", ""); err != nil {
		t.Fatalf("failed to approve draft: %v", err)
	}

	// Step 6: Verify approval
	approved := draftsWithStatus(t, db, "approved")
	if len(approved) != 1 {
		t.Fatalf("expected 1 approved draft, got %d", len(approved))
	}

	// Step 7: Verify item is now seen (dedup)
	seen, err := db.HasSeen("test-source:integration-001")
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("expected item to be marked as seen")
	}

	// Step 8: Second poll should return same items but runner deduplicates
	totalLLMCalls := callCount
	callCount = 0
	items2, err := runner.PollAll(ctx)
	if err != nil {
		t.Fatalf("second PollAll failed: %v", err)
	}
	// Runner filters out seen items, so items2 should be empty
	if len(items2) != 0 {
		t.Errorf("expected 0 new items on second poll (dedup), got %d", len(items2))
	}

	fmt.Printf("Integration test passed: %d LLM calls made, 1 draft created and approved\n", totalLLMCalls)
}

func TestIntegrationCrossSourceDedup(t *testing.T) {
	// Mock LLM server — same as main integration test.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody struct {
			Prompt string          `json:"prompt"`
			System string          `json:"system"`
			Format json.RawMessage `json:"format"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		var response string
		if isJSONFormat(reqBody.Format) {
			if strings.Contains(reqBody.System, "fact-checking") || strings.Contains(reqBody.System, "grounding") {
				response = `{"issues": []}`
			} else if strings.Contains(reqBody.System, "Score each item") || strings.Contains(reqBody.System, "threat intelligence analyst evaluating") {
				response = `{"credibility": 4.5, "actionability": 4.0, "novelty": 4.5, "summary": "High-quality advisory"}`
			} else {
				response = `{"tactics": ["Initial Access"], "techniques": ["T1566"], "iocs": [], "cves": ["CVE-2026-5555"], "platforms": ["linux"], "summary": "Test extraction"}`
			}
		} else {
			response = structuredBriefJSON(map[string]any{
				"id": "brief-dedup-test", "slug": "dedup-test-brief", "title": "Dedup Test Brief",
				"summary": "Testing cross-source dedup", "content": "## Overview\nCross-source dedup test.\n", "severity": "high",
				"tags": []any{"test"},
				"rules": []any{map[string]any{
					"title": "Test Rule", "description": "Detects malware.exe",
					"logsource": map[string]any{"category": "process_creation", "product": "windows"},
					"detection": map[string]any{
						"selections": []any{map[string]any{"name": "selection", "fields": []any{map[string]any{"field": "Image", "modifier": "endswith", "values": []any{"\\malware.exe"}}}}},
						"condition":  "selection",
					},
					"level": "high",
					"tags":  []any{"attack.initial_access", "attack.t1566.001"},
				}},
				"ttps": []any{map[string]any{"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing"}},
				"iocs": []any{map[string]any{"type": "domain", "value": "malware-c2.badactor.xyz", "context": "C2 server"}},
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"response": response,
		})
	}))
	defer server.Close()

	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	llmClient := llm.NewOllamaClient(server.URL, "test-model")

	pipe := pipeline.New(pipeline.Config{
		DB:               db,
		LLMClient:        llmClient,
		QualityThreshold: 3.0,
		Logger:           logger,
	})

	ctx := context.Background()

	// Item 1: First report of CVE-2026-5555 from reddit.
	item1 := scraper.RawItem{
		SourceID:    "reddit:dedup-001",
		Source:      "reddit",
		Title:       "New Critical RCE CVE-2026-5555",
		URL:         "https://reddit.com/r/netsec/example",
		Content:     "CVE-2026-5555 is a critical RCE vulnerability in Example Server v3.1. Remote attackers can execute arbitrary code via crafted HTTP requests.",
		PublishedAt: time.Now(),
		Metadata:    map[string]string{"cve": "CVE-2026-5555"},
	}
	if err := pipe.Process(ctx, []scraper.RawItem{item1}); err != nil {
		t.Fatalf("processing item1: %v", err)
	}

	drafts1 := draftsWithStatus(t, db, "pending")
	if len(drafts1) != 1 {
		t.Fatalf("expected 1 draft after item1, got %d", len(drafts1))
	}

	// Item 2: Same CVE from a different source (abuse.ch), no new info → should be skipped.
	item2 := scraper.RawItem{
		SourceID:    "abuse-ch:dedup-001",
		Source:      "abuse-ch",
		Title:       "CVE-2026-5555 vulnerability report",
		URL:         "https://abuse.ch/example",
		Content:     "CVE-2026-5555 has been reported as a remote code execution issue affecting Example Server.",
		PublishedAt: time.Now(),
		Metadata:    map[string]string{"cve": "CVE-2026-5555"},
	}
	if err := pipe.Process(ctx, []scraper.RawItem{item2}); err != nil {
		t.Fatalf("processing item2: %v", err)
	}

	drafts2 := draftsWithStatus(t, db, "pending")
	if len(drafts2) != 1 {
		t.Fatalf("expected still 1 draft after duplicate item2, got %d", len(drafts2))
	}

	// Item 3: Same CVE from CISA with exploit PoC → should be processed as update.
	item3 := scraper.RawItem{
		SourceID:    "cisa-kev:dedup-001",
		Source:      "cisa-kev",
		Title:       "CVE-2026-5555 actively exploited",
		URL:         "https://cisa.gov/kev/CVE-2026-5555",
		Content:     "CVE-2026-5555 proof of concept exploit code has been released. This vulnerability is actively exploited in the wild. CISA has added it to the KEV catalog.",
		PublishedAt: time.Now(),
		Metadata:    map[string]string{"cve": "CVE-2026-5555"},
	}
	if err := pipe.Process(ctx, []scraper.RawItem{item3}); err != nil {
		t.Fatalf("processing item3: %v", err)
	}

	// DedupUpdate now merges into the existing draft rather than creating a
	// new one, so we still have 1 draft — enriched with CISA KEV's reference.
	drafts3 := draftsWithStatus(t, db, "pending")
	if len(drafts3) != 1 {
		t.Fatalf("expected 1 draft after update item3 (merged, not new), got %d", len(drafts3))
	}

	// The merged draft should reference the CISA KEV URL.
	if !strings.Contains(drafts3[0].BriefYAML, "https://cisa.gov/kev/CVE-2026-5555") {
		t.Errorf("expected merged draft to contain CISA KEV reference, got: %s", drafts3[0].BriefYAML)
	}

	// item1 became the draft, item2 was dropped as a duplicate before the
	// quality gate, and item3 cleared the gate and was folded into the draft.
	want := pipeline.DecisionCounts{Processed: 3, PassedQuality: 2, Drafts: 1, Merged: 1}
	if got := pipe.Decisions(time.Hour); got != want {
		t.Errorf("decisions = %+v, want %+v", got, want)
	}

	// Verify all items are marked as seen.
	for _, sid := range []string{"reddit:dedup-001", "abuse-ch:dedup-001", "cisa-kev:dedup-001"} {
		seen, err := db.HasSeen(sid)
		if err != nil {
			t.Fatal(err)
		}
		if !seen {
			t.Errorf("expected %s to be marked as seen", sid)
		}
	}

	fmt.Println("Cross-source dedup integration test passed: 1 enriched draft, 1 plain duplicate skipped, 1 update merged")
}

// Items the pipeline drops must show up in its decision counts as what they
// were: a low-quality item is only processed, while a brief that clears the
// quality gate and is then rejected as ungrounded is counted as both. The
// starvation check relies on that difference.
func TestIntegrationDecisionCountsForRejectedItems(t *testing.T) {
	tests := []struct {
		name    string
		quality string
		want    pipeline.DecisionCounts
	}{
		{
			name:    "fails the quality gate",
			quality: `{"credibility": 1, "actionability": 1, "novelty": 1, "summary": "marketing"}`,
			want:    pipeline.DecisionCounts{Processed: 1},
		},
		{
			name:    "passes the quality gate but the brief is ungrounded",
			quality: `{"credibility": 4.5, "actionability": 4.0, "novelty": 4.5, "summary": "advisory"}`,
			want:    pipeline.DecisionCounts{Processed: 1, PassedQuality: 1, RejectedUngrounded: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var reqBody struct {
					System string          `json:"system"`
					Format json.RawMessage `json:"format"`
				}
				json.NewDecoder(r.Body).Decode(&reqBody)

				var response string
				switch {
				case strings.Contains(reqBody.System, "fact-checking"):
					response = `{"issues": [{"kind": "unsupported_claim", "field": "title", "brief_quote": "Ungrounded Test Brief", "reason": "claim the source never made"}]}`
				case !isJSONFormat(reqBody.Format):
					response = structuredBriefJSON(map[string]any{
						"id": "brief-ungrounded", "slug": "ungrounded-brief", "title": "Ungrounded Test Brief",
						"summary": "A brief the grounding check rejects", "content": "## Overview\nClaims the source never made.\n", "severity": "high",
						"tags": []any{"test"},
						"rules": []any{map[string]any{
							"title": "Test Rule", "description": "Detects malware.exe",
							"logsource": map[string]any{"category": "process_creation", "product": "windows"},
							"detection": map[string]any{
								"selections": []any{map[string]any{"name": "selection", "fields": []any{map[string]any{"field": "Image", "modifier": "endswith", "values": []any{"\\malware.exe"}}}}},
								"condition":  "selection",
							},
							"level": "high",
							"tags":  []any{"attack.initial_access", "attack.t1566.001"},
						}},
					})
				case strings.Contains(reqBody.System, "threat intelligence analyst evaluating"):
					response = tt.quality
				default:
					response = `{"tactics": ["Initial Access"], "techniques": ["T1566"], "iocs": [], "cves": [], "platforms": ["windows"], "summary": "Test extraction"}`
				}
				json.NewEncoder(w).Encode(map[string]interface{}{"response": response})
			}))
			defer server.Close()

			db, err := storage.Open(":memory:")
			if err != nil {
				t.Fatalf("failed to open database: %v", err)
			}
			defer db.Close()

			pipe := pipeline.New(pipeline.Config{
				DB:               db,
				LLMClient:        llm.NewOllamaClient(server.URL, "test-model"),
				QualityThreshold: 3.0,
				Logger:           slog.New(slog.NewTextHandler(os.Stdout, nil)),
			})
			item := scraper.RawItem{
				SourceID:    "test-source:rejected-001",
				Source:      "test-source",
				Title:       "Unverifiable claims about a campaign",
				Content:     "A campaign is reported to abuse phishing emails with malicious attachments, but the report names no victims, tooling or infrastructure.",
				PublishedAt: time.Now(),
			}
			if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
				t.Fatalf("pipeline.Process failed: %v", err)
			}

			if got := pipe.Decisions(time.Hour); got != tt.want {
				t.Errorf("decisions = %+v, want %+v", got, tt.want)
			}
			if drafts := draftsWithStatus(t, db, "pending"); len(drafts) != 0 {
				t.Errorf("expected no draft, got %d", len(drafts))
			}
		})
	}
}

// draftsWithStatus collects the drafts with the given status, newest first.
func draftsWithStatus(t *testing.T, db *storage.DB, status string) []*storage.Draft {
	t.Helper()
	var drafts []*storage.Draft
	for d, err := range db.DraftsWithStatus(status) {
		if err != nil {
			t.Fatalf("listing %s drafts: %v", status, err)
		}
		drafts = append(drafts, d)
	}
	return drafts
}

// isJSONFormat reports whether an Ollama request asks for plain JSON mode. A
// schema-constrained request (brief generation) carries an object instead.
func isJSONFormat(format json.RawMessage) bool { return string(format) == `"json"` }

// structuredBriefJSON is the answer a schema-constrained model gives for a brief:
// the fields of the brief response schema, as JSON.
func structuredBriefJSON(fields map[string]any) string {
	b, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return string(b)
}
