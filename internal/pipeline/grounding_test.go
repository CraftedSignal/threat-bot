package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"gopkg.in/yaml.v3"
)

func TestGroundingChecker_Grounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": `{"issues": []}`,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	checker := NewGroundingChecker(client)

	result, err := checker.Check(context.Background(), "Test Title", "Test content about a vulnerability", "title: Test Brief")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Grounded {
		t.Error("expected brief to be grounded")
	}
	if len(result.Issues) > 0 {
		t.Errorf("expected no issues, got: %v", result.Issues)
	}
}

func TestGroundingChecker_NotGrounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": `{"issues": [{"kind":"unsupported_claim","field":"summary","brief_quote":"Fabricated","reason":"CVE-2024-9999 not mentioned in source"},{"kind":"unsupported_claim","field":"title","brief_quote":"title","reason":"Attribution to APT28 not supported by source"}]}`,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	checker := NewGroundingChecker(client)

	result, err := checker.Check(context.Background(), "Test Title", "Some content", "title: Fabricated Brief")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Grounded {
		t.Error("expected brief to NOT be grounded")
	}
	if len(result.Issues) != 2 {
		t.Errorf("expected 2 issues, got %d: %v", len(result.Issues), result.Issues)
	}
}

func TestGroundingChecker_LLMError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	checker := NewGroundingChecker(client)

	_, err := checker.Check(context.Background(), "Title", "Content", "brief yaml")
	if err == nil {
		t.Error("expected error when LLM fails")
	}
}

func TestGroundingChecker_TruncatesLongSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": `{"issues": []}`,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	checker := NewGroundingChecker(client)

	longContent := make([]byte, 20000)
	for i := range longContent {
		longContent[i] = 'a'
	}

	result, err := checker.Check(context.Background(), "Title", string(longContent), "brief yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Grounded {
		t.Error("expected grounded result")
	}
}

func TestGroundingRepairRestoresAttestedEvidenceFromOriginal(t *testing.T) {
	const attributedEvidence = `exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.huntress.com/blog/token-replay-spray
  observed_at: "2026-10-22T12:00:00Z"
  confidence: high
references:
  - https://www.huntress.com/blog/token-replay-spray
`
	original := validWindowsPathBriefYAML + attributedEvidence
	// The model restates only the status; the attribution is the pipeline's.
	repaired := `{"id":"brief-x","slug":"x","title":"Windows Path Detection","summary":"Detects a Windows binary path.","severity":"medium","content":"## Overview\nx","exploitation_evidence":{"status":"confirmed_active"}}`
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: repaired}}}

	got, err := NewGroundingChecker(client).Repair(
		context.Background(), "M365 Token Spray and Replay", "Observed malicious token replay.", original, []string{"unsupported attribution"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBriefContract(got); err != nil {
		t.Fatalf("grounding repair violates the brief contract: %v\n%s", err, got)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	evidence, ok := doc["exploitation_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured exploitation evidence, got %#v", doc["exploitation_evidence"])
	}
	if evidence["status"] != "confirmed_active" || evidence["source_url"] != "https://www.huntress.com/blog/token-replay-spray" {
		t.Fatalf("attribution was not restored from the validated original: %#v", evidence)
	}
	if doc["id"] != "brief-2026-10-windows-path" || doc["published_at"] != "2026-10-19T08:00:00Z" {
		t.Fatalf("identity fields not carried over from the original: id=%v published_at=%v", doc["id"], doc["published_at"])
	}
}

func TestGroundingRepairDowngradesUnattributedConfirmation(t *testing.T) {
	repaired := `{"id":"x","slug":"x","title":"T","summary":"S","severity":"medium","content":"c","exploitation_evidence":{"status":"confirmed_active"}}`
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: repaired}}}
	got, err := NewGroundingChecker(client).Repair(context.Background(), "t", "c", validWindowsPathBriefYAML, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	evidence, _ := doc["exploitation_evidence"].(map[string]any)
	if evidence["status"] != "unknown" {
		t.Fatalf("confirmed_active without a source was kept: %#v", doc["exploitation_evidence"])
	}
}

func TestGroundingRepairNormalizesPartialObservedAt(t *testing.T) {
	for raw, want := range map[string]string{
		"2026-10":              "2026-10-01T00:00:00Z",
		"2025":                 "2025-01-01T00:00:00Z",
		"2026-11-08":           "2026-11-08T00:00:00Z",
		"2026-11-08T09:30:00Z": "2026-11-08T09:30:00Z",
	} {
		repaired := `{"id":"x","slug":"x","title":"T","summary":"S","severity":"medium","content":"c","exploitation_evidence":{"status":"confirmed_active","source_url":"https://example.com/a","observed_at":"` + raw + `","confidence":"high"}}`
		client := &briefScriptedLLM{replies: []briefLLMReply{{text: repaired}}}
		got, err := NewGroundingChecker(client).Repair(context.Background(), "t", "c", validWindowsPathBriefYAML, []string{"x"})
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		cleaned, _, err := NewBriefValidator().Validate(got)
		if err != nil {
			t.Fatalf("observed_at %q rejected by validation: %v", raw, err)
		}
		var doc struct {
			Evidence struct {
				ObservedAt string `yaml:"observed_at"`
			} `yaml:"exploitation_evidence"`
		}
		if err := yaml.Unmarshal([]byte(cleaned), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Evidence.ObservedAt != want {
			t.Errorf("observed_at %q -> %q, want %q", raw, doc.Evidence.ObservedAt, want)
		}
	}
}

func TestGroundingRepairDropsClaimsTheModelDeleted(t *testing.T) {
	original := validWindowsPathBriefYAML + "threat_actor: APT29\nhas_poc: true\n"
	repaired := `{"id":"x","slug":"x","title":"T","summary":"S","severity":"medium","content":"c"}`
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: repaired}}}
	got, err := NewGroundingChecker(client).Repair(context.Background(), "t", "c", original, []string{"unsupported attribution"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["threat_actor"]; ok {
		t.Fatalf("deleted threat_actor came back: %s", got)
	}
	if _, ok := doc["rules"]; ok {
		t.Fatalf("deleted rules came back: %s", got)
	}
	if doc["has_poc"] != true {
		t.Fatalf("pipeline-owned has_poc was not preserved: %s", got)
	}
}

func TestGroundingRepairClassifiesTruncation(t *testing.T) {
	cut := briefLLMReply{err: &llm.FinishReasonError{Reason: "MAX_TOKENS", Text: `{"id":"x","summ`}}
	client := &briefScriptedLLM{replies: []briefLLMReply{cut, cut}}
	_, err := NewGroundingChecker(client).Repair(context.Background(), "t", "c", validWindowsPathBriefYAML, []string{"x"})
	var finish *llm.FinishReasonError
	var invalid *InvalidBriefYAMLError
	if !errors.As(err, &finish) || !finish.Truncated() || !errors.As(err, &invalid) || invalid.Raw != `{"id":"x","summ` {
		t.Fatalf("err = %#v, want InvalidBriefYAMLError wrapping a truncated FinishReasonError", err)
	}
}

func TestGroundingRepairSystemPromptCarriesSigmaGuidance(t *testing.T) {
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: `{"id":"x","slug":"x","title":"T","summary":"S","severity":"medium","content":"c"}`}}}
	if _, err := NewGroundingChecker(client).Repair(context.Background(), "t", "c", validWindowsPathBriefYAML, []string{"x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(client.systems[0], sigmaStructureGuidance) || !strings.Contains(briefSystemPrompt, sigmaStructureGuidance) {
		t.Errorf("repair and assembly prompts must share the SIGMA STRUCTURE guidance: %q", client.systems[0])
	}
}

func TestGroundingRepairCVERetentionUsesExactIDs(t *testing.T) {
	original := "id: brief-2026-10-cve-2026-1234\nslug: 2026-10-cve-2026-1234\ntitle: T\nsummary: S\nseverity: medium\npublished_at: \"2026-10-19T08:00:00Z\"\ncves:\n  - id: CVE-2026-1234\n  - id: CVE-2026-5555\n"
	// CVE-2026-1234 is only a prefix of the CVE-2026-12345 the revision
	// mentions, and CVE-2026-5555 survives only inside the echoed id and slug.
	repaired := `{"id":"brief-2026-10-cve-2026-5555","slug":"2026-10-cve-2026-5555","title":"T","summary":"S","severity":"medium","content":"Affects CVE-2026-12345 only."}`
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: repaired}}}
	got, err := NewGroundingChecker(client).Repair(context.Background(), "t", "c", original, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	if cves, ok := doc["cves"]; ok {
		t.Fatalf("cves kept without an exact mention: %#v", cves)
	}

	keep := `{"id":"x","slug":"x","title":"T","summary":"S","severity":"medium","content":"Fixes cve-2026-1234 now."}`
	client = &briefScriptedLLM{replies: []briefLLMReply{{text: keep}}}
	got, err = NewGroundingChecker(client).Repair(context.Background(), "t", "c", original, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	doc = nil
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	if list, _ := doc["cves"].([]any); len(list) != 1 {
		t.Fatalf("exactly mentioned CVE must be kept alone: %#v", doc["cves"])
	}
}

// scriptedGroundingLLM answers the structured grounding check with a fixed report.
type scriptedGroundingLLM struct {
	noopLLM
	report groundingReport
}

func (s scriptedGroundingLLM) GenerateStructured(_ context.Context, _, _ string, _ *llm.Schema, out any) error {
	*out.(*groundingReport) = s.report
	return nil
}

func checkWithReport(t *testing.T, logs *bytes.Buffer, brief string, issues ...groundingIssue) *GroundingResult {
	t.Helper()
	checker := NewGroundingChecker(scriptedGroundingLLM{report: groundingReport{Issues: issues}}).
		WithLogger(slog.New(slog.NewTextHandler(logs, nil)))
	result, err := checker.Check(context.Background(), "T", "source", brief)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestGroundingCheckOmissionIsGrounded(t *testing.T) {
	var logs bytes.Buffer
	res := checkWithReport(t, &logs, "summary: Synology flaw\n",
		groundingIssue{Kind: "omission", Field: "affected_products", Reason: "failed to include version ranges"})
	if !res.Grounded || len(res.Issues) != 0 {
		t.Fatalf("omission must not unground: %+v", res)
	}
	if !strings.Contains(logs.String(), "grounding issue dropped") || !strings.Contains(logs.String(), "kind=omission") {
		t.Errorf("drop not logged: %s", logs.String())
	}
}

func TestGroundingCheckQuotedUnsupportedClaimIsUngrounded(t *testing.T) {
	var logs bytes.Buffer
	res := checkWithReport(t, &logs, "summary: APT29  used\n  the flaw\n",
		groundingIssue{Kind: "unsupported_claim", Field: "summary", BriefQuote: "apt29 used the FLAW", Reason: "no attribution in source"})
	if res.Grounded || len(res.Issues) != 1 || res.Issues[0] != "summary: no attribution in source (apt29 used the FLAW)" {
		t.Fatalf("got %+v", res)
	}
	if strings.Contains(logs.String(), "dropped") {
		t.Errorf("kept issue must not be logged as dropped: %s", logs.String())
	}
}

// The checker sometimes quotes the source instead of the brief (prod,
// 2026-11-12: an OpenSSH brief claiming root access). The claim is still
// unsupported, so a quote that does not match must never let it through.
func TestGroundingCheckUnsupportedClaimWithUnmatchedQuoteIsKept(t *testing.T) {
	var logs bytes.Buffer
	res := checkWithReport(t, &logs, "summary: grants root access\n",
		groundingIssue{Kind: "unsupported_claim", Field: "summary", BriefQuote: "text quoted from the source instead", Reason: "source does not say root"})
	if res.Grounded || len(res.Issues) != 1 || res.Issues[0] != "summary: source does not say root" {
		t.Fatalf("got %+v", res)
	}
	if strings.Contains(logs.String(), "dropped") {
		t.Errorf("unsupported claim must not be dropped: %s", logs.String())
	}
}

func TestGroundingSourceExcludesInstruction(t *testing.T) {
	item := ghsaItem("GHSA-x")
	src := groundingSource(item)
	if strings.Contains(src, "Copy") || strings.Contains(src, "authoritative") {
		t.Errorf("instruction leaked into grounding source: %s", src)
	}
	if !strings.Contains(src, "npm/foo | vulnerable: < 1.4.2") {
		t.Errorf("data missing: %s", src)
	}
	if !strings.Contains(structuredAdvisoryFacts(item), "Copy package names") {
		t.Error("generation facts must keep the instruction")
	}
}
