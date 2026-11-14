package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/sigma"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"gopkg.in/yaml.v3"
)

type briefLLMReply struct {
	text string
	err  error
}

type briefScriptedLLM struct {
	replies []briefLLMReply
	prompts []string
	systems []string
}

func (s *briefScriptedLLM) Generate(_ context.Context, prompt, system string) (string, error) {
	s.prompts = append(s.prompts, prompt)
	s.systems = append(s.systems, system)
	if len(s.prompts) > len(s.replies) {
		return "", errors.New("unexpected LLM call")
	}
	reply := s.replies[len(s.prompts)-1]
	return reply.text, reply.err
}

func (s *briefScriptedLLM) GenerateJSON(context.Context, string, string, any) error {
	return errors.New("unexpected GenerateJSON call")
}

const validWindowsPathBriefYAML = `id: brief-2026-10-windows-path
slug: 2026-10-windows-path
title: Windows Path Detection
summary: Detects a Windows binary path.
severity: medium
published_at: "2026-10-19T08:00:00Z"
rules:
  - title: Detect Windows Binary
    detection:
      selection:
        Image|endswith: '\Windows\System32\cmd.exe'
      condition: selection
`

func TestBriefAssemblyMakesOneCall(t *testing.T) {
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: validWindowsPathBriefYAML}}}

	if _, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{
		Title: "Windows Path Detection", Content: "Enough source content for assembly.", Source: "sigma-hq",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(client.prompts) != 1 {
		t.Fatalf("LLM calls = %d, want 1", len(client.prompts))
	}
}

func TestBriefAssemblyAddsDayToMonthOnlyGeneratedID(t *testing.T) {
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: `id: brief-2026-10-rmm-abuse
slug: 2026-10-rmm-abuse
title: RMM Abuse
summary: Detection logic for commonly abused RMM tools.
severity: medium
published_at: "2026-10-01T14:09:00Z"
`}}}

	got, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{
		Title: "RMM Abuse", Content: "Detection logic for commonly abused RMM tools.", Source: "elastic",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		ID          string `yaml:"id"`
		Slug        string `yaml:"slug"`
		PublishedAt string `yaml:"published_at"`
	}
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatal(err)
	}
	published, err := time.Parse(time.RFC3339, parsed.PublishedAt)
	if err != nil {
		t.Fatal(err)
	}
	wantID := "brief-" + published.UTC().Format("2006-01-02") + "-rmm-abuse"
	if parsed.ID != wantID {
		t.Fatalf("id = %q, want %q", parsed.ID, wantID)
	}
	if parsed.Slug != "2026-10-rmm-abuse" {
		t.Fatalf("slug = %q, want stable month-scoped public slug", parsed.Slug)
	}
}

func TestBriefAssembly(t *testing.T) {
	briefYAML := "id: \"brief-2026-02-16-test\"\nslug: \"2026-02-test\"\ntitle: \"Test Threat\"\nsummary: \"A test threat\"\nseverity: \"high\"\npublished_at: \"2026-02-16T10:00:00Z\"\ncontent: |\n  ## Overview\n  A test.\ntags:\n  - test\nrules:\n  - title: \"Detect cmd.exe\"\n    description: \"Detects cmd\"\n    logsource:\n      category: process_creation\n      product: windows\n    detection:\n      selection:\n        CommandLine|contains: assoc\n      condition: selection\n    level: medium\n    tags:\n      - attack.execution\n      - attack.t1059.003\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{"response": wireJSON(t, briefYAML)}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	assembler := NewBriefAssembler(client)

	item := scraper.RawItem{Title: "Test Threat", Content: "A new campaign...", Source: "cisa"}
	extraction := &ExtractionResult{Tactics: []string{"execution"}, Techniques: []string{"T1059.003"}, Summary: "Test threat"}
	sigmaRules := []sigma.Rule{{Title: "Detect cmd.exe", ID: "test-1"}}

	briefContent, err := assembler.Assemble(context.Background(), item, extraction, sigmaRules)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(briefContent), &parsed); err != nil {
		t.Fatalf("not valid YAML: %v", err)
	}
	if parsed["title"] != "Test Threat" {
		t.Errorf("unexpected title: %v", parsed["title"])
	}
}

func TestPipelineQuarantinesMalformedBriefBeforeMarkingSeen(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pipe := &Pipeline{
		db:     db,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	item := scraper.RawItem{SourceID: "broken-1", Source: "feed", Title: "Broken"}
	invalid := &InvalidBriefYAMLError{Err: errors.New("unknown escape"), Raw: `title: "C:\Windows"`}
	if err := pipe.quarantineInvalidBrief(item, invalid); err != nil {
		t.Fatal(err)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("quarantined item was not marked seen")
	}
}

func TestAssemblyPromptAdvertisesEvidenceConfidence(t *testing.T) {
	if !strings.Contains(briefSystemPrompt, "evidence:") {
		t.Error("assembly prompt missing ttp evidence field")
	}
	if !strings.Contains(briefSystemPrompt, "confidence:") {
		t.Error("assembly prompt missing ttp confidence field")
	}
}

func TestBriefPromptRequiresGroundedHuntWhenPortableRuleIsUnavailable(t *testing.T) {
	for _, want := range []string{
		"MUST emit at least one action_plan.hunt_leads entry",
		"product-native telemetry",
		"scheduled-search activity",
		"export or result volume",
		"search count per user",
		"do not invent a fixed threshold",
	} {
		if !strings.Contains(briefSystemPrompt, want) && !strings.Contains(briefPrompt, want) {
			t.Fatalf("brief prompts do not require %q", want)
		}
	}
}

func TestBriefPromptUsesPrimaryAdvisoriesForCVEApplicabilityAndRemediation(t *testing.T) {
	for _, want := range []string{
		"use that primary advisory for product applicability",
		"Preserve the vendor's exact version/build strings",
		"If the primary advisory is unavailable",
		"never add filler to meet a length target",
	} {
		if !strings.Contains(briefSystemPrompt, want) {
			t.Fatalf("brief prompt lacks primary-source requirement %q", want)
		}
	}
}

func TestBriefAssemblySanitizesCopiedUpdateTitle(t *testing.T) {
	briefYAML := "id: \"brief-2026-07-python-rce\"\nslug: \"2026-07-python-rce\"\ntitle: \"[UPDATE] Python: Schwachstelle ermöglicht Codeausführung\"\nsummary: \"A Python vulnerability allows remote code execution.\"\nseverity: \"high\"\npublished_at: \"2026-07-10T10:00:00Z\"\ncontent: |\n  ## Overview\n  test.\n"

	var request map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		resp := map[string]any{"response": wireJSON(t, briefYAML)}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	assembler := NewBriefAssembler(client)
	item := scraper.RawItem{
		Title:   "[UPDATE] Python: Schwachstelle ermöglicht Codeausführung",
		Content: "Ein entfernter Angreifer kann beliebigen Programmcode ausführen.",
		Source:  "bsi",
	}
	extraction := &ExtractionResult{
		AffectedProducts: []string{"Python"},
		Summary:          "A Python vulnerability allows remote code execution.",
		VulnClass:        "remote code execution",
	}

	briefContent, err := assembler.Assemble(context.Background(), item, extraction, nil)
	if err != nil {
		t.Fatal(err)
	}

	prompt, _ := request["prompt"].(string)
	if strings.Contains(prompt, "Title: [UPDATE]") {
		t.Fatalf("prompt preserved update marker:\n%s", prompt)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(briefContent), &parsed); err != nil {
		t.Fatalf("not valid YAML: %v", err)
	}
	if got, want := parsed["title"], "Python Remote Code Execution Vulnerability"; got != want {
		t.Fatalf("title = %q, want %q", got, want)
	}
}

func TestNormalizeBriefTitleStripsUpdateMarkerFromEnglishTitle(t *testing.T) {
	item := scraper.RawItem{Title: "[UPDATE] Apache HTTP Server RCE"}
	got := normalizeBriefTitle("[UPDATE] Apache HTTP Server RCE", item, nil)
	if want := "Apache HTTP Server RCE"; got != want {
		t.Fatalf("title = %q, want %q", got, want)
	}
}

func TestNormalizeBriefTitleMovesLeadingCVEAfterProduct(t *testing.T) {
	item := scraper.RawItem{Title: "CVE-2024-53677: Apache Struts File Upload RCE"}
	extraction := &ExtractionResult{AffectedProducts: []string{"Apache Struts"}, CVEs: []string{"CVE-2024-53677"}}
	got := normalizeBriefTitle(item.Title, item, extraction)
	if want := "Apache Struts: File Upload RCE (CVE-2024-53677)"; got != want {
		t.Fatalf("title = %q, want %q", got, want)
	}
}

func TestNormalizeBriefTitlePreservesBroadCVETitle(t *testing.T) {
	item := scraper.RawItem{Title: "CVE-2026-1111 and CVE-2026-2222 in multiple products"}
	extraction := &ExtractionResult{AffectedProducts: []string{"Product A", "Product B"}}
	if got := normalizeBriefTitle(item.Title, item, extraction); got != item.Title {
		t.Fatalf("broad title changed to %q", got)
	}
}

func TestBriefAssemblyPassesStructuredAdvisoryFacts(t *testing.T) {
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: validWindowsPathBriefYAML}}}
	_, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{
		Title:   "RCE in foo",
		Content: "Advisory body.",
		Source:  "ghsa",
		Metadata: map[string]string{
			"ghsa":              "GHSA-aaaa-bbbb-cccc",
			"affected_packages": "npm/foo | vulnerable: >= 1.0.0, < 1.4.2 | patched: 1.4.2",
			"cvss":              "8.8",
			"cvss_vector":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prompt := client.prompts[0]
	for _, want := range []string{"<structured_advisory_facts>", "npm/foo | vulnerable: >= 1.0.0, < 1.4.2 | patched: 1.4.2", "CVSS score: 8.8", "CVSS:3.1/AV:N"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}

	client = &briefScriptedLLM{replies: []briefLLMReply{{text: validWindowsPathBriefYAML}}}
	if _, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{
		Title: "Blog", Content: "Body.", Source: "rss", Metadata: map[string]string{"cvss": "9.0"},
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(client.prompts[0], "<structured_advisory_facts>") {
		t.Error("non-advisory source must not get structured facts block")
	}
}

func TestBriefAssemblyMakesSingleCVESlugUnique(t *testing.T) {
	reply := `id: brief-2026-11-ibm-api-connect-ssrf
slug: 2026-11-ibm-api-connect-ssrf
title: IBM API Connect SSRF
summary: SSRF in IBM API Connect.
severity: high
published_at: "2026-11-01T14:09:00Z"
`
	var slugs []string
	for _, id := range []string{"CVE-2026-1111", "CVE-2026-2222"} {
		client := &briefScriptedLLM{replies: []briefLLMReply{{text: reply}}}
		got, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{
			SourceID: id, Title: "IBM API Connect SSRF", Content: "Enough content.", Source: "nvd",
		}, &ExtractionResult{CVEs: []string{id}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			ID   string `yaml:"id"`
			Slug string `yaml:"slug"`
		}
		if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatal(err)
		}
		suffix := "-" + strings.ToLower(id)
		if !strings.HasSuffix(parsed.Slug, suffix) || !strings.HasSuffix(parsed.ID, suffix) || !strings.HasPrefix(parsed.Slug, "2026-11-") {
			t.Fatalf("slug=%q id=%q, want month prefix and suffix %q", parsed.Slug, parsed.ID, suffix)
		}
		slugs = append(slugs, parsed.Slug)
	}
	if slugs[0] == slugs[1] {
		t.Fatalf("slugs collide: %v", slugs)
	}
}
