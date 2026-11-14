package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

func TestPipelineRepairsUngroundedBriefBeforeSaving(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	groundingCalls, generationCalls := 0, 0
	var logs bytes.Buffer
	groundedBrief := strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1)
	repairedBrief := strings.Replace(groundedBrief, "published_at: \"2026-10-19T08:00:00Z\"\n", "", 1)
	brief := groundedBrief + "\nthreat_actor: APT29\n"
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			generationCalls++
			if generationCalls == 1 {
				return brief, nil
			}
			return repairedBrief, nil
		},
		generateJSON: func(_ context.Context, prompt, system string, out any) error {
			if system != groundingSystem {
				return fmt.Errorf("unexpected JSON system: %s", system)
			}
			groundingCalls++
			result := out.(*GroundingResult)
			result.Grounded = !strings.Contains(prompt, "threat_actor: APT29")
			if !result.Grounded {
				result.Issues = []string{"unsupported attack chain"}
			}
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	item := scraper.RawItem{SourceID: "kev:repair", Source: "cisa-kev", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", Title: "APT29 credential theft advisory", Content: strings.Repeat("APT29 credential theft was confirmed. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !seen || pipe.Decisions(time.Hour).Drafts != 1 || groundingCalls != 2 || generationCalls != 2 {
		t.Fatalf("seen=%v drafts=%d grounding=%d generation=%d logs=%s", seen, pipe.Decisions(time.Hour).Drafts, groundingCalls, generationCalls, logs.String())
	}
	for draft, err := range db.DraftsWithStatus(storage.StatusPending) {
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(draft.BriefYAML), &doc); err != nil {
			t.Fatal(err)
		}
		if _, err := time.Parse(time.RFC3339, fmt.Sprint(doc["published_at"])); err != nil {
			t.Fatalf("grounding repair dropped publication date: %v", err)
		}
	}
}

func TestPipelineAcceptsGroundingRepairWithYAMLHazardsInText(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	groundingCalls, generationCalls := 0, 0
	var logs bytes.Buffer
	groundedBrief := strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1)
	ungroundedBrief := groundedBrief + "\nthreat_actor: APT29\n"
	// A bare "CVE-...: ..." title is a YAML syntax error when the model
	// writes YAML by hand; in a schema-constrained answer it is just text.
	hazardRepair := strings.Replace(groundedBrief, "title: Windows Path Detection", "title: 'CVE-2025-55702: Windows Path Detection'", 1)
	client := shutdownStageLLM{
		generate: func(_ context.Context, prompt, system string) (string, error) {
			generationCalls++
			switch generationCalls {
			case 1:
				return ungroundedBrief, nil
			case 2:
				return hazardRepair, nil
			default:
				return "", fmt.Errorf("unexpected generation call %d", generationCalls)
			}
		},
		generateJSON: func(_ context.Context, prompt, system string, out any) error {
			if system != groundingSystem {
				return fmt.Errorf("unexpected JSON system: %s", system)
			}
			groundingCalls++
			result := out.(*GroundingResult)
			result.Grounded = !strings.Contains(prompt, "threat_actor: APT29")
			if !result.Grounded {
				result.Issues = []string{"unsupported attribution"}
			}
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	item := scraper.RawItem{SourceID: "nvd:CVE-2025-55702", Source: "cisa-kev", URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-55702", Title: "CVE-2025-55702 advisory", Content: strings.Repeat("The vendor confirms the vulnerability. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !seen || pipe.Decisions(time.Hour).Drafts != 1 || groundingCalls != 2 || generationCalls != 2 {
		t.Fatalf("seen=%v drafts=%d grounding=%d generation=%d logs=%s", seen, pipe.Decisions(time.Hour).Drafts, groundingCalls, generationCalls, logs.String())
	}
	if strings.Contains(logs.String(), "pipeline error") || strings.Contains(logs.String(), "quarantined malformed brief") {
		t.Fatalf("grounding repair was not accepted: %s", logs.String())
	}
}

func TestPipelineQuarantinesInvalidGroundingRepair(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	var logs bytes.Buffer
	brief := validWindowsPathBriefYAML + "\nthreat_actor: APT29\n"
	// A repair whose title is an object instead of a string cannot be decoded
	// into the brief schema.
	repaired := `{"id":"brief-2026-10-windows-path","slug":"2026-10-windows-path","title":{"nested":"map"}}`
	generationCalls := 0
	client := shutdownStageLLM{
		generate: func(_ context.Context, _, _ string) (string, error) {
			generationCalls++
			if generationCalls > 1 {
				return repaired, nil
			}
			return brief, nil
		},
		generateJSON: func(_ context.Context, prompt, system string, out any) error {
			if system != groundingSystem {
				return fmt.Errorf("unexpected JSON system: %s", system)
			}
			result := out.(*GroundingResult)
			result.Grounded = false
			result.Issues = []string{"unsupported attribution"}
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	item := scraper.RawItem{SourceID: "kev:invalid-repair", Source: "cisa-kev", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", Title: "APT29 advisory", Content: strings.Repeat("APT29 advisory. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !seen || pipe.Decisions(time.Hour).Drafts != 0 {
		t.Fatalf("seen=%v drafts=%d logs=%s", seen, pipe.Decisions(time.Hour).Drafts, logs.String())
	}
	if !strings.Contains(logs.String(), "quarantined malformed brief") || strings.Contains(logs.String(), "pipeline error") {
		t.Fatalf("repair failure was not isolated: %s", logs.String())
	}
}

func TestPipelineRetainsUngroundedItemForRetry(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	groundingCalls := 0
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return validWindowsPathBriefYAML, nil },
		generateJSON: func(_ context.Context, _, system string, out any) error {
			if system != groundingSystem {
				return fmt.Errorf("unexpected JSON system: %s", system)
			}
			groundingCalls++
			result := out.(*GroundingResult)
			result.Grounded = false
			result.Issues = []string{"unsupported attack chain"}
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{SourceID: "kev:retry", Source: "cisa-kev", Title: "Vendor security advisory", Content: strings.Repeat("Confirmed vendor notice. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if seen || pipe.Decisions(time.Hour).Drafts != 0 || groundingCalls != 2 {
		t.Fatalf("seen=%v drafts=%d grounding=%d", seen, pipe.Decisions(time.Hour).Drafts, groundingCalls)
	}
}

func TestPipelineGroundingCheckExcludesPipelineOwnedFields(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	var checked []string
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return validWindowsPathBriefYAML, nil },
		generateJSON: func(_ context.Context, prompt, system string, out any) error {
			if system != groundingSystem {
				return fmt.Errorf("unexpected JSON system: %s", system)
			}
			checked = append(checked, prompt)
			out.(*GroundingResult).Grounded = true
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{SourceID: "kev:scope", Source: "cisa-kev", URL: "https://example.test/own-item-url", Title: "Vendor security advisory", Content: strings.Repeat("Confirmed vendor notice. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if len(checked) == 0 {
		t.Fatal("grounding never ran")
	}
	brief := checked[0][strings.Index(checked[0], "## Generated Brief"):]
	if strings.Contains(brief, "own-item-url") {
		t.Errorf("checker saw pipeline-owned fields:\n%s", brief)
	}
}

func TestPipelineQuarantinesAfterMaxGroundingAttempts(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return validWindowsPathBriefYAML, nil },
		generateJSON: func(_ context.Context, _, _ string, out any) error {
			r := out.(*GroundingResult)
			r.Grounded = false
			r.Issues = []string{"unsupported attack chain"}
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, MaxGroundingAttempts: 3, RetryBackoff: -time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{SourceID: "kev:cap", Source: "cisa-kev", Title: "Vendor security advisory", Content: strings.Repeat("Confirmed vendor notice. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	for attempt := 1; attempt <= 3; attempt++ {
		if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
			t.Fatal(err)
		}
		seen, err := db.HasSeen(item.SourceID)
		if err != nil {
			t.Fatal(err)
		}
		if want := attempt == 3; seen != want {
			t.Fatalf("attempt %d: seen=%v want %v", attempt, seen, want)
		}
	}
	reason, ok, err := db.PipelineQuarantineReason(item.SourceID)
	if err != nil || !ok {
		t.Fatalf("not quarantined: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(reason, "ungrounded after 3 attempts") {
		t.Errorf("reason = %q", reason)
	}
}
