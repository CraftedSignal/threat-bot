package pipeline

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func ghsaItem(id string) scraper.RawItem {
	return scraper.RawItem{
		SourceID: "ghsa:" + id, Source: "ghsa", URL: "https://github.com/advisories/" + id,
		Title:   "Vendor security advisory",
		Content: strings.Repeat("Confirmed vendor notice. ", 30),
		Metadata: map[string]string{
			"affected_packages": "npm/foo | vulnerable: < 1.4.2 | patched: 1.4.2",
			"cvss":              "8.8",
			"cvss_vector":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		SigmaRule: &scraper.SigmaRule{Title: "Rule"},
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The facts the model was told to copy must be part of what the checker and
// the repair step treat as source material.
func TestGroundingSourceIncludesPromptedStructuredFacts(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	var checkPrompts, repairPrompts []string
	client := shutdownStageLLM{
		generate: func(_ context.Context, prompt, system string) (string, error) {
			if strings.HasPrefix(system, "Revise the threat brief") {
				repairPrompts = append(repairPrompts, prompt)
			}
			return validWindowsPathBriefYAML, nil
		},
		generateJSON: func(_ context.Context, prompt, system string, out any) error {
			if system != groundingSystem {
				return fmt.Errorf("unexpected system")
			}
			checkPrompts = append(checkPrompts, prompt)
			r := out.(*GroundingResult)
			r.Grounded = false
			r.Issues = []string{"x"}
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: quietLogger()})
	if err := pipe.Process(context.Background(), []scraper.RawItem{ghsaItem("GHSA-a")}); err != nil {
		t.Fatal(err)
	}
	if len(checkPrompts) == 0 || len(repairPrompts) == 0 {
		t.Fatalf("checks=%d repairs=%d", len(checkPrompts), len(repairPrompts))
	}
	for name, p := range map[string]string{"check": checkPrompts[0], "repair": repairPrompts[0]} {
		for _, want := range []string{"CVSS score: 8.8", "CVSS:3.1/AV:N", "npm/foo | vulnerable: < 1.4.2"} {
			if !strings.Contains(p, want) {
				t.Errorf("%s source missing %q", name, want)
			}
		}
	}
}

func groundingFailThenPass(failFirst int) (shutdownStageLLM, *int) {
	calls := 0
	return shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return validWindowsPathBriefYAML, nil },
		generateJSON: func(_ context.Context, _, _ string, out any) error {
			calls++
			r := out.(*GroundingResult)
			r.Grounded = calls > failFirst
			if !r.Grounded {
				r.Issues = []string{"x"}
			}
			return nil
		},
	}, &calls
}

func TestGroundingAttemptsClearedWhenGroundingSucceeds(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	// First Process: initial check + recheck both fail (attempt 1). Second: passes.
	client, _ := groundingFailThenPass(2)
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: quietLogger()})
	item := ghsaItem("GHSA-b")
	for i := 0; i < 2; i++ {
		if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
			t.Fatal(err)
		}
	}
	if seen, _ := db.HasSeen(item.SourceID); !seen {
		t.Fatal("item should have passed on second run")
	}
	if n, err := db.RecordGroundingAttempt(item.SourceID); err != nil || n != 1 {
		t.Fatalf("attempt after success = %d err=%v, want 1 (counter reset)", n, err)
	}
}

func TestGroundingAttemptsClearedOnReplayAndReseed(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	record := func(id string) {
		t.Helper()
		if _, err := db.RecordGroundingAttempt(id); err != nil {
			t.Fatal(err)
		}
	}
	record("ghsa:replay")
	record("ghsa:replay")
	if err := db.QueueReplay("ghsa", "ghsa:replay", "{}"); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.RecordGroundingAttempt("ghsa:replay"); n != 1 {
		t.Errorf("after QueueReplay attempt = %d, want 1", n)
	}

	record("ghsa:single")
	record("ghsa:single")
	if err := db.MarkSeen("ghsa:single", "ghsa", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReseedSource("ghsa", time.Now().Add(-time.Hour), "ghsa:single"); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.RecordGroundingAttempt("ghsa:single"); n != 1 {
		t.Errorf("after single ReseedSource attempt = %d, want 1", n)
	}

	record("ghsa:bulk")
	record("ghsa:bulk")
	if err := db.MarkSeen("ghsa:bulk", "ghsa", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReseedSource("ghsa", time.Now().Add(-time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.RecordGroundingAttempt("ghsa:bulk"); n != 1 {
		t.Errorf("after bulk ReseedSource attempt = %d, want 1", n)
	}
}

// The pipeline only caps severity downward (severity.go, source_normalize.go)
// or overrides it for rumours; any other LLM label survives to publication, so
// the checker must still see it, with guidance on how to judge it.
func TestGroundingViewKeepsSeverityForChecker(t *testing.T) {
	if v := groundingView("title: t\nseverity: critical\n", ""); !strings.Contains(v, "severity: critical") {
		t.Errorf("severity hidden from checker:\n%s", v)
	}
	if !strings.Contains(groundingSystem, "severity") {
		t.Error("grounding system prompt must explain how to judge the severity label")
	}
}

func TestPipelineGroundingCheckSeesSurvivingLLMSeverity(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	var prompt string
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			return strings.Replace(validWindowsPathBriefYAML, "severity: medium", "severity: critical", 1), nil
		},
		generateJSON: func(_ context.Context, p, _ string, out any) error {
			if prompt == "" {
				prompt = p
			}
			out.(*GroundingResult).Grounded = true
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: quietLogger()})
	item := ghsaItem("GHSA-c")
	item.Metadata["cvss"] = "9.8" // the CVSS band keeps "critical" a surviving label
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "severity: critical") {
		t.Errorf("surviving LLM severity was not checked:\n%s", prompt)
	}
}
