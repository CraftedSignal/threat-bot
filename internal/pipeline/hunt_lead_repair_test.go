package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

const ttpsOnlyBriefYAML = `id: brief-2026-10-ttps
slug: 2026-10-ttps
title: Loader abuses scheduled tasks
summary: A loader persists through scheduled tasks.
content: The loader creates a scheduled task named Updater for persistence.
severity: medium
published_at: "2026-10-19T08:00:00Z"
ttps:
  - technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: The loader creates a scheduled task named Updater.
`

func huntLeadRepairPipeline(t *testing.T, calls *int, reply func(out any) error) *Pipeline {
	t.Helper()
	db := mustOpenTestDB(t)
	t.Cleanup(func() { db.Close() })
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return "", errors.New("unexpected Generate") },
		generateJSON: func(_ context.Context, _, system string, out any) error {
			*calls++
			if system != huntLeadRepairSystem {
				return fmt.Errorf("unexpected JSON system: %s", system)
			}
			return reply(out)
		},
	}
	return New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func TestRepairMissingHuntLeadAddsLeadCoveringTTPs(t *testing.T) {
	calls := 0
	p := huntLeadRepairPipeline(t, &calls, func(out any) error {
		r := out.(*huntLeadRepairResult)
		r.HuntLeads = []huntLeadSuggestion{{
			Lead: "Scheduled tasks named Updater created by non-admin processes", TechniqueID: "T1053",
			DataNeeded: []string{"Windows Security 4698 task creation events"}, Priority: "medium", Confidence: "medium",
			Disposition: "hunt_now", Evidence: "The loader creates a scheduled task named Updater.",
		}}
		return nil
	})
	if issues := ValidatePublicationConsistency(ttpsOnlyBriefYAML); len(issues) == 0 {
		t.Fatal("fixture should start with a TTP coverage issue")
	}
	got, repaired := p.repairMissingHuntLead(context.Background(), scraper.RawItem{Title: "Loader", Content: "The loader creates a scheduled task named Updater."}, ttpsOnlyBriefYAML)
	if !repaired || calls != 1 {
		t.Fatalf("repaired=%v calls=%d, want one successful attempt", repaired, calls)
	}
	if !strings.Contains(got, "Scheduled tasks named Updater") {
		t.Fatalf("hunt lead missing from brief:\n%s", got)
	}
	if issues := ValidatePublicationConsistency(got); len(issues) != 0 {
		t.Fatalf("repaired brief still has issues: %v", issues)
	}
}

func TestRepairMissingHuntLeadSkipsBriefsThatNeedNone(t *testing.T) {
	calls := 0
	p := huntLeadRepairPipeline(t, &calls, func(any) error { return nil })
	got, repaired := p.repairMissingHuntLead(context.Background(), scraper.RawItem{}, validWindowsPathBriefYAML)
	if repaired || calls != 0 || got != validWindowsPathBriefYAML {
		t.Fatalf("repaired=%v calls=%d; a brief with rules must not trigger the LLM", repaired, calls)
	}
}

func TestRepairMissingHuntLeadIsOneAttemptAndLeavesBriefOnFailure(t *testing.T) {
	for name, reply := range map[string]func(any) error{
		"llm error":    func(any) error { return errors.New("boom") },
		"empty answer": func(any) error { return nil },
		"lead no cover": func(out any) error {
			out.(*huntLeadRepairResult).HuntLeads = []huntLeadSuggestion{{Lead: "x", TechniqueID: "T9999"}}
			return nil
		},
	} {
		calls := 0
		p := huntLeadRepairPipeline(t, &calls, reply)
		got, repaired := p.repairMissingHuntLead(context.Background(), scraper.RawItem{}, ttpsOnlyBriefYAML)
		if repaired || calls != 1 || got != ttpsOnlyBriefYAML {
			t.Errorf("%s: repaired=%v calls=%d, want exactly one attempt and the brief unchanged", name, repaired, calls)
		}
	}
}
