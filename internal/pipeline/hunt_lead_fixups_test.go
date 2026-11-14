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

func groundedHuntLeadPipeline(t *testing.T, grounded bool, groundingErr error, groundingCalls *int) *Pipeline {
	t.Helper()
	db := mustOpenTestDB(t)
	t.Cleanup(func() { db.Close() })
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return "", errors.New("unexpected Generate") },
		generateJSON: func(_ context.Context, prompt, system string, out any) error {
			switch system {
			case huntLeadRepairSystem:
				out.(*huntLeadRepairResult).HuntLeads = []huntLeadSuggestion{{
					Lead: "Scheduled tasks named Updater", TechniqueID: "T1053",
					DataNeeded: []string{"Task creation events"}, Evidence: "The loader creates a scheduled task named Updater.",
				}}
				return nil
			case groundingSystem:
				*groundingCalls++
				if !strings.Contains(prompt, "Scheduled tasks named Updater") {
					return fmt.Errorf("grounding was not run on the repaired brief")
				}
				if groundingErr != nil {
					return groundingErr
				}
				res := out.(*GroundingResult)
				res.Grounded = grounded
				if !grounded {
					res.Issues = []string{"hunt lead invents telemetry"}
				}
				return nil
			}
			return fmt.Errorf("unexpected JSON system: %s", system)
		},
	}
	return New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func TestHuntLeadRepairIsGroundedBeforeItClearsReview(t *testing.T) {
	item := scraper.RawItem{Title: "Loader", URL: "https://example.com/a", Content: "The loader creates a scheduled task named Updater."}

	calls := 0
	p := groundedHuntLeadPipeline(t, true, nil, &calls)
	got, ok := p.repairMissingHuntLeadGrounded(context.Background(), item, ttpsOnlyBriefYAML)
	if !ok || calls != 1 || len(ValidatePublicationConsistency(got)) != 0 {
		t.Fatalf("grounded repair: ok=%v calls=%d issues=%v", ok, calls, ValidatePublicationConsistency(got))
	}

	calls = 0
	p = groundedHuntLeadPipeline(t, false, nil, &calls)
	got, ok = p.repairMissingHuntLeadGrounded(context.Background(), item, ttpsOnlyBriefYAML)
	if ok || calls != 1 || got != ttpsOnlyBriefYAML {
		t.Fatalf("ungrounded repair: ok=%v calls=%d changed=%v; the brief must stay as it was and held", ok, calls, got != ttpsOnlyBriefYAML)
	}
	if len(ValidatePublicationConsistency(got)) == 0 {
		t.Fatal("an ungrounded repair cleared the review issue")
	}

	calls = 0
	p = groundedHuntLeadPipeline(t, true, errors.New("model down"), &calls)
	if got, ok = p.repairMissingHuntLeadGrounded(context.Background(), item, ttpsOnlyBriefYAML); ok || got != ttpsOnlyBriefYAML {
		t.Fatal("a failed grounding check must leave the brief held")
	}
}

func TestHuntLeadRepairGroundsOnlyTheAddedLeads(t *testing.T) {
	item := scraper.RawItem{Title: "Loader", URL: "https://example.com/a", Content: "The loader creates a scheduled task named Updater."}
	brief := ttpsOnlyBriefYAML + "pipeline_added_field: Deterministic enrichment text absent from the source.\n"

	db := mustOpenTestDB(t)
	t.Cleanup(func() { db.Close() })
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return "", errors.New("unexpected Generate") },
		generateJSON: func(_ context.Context, prompt, system string, out any) error {
			switch system {
			case huntLeadRepairSystem:
				out.(*huntLeadRepairResult).HuntLeads = []huntLeadSuggestion{{
					Lead: "Scheduled tasks named Updater", TechniqueID: "T1053",
					DataNeeded: []string{"Task creation events"}, Evidence: "The loader creates a scheduled task named Updater.",
				}}
				return nil
			case groundingSystem:
				// A whole-brief check would see the pipeline-added field and fail.
				out.(*GroundingResult).Grounded = !strings.Contains(prompt, "Deterministic enrichment text")
				return nil
			}
			return fmt.Errorf("unexpected JSON system: %s", system)
		},
	}
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	got, ok := p.repairMissingHuntLeadGrounded(context.Background(), item, brief)
	if !ok || !strings.Contains(got, "Scheduled tasks named Updater") {
		t.Fatalf("ok=%v; grounding must only cover the added hunt leads", ok)
	}
}
