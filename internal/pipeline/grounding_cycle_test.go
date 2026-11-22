package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

func TestGroundingIssueCycleDetectsRecurringFieldAndSubject(t *testing.T) {
	history, repeated := trackGroundingIssueCycle(nil, []string{"affected_products: missing source-supported fact for TeamCity: Versions before 2026.1.4 are affected."})
	if repeated || len(history) != 1 {
		t.Fatalf("first finding should seed history: repeated=%v history=%v", repeated, history)
	}

	next, repeated := trackGroundingIssueCycle(history, []string{"recommendation: missing source-supported fact for TeamCity: The fixed release is unclear."})
	if repeated {
		t.Fatal("a different field should remain eligible for repair")
	}
	if len(next) != 2 {
		t.Fatalf("history length = %d, want 2", len(next))
	}

	_, repeated = trackGroundingIssueCycle(next, []string{"affected_products: missing source-supported fact for TeamCity (>= 2026.1): New version detail."})
	if !repeated {
		t.Fatalf("the same field and product with changed version prose should stop the repair cycle: first=%q second=%q", groundingIssueIdentity("affected_products: missing source-supported fact for TeamCity: Versions before 2026.1.4 are affected."), groundingIssueIdentity("affected_products: missing source-supported fact for TeamCity (>= 2026.1): New version detail."))
	}
}

func TestGroundingIssueHistoryPersistsInCandidateCheckpoint(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: quietLogger()})
	item := scraper.RawItem{SourceID: "grounding-cycle:test", Source: "nvd", Title: "TeamCity advisory"}
	want := []string{"affected_products:teamcity", "recommendation:teamcity"}
	state := processingCandidate{Item: item, GroundingIssueHistory: want}
	key := p.processingInputKey(item)
	if err := p.saveCandidate(key, state, time.Time{}); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || checkpoint == nil {
		t.Fatalf("missing checkpoint: %+v %v", checkpoint, err)
	}
	var restored processingCandidate
	if err := yaml.Unmarshal([]byte(checkpoint.Payload), &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.GroundingIssueHistory) != len(want) {
		t.Fatalf("restored issue history = %v, want %v", restored.GroundingIssueHistory, want)
	}
	for i := range want {
		if restored.GroundingIssueHistory[i] != want[i] {
			t.Fatalf("restored issue history = %v, want %v", restored.GroundingIssueHistory, want)
		}
	}
}

func TestGroundingIssueCycleKeepsDistinctSubjectsAndLegacyEmptyHistory(t *testing.T) {
	next, repeated := trackGroundingIssueCycle(nil, []string{"affected_products: missing source-supported fact for TeamCity: Missing versions."})
	if repeated || len(next) != 1 {
		t.Fatalf("first finding should seed a legacy checkpoint: repeated=%v history=%v", repeated, next)
	}

	next, repeated = trackGroundingIssueCycle(next, []string{"affected_products: missing source-supported fact for YouTrack: Missing versions."})
	if repeated || len(next) != 2 {
		t.Fatalf("a distinct product must remain retryable: repeated=%v history=%v", repeated, next)
	}

	qualified, repeated := trackGroundingIssueCycle(next, []string{"affected_products: missing source-supported fact for YouTrack (Agent): Missing versions."})
	if repeated || len(qualified) != 3 {
		t.Fatalf("a product-name qualifier must remain part of its identity: repeated=%v history=%v", repeated, qualified)
	}
}

func TestGroundingIssueCycleKeepsNumericProductQualifiers(t *testing.T) {
	history, _ := trackGroundingIssueCycle(nil, []string{"affected_products: missing source-supported fact for Exchange: Missing affected version."})
	next, repeated := trackGroundingIssueCycle(history, []string{"affected_products: missing source-supported fact for Exchange (2019): Missing affected version."})
	if repeated || len(next) != 2 {
		t.Fatalf("numeric product qualifier was collapsed into another subject: repeated=%v history=%v", repeated, next)
	}

	_, repeated = trackGroundingIssueCycle(history, []string{"affected_products: missing source-supported fact for Exchange (>= 2019): Missing affected version."})
	if !repeated {
		t.Fatal("explicit version range should normalize to the base product")
	}
}

func TestPipelineQuarantinesWhenGroundingRecheckCycles(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	checks, repairs := 0, 0
	cycle := []string{
		"missing source-supported fact for TeamCity: Affected version scope is incomplete.",
		"missing source-supported fact for JetBrains: Fixed release is unclear.",
		"missing source-supported fact for TeamCity: Affected version scope is incomplete.",
		"missing source-supported fact for JetBrains: Fixed release is unclear.",
	}
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			repairs++
			return validWindowsPathBriefYAML, nil
		},
		generateJSON: func(_ context.Context, _, system string, out any) error {
			if system != groundingSystem {
				t.Fatalf("unexpected JSON stage: %s", system)
			}
			checks++
			result := out.(*GroundingResult)
			result.Issues = []string{cycle[checks-1]}
			return nil
		},
	}
	p := New(Config{DB: db, LLMClient: client, Logger: quietLogger(), RetryBackoff: -time.Second, MaxGroundingAttempts: 5})
	item := scraper.RawItem{SourceID: "grounding-cycle:teamcity", Source: "research", URL: "https://vendor.example/teamcity", Title: "TeamCity security advisory", Content: strings.Repeat("TeamCity security advisory. ", 30), Enriched: true}
	key := p.processingInputKey(item)
	state := processingCandidate{Item: item, BriefYAML: validWindowsPathBriefYAML, Score: 5, Confidence: 1}
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			checkpoint, err := db.GetProcessingCheckpoint(item.SourceID)
			if err != nil || checkpoint == nil {
				reason, quarantined, qerr := db.PipelineQuarantineReason(item.SourceID)
				t.Fatalf("attempt %d lost retry checkpoint: %+v %v checks=%d repairs=%d quarantined=%v reason=%q quarantine_error=%v", attempt, checkpoint, err, checks, repairs, quarantined, reason, qerr)
			}
			if err := yaml.Unmarshal([]byte(checkpoint.Payload), &state); err != nil {
				t.Fatal(err)
			}
		}
		if err := p.processCandidate(context.Background(), key, state); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if checks != 4 || repairs != 3 {
		t.Fatalf("cycle used checks=%d repairs=%d, want 4 and 3", checks, repairs)
	}
	if _, ok, err := db.PipelineQuarantineReason(item.SourceID); err != nil || !ok {
		t.Fatalf("repeated finding was not quarantined: ok=%v err=%v", ok, err)
	}
	if checkpoint, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || checkpoint != nil {
		t.Fatalf("quarantined candidate retained a retry checkpoint: %+v %v", checkpoint, err)
	}
}
