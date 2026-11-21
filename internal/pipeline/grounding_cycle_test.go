package pipeline

import (
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
