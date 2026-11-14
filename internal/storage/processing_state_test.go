package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestProcessingStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cp := ProcessingCheckpoint{SourceID: "src", InputKey: "v1", Payload: "candidate", RetryAt: time.Now().Add(time.Hour)}
	if err := db.PutProcessingCheckpoint(cp); err != nil {
		t.Fatal(err)
	}
	if err := db.PutBatchJob([]string{"a", "b"}, "remote/job"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.GetProcessingCheckpoint("src")
	if err != nil || got == nil || got.Payload != "candidate" || got.InputKey != "v1" || !got.RetryAt.Equal(cp.RetryAt) {
		t.Fatalf("checkpoint: %+v %v", got, err)
	}
	if job, ok, err := db.GetBatchJob("b"); err != nil || !ok || job != "remote/job" {
		t.Fatalf("job: %q %v %v", job, ok, err)
	}
	if err := db.DeleteBatchJob([]string{"a"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.GetBatchJob("b"); !ok {
		t.Fatal("unrelated batch key lost")
	}
}

func TestPublicationIntentIsAtomicWithDraftUpdate(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	d := &Draft{ID: "draft", Source: "test", Status: StatusApproved, BriefYAML: "old", CreatedAt: time.Now()}
	if err := db.CreateDraft(d); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordDraftUpdateWithPublication("missing", "bad", UpdateEvent{At: time.Now()}, "src", true); err == nil {
		t.Fatal("missing draft accepted")
	}
	intents, err := db.ListPublicationIntents()
	if err != nil || len(intents) != 0 {
		t.Fatalf("orphan intents: %v %v", intents, err)
	}
	if err := db.RecordDraftUpdateWithPublication("draft", "new", UpdateEvent{At: time.Now()}, "src", true); err != nil {
		t.Fatal(err)
	}
	intents, err = db.ListPublicationIntents()
	if err != nil || len(intents) != 1 || intents[0].BriefYAML != "new" {
		t.Fatalf("intent lost: %v %v", intents, err)
	}
	if err := db.DeletePublicationIntent("draft", "old"); err != nil {
		t.Fatal(err)
	}
	intents, _ = db.ListPublicationIntents()
	if len(intents) != 1 {
		t.Fatal("stale ack deleted newer intent")
	}
}

func TestChangedRevisionIsEligibleAndLegacyBaselineDoesNotReplay(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.MarkSeen("old", "test", "title"); err != nil {
		t.Fatal(err)
	}
	if seen, err := db.HasSeenRevision("old", "baseline"); err != nil || !seen {
		t.Fatalf("legacy replay: %v %v", seen, err)
	}
	if seen, err := db.HasSeenRevision("old", "changed"); err != nil || seen {
		t.Fatalf("changed source lost: %v %v", seen, err)
	}
	if err := db.MarkSeenRevision("old", "test", "title", "changed"); err != nil {
		t.Fatal(err)
	}
	if seen, _ := db.HasSeenRevision("old", "changed"); !seen {
		t.Fatal("completed revision not recorded")
	}
}
func TestConcurrentBatchClaimHasOneOwner(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "claim.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() { ok, err := db.ClaimBatchJob([]string{"a", "b"}, "intent"); results <- ok; errs <- err }()
	}
	n := 0
	for range 2 {
		if <-results {
			n++
		}
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n != 1 {
		t.Fatalf("paid work has %d owners", n)
	}
	if ok, err := db.ClaimBatchJob([]string{"c", "b"}, "another"); err != nil || ok {
		t.Fatalf("overlap claimed: %v %v", ok, err)
	}
	if _, ok, _ := db.GetBatchJob("c"); ok {
		t.Fatal("partial claim leaked")
	}
}

func TestBatchReconciliationCASNeverPartiallyOverwrites(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.PutBatchJob([]string{"a"}, "old")
	db.PutBatchJob([]string{"b"}, "newer")
	if ok, err := db.CompareAndSwapBatchJob([]string{"a", "b"}, "old", "replacement"); err != nil || ok {
		t.Fatalf("stale batch owner won: %v %v", ok, err)
	}
	if ref, _, _ := db.GetBatchJob("a"); ref != "old" {
		t.Fatal("partial reconciliation")
	}
	if ok, err := db.CompareAndSwapBatchJob([]string{"a"}, "old", ""); err != nil || !ok {
		t.Fatalf("unsent claim not released: %v %v", ok, err)
	}
	if _, ok, _ := db.GetBatchJob("a"); ok {
		t.Fatal("released claim remains")
	}
}
func TestProcessingSummarySeparatesRetriesFromChangedInputs(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	since := time.Now().Add(-time.Minute)
	for _, event := range []struct{ key, outcome string }{{"v1", "error"}, {"v1", "completed"}, {"v2", "completed"}} {
		if err := db.RecordProcessingEvent("source", event.key, "attempt", "process", event.outcome); err != nil {
			t.Fatal(err)
		}
	}
	s, err := db.ProcessingSummary(since)
	if err != nil {
		t.Fatal(err)
	}
	if s.ProcessPasses != 3 || s.DistinctInputs != 2 || s.RepeatedInputPasses != 1 || s.DistinctSources != 1 || s.ErrorPasses != 1 {
		t.Fatalf("misleading retry accounting: %+v", s)
	}
}
func TestArtifactRetentionPreservesUnresolvedWork(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	db.PutLLMCache("old", "{}")
	db.PutLLMCache("new", "{}")
	if _, err := db.db.Exec("UPDATE llm_cache SET created_at=? WHERE cache_key='old'", now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	db.PutBatchJob([]string{"paid"}, "remote/job")
	db.PutProcessingCheckpoint(ProcessingCheckpoint{SourceID: "pending", InputKey: "key", Payload: "candidate"})
	if err := db.PruneProcessingArtifacts(now); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.GetLLMCache("old"); ok {
		t.Fatal("expired cache retained")
	}
	if _, ok, _ := db.GetLLMCache("new"); !ok {
		t.Fatal("fresh cache removed")
	}
	if _, ok, _ := db.GetBatchJob("paid"); !ok {
		t.Fatal("unresolved paid work deleted")
	}
	if cp, _ := db.GetProcessingCheckpoint("pending"); cp == nil {
		t.Fatal("candidate lost to retention")
	}
}
