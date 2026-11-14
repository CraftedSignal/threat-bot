package storage

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckpointLookupReturnsStoredInputKeyBySource(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "checkpoint.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Storage retrieves saved work; policy/evidence compatibility belongs to
	// the pipeline that understands the stored keys.
	retry := time.Date(2026, 11, 14, 12, 30, 0, 123, time.UTC)
	for _, cp := range []ProcessingCheckpoint{
		{SourceID: "src", InputKey: "old-input-policy", Payload: "saved-candidate", RetryAt: retry},
		{SourceID: "other", InputKey: "other-input", Payload: "other-candidate"},
	} {
		if err := db.PutProcessingCheckpoint(cp); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.GetProcessingCheckpoint("src")
	if err != nil || got == nil || got.SourceID != "src" || got.InputKey != "old-input-policy" || got.Payload != "saved-candidate" || !got.RetryAt.Equal(retry) {
		t.Fatalf("stored checkpoint metadata lost: %+v %v", got, err)
	}
	if got, err := db.GetProcessingCheckpoint("missing"); err != nil || got != nil {
		t.Fatalf("missing source lookup: %+v %v", got, err)
	}
	if err := db.PutProcessingCheckpoint(ProcessingCheckpoint{SourceID: "src", InputKey: "new-input-policy", Payload: "replacement", RetryAt: retry}); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetProcessingCheckpoint("src")
	if err != nil || got == nil || got.InputKey != "new-input-policy" || got.Payload != "replacement" {
		t.Fatalf("source lookup did not return current checkpoint: %+v %v", got, err)
	}
	other, err := db.GetProcessingCheckpoint("other")
	if err != nil || other == nil || other.InputKey != "other-input" {
		t.Fatalf("checkpoint replacement affected another source: %+v %v", other, err)
	}
}

func TestTerminalCheckpointCleanupFailureRollsBackSeenState(t *testing.T) {
	for _, revised := range []bool{false, true} {
		t.Run(map[bool]string{false: "first completion", true: "changed revision"}[revised], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint.db")
			db, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { db.Close() }()
			if revised {
				if err := db.MarkSeenRevision("src", "feed", "old title", "old-revision", "old-evidence"); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.PutProcessingCheckpoint(ProcessingCheckpoint{SourceID: "src", InputKey: "new-input", Payload: "candidate"}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.db.Exec(`CREATE TRIGGER fail_checkpoint_cleanup AFTER DELETE ON processing_checkpoints BEGIN SELECT RAISE(FAIL,'checkpoint cleanup unavailable'); END`); err != nil {
				t.Fatal(err)
			}
			err = db.MarkSeenRevision("src", "feed", "new title", "new-revision", "new-evidence")
			if err == nil || !strings.Contains(err.Error(), "checkpoint cleanup unavailable") {
				t.Fatalf("terminal completion ignored failed checkpoint cleanup: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if seen, err := db.HasSeenRevision("src", "new-revision"); err != nil || seen {
				t.Fatalf("failed completion consumed revision: seen=%v err=%v", seen, err)
			}
			if seen, err := db.SeenEvidenceMatches("src", "new-evidence"); err != nil || seen {
				t.Fatalf("failed completion consumed evidence: seen=%v err=%v", seen, err)
			}
			if revised {
				if seen, err := db.HasSeenRevision("src", "old-revision"); err != nil || !seen {
					t.Fatalf("rollback lost prior seen revision: %v %v", seen, err)
				}
				if seen, err := db.SeenEvidenceMatches("src", "old-evidence"); err != nil || !seen {
					t.Fatalf("rollback lost prior seen evidence: %v %v", seen, err)
				}
			} else if seen, err := db.HasSeen("src"); err != nil || seen {
				t.Fatalf("rollback retained newly inserted seen row: %v %v", seen, err)
			}
			cp, err := db.GetProcessingCheckpoint("src")
			if err != nil || cp == nil || cp.Payload != "candidate" || cp.InputKey != "new-input" {
				t.Fatalf("failed completion lost saved candidate: %+v %v", cp, err)
			}
			if _, err := db.db.Exec("DROP TRIGGER fail_checkpoint_cleanup"); err != nil {
				t.Fatal(err)
			}
			if err := db.MarkSeenRevision("src", "feed", "new title", "new-revision", "new-evidence"); err != nil {
				t.Fatal(err)
			}
			if cp, err := db.GetProcessingCheckpoint("src"); err != nil || cp != nil {
				t.Fatalf("successful retry retained candidate: %+v %v", cp, err)
			}
			if seen, err := db.HasSeenRevision("src", "new-revision"); err != nil || !seen {
				t.Fatalf("successful retry lost terminal revision: %v %v", seen, err)
			}
		})
	}
}

func TestTerminalCheckpointCleanupPreservesOtherDurableWork(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "checkpoint.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, id := range []string{"src", "other"} {
		if err := db.PutProcessingCheckpoint(ProcessingCheckpoint{SourceID: id, InputKey: "input", Payload: "candidate"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RecordProcessingEvent("src", "input", "attempt", "grounding", "accepted"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordGroundingAttempt("src"); err != nil {
		t.Fatal(err)
	}
	if err := db.PutBatchJob([]string{"paid"}, "remote/job"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateDraftWithPublication(&Draft{ID: "draft", Status: StatusPending, BriefYAML: "saved publication", CreatedAt: time.Now()}, "claim"); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSeenRevision("src", "feed", "title", "revision", "evidence"); err != nil {
		t.Fatal(err)
	}
	if cp, err := db.GetProcessingCheckpoint("src"); err != nil || cp != nil {
		t.Fatalf("completed checkpoint retained: %+v %v", cp, err)
	}
	if cp, err := db.GetProcessingCheckpoint("other"); err != nil || cp == nil {
		t.Fatalf("unrelated checkpoint deleted: %+v %v", cp, err)
	}
	if seen, err := db.HasSeenRevision("src", "revision"); err != nil || !seen {
		t.Fatalf("completion revision lost: %v %v", seen, err)
	}
	if seen, err := db.SeenEvidenceMatches("src", "evidence"); err != nil || !seen {
		t.Fatalf("completion evidence lost: %v %v", seen, err)
	}
	var events int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM processing_history WHERE source_id='src'").Scan(&events); err != nil || events != 1 {
		t.Fatalf("completion erased processing history: %d %v", events, err)
	}
	if attempts, err := db.RecordGroundingAttempt("src"); err != nil || attempts != 2 {
		t.Fatalf("completion changed grounding counters: %d %v", attempts, err)
	}
	if job, ok, err := db.GetBatchJob("paid"); err != nil || !ok || job != "remote/job" {
		t.Fatalf("completion lost pending paid job: %q %v %v", job, ok, err)
	}
	if intents, err := db.ListPublicationIntents(); err != nil || len(intents) != 1 || intents[0].BriefYAML != "saved publication" {
		t.Fatalf("completion lost publication recovery: %+v %v", intents, err)
	}
}
