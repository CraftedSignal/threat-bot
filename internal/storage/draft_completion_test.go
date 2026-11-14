package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func completionResult(id string) DraftProcessingResult {
	return DraftProcessingResult{
		Draft:    &Draft{ID: id, Status: StatusPending, Source: "feed", SourceIDs: `["src"]`, BriefYAML: "candidate", CreatedAt: time.Now()},
		SourceID: "src", SourceTitle: "Source title", Revision: "revision", EvidenceKey: "evidence",
		ExpectedInputKey: "expected",
		ContentIndex:     []ContentIndexEntry{{DraftID: id, SourceID: "src", Source: "feed", CreatedAt: time.Now()}},
	}
}

func TestDraftCompletionRejectsReplacedCheckpoint(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "completion.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	retryAt := time.Now().Add(time.Hour).UTC()
	if err := db.PutProcessingCheckpoint(ProcessingCheckpoint{SourceID: "src", InputKey: "newer-input", Payload: "newer-candidate", RetryAt: retryAt}); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteDraftProcessing(completionResult("stale")); err == nil {
		t.Fatal("stale completion consumed a newer checkpoint")
	}
	checkpoint, err := db.GetProcessingCheckpoint("src")
	if err != nil || checkpoint == nil || checkpoint.InputKey != "newer-input" || checkpoint.Payload != "newer-candidate" || !checkpoint.RetryAt.Equal(retryAt) {
		t.Fatalf("newer checkpoint changed: %+v %v", checkpoint, err)
	}
	if draft, err := db.GetDraft("stale"); err == nil || draft != nil {
		t.Fatalf("stale completion left draft: %+v %v", draft, err)
	}
	if entries, err := db.FindBySourceID("src"); err != nil || len(entries) != 0 {
		t.Fatalf("stale completion left content associations: %+v %v", entries, err)
	}
	if seen, err := db.HasSeen("src"); err != nil || seen {
		t.Fatalf("stale completion completed source: %v %v", seen, err)
	}
}

func TestDraftCompletionRejectsMissingCheckpoint(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "completion.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.CompleteDraftProcessing(completionResult("orphan")); err == nil {
		t.Fatal("completion without its checkpoint created a draft")
	}
	if draft, err := db.GetDraft("orphan"); err == nil || draft != nil {
		t.Fatalf("missing checkpoint left draft: %+v %v", draft, err)
	}
	if seen, err := db.HasSeen("src"); err != nil || seen {
		t.Fatalf("missing checkpoint completed source: %v %v", seen, err)
	}
}

func TestDraftCompletionRejectsDuplicateCompletion(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "completion.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PutProcessingCheckpoint(ProcessingCheckpoint{SourceID: "src", InputKey: "expected", Payload: "candidate"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteDraftProcessing(completionResult("winner")); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteDraftProcessing(completionResult("duplicate")); err == nil {
		t.Fatal("stale completion created another draft after its checkpoint was consumed")
	}
	entries, err := db.FindBySourceID("src")
	if err != nil || len(entries) != 1 || entries[0].DraftID != "winner" {
		t.Fatalf("completion did not retain exactly one canonical result: %+v %v", entries, err)
	}
}
