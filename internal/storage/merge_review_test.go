package storage

import (
	"path/filepath"
	"testing"
)

func TestEnsureMergeReviewHoldRollsBackIncompleteVisibility(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "hold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.db.Exec(`CREATE TRIGGER fail_review_history BEFORE INSERT ON processing_history BEGIN SELECT RAISE(FAIL,'history unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	hold := MergeReviewHold{SourceID: "source", Source: "fixture", Title: "Synthetic review", RawOutput: "candidate", Reason: "unsupported claim", InputKey: "input", AttemptID: "attempt"}
	if recorded, err := db.EnsureMergeReviewHold(hold); err == nil || recorded {
		t.Fatalf("failed transaction reported success: recorded=%v err=%v", recorded, err)
	}
	if _, ok, err := db.PipelineQuarantineReason(hold.SourceID); err != nil || ok {
		t.Fatalf("history failure left partial quarantine: present=%v err=%v", ok, err)
	}
	if _, err := db.db.Exec("DROP TRIGGER fail_review_history"); err != nil {
		t.Fatal(err)
	}
	if recorded, err := db.EnsureMergeReviewHold(hold); err != nil || !recorded {
		t.Fatalf("repair did not record review: recorded=%v err=%v", recorded, err)
	}
}

func TestEnsureMergeReviewHoldRepairsLegacyPartialRecordsIdempotently(t *testing.T) {
	for _, present := range []string{"neither", "quarantine", "history"} {
		t.Run(present, func(t *testing.T) {
			db, err := Open(filepath.Join(t.TempDir(), "hold.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			hold := MergeReviewHold{SourceID: "source", Source: "fixture", Title: "Synthetic review", RawOutput: "candidate", Reason: "unsupported claim", InputKey: "input", AttemptID: "attempt"}
			if present == "quarantine" {
				if err := db.QuarantinePipelineItem(hold.SourceID, hold.Source, hold.Title, hold.RawOutput, hold.Reason); err != nil {
					t.Fatal(err)
				}
			}
			if present == "history" {
				if err := db.RecordProcessingEvent(hold.SourceID, hold.InputKey, hold.AttemptID, "merge_editorial", "held"); err != nil {
					t.Fatal(err)
				}
			}
			for i := range 3 {
				recorded, err := db.EnsureMergeReviewHold(hold)
				if err != nil || recorded != (i == 0 && present != "history") {
					t.Fatalf("repair %d: recorded=%v err=%v", i, recorded, err)
				}
			}
			if reason, ok, err := db.PipelineQuarantineReason(hold.SourceID); err != nil || !ok || reason != hold.Reason {
				t.Fatalf("missing review visibility: reason=%q present=%v err=%v", reason, ok, err)
			}
			var count int
			if err := db.db.QueryRow("SELECT COUNT(*) FROM processing_history").Scan(&count); err != nil || count != 1 {
				t.Fatalf("repeated repair duplicated event: count=%d err=%v", count, err)
			}
			// A delivery timestamp can change the input key while the saved
			// assessment and its semantic evidence remain exactly the same.
			hold.InputKey = "refreshed-delivery-clock"
			if recorded, err := db.EnsureMergeReviewHold(hold); err != nil || recorded {
				t.Fatalf("delivery-only change duplicated review: recorded=%v err=%v", recorded, err)
			}
			// A later assessment, including one for a changed semantic target,
			// keeps its own durable event instead of aliasing the earlier hold.
			hold.AttemptID = "next-attempt"
			if recorded, err := db.EnsureMergeReviewHold(hold); err != nil || !recorded {
				t.Fatalf("distinct review was conflated: recorded=%v err=%v", recorded, err)
			}
			if err := db.db.QueryRow("SELECT COUNT(*) FROM processing_history").Scan(&count); err != nil || count != 2 {
				t.Fatalf("distinct review event absent: count=%d err=%v", count, err)
			}
		})
	}
}

func TestEnsureMergeReviewHoldKeepsLatestAssessmentVisible(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "hold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hold := MergeReviewHold{SourceID: "source", Source: "fixture", Title: "Synthetic review", RawOutput: "first candidate", Reason: "first unsupported claim", InputKey: "input", AttemptID: "first-attempt"}
	if recorded, err := db.EnsureMergeReviewHold(hold); err != nil || !recorded {
		t.Fatalf("first hold: recorded=%v err=%v", recorded, err)
	}
	firstHold := hold
	hold.RawOutput, hold.Reason, hold.AttemptID = "revised candidate", "different unsupported claim", "second-attempt"
	for i := range 3 {
		recorded, err := db.EnsureMergeReviewHold(hold)
		if err != nil || recorded != (i == 0) {
			t.Fatalf("second hold pass %d: recorded=%v err=%v", i, recorded, err)
		}
		var raw, reason string
		if err := db.db.QueryRow("SELECT raw_output,error_message FROM pipeline_quarantine WHERE source_id=?", hold.SourceID).Scan(&raw, &reason); err != nil {
			t.Fatal(err)
		}
		if raw != hold.RawOutput || reason != hold.Reason {
			t.Fatalf("latest review is stale: raw=%q reason=%q", raw, reason)
		}
		var count int
		if err := db.db.QueryRow("SELECT COUNT(*) FROM processing_history").Scan(&count); err != nil || count != 2 {
			t.Fatalf("review history duplicated or lost: count=%d err=%v", count, err)
		}
	}
	if recorded, err := db.EnsureMergeReviewHold(firstHold); err != nil || recorded {
		t.Fatalf("earlier assessment repair added history: recorded=%v err=%v", recorded, err)
	}
	if reason, ok, err := db.PipelineQuarantineReason(hold.SourceID); err != nil || !ok || reason != hold.Reason {
		t.Fatalf("earlier repair overwrote latest review: reason=%q present=%v err=%v", reason, ok, err)
	}
	// A missing visibility row must still be reconstructed when its durable
	// history already exists, without emitting another held event.
	if _, err := db.db.Exec("DELETE FROM pipeline_quarantine WHERE source_id=?", hold.SourceID); err != nil {
		t.Fatal(err)
	}
	if recorded, err := db.EnsureMergeReviewHold(hold); err != nil || recorded {
		t.Fatalf("missing-row repair duplicated history: recorded=%v err=%v", recorded, err)
	}
	if reason, ok, err := db.PipelineQuarantineReason(hold.SourceID); err != nil || !ok || reason != hold.Reason {
		t.Fatalf("missing-row repair lost latest reason: reason=%q present=%v err=%v", reason, ok, err)
	}
}

func TestEnsureMergeReviewHoldReplacementFailureRollsBack(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "hold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hold := MergeReviewHold{SourceID: "source", Source: "fixture", Title: "Synthetic review", RawOutput: "first candidate", Reason: "first reason", InputKey: "input", AttemptID: "first-attempt"}
	if recorded, err := db.EnsureMergeReviewHold(hold); err != nil || !recorded {
		t.Fatalf("first hold: recorded=%v err=%v", recorded, err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER fail_review_update BEFORE UPDATE ON pipeline_quarantine BEGIN SELECT RAISE(FAIL,'review update unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	hold.RawOutput, hold.Reason, hold.AttemptID = "second candidate", "second reason", "second-attempt"
	if recorded, err := db.EnsureMergeReviewHold(hold); err == nil || recorded {
		t.Fatalf("failed replacement reported success: recorded=%v err=%v", recorded, err)
	}
	var raw, reason string
	if err := db.db.QueryRow("SELECT raw_output,error_message FROM pipeline_quarantine WHERE source_id=?", hold.SourceID).Scan(&raw, &reason); err != nil {
		t.Fatal(err)
	}
	if raw != "first candidate" || reason != "first reason" {
		t.Fatalf("failed replacement changed review: raw=%q reason=%q", raw, reason)
	}
	var count int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM processing_history").Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed replacement committed history: count=%d err=%v", count, err)
	}
}
