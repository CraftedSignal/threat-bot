package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRumourCandidateRoundTripUpsertAndPublish(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	for _, c := range []*RumourCandidate{{ClaimKey: "claim-1", SourceIDs: []string{"a"}, SourceURLs: []string{"https://x.com/a/status/1"}, AssessmentJSON: `{"likelihood":"roughly even chance"}`, Status: "below_gate", FirstSeen: now, LastSeen: now}, {ClaimKey: "claim-1", SourceIDs: []string{"a", "b"}, SourceURLs: []string{"https://x.com/a/status/1", "https://bsky.app/x"}, AssessmentJSON: `{"likelihood":"likely"}`, Status: "below_gate", LastSeen: now.Add(time.Hour)}} {
		if err := db.UpsertRumourCandidate(c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.GetRumourCandidate("claim-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "below_gate" || len(got.SourceIDs) != 2 || len(got.SourceURLs) != 2 || got.FirstSeen.IsZero() {
		t.Fatalf("got=%+v", got)
	}
	if err := db.MarkRumourCandidatePublished("claim-1"); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetRumourCandidate("claim-1")
	if got.Status != "published" || len(got.SourceIDs) != 2 {
		t.Fatalf("published=%+v", got)
	}
}

func TestRumourCandidateMigrationIsAdditive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.GetRumourCandidate("missing"); err != nil {
		t.Fatal(err)
	}
}
