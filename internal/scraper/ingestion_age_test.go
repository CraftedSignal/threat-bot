package scraper

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

type agingIntakeScraper struct{ items []RawItem }

func (s agingIntakeScraper) Name() string                                       { return "aging-intake" }
func (s agingIntakeScraper) Poll(context.Context, time.Time) ([]RawItem, error) { return s.items, nil }

func TestAgeFilterPreservesDurablePendingIntake(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/age.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := time.Now().Add(-48 * time.Hour)
	pending := RawItem{SourceID: "paid-pending", Source: "aging-intake", Content: "retained evidence", PublishedAt: old}
	pending.Revision = pending.ContentRevision()
	payload, _ := json.Marshal(pending)
	if err := db.CommitIngestion("", time.Time{}, []storage.IngestionCandidate{{SourceID: pending.SourceID, Source: pending.Source, Revision: pending.Revision, Payload: string(payload)}}); err != nil {
		t.Fatal(err)
	}
	ordinary := RawItem{SourceID: "unrelated-old", Source: "aging-intake", PublishedAt: old}
	runner := NewRunner(db, testLogger(), 24*time.Hour)
	runner.RegisterWithInterval(agingIntakeScraper{items: []RawItem{pending, ordinary}}, time.Hour)
	items, err := runner.PollAll(context.Background())
	if err != nil || len(items) != 1 || items[0].SourceID != pending.SourceID {
		t.Fatalf("age filter erased paid pending source: %+v %v", items, err)
	}
	if seen, _ := db.HasSeenRevision(pending.SourceID, pending.Revision); seen {
		t.Fatal("pending source marked seen by age filter")
	}
	if seen, _ := db.HasSeen(ordinary.SourceID); !seen {
		t.Fatal("unrelated old source no longer age-filtered")
	}
	// A fresh runner with an empty upstream must still drain the same payload.
	restarted := NewRunner(db, testLogger(), 24*time.Hour)
	restarted.RegisterWithInterval(agingIntakeScraper{}, time.Hour)
	items, err = restarted.PollAll(context.Background())
	if err != nil || len(items) != 1 || items[0].Content != pending.Content {
		t.Fatalf("upstream disappearance lost pending source: %+v %v", items, err)
	}
}
