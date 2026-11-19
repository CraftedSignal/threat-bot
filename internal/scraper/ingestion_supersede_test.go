package scraper

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

type revisingScraper struct{ items []RawItem }

func (s revisingScraper) Name() string                                       { return "revising" }
func (s revisingScraper) Poll(context.Context, time.Time) ([]RawItem, error) { return s.items, nil }

// A fresh observation is the current state of its source. A queued older
// revision of the same source must not be processed alongside it in the same
// cycle, and an unchanged queued revision must not be processed twice.
func TestFreshObservationSupersedesQueuedRevisionInSameCycle(t *testing.T) {
	for name, freshContent := range map[string]string{"revised": "Vendor advisory now lists the fixed release.", "unchanged": "Vendor advisory text."} {
		t.Run(name, func(t *testing.T) {
			db, err := storage.Open(t.TempDir() + "/supersede.db")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Now().Add(-time.Hour)
			queued := RawItem{SourceID: "advisory", Source: "revising", Content: "Vendor advisory text.", PublishedAt: now}
			queued.Revision = queued.ContentRevision()
			payload, _ := json.Marshal(queued)
			if err := db.CommitIngestion("", time.Time{}, []storage.IngestionCandidate{{SourceID: queued.SourceID, Source: queued.Source, Revision: queued.Revision, Payload: string(payload)}}); err != nil {
				t.Fatal(err)
			}
			fresh := RawItem{SourceID: "advisory", Source: "revising", Content: freshContent, PublishedAt: now}
			runner := NewRunner(db, testLogger(), 24*time.Hour)
			runner.RegisterWithInterval(revisingScraper{items: []RawItem{fresh}}, time.Hour)
			items, err := runner.PollAll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != 1 || items[0].Content != freshContent {
				t.Fatalf("cycle delivered %d observations of one source: %+v", len(items), items)
			}
		})
	}
}
