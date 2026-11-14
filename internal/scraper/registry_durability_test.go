package scraper

import (
	"context"
	"errors"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"testing"
	"time"
)

type failingRunnerStore struct {
	*storage.DB
	readErr, markErr, saveErr error
}

func (s *failingRunnerStore) HasSeen(id string) (bool, error) {
	if s.readErr != nil {
		return false, s.readErr
	}
	return s.DB.HasSeen(id)
}
func (s *failingRunnerStore) MarkSeen(id, source, title string) error {
	if s.markErr != nil {
		return s.markErr
	}
	return s.DB.MarkSeen(id, source, title)
}
func (s *failingRunnerStore) SaveScraperState(source string, at time.Time, cursor string) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.DB.SaveScraperState(source, at, cursor)
}

func TestRunnerStorageFailureKeepsCheckpointAndRetries(t *testing.T) {
	for _, kind := range []string{"seen read", "old item write", "checkpoint write"} {
		t.Run(kind, func(t *testing.T) {
			db, err := storage.Open(t.TempDir() + "/state.db")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			prior := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
			if err := db.SaveScraperState("anchor-source", prior, "old"); err != nil {
				t.Fatal(err)
			}
			item := RawItem{SourceID: "item-1", Source: "anchor-source", Title: "Synthetic advisory", PublishedAt: time.Now().Add(-time.Hour)}
			injected := errors.New("synthetic storage failure")
			store := &failingRunnerStore{DB: db}
			switch kind {
			case "seen read":
				store.readErr = injected
			case "old item write":
				store.markErr = injected
				item.PublishedAt = time.Now().Add(-48 * time.Hour)
			case "checkpoint write":
				store.saveErr = injected
				if err := db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
					t.Fatal(err)
				}
			}
			r := NewRunner(db, testLogger(), 24*time.Hour)
			r.db = store
			r.RegisterWithInterval(anchorSourceScraper{item: item}, time.Hour)
			items, err := r.PollAll(context.Background())
			if !errors.Is(err, injected) {
				t.Fatalf("storage failure not returned: %v", err)
			}
			if len(items) != 0 {
				t.Fatalf("failed source acknowledged items: %v", items)
			}
			state, err := db.GetScraperState("anchor-source")
			if err != nil {
				t.Fatal(err)
			}
			if !state.LastPoll.Equal(prior) || state.Cursor != "old" {
				t.Fatalf("checkpoint advanced: %+v", state)
			}
			health := r.HealthSummary()
			if len(health) != 1 || health[0].ConsecutiveErrors != 1 {
				t.Fatalf("failed source marked healthy: %+v", health)
			}
			store.readErr, store.markErr, store.saveErr = nil, nil, nil
			if _, err := r.PollAll(context.Background()); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
			health = r.HealthSummary()
			if health[0].LastSuccess.IsZero() {
				t.Fatal("storage failure delayed retry for full poll interval")
			}
		})
	}
}
