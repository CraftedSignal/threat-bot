package scraper

import (
	"context"
	"errors"
	"fmt"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRSSStorageRecoveryRetainsFetchedItem(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("If-None-Match") == `"fixture-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"fixture-v1"`)
		w.Header().Set("Content-Type", "application/rss+xml")
		_, _ = fmt.Fprintf(w, `<rss version="2.0"><channel><title>Fixture</title><link>https://example.invalid/</link><description>Fixture</description><item><guid>fixture-1</guid><title>Synthetic advisory</title><link>https://example.invalid/advisory</link><pubDate>%s</pubDate><description>Benign review fixture</description></item></channel></rss>`, time.Now().Add(-time.Minute).UTC().Format(time.RFC1123Z))
	}))
	defer server.Close()
	db, err := storage.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &failingRunnerStore{DB: db, readErr: errors.New("synthetic read failure")}
	runner := NewRunner(db, testLogger(), time.Hour)
	runner.db = store
	runner.RegisterWithInterval(NewRSS("fixture", server.URL), time.Hour)
	if _, err := runner.PollAll(context.Background()); err == nil {
		t.Fatal("expected injected failure")
	}
	store.readErr = nil
	items, err := runner.PollAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("retry lost fetched item: requests=%d items=%d health=%+v", requests, len(items), runner.HealthSummary())
	}
}

func TestRunnerCheckpointCannotAdvanceIntoFuture(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	item := RawItem{SourceID: "future-fixture", Source: "anchor-source", Title: "Synthetic scheduled advisory", PublishedAt: time.Now().Add(24 * time.Hour)}
	if err := db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(db, testLogger(), 48*time.Hour)
	runner.RegisterWithInterval(anchorSourceScraper{item: item}, time.Hour)
	if _, err := runner.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := db.GetScraperState("anchor-source")
	if err != nil {
		t.Fatal(err)
	}
	if state.LastPoll.After(time.Now()) {
		t.Fatalf("checkpoint is future-dated despite normalized item: %s", state.LastPoll)
	}
}

type checkpointWindowSource struct{ item RawItem }

func (s checkpointWindowSource) Name() string { return "checkpoint-window" }
func (s checkpointWindowSource) Poll(_ context.Context, since time.Time) ([]RawItem, error) {
	if s.item.PublishedAt.Before(since) {
		return nil, nil
	}
	return []RawItem{s.item}, nil
}

func TestRunnerRecoversStoredFutureCheckpoint(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.SaveScraperState("checkpoint-window", time.Now().Add(24*time.Hour), "future"); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(db, testLogger(), time.Hour)
	r.RegisterWithInterval(checkpointWindowSource{item: RawItem{SourceID: "current", Source: "checkpoint-window", Title: "Synthetic advisory", PublishedAt: time.Now().Add(-time.Minute)}}, time.Hour)
	items, err := r.PollAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatal("future stored checkpoint suppressed current items")
	}
}

func TestRSSCorrectionRetainedAcross304Checkpoints(t *testing.T) {
	updated := time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("If-None-Match") == `"correction-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"correction-v1"`)
		_, _ = fmt.Fprintf(w, `<feed xmlns="http://www.w3.org/2005/Atom"><title>Corrections</title><id>fixture</id><updated>%s</updated><entry><id>advisory</id><title>Corrected advisory</title><link href="https://example.invalid/advisory"/><published>2020-01-01T00:00:00Z</published><updated>%s</updated><content>Benign corrected product scope.</content></entry></feed>`, updated.Format(time.RFC3339), updated.Format(time.RFC3339))
	}))
	defer server.Close()
	feed := NewRSS("fixture", server.URL)
	items, err := feed.Poll(context.Background(), updated.Add(time.Hour))
	if err != nil || len(items) != 0 {
		t.Fatalf("initial window: items=%v err=%v", items, err)
	}
	items, err = feed.Poll(context.Background(), updated.Add(-time.Hour))
	if err != nil || len(items) != 1 {
		t.Fatalf("304 discarded retained correction: items=%v err=%v", items, err)
	}
	if requests != 2 || !items[0].UpdatedAt.Equal(updated) || items[0].PublishedAt.Year() != 2020 {
		t.Fatalf("correction history not retained: requests=%d item=%+v", requests, items[0])
	}
}

func TestRunnerCorrectionCheckpointUsesUpdatedEvidence(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	prior := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	updated := prior.Add(time.Hour)
	item := RawItem{SourceID: "corrected", Source: "anchor-source", Title: "Corrected advisory", PublishedAt: prior.AddDate(-1, 0, 0), UpdatedAt: updated}
	if err := db.SaveScraperState(item.Source, prior, "prior"); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSeenRevision(item.SourceID, item.Source, item.Title, item.ContentRevision()); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(db, testLogger(), 24*time.Hour)
	runner.RegisterWithInterval(anchorSourceScraper{item: item}, time.Hour)
	if _, err := runner.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := db.GetScraperState(item.Source)
	if err != nil {
		t.Fatal(err)
	}
	if !state.LastPoll.Equal(updated) {
		t.Fatalf("correction checkpoint ignored update date: got=%s want=%s", state.LastPoll, updated)
	}
}
