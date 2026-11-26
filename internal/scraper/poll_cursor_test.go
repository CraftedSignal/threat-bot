package scraper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

// windowSource returns every item at or after since, like a feed or API whose
// result window is bounded by the cursor.
type windowSource struct {
	mu        sync.Mutex
	items     []RawItem
	sinceSeen []time.Time
}

func (s *windowSource) Name() string { return "window-source" }
func (s *windowSource) Poll(_ context.Context, since time.Time) ([]RawItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sinceSeen = append(s.sinceSeen, since)
	var out []RawItem
	for _, item := range s.items {
		if !itemFreshness(item).Before(since) {
			out = append(out, item)
		}
	}
	return out, nil
}

// An item held for review stays unseen for days. It must not pin the source
// cursor: otherwise every poll re-reads an ever-growing window. The queue keeps
// the held item, so moving the cursor loses nothing.
func TestHeldItemDoesNotPinSourceCursor(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/cursor.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	held := RawItem{SourceID: "held", Source: "window-source", Title: "Held advisory", Content: "Awaiting editorial review.", PublishedAt: now.Add(-6 * time.Hour)}
	source := &windowSource{items: []RawItem{held}}
	runner := NewRunner(db, testLogger(), 24*time.Hour)
	runner.RegisterWithInterval(source, time.Nanosecond)
	first, err := runner.PollAll(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatalf("first poll: %v %v", first, err)
	}
	// The pipeline holds the item: it is never marked seen.
	state, err := db.GetScraperState(source.Name())
	if err != nil || state == nil || !state.LastPoll.Equal(held.PublishedAt) {
		t.Fatalf("cursor did not advance past the read window: %+v %v", state, err)
	}
	queued, err := db.HasIngestionCandidate(held.SourceID, held.ContentRevision())
	if err != nil || !queued {
		t.Fatalf("held item not retained durably when the cursor moved: %v %v", queued, err)
	}

	// Later items keep moving the cursor; the held item is still delivered
	// from the queue until it is processed.
	later := RawItem{SourceID: "later", Source: "window-source", Title: "Later advisory", Content: "New evidence.", PublishedAt: now.Add(-time.Hour)}
	source.mu.Lock()
	source.items = append(source.items, later)
	source.mu.Unlock()
	second, err := runner.PollAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, item := range second {
		got[item.SourceID]++
	}
	if got["held"] != 1 || got["later"] != 1 {
		t.Fatalf("second poll delivered %v, want the held and the later item once each", got)
	}
	if state, _ := db.GetScraperState(source.Name()); !state.LastPoll.Equal(later.PublishedAt) {
		t.Fatalf("cursor did not move past the later item: %+v", state)
	}
	if source.sinceSeen[1].Before(held.PublishedAt) {
		t.Fatalf("second poll re-read from %s, before the acknowledged window %s", source.sinceSeen[1], held.PublishedAt)
	}
}

// A full intake queue keeps the cursor so nothing is acknowledged that is not
// retained; the items are still processed this cycle.
func TestFullIntakeQueueKeepsSourceCursor(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/cursor.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The filler occupies the queue while this source polls. It is already
	// processed, so delivery drops it before decoding its payload.
	if err := db.CommitIngestion("other", time.Time{}, []storage.IngestionCandidate{{SourceID: "filler", Source: "other", Revision: "r", Payload: strings.Repeat("x", storage.MaxIngestionQueueBytes-10)}}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSeenRevision("filler", "other", "filler", "r"); err != nil {
		t.Fatal(err)
	}
	prior := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)
	if err := db.SaveScraperState("window-source", prior, "prior"); err != nil {
		t.Fatal(err)
	}
	item := RawItem{SourceID: "fresh", Source: "window-source", Title: "Fresh advisory", Content: "Evidence that does not fit the queue.", PublishedAt: time.Now().Add(-time.Hour)}
	runner := NewRunner(db, testLogger(), 24*time.Hour)
	runner.RegisterWithInterval(&windowSource{items: []RawItem{item}}, time.Nanosecond)
	items, err := runner.PollAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range items {
		found = found || it.SourceID == "fresh"
	}
	if !found {
		t.Fatal("item dropped when the queue was full")
	}
	if state, _ := db.GetScraperState("window-source"); !state.LastPoll.Equal(prior) {
		t.Fatalf("cursor advanced past an item the queue could not retain: %+v", state)
	}
}

// NVD reports how many records a modification window holds. A correction
// backlog larger than the page budget is read in bounded windows, oldest first,
// so the source catches up instead of failing every poll.
func TestNVDBacklogLargerThanPageBudgetIsReadInBoundedWindows(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	since := now.Add(-10 * 24 * time.Hour)
	budget := nvdMaxModifiedPages * nvdModifiedPageSize
	// One modified record per minute for ten days: far more than the budget.
	perMinute := func(start, end time.Time) int {
		if !end.After(start) {
			return 0
		}
		return int(end.Sub(start) / time.Minute)
	}
	var mu sync.Mutex
	var windows [][2]time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !q.Has("lastModStartDate") {
			_ = json.NewEncoder(w).Encode(nvdResponse{})
			return
		}
		start, _ := time.Parse("2006-01-02T15:04:05.000", q.Get("lastModStartDate"))
		end, _ := time.Parse("2006-01-02T15:04:05.000", q.Get("lastModEndDate"))
		mu.Lock()
		windows = append(windows, [2]time.Time{start, end})
		mu.Unlock()
		total := perMinute(start, end)
		var index int
		fmt.Sscan(q.Get("startIndex"), &index)
		page := []nvdVulnerability{}
		for i := index; i < total && i < index+nvdModifiedPageSize; i++ {
			modified := start.Add(time.Duration(i) * time.Minute)
			v := secondaryScoredCVE(fmt.Sprintf("CVE-2024-%05d", i), modified.AddDate(-1, 0, 0), 3.1)
			v.CVE.LastModified = modified.Format("2006-01-02T15:04:05.000")
			page = append(page, v)
		}
		_ = json.NewEncoder(w).Encode(nvdResponse{TotalResults: total, Vulnerabilities: page})
	}))
	defer srv.Close()
	n := &NVD{client: srv.Client(), pageDelay: time.Nanosecond}
	items, through, err := n.pollWindow(context.Background(), since, srv.URL)
	if err != nil {
		t.Fatalf("backlog larger than the page budget failed the poll: %v", err)
	}
	if !through.After(since) || !through.Before(now) {
		t.Fatalf("window end %s not inside the backlog (%s, %s)", through, since, now)
	}
	if want := perMinute(since, through); len(items) != want || want > budget {
		t.Fatalf("read %d items, want the complete bounded window of %d (budget %d)", len(items), want, budget)
	}
	for _, item := range items {
		if item.UpdatedAt.After(through) {
			t.Fatalf("item %s modified %s is outside the window ending %s", item.SourceID, item.UpdatedAt, through)
		}
	}
	// The next poll starts where this one ended and keeps catching up.
	more, next, err := n.pollWindow(context.Background(), through, srv.URL)
	if err != nil || !next.After(through) || len(more) == 0 {
		t.Fatalf("follow-up window did not progress: items=%d end=%s err=%v", len(more), next, err)
	}
}

// A bulk NVD update can modify more records within the shortest window than a
// poll may read. The poll reads the budget and still moves past that window:
// a cursor stuck on one minute would stop all NVD ingestion.
func TestNVDBulkUpdateBeyondBudgetStillProgresses(t *testing.T) {
	budget := nvdMaxModifiedPages * nvdModifiedPageSize
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !q.Has("lastModStartDate") {
			_ = json.NewEncoder(w).Encode(nvdResponse{})
			return
		}
		var index, perPage int
		fmt.Sscan(q.Get("startIndex"), &index)
		fmt.Sscan(q.Get("resultsPerPage"), &perPage)
		total := budget + 1
		page := []nvdVulnerability{}
		for i := index; i < total && i < index+perPage; i++ {
			page = append(page, secondaryScoredCVE(fmt.Sprintf("CVE-2020-%05d", i), time.Now().AddDate(-6, 0, 0), 3.1))
		}
		_ = json.NewEncoder(w).Encode(nvdResponse{TotalResults: total, Vulnerabilities: page})
	}))
	defer srv.Close()
	var logs bytes.Buffer
	n := &NVD{client: srv.Client(), pageDelay: time.Nanosecond, logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	since := time.Now().Add(-time.Hour)
	items, through, err := n.pollWindow(context.Background(), since, srv.URL)
	if err != nil {
		t.Fatalf("bulk update stalled the poll: %v", err)
	}
	if !through.After(since) {
		t.Fatalf("window end %s did not move past %s", through, since)
	}
	if len(items) != budget {
		t.Fatalf("read %d modified records, want the %d-record budget", len(items), budget)
	}
	if !strings.Contains(logs.String(), "beyond the page budget skipped") || !strings.Contains(logs.String(), `"skipped":1`) {
		t.Fatalf("skipped records not reported: %s", logs.String())
	}
}
