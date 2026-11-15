package scraper

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func durableEvent(at time.Time, key, text string) []byte {
	b, _ := json.Marshal(map[string]any{"did": "did:plc:durable", "time_us": at.UnixMicro(), "kind": "commit", "commit": map[string]any{"operation": "create", "collection": "app.bsky.feed.post", "rkey": key, "record": map[string]string{"text": text, "createdAt": at.Add(-time.Hour).Format(time.RFC3339Nano)}}})
	return b
}

func durableStream(t *testing.T, events [][]byte, abrupt bool) (string, *[]int64, *sync.Mutex) {
	t.Helper()
	var cursors []int64
	mu := &sync.Mutex{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
		mu.Lock()
		cursors = append(cursors, cursor)
		mu.Unlock()
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for _, ev := range events {
			if err := c.Write(r.Context(), websocket.MessageText, ev); err != nil {
				return
			}
		}
		if !abrupt {
			_, _, _ = c.Read(r.Context())
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), &cursors, mu
}

func durableRunner(db *storage.DB, endpoint string, cap int) *Runner {
	r := NewRunner(db, testLogger(), 24*time.Hour)
	r.RegisterWithInterval(NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: endpoint, CandidateCap: cap, ReadWindow: 40 * time.Millisecond}), time.Hour)
	return r
}

func TestBlueskyDurableHandoffSurvivesRestartAndDoesNotPinAtCap(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	events := [][]byte{durableEvent(at, "one", "CVE-2026-111497 reproduced heap memory disclosure"), durableEvent(at.Add(time.Second), "two", "CVE-2026-111498 reproduced heap memory disclosure"), durableEvent(at.Add(2*time.Second), "three", "CVE-2026-111499 reproduced heap memory disclosure")}
	endpoint, cursors, mu := durableStream(t, events, false)
	path := t.TempDir() + "/queue.db"
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := durableRunner(db, endpoint, 2)
	items, err := r.PollAll(context.Background())
	if err != nil || len(items) != 2 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	state, err := db.GetScraperState("bluesky-discovery")
	if err != nil || state == nil || !state.LastPoll.Equal(at.Add(time.Second)) {
		t.Fatalf("unseen candidates pinned consumed watermark: state=%+v err=%v", state, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r = durableRunner(db, endpoint, 2)
	items, err = r.PollAll(context.Background())
	if err != nil || len(items) != 3 {
		t.Fatalf("restart lost candidates or overlap consumed cap: items=%+v err=%v", items, err)
	}
	mu.Lock()
	last := (*cursors)[1]
	mu.Unlock()
	if last != at.Add(-4*time.Second).UnixMicro() {
		t.Fatalf("restart cursor=%d; want a fixed five-second overlap", last)
	}
	for _, item := range items {
		if err := db.MarkSeenRevision(item.SourceID, item.Source, item.Title, item.Revision); err != nil {
			t.Fatal(err)
		}
	}
	// Poll is interval-skipped; durable completion must still suppress delivery.
	if items, err := r.PollAll(context.Background()); err != nil || len(items) != 0 {
		t.Fatalf("completed queue was redelivered: %v %v", items, err)
	}
}

func TestBlueskyDurableEmptyCandidateWindowAdvancesConsumedEvents(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	endpoint, _, _ := durableStream(t, [][]byte{[]byte(fmt.Sprintf(`{"kind":"identity","time_us":%d}`, at.UnixMicro())), durableEvent(at.Add(time.Second), "noise", "hello world")}, false)
	db, err := storage.Open(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	items, err := durableRunner(db, endpoint, 2).PollAll(context.Background())
	if err != nil || len(items) != 0 {
		t.Fatalf("items=%v err=%v", items, err)
	}
	state, err := db.GetScraperState("bluesky-discovery")
	if err != nil || state == nil || !state.LastPoll.Equal(at.Add(time.Second)) {
		t.Fatalf("nonmatching window pinned progress: %+v %v", state, err)
	}
}

func TestBlueskyDurablePartialFailurePreservesConsumedCandidates(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	endpoint, _, _ := durableStream(t, [][]byte{durableEvent(at, "one", "CVE-2026-111497 reproduced heap memory disclosure")}, true)
	db, err := storage.Open(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := durableRunner(db, endpoint, 2)
	items, err := r.PollAll(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("partial window candidate lost: %v %v", items, err)
	}
	state, err := db.GetScraperState("bluesky-discovery")
	if err != nil || state == nil || !state.LastPoll.Equal(at) {
		t.Fatalf("partial safe prefix lost: %+v %v", state, err)
	}
	if r.HealthSummary()[0].ConsecutiveErrors != 1 {
		t.Fatal("partial read failure was reported as success")
	}
}

func TestBlueskyDurableCheckpointFailureRollsBackQueue(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	endpoint, _, _ := durableStream(t, [][]byte{durableEvent(at, "one", "CVE-2026-111497 reproduced heap memory disclosure")}, false)
	path := t.TempDir() + "/queue.db"
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER fail_checkpoint BEFORE INSERT ON scraper_state BEGIN SELECT RAISE(ABORT,'injected checkpoint failure'); END`); err != nil {
		t.Fatal(err)
	}
	r := durableRunner(db, endpoint, 1)
	items, err := r.PollAll(context.Background())
	if err == nil || len(items) != 0 {
		t.Fatalf("failed durable handoff was delivered: items=%v err=%v", items, err)
	}
	state, err := db.GetScraperState("bluesky-discovery")
	if err != nil || state != nil {
		t.Fatalf("failed handoff advanced: %+v %v", state, err)
	}
	if _, err := raw.Exec(`DROP TRIGGER fail_checkpoint`); err != nil {
		t.Fatal(err)
	}
	r = durableRunner(db, endpoint, 1)
	if items, err = r.PollAll(context.Background()); err != nil || len(items) != 1 {
		t.Fatalf("retry lost candidate: %v %v", items, err)
	}
}

type cancelAfterDurableCandidate struct {
	*BlueskyJetstream
	cancel context.CancelFunc
}

func (s cancelAfterDurableCandidate) PollWindow(ctx context.Context, since time.Time, eligible func(RawItem) (bool, error)) (streamWindow, error) {
	return s.BlueskyJetstream.PollWindow(ctx, since, func(item RawItem) (bool, error) {
		ok, err := eligible(item)
		if ok && err == nil {
			s.cancel()
		}
		return ok, err
	})
}
func TestBlueskyDurableCancellationPersistsSafePrefixForRetry(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	endpoint, _, _ := durableStream(t, [][]byte{durableEvent(at, "one", "CVE-2026-111497 reproduced heap memory disclosure")}, false)
	db, err := storage.Open(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewRunner(db, testLogger(), 24*time.Hour)
	r.RegisterWithInterval(cancelAfterDurableCandidate{NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: endpoint, CandidateCap: 2, ReadWindow: time.Second}).(*BlueskyJetstream), cancel}, time.Hour)
	_, err = r.PollAll(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	state, err := db.GetScraperState("bluesky-discovery")
	if err != nil || state == nil || !state.LastPoll.Equal(at) {
		t.Fatalf("cancellation lost consumed prefix: %+v %v", state, err)
	}
	// Even with the next network poll interval-skipped, queued work survives.
	r = durableRunner(db, endpoint, 2)
	r.entries[0].lastPoll = time.Now()
	items, err := r.PollAll(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("canceled candidate lost: %v %v", items, err)
	}
}
