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

func TestBlueskyCF127SerializedQueueSurvivesAcknowledgedRestartWithoutPolling(t *testing.T) {
	// Frozen synthetic RawItem bytes serialized by deployed cf127895fdc29c7c,
	// not by the code under test. No private production data.
	const payload = `{"SourceID":"bluesky-discovery:did:plc:cf127-fixture:queued-post","Source":"bluesky-discovery","Title":"CVE-2026-111497 reproduced heap memory disclosure","URL":"https://bsky.app/profile/did:plc:cf127-fixture/post/queued-post","Content":"CVE-2026-111497 reproduced heap memory disclosure","PublishedAt":"2026-11-15T09:00:00Z","UpdatedAt":"0001-01-01T00:00:00Z","Revision":"030ebf353fa9e51a0f12af6c00d4c2acc77afb1f01b9561107b7a0d702ad35a4","Metadata":null,"Discovery":{"Platform":"bluesky","OriginalURL":"https://bsky.app/profile/did:plc:cf127-fixture/post/queued-post","DiscoveryURL":"https://bsky.app/profile/did:plc:cf127-fixture/post/queued-post","Author":"did:plc:cf127-fixture","ParentURLs":null,"QuoteURLs":null,"ContextComplete":true},"SigmaRule":null,"NeedsFullArticle":false,"BodyCVEsAreSubjects":false,"CorroborationOnly":false,"Enriched":false}`
	const source = "bluesky-discovery"
	const sourceID = "bluesky-discovery:did:plc:cf127-fixture:queued-post"
	const revision = "030ebf353fa9e51a0f12af6c00d4c2acc77afb1f01b9561107b7a0d702ad35a4"
	const cursor = "1794736800000000"
	watermark := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	path := t.TempDir() + "/deployed-queue.db"
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// Seed the deployed layout directly; the new public ingestion API must
	// not construct or reserialize the compatibility fixture.
	if _, err := raw.Exec(`CREATE TABLE ingestion_candidates (
 source_id TEXT NOT NULL, revision TEXT NOT NULL, source TEXT NOT NULL,
 payload TEXT NOT NULL, payload_bytes INTEGER NOT NULL, queued_at TEXT NOT NULL,
 delivered_at TEXT NOT NULL DEFAULT '', PRIMARY KEY(source_id,revision));
 CREATE TABLE scraper_state (source TEXT PRIMARY KEY, last_poll DATETIME NOT NULL, cursor TEXT);`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO ingestion_candidates(source_id,revision,source,payload,payload_bytes,queued_at) VALUES(?,?,?,?,?,?)`, sourceID, revision, source, payload, len(payload), "2026-11-15T10:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO scraper_state(source,last_poll,cursor) VALUES(?,?,?)`, source, watermark, cursor); err != nil {
		t.Fatal(err)
	}

	for restart := 0; restart < 4; restart++ {
		func() {
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			// No scrapers are registered: delivery has no replay/network path.
			runner := NewRunner(db, testLogger(), 24*time.Hour)
			items, err := runner.PollAll(context.Background())
			if err != nil {
				t.Fatalf("restart %d: drain serialized queue: %v", restart, err)
			}
			wantCount := 1
			if restart >= 2 {
				wantCount = 0
			}
			if len(items) != wantCount {
				t.Fatalf("restart %d: delivered %d candidates, want %d", restart, len(items), wantCount)
			}
			state, err := db.GetScraperState(source)
			if err != nil || state == nil || state.Source != source || state.Cursor != cursor || !state.LastPoll.Equal(watermark) {
				t.Fatalf("restart %d changed deployed source cursor: state=%+v err=%v", restart, state, err)
			}
			var queued int
			if err := raw.QueryRow(`SELECT COUNT(*) FROM ingestion_candidates`).Scan(&queued); err != nil || queued != wantCount {
				t.Fatalf("restart %d: queued=%d want=%d err=%v", restart, queued, wantCount, err)
			}
			seen, err := db.HasSeenRevision(sourceID, revision)
			if err != nil || seen != (restart >= 2) {
				t.Fatalf("restart %d acknowledged delivery before processing or lost acknowledgement: seen=%v err=%v", restart, seen, err)
			}
			if restart >= 2 {
				return
			}
			item := items[0]
			serialized, err := json.Marshal(item)
			if err != nil || string(serialized) != payload || item.Source != source || item.SourceID != sourceID || item.Revision != revision {
				t.Fatalf("restart %d changed frozen payload/source/revision: err=%v", restart, err)
			}
			var storedPayload string
			if err := raw.QueryRow(`SELECT payload FROM ingestion_candidates WHERE source_id=? AND revision=?`, sourceID, revision).Scan(&storedPayload); err != nil || storedPayload != payload {
				t.Fatalf("restart %d modified unresolved payload: %v", restart, err)
			}
			if restart == 1 {
				if err := db.MarkSeenRevision(item.SourceID, item.Source, item.Title, item.Revision); err != nil {
					t.Fatal(err)
				}
			}
		}()
	}
}
