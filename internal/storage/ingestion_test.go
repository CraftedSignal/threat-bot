package storage

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIngestionTransactionRollsBackOnQueueWriteFailure(t *testing.T) {
	db, err := Open(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.db.Exec(`CREATE TRIGGER fail_queue BEFORE INSERT ON ingestion_candidates WHEN NEW.source_id='two' BEGIN SELECT RAISE(ABORT,'queue unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	err = db.CommitIngestion("stream", at, []IngestionCandidate{{SourceID: "one", Revision: "r1", Payload: "one"}, {SourceID: "two", Revision: "r2", Payload: "two"}})
	if err == nil {
		t.Fatal("failed queue write succeeded")
	}
	var n int
	if err = db.db.QueryRow(`SELECT COUNT(*) FROM ingestion_candidates`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial queue commit: count=%d err=%v", n, err)
	}
	if state, err := db.GetScraperState("stream"); err != nil || state != nil {
		t.Fatalf("failed queue write advanced cursor: %+v %v", state, err)
	}
}

func TestIngestionBackpressureRetainsCursorAndCandidates(t *testing.T) {
	db, err := Open(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Simulate a full unresolved payload budget without allocating 128 MiB.
	if _, err = db.db.Exec(`INSERT INTO ingestion_candidates(source_id,revision,source,payload,payload_bytes,queued_at) VALUES('held','r','stream','held',134217728,'2026-11-15T09:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	err = db.CommitIngestion("stream", time.Now(), []IngestionCandidate{{SourceID: "new", Revision: "r", Payload: "new"}})
	if !errors.Is(err, ErrIngestionBackpressure) {
		t.Fatalf("full queue did not apply backpressure: %v", err)
	}
	if state, err := db.GetScraperState("stream"); err != nil || state != nil {
		t.Fatalf("full queue advanced cursor: %+v %v", state, err)
	}
	var n int
	if err = db.db.QueryRow(`SELECT COUNT(*) FROM ingestion_candidates`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("full queue dropped held or retained partial new candidate: %d %v", n, err)
	}
}

func TestIngestionDeliveryRotatesHeldCandidatesAndPrioritizesFresh(t *testing.T) {
	db, err := Open(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	var pending []IngestionCandidate
	for i := 0; i < 5; i++ {
		pending = append(pending, IngestionCandidate{SourceID: fmt.Sprintf("held-%d", i), Revision: "r", Payload: "held"})
	}
	if err := db.CommitIngestion("stream", at, pending); err != nil {
		t.Fatal(err)
	}
	delivered := map[string]bool{}
	first, err := db.NextIngestionCandidates(2)
	if err != nil || len(first) != 2 {
		t.Fatalf("first=%v %v", first, err)
	}
	for _, c := range first {
		delivered[c.SourceID] = true
	}
	if err := db.CommitIngestion("stream", at.Add(time.Second), []IngestionCandidate{{SourceID: "fresh", Revision: "r", Payload: "fresh"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		batch, err := db.NextIngestionCandidates(2)
		if err != nil || len(batch) != 2 {
			t.Fatalf("batch=%v %v", batch, err)
		}
		for _, c := range batch {
			delivered[c.SourceID] = true
		}
	}
	if len(delivered) != 6 {
		t.Fatalf("held candidates starved new/backlog: %v", delivered)
	}
	// Idempotent overlap cannot replace payloads, create duplicates or regress.
	if err := db.CommitIngestion("stream", at.Add(-time.Hour), pending); err != nil {
		t.Fatal(err)
	}
	state, err := db.GetScraperState("stream")
	if err != nil || !state.LastPoll.Equal(at.Add(time.Second)) {
		t.Fatalf("watermark regressed: %+v %v", state, err)
	}
	var n int
	if err = db.db.QueryRow(`SELECT COUNT(*) FROM ingestion_candidates`).Scan(&n); err != nil || n != 6 {
		t.Fatalf("retry duplicated candidates: %d %v", n, err)
	}
	if err := db.MarkSeenRevision("held-0", "stream", "held", "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.NextIngestionCandidates(20); err != nil {
		t.Fatal(err)
	}
	if err = db.db.QueryRow(`SELECT COUNT(*) FROM ingestion_candidates WHERE source_id='held-0'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("completed candidate retained: %d %v", n, err)
	}
}

func TestIngestionDeliveryBoundsPayloadMemoryWithoutDroppingCandidates(t *testing.T) {
	db, err := Open(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	payload := strings.Repeat("x", 3<<20)
	if err := db.CommitIngestion("stream", time.Now(), []IngestionCandidate{{SourceID: "one", Revision: "r", Payload: payload}, {SourceID: "two", Revision: "r", Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	batch, err := db.NextIngestionCandidates(200)
	if err != nil || len(batch) != 1 {
		t.Fatalf("delivery accumulated oversized payload batch: count=%d err=%v", len(batch), err)
	}
	next, err := db.NextIngestionCandidates(200)
	if err != nil || len(next) != 1 || next[0].SourceID == batch[0].SourceID {
		t.Fatalf("bounded delivery starved remaining candidate: %+v %v", next, err)
	}
}

func TestIngestionDeliveryServicesHeldAndFreshUnderContinuousArrivals(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		limit, freshCount, heldBytes, freshBytes int
	}{
		{"count saturated", 200, 200, 4, 4},
		{"single candidate count", 1, 1, 4, 4},
		{"byte saturated", 200, 1, 4, 4 << 20},
		{"oversized held candidate", 200, 1, 5 << 20, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := Open(t.TempDir() + "/queue.db")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.CommitIngestion("stream", time.Now(), []IngestionCandidate{{SourceID: "held", Source: "stream", Revision: "r", Payload: strings.Repeat("h", tc.heldBytes)}}); err != nil {
				t.Fatal(err)
			}
			initial, err := db.NextIngestionCandidates(tc.limit)
			if err != nil || len(initial) != 1 {
				t.Fatalf("initial delivery count=%d err=%v", len(initial), err)
			}
			heldDeliveries, freshDeliveries := 0, 0
			for round := 0; round < 5; round++ {
				var fresh []IngestionCandidate
				for i := 0; i < tc.freshCount; i++ {
					fresh = append(fresh, IngestionCandidate{SourceID: fmt.Sprintf("fresh-%d-%d", round, i), Source: "stream", Revision: "r", Payload: strings.Repeat("f", tc.freshBytes)})
				}
				if err := db.CommitIngestion("stream", time.Now(), fresh); err != nil {
					t.Fatal(err)
				}
				batch, err := db.NextIngestionCandidates(tc.limit)
				if err != nil {
					t.Fatal(err)
				}
				totalBytes := 0
				for _, c := range batch {
					totalBytes += len(c.Payload)
					if c.SourceID == "held" {
						heldDeliveries++
						continue
					}
					freshDeliveries++
					if err := db.MarkSeenRevision(c.SourceID, c.Source, "fresh", "r"); err != nil {
						t.Fatal(err)
					}
				}
				if len(batch) > tc.limit || (totalBytes > 4<<20 && len(batch) != 1) {
					t.Fatalf("delivery exceeded count/byte bound: count=%d bytes=%d", len(batch), totalBytes)
				}
			}
			if heldDeliveries < 2 || freshDeliveries == 0 {
				t.Fatalf("continuous arrivals starved a class: held deliveries=%d fresh deliveries=%d", heldDeliveries, freshDeliveries)
			}
		})
	}
}

func TestIngestionMigrationCreatesDurableQueue(t *testing.T) {
	path := t.TempDir() + "/queue.db"
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`INSERT INTO ingestion_candidates(source_id,revision,source,payload,payload_bytes,queued_at) VALUES('pending','r','stream','payload',7,'2026-11-15T09:00:00Z')`); err != nil {
		_ = db.Close()
		t.Fatalf("migration did not create durable queue: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var payload string
	if err := db.db.QueryRow(`SELECT payload FROM ingestion_candidates WHERE source_id='pending' AND revision='r'`).Scan(&payload); err != nil || payload != "payload" {
		t.Fatalf("migration lost existing queued work: payload=%q err=%v", payload, err)
	}
	var index string
	if err := db.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='ingestion_delivery_fair'`).Scan(&index); err != nil {
		t.Fatalf("fair retry index missing: %v", err)
	}
}
