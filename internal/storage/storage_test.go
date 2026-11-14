package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"path/filepath"
	"testing"
	"time"
)

func collectDrafts(t *testing.T, drafts iter.Seq2[*Draft, error]) []*Draft {
	t.Helper()
	var out []*Draft
	for d, err := range drafts {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func requireBlockedByHeldSQLiteLock(t *testing.T, started <-chan struct{}, done <-chan error) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("database operation did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("database operation completed while the write lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWriteWaitsForShortLivedContention(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	blocker, err := db.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	if _, err := blocker.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = blocker.ExecContext(ctx, "ROLLBACK")
	}()

	writeStarted := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		close(writeStarted)
		writeDone <- db.MarkSeen("contended-source", "test", "Contended write")
	}()

	// The writer must wait for this short-lived lock rather than immediately
	// failing the scrape with SQLITE_BUSY / "database is locked".
	requireBlockedByHeldSQLiteLock(t, writeStarted, writeDone)
	if _, err := blocker.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write failed during short-lived contention: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write did not resume after the lock was released")
	}
}

func TestReseedSourceRewindsPollAndOnlyClearsRequestedItem(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, id := range []string{"oss-security:first", "oss-security:second", "other:item"} {
		source := "oss-security"
		if id == "other:item" {
			source = "other"
		}
		if err := db.MarkSeen(id, source, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SaveScraperState("oss-security", time.Now().UTC(), "old-cursor"); err != nil {
		t.Fatal(err)
	}
	since := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	removed, err := db.ReseedSource("oss-security", since, "oss-security:first")
	if err != nil || removed != 1 {
		t.Fatalf("ReseedSource removed=%d err=%v", removed, err)
	}
	for id, want := range map[string]bool{"oss-security:first": false, "oss-security:second": true, "other:item": true} {
		got, err := db.HasSeen(id)
		if err != nil || got != want {
			t.Fatalf("HasSeen(%q)=%v err=%v, want %v", id, got, err, want)
		}
	}
	state, err := db.GetScraperState("oss-security")
	if err != nil || state == nil || !state.LastPoll.Equal(since) || state.Cursor != "" {
		t.Fatalf("scraper state=%+v err=%v, want last_poll=%s and empty cursor", state, err, since)
	}
}

func TestQueueReplayKeepsItemPendingUntilSeenAgain(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, id := range []string{"ghsa:GHSA-first", "ghsa:GHSA-second"} {
		if err := db.MarkSeen(id, "ghsa", id); err != nil {
			t.Fatal(err)
		}
	}
	// Queueing again replaces the stored item instead of failing.
	for _, itemJSON := range []string{`{"SourceID":"ghsa:GHSA-first","Title":"old"}`, `{"SourceID":"ghsa:GHSA-first","Title":"new"}`} {
		if err := db.QueueReplay("ghsa", "ghsa:GHSA-first", itemJSON); err != nil {
			t.Fatal(err)
		}
	}
	for id, want := range map[string]bool{"ghsa:GHSA-first": false, "ghsa:GHSA-second": true} {
		got, err := db.HasSeen(id)
		if err != nil || got != want {
			t.Fatalf("HasSeen(%q)=%v err=%v, want %v", id, got, err, want)
		}
	}
	pending, err := db.PendingReplays(time.Now().Add(-time.Hour))
	if err != nil || len(pending) != 1 || pending[0] != `{"SourceID":"ghsa:GHSA-first","Title":"new"}` {
		t.Fatalf("pending=%q err=%v, want the latest queued item", pending, err)
	}

	// Processing marks the item seen again, which completes its replay.
	if err := db.MarkSeen("ghsa:GHSA-first", "ghsa", "new"); err != nil {
		t.Fatal(err)
	}
	pending, err = db.PendingReplays(time.Now().Add(-time.Hour))
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending=%q err=%v, want none after the item was seen", pending, err)
	}
}

func TestPendingReplaysDropsExpiredItems(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueueReplay("nvd", "nvd:CVE-2026-118252", `{"SourceID":"nvd:CVE-2026-118252"}`); err != nil {
		t.Fatal(err)
	}
	// A cutoff after the queue time expires the item for good.
	for _, cutoff := range []time.Time{time.Now().Add(time.Minute), time.Now().Add(-time.Hour)} {
		pending, err := db.PendingReplays(cutoff)
		if err != nil || len(pending) != 0 {
			t.Fatalf("PendingReplays(%s)=%q err=%v, want the expired item gone", cutoff, pending, err)
		}
	}
}

func TestOpenRejectsReservedSQLiteOptions(t *testing.T) {
	tests := map[string]string{
		"transaction lock":       "_txlock=deferred",
		"busy timeout pragma":    "_pragma=busy_timeout%281%29",
		"foreign keys pragma":    "_pragma=foreign_keys%28OFF%29",
		"busy timeout shorthand": "_busy_timeout=1",
		"timeout alias":          "_timeout=1",
		"foreign keys shorthand": "_foreign_keys=off",
		"foreign keys alias":     "_fk=off",
	}

	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db") + "?" + query)
			if db != nil {
				_ = db.Close()
			}
			if err == nil {
				t.Fatalf("Open accepted application-managed SQLite option %q", query)
			}
		})
	}
}

func TestOpenAllowsUnmanagedSQLiteOptions(t *testing.T) {
	tests := map[string]string{
		"cache size":           "_pragma=cache_size%28123%29",
		"deferred constraints": "_pragma=defer_foreign_keys%28ON%29",
	}
	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db") + "?" + query)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
		})
	}
}

func TestOpenConfiguresEveryConnection(t *testing.T) {
	const wantBusyTimeout = 5 * time.Second

	db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	conn1, err := db.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	conn2, err := db.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	for i, conn := range []*sql.Conn{conn1, conn2} {
		var busyTimeout, foreignKeys int
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatalf("connection %d busy_timeout: %v", i+1, err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatalf("connection %d foreign_keys: %v", i+1, err)
		}
		if busyTimeout != int(wantBusyTimeout/time.Millisecond) {
			t.Errorf("connection %d busy_timeout = %d, want %d", i+1, busyTimeout, wantBusyTimeout/time.Millisecond)
		}
		if foreignKeys != 1 {
			t.Errorf("connection %d foreign_keys = %d, want 1", i+1, foreignKeys)
		}
	}
}

func TestReadWriteTransactionDoesNotLoseWriteLockRace(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.MarkSeen("transaction-row", "test", "before"); err != nil {
		t.Fatal(err)
	}

	tx, err := db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	var title string
	if err := tx.QueryRow("SELECT title FROM seen_items WHERE source_id = ?", "transaction-row").Scan(&title); err != nil {
		t.Fatal(err)
	}

	competingWriteStarted := make(chan struct{})
	competingWrite := make(chan error, 1)
	go func() {
		close(competingWriteStarted)
		competingWrite <- db.MarkSeen("competing-row", "test", "competing")
	}()

	requireBlockedByHeldSQLiteLock(t, competingWriteStarted, competingWrite)

	if _, err := tx.Exec("UPDATE seen_items SET title = ? WHERE source_id = ?", "after", "transaction-row"); err != nil {
		t.Fatalf("read/write transaction lost the write-lock race: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-competingWrite:
		if err != nil {
			t.Fatalf("competing write did not resume: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("competing write did not resume after transaction committed")
	}
}

func TestSeenItems(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	seen, err := db.HasSeen("test-source-1")
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Error("should not be seen yet")
	}

	if err := db.MarkSeen("test-source-1", "sigma-hq", "Test Rule"); err != nil {
		t.Fatal(err)
	}

	seen, err = db.HasSeen("test-source-1")
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("should be seen")
	}
}

func TestLLMCache(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, ok, err := db.GetLLMCache("missing"); err != nil || ok {
		t.Fatalf("missing cache entry = ok %v, err %v", ok, err)
	}
	if err := db.PutLLMCache("key", `{"score":4}`); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.GetLLMCache("key")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got != `{"score":4}` {
		t.Fatalf("cache entry = %q, %v", got, ok)
	}
}

func TestQuarantinePipelineItemIsDurableAndIdempotent(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.QuarantinePipelineItem("source-1", "feed", "Broken brief", "bad: \\q", "unknown escape"); err != nil {
		t.Fatal(err)
	}
	if err := db.QuarantinePipelineItem("source-1", "feed", "Broken brief", "replacement", "second error"); err != nil {
		t.Fatal(err)
	}

	var count int
	var raw string
	if err := db.db.QueryRow(`SELECT COUNT(*), raw_output FROM pipeline_quarantine WHERE source_id = ?`, "source-1").Scan(&count, &raw); err != nil {
		t.Fatal(err)
	}
	if count != 1 || raw != "bad: \\q" {
		t.Fatalf("quarantine count=%d raw=%q, want one durable first failure", count, raw)
	}
}

func TestDrafts(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	d := &Draft{
		ID:        "draft-1",
		Status:    StatusPending,
		Score:     4.2,
		Source:    "cisa",
		SourceIDs: `["src-1","src-2"]`,
		BriefYAML: "title: Test Brief\n",
		CreatedAt: time.Now(),
	}
	if err := db.CreateDraft(d); err != nil {
		t.Fatal(err)
	}

	drafts := collectDrafts(t, db.DraftsWithStatus(StatusPending))
	if len(drafts) != 1 {
		t.Fatalf("expected 1 draft, got %d", len(drafts))
	}
	if drafts[0].ID != "draft-1" {
		t.Errorf("expected draft-1, got %s", drafts[0].ID)
	}

	got, err := db.GetDraft("draft-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Score != 4.2 {
		t.Errorf("expected score 4.2, got %f", got.Score)
	}

	if err := db.UpdateDraftStatus("draft-1", StatusApproved, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateDraftStatus("missing-draft", StatusRejected, "superseded"); err == nil {
		t.Fatal("missing draft status update silently succeeded")
	}
	got, _ = db.GetDraft("draft-1")
	if got.Status != StatusApproved {
		t.Errorf("expected approved, got %s", got.Status)
	}

	drafts = collectDrafts(t, db.DraftsWithStatus(StatusPending))
	if len(drafts) != 0 {
		t.Errorf("expected 0 pending, got %d", len(drafts))
	}
}

func TestDraftValidationNotes(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	draft := &Draft{
		ID:              "draft-test-notes",
		Status:          StatusPending,
		Score:           4.0,
		Source:          "test",
		BriefYAML:       "title: test",
		ValidationNotes: `["removed invalid tactic TA0099","stripped null iocs"]`,
		CreatedAt:       time.Now(),
	}

	if err := db.CreateDraft(draft); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetDraft("draft-test-notes")
	if err != nil {
		t.Fatal(err)
	}
	if got.ValidationNotes != draft.ValidationNotes {
		t.Errorf("ValidationNotes = %q, want %q", got.ValidationNotes, draft.ValidationNotes)
	}
}

func TestApplyEditorialCorrectionCapturesPreviousStateAndMetadata(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.CreateDraft(&Draft{ID: "approved", Status: StatusApproved, BriefYAML: "old", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	oldEvent := UpdateEvent{At: time.Date(2026, 10, 1, 1, 2, 3, 0, time.UTC), Level: "L1", Summary: "old contaminated event", Sources: []string{"test"}}
	if err := db.RecordDraftUpdate("approved", "old", oldEvent); err != nil {
		t.Fatal(err)
	}
	before, err := db.GetDraft("approved")
	if err != nil {
		t.Fatal(err)
	}
	newAt := time.Date(2026, 10, 2, 2, 3, 4, 0, time.UTC)
	correction := EditorialCorrection{
		DraftID: "approved", BriefID: "brief-1", PreviousYAML: "old", RevisedYAML: "new",
		RevisedLastmod: &newAt, RevisedUpdateLog: `[ { "at": "2026-10-02T02:03:04Z", "level": "L1", "summary": "verified update", "sources": ["test"] } ]`,
		RevisedUpdateCount: 1, Operator: "analyst@example.com", Reason: "Correct false mapping", BackupPath: "/tmp/approved-old.yaml",
	}
	if err := db.ApplyEditorialCorrection(correction); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetDraft("approved")
	if err != nil || got.BriefYAML != "new" || got.Lastmod == nil || !got.Lastmod.Equal(newAt) || got.UpdateCount != 1 || got.UpdateLog != correction.RevisedUpdateLog {
		t.Fatalf("updated draft: %+v, %v", got, err)
	}
	var priorYAML, priorLog, operator, reason string
	var priorCount int
	if err := db.db.QueryRow(`SELECT previous_yaml, previous_update_log, previous_update_count, operator, reason FROM draft_editorial_corrections WHERE draft_id = ?`, "approved").Scan(&priorYAML, &priorLog, &priorCount, &operator, &reason); err != nil {
		t.Fatal(err)
	}
	if priorYAML != "old" || priorLog != before.UpdateLog || priorCount != before.UpdateCount || operator != correction.Operator || reason != correction.Reason {
		t.Fatalf("audit = %q, %q, %d, %q, %q", priorYAML, priorLog, priorCount, operator, reason)
	}
	if _, err := db.db.Exec(`UPDATE draft_editorial_corrections SET reason = 'tampered' WHERE draft_id = ?`, "approved"); err == nil {
		t.Fatal("audit update must be rejected")
	}
	if _, err := db.db.Exec(`DELETE FROM draft_editorial_corrections WHERE draft_id = ?`, "approved"); err == nil {
		t.Fatal("audit deletion must be rejected")
	}
}

func TestApplyEditorialCorrectionRejectsStaleAndRollsBackAuditFailure(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, draft := range []*Draft{
		{ID: "approved", Status: StatusApproved, BriefYAML: "old", CreatedAt: time.Now()},
		{ID: "pending", Status: StatusPending, BriefYAML: "old", CreatedAt: time.Now()},
	} {
		if err := db.CreateDraft(draft); err != nil {
			t.Fatal(err)
		}
	}
	base := EditorialCorrection{DraftID: "approved", BriefID: "brief-1", PreviousYAML: "old", RevisedYAML: "new", Operator: "analyst", Reason: "Correct false mapping", BackupPath: "/tmp/backup.yaml"}
	stale := base
	stale.PreviousYAML = "wrong"
	if err := db.ApplyEditorialCorrection(stale); err == nil {
		t.Fatal("stale YAML must not be overwritten")
	}
	pending := base
	pending.DraftID = "pending"
	if err := db.ApplyEditorialCorrection(pending); err == nil {
		t.Fatal("pending draft must not be amended")
	}
	var count int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM draft_editorial_corrections`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unexpected audit records: %d, %v", count, err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER fail_editorial_insert BEFORE INSERT ON draft_editorial_corrections BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyEditorialCorrection(base); err == nil {
		t.Fatal("expected audit write failure")
	}
	got, err := db.GetDraft("approved")
	if err != nil || got.BriefYAML != "old" {
		t.Fatalf("audit failure changed draft: %+v, %v", got, err)
	}
}

func TestScraperState(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	state, err := db.GetScraperState("sigma-hq")
	if err != nil {
		t.Fatal(err)
	}
	if state != nil {
		t.Error("should be nil for unknown source")
	}

	now := time.Now().Truncate(time.Second)
	if err := db.SaveScraperState("sigma-hq", now, "abc123"); err != nil {
		t.Fatal(err)
	}

	state, err = db.GetScraperState("sigma-hq")
	if err != nil {
		t.Fatal(err)
	}
	if state == nil {
		t.Fatal("expected state")
	}
	if state.Cursor != "abc123" {
		t.Errorf("expected cursor abc123, got %s", state.Cursor)
	}
}

func TestScraperLastPollAcceptsPostgresTextTimestamp(t *testing.T) {
	var scanned scraperLastPoll
	if err := scanned.Scan("2026-11-04 16:39:37.123456+00"); err != nil {
		t.Fatalf("Scan PostgreSQL timestamp: %v", err)
	}
	want := time.Date(2026, time.November, 4, 16, 39, 37, 123456000, time.UTC)
	if got := time.Time(scanned); !got.Equal(want) {
		t.Fatalf("scanned timestamp = %s, want %s", got, want)
	}
}

func TestScraperLastPollAcceptsDuplicatedSQLiteTimezone(t *testing.T) {
	var scanned scraperLastPoll
	if err := scanned.Scan("2026-10-30 09:30:12.3875448 +0900 +0900"); err != nil {
		t.Fatalf("Scan duplicated SQLite timezone: %v", err)
	}
	want := time.Date(2026, time.October, 30, 9, 30, 12, 387544800, time.FixedZone("", 9*60*60))
	if got := time.Time(scanned); !got.Equal(want) {
		t.Fatalf("scanned timestamp = %s, want %s", got, want)
	}
}

func TestScraperLastPollRejectsConflictingDuplicatedSQLiteTimezone(t *testing.T) {
	var scanned scraperLastPoll
	if err := scanned.Scan("2026-10-30 09:30:12.3875448 +0900 +0800"); err == nil {
		t.Fatal("expected conflicting duplicated SQLite timezones to be rejected")
	}
}

func TestGoldenExamples(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.AddGoldenExample("T1566", "spearphishing email observed", "cisa"); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Idempotent on (technique, evidence): second insert must not duplicate.
	if err := db.AddGoldenExample("T1566", "spearphishing email observed", "cisa"); err != nil {
		t.Fatalf("add 2: %v", err)
	}
	got, err := db.GoldenExamples()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 golden example, got %d", len(got))
	}
	if got[0].Technique != "T1566" || got[0].Evidence == "" {
		t.Errorf("unexpected example: %+v", got[0])
	}
}

func TestDigestCluster(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	digestID := "daily-2026-04-06"
	now := time.Now().Truncate(time.Second)

	// Save first cluster
	c1 := DigestCluster{
		DigestID:   digestID,
		ClusterKey: "cluster-1",
		BriefIDs:   `["brief-1","brief-2"]`,
		Summary:    "First cluster summary",
		CreatedAt:  now,
	}
	if err := db.SaveDigestCluster(c1); err != nil {
		t.Fatal(err)
	}

	// Save second cluster
	c2 := DigestCluster{
		DigestID:   digestID,
		ClusterKey: "cluster-2",
		BriefIDs:   `["brief-3"]`,
		Summary:    "Second cluster summary",
		CreatedAt:  now,
	}
	if err := db.SaveDigestCluster(c2); err != nil {
		t.Fatal(err)
	}

	// List clusters
	clusters, err := db.ListDigestClusters(digestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(clusters))
	}

	// Verify cluster order and content
	if clusters[0].ClusterKey != "cluster-1" {
		t.Errorf("expected cluster-1, got %s", clusters[0].ClusterKey)
	}
	if clusters[1].ClusterKey != "cluster-2" {
		t.Errorf("expected cluster-2, got %s", clusters[1].ClusterKey)
	}

	// Upsert cluster-1 with updated data
	c1Updated := DigestCluster{
		DigestID:   digestID,
		ClusterKey: "cluster-1",
		BriefIDs:   `["brief-1","brief-2","brief-4"]`,
		Summary:    "Updated cluster 1 summary",
		CreatedAt:  now,
	}
	if err := db.SaveDigestCluster(c1Updated); err != nil {
		t.Fatal(err)
	}

	// List again and verify update
	clusters, err = db.ListDigestClusters(digestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters after upsert, got %d", len(clusters))
	}

	// Check that the update took effect
	if clusters[0].BriefIDs != `["brief-1","brief-2","brief-4"]` {
		t.Errorf("expected updated brief_ids, got %s", clusters[0].BriefIDs)
	}
	if clusters[0].Summary != "Updated cluster 1 summary" {
		t.Errorf("expected updated summary, got %s", clusters[0].Summary)
	}
}

func TestApprovedDraftsSinceStreamsNewestFirst(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	for _, d := range []*Draft{
		{ID: "old", Status: StatusApproved, Source: "s", BriefYAML: "title: old", CreatedAt: now.AddDate(0, 0, -10)},
		{ID: "newer", Status: StatusApproved, Source: "s", BriefYAML: "title: newer", CreatedAt: now.Add(-2 * time.Hour)},
		{ID: "newest", Status: StatusApproved, Source: "s", BriefYAML: "title: newest", CreatedAt: now.Add(-time.Hour)},
		{ID: "pending", Status: StatusPending, Source: "s", BriefYAML: "title: pending", CreatedAt: now},
	} {
		if err := db.CreateDraft(d); err != nil {
			t.Fatal(err)
		}
	}

	var ids []string
	for _, d := range collectDrafts(t, db.ApprovedDraftsSince(now.AddDate(0, 0, -1))) {
		ids = append(ids, d.ID)
	}
	if len(ids) != 2 || ids[0] != "newest" || ids[1] != "newer" {
		t.Fatalf("approved drafts since yesterday = %v, want [newest newer]", ids)
	}

	// Stopping early releases the rows, so the database stays writable.
	for range db.ApprovedDraftsSince(now.AddDate(0, 0, -30)) {
		break
	}
	if err := db.UpdateDraftStatus("old", StatusRejected, "stale"); err != nil {
		t.Fatalf("update after stopping a draft scan early: %v", err)
	}
}

// Any write to a draft's YAML drops its stored correlation summary, and a
// summary computed from an older YAML is never stored.
func TestDraftCorrelationFollowsBriefYAML(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.CreateDraft(&Draft{ID: "d", Status: StatusApproved, Source: "s", BriefYAML: "title: v1", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	summary := func() string {
		t.Helper()
		for c, err := range db.ApprovedDraftCorrelationsSince(time.Now().AddDate(0, 0, -1)) {
			if err != nil {
				t.Fatal(err)
			}
			return c.Summary
		}
		t.Fatal("draft not listed")
		return ""
	}

	if got := summary(); got != "" {
		t.Fatalf("new draft summary = %q, want none", got)
	}
	if err := db.SaveDraftCorrelation("d", "title: v1", "s1"); err != nil {
		t.Fatal(err)
	}
	if got := summary(); got != "s1" {
		t.Fatalf("summary = %q, want s1", got)
	}
	if err := db.SaveDraftCorrelation("d", "title: v0", "stale"); err != nil {
		t.Fatal(err)
	}
	if got := summary(); got != "s1" {
		t.Fatalf("summary from an older YAML was stored: %q", got)
	}

	if err := db.UpdateDraftYAML("d", "title: v2"); err != nil {
		t.Fatal(err)
	}
	if got := summary(); got != "" {
		t.Fatalf("summary after UpdateDraftYAML = %q, want none", got)
	}
	if err := db.SaveDraftCorrelation("d", "title: v2", "s2"); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordDraftUpdate("d", "title: v3", UpdateEvent{At: time.Now(), Level: "L1", Summary: "merged"}); err != nil {
		t.Fatal(err)
	}
	if got := summary(); got != "" {
		t.Fatalf("summary after RecordDraftUpdate = %q, want none", got)
	}
}

func TestRecordDraftUpdateWithSourceAppendsUniqueProvenance(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.CreateDraft(&Draft{
		ID: "merged", Status: StatusApproved, SourceIDs: `["source:one"]`, BriefYAML: "title: before", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	event := UpdateEvent{At: time.Now().UTC(), Level: "L3", Summary: "confirmed exploitation"}
	if err := db.RecordDraftUpdateWithSource("merged", "title: after", event, "source:two"); err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft("merged")
	if err != nil {
		t.Fatal(err)
	}
	if draft.SourceIDs != `["source:one","source:two"]` {
		t.Fatalf("source IDs = %s", draft.SourceIDs)
	}
	if err := db.RecordDraftUpdateWithSource("merged", "title: after again", event, "source:two"); err != nil {
		t.Fatal(err)
	}
	draft, _ = db.GetDraft("merged")
	if draft.SourceIDs != `["source:one","source:two"]` {
		t.Fatalf("duplicate source ID was appended: %s", draft.SourceIDs)
	}
}

// epssRows yields n synthetic EPSS rows, then err if it is non-nil.
func epssRows(n int, epss float64, err error) iter.Seq2[EPSSRow, error] {
	return func(yield func(EPSSRow, error) bool) {
		for i := range n {
			if !yield(EPSSRow{CVEID: fmt.Sprintf("CVE-2026-%06d", i), EPSS: epss, Percentile: 0.5}, nil) {
				return
			}
		}
		if err != nil {
			yield(EPSSRow{}, err)
		}
	}
}

func requireEPSS(t *testing.T, db *DB, cveID string, want float64, wantFound bool) {
	t.Helper()
	row, found, err := db.EPSSScore(cveID)
	if err != nil {
		t.Fatal(err)
	}
	if found != wantFound || (found && row.EPSS != want) {
		t.Fatalf("%s: found=%v epss=%v, want found=%v epss=%v", cveID, found, row.EPSS, wantFound, want)
	}
}

func requireNoEPSSStaging(t *testing.T, db *DB) {
	t.Helper()
	var n int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name = 'epss_scores_next'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("EPSS staging table left behind")
	}
}

func TestReplaceEPSSScoresAcrossBatches(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.db.SetMaxOpenConns(1) // one connection, so :memory: is one database

	total := 2*epssLoadBatchRows + 345
	n, err := db.ReplaceEPSSScores(epssRows(total, 0.25, nil))
	if err != nil || n != total {
		t.Fatalf("loaded %d rows (err %v), want %d", n, err, total)
	}
	requireEPSS(t, db, "CVE-2026-000000", 0.25, true)
	requireEPSS(t, db, fmt.Sprintf("CVE-2026-%06d", total-1), 0.25, true)

	// A smaller set replaces the whole table.
	if _, err := db.ReplaceEPSSScores(epssRows(100, 0.75, nil)); err != nil {
		t.Fatal(err)
	}
	requireEPSS(t, db, "CVE-2026-000099", 0.75, true)
	requireEPSS(t, db, "CVE-2026-000100", 0, false)
	requireNoEPSSStaging(t, db)
}

// A reload that fails after some batches were committed to staging leaves
// the current scores untouched.
func TestReplaceEPSSScoresKeepsScoresOnError(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.db.SetMaxOpenConns(1)

	if _, err := db.ReplaceEPSSScores(epssRows(100, 0.25, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReplaceEPSSScores(epssRows(epssLoadBatchRows+2000, 0.75, errors.New("download cut off"))); err == nil {
		t.Fatal("expected the failed reload to return its error")
	}
	requireEPSS(t, db, "CVE-2026-000050", 0.25, true)
	requireEPSS(t, db, fmt.Sprintf("CVE-2026-%06d", epssLoadBatchRows), 0, false)
	requireNoEPSSStaging(t, db)
}

func TestPublishOutbox(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	seq1, err := db.UpsertPublishOutbox("a", OutboxKindBrief, "v1")
	if err != nil {
		t.Fatal(err)
	}
	seq2, err := db.UpsertPublishOutbox("a", OutboxKindBrief, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if seq2 <= seq1 {
		t.Fatalf("seq did not advance: %d then %d", seq1, seq2)
	}
	rows, err := db.ListPublishOutbox()
	if err != nil || len(rows) != 1 || rows[0].Payload != "v2" || rows[0].Seq != seq2 {
		t.Fatalf("rows = %+v, %v", rows, err)
	}

	// Stale seq: the newer snapshot stays.
	if err := db.DeletePublishOutboxIfSeq("a", seq1); err != nil {
		t.Fatal(err)
	}
	if rows, _ := db.ListPublishOutbox(); len(rows) != 1 {
		t.Fatalf("stale delete removed row: %+v", rows)
	}
	if err := db.DeletePublishOutboxIfSeq("a", seq2); err != nil {
		t.Fatal(err)
	}
	if rows, _ := db.ListPublishOutbox(); len(rows) != 0 {
		t.Fatalf("matching delete kept row: %+v", rows)
	}
}

func TestGroundingAttemptsCountPerItem(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for want := 1; want <= 3; want++ {
		got, err := db.RecordGroundingAttempt("ghsa:A")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("attempt = %d, want %d", got, want)
		}
	}
	if got, err := db.RecordGroundingAttempt("ghsa:B"); err != nil || got != 1 {
		t.Fatalf("independent item attempt = %d, err=%v, want 1", got, err)
	}
}
