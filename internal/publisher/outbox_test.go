package publisher

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func outboxTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func outboxBriefYAML(id, title string) string {
	return fmt.Sprintf(`id: %q
slug: "2026-02-20-%s"
title: %q
summary: "A test"
content: |
  ## Overview
  This security notice records the reported issue for analyst review.

  ## Recommendation
  Review the cited advisory and assess the affected assets before remediation.
severity: "high"
published_at: "2026-02-20T10:00:00Z"
`, id, id, title)
}

func outboxIDs(t *testing.T, db *storage.DB) map[string]int64 {
	t.Helper()
	rows, err := db.ListPublishOutbox()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, r := range rows {
		ids[r.ID] = r.Seq
	}
	return ids
}

func TestOutboxRestoresPendingAfterRestart(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	for _, id := range []string{"brief-a", "brief-b"} {
		if err := p.Publish(outboxBriefYAML(id, "Title "+id)); err != nil {
			t.Fatal(err)
		}
	}

	_, fresh := newFakeFeedRepo(t)
	fresh.outbox = db
	n, err := fresh.RestoreOutbox()
	if err != nil || n != 2 {
		t.Fatalf("RestoreOutbox = %d, %v", n, err)
	}
	if len(fresh.pending) != 2 || fresh.pending[0].ID != "brief-a" || fresh.pending[1].ID != "brief-b" {
		t.Fatalf("pending = %+v", fresh.pending)
	}
	if got := outboxIDs(t, db); len(got) != 2 {
		t.Fatalf("restore changed outbox: %v", got)
	}
}

func TestOutboxSuccessfulFlushRemovesRows(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox = db
	p.UseSegmented = true
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1"})
	if err := p.Publish(outboxBriefYAML("brief-a", "A")); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := outboxIDs(t, db); len(got) != 0 {
		t.Fatalf("outbox after flush: %v", got)
	}
}

func TestOutboxFailedFlushKeepsRows(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	p.UseSegmented = true
	p.apiURL = "http://127.0.0.1:1" // unreachable
	if err := p.Publish(outboxBriefYAML("brief-a", "A")); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err == nil {
		t.Fatal("expected flush failure")
	}
	if got := outboxIDs(t, db); len(got) != 1 {
		t.Fatalf("outbox after failed flush: %v", got)
	}
}

func TestOutboxRebufferedDuringFlushKeepsRow(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	if err := p.Publish(outboxBriefYAML("brief-a", "old")); err != nil {
		t.Fatal(err)
	}
	flushed := p.outboxSnapshot()
	if err := p.Publish(outboxBriefYAML("brief-a", "new")); err != nil {
		t.Fatal(err)
	}
	p.clearOutbox(flushed)
	rows, err := db.ListPublishOutbox()
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %v, %v", rows, err)
	}
	if rows[0].Payload != outboxBriefYAML("brief-a", "new") {
		t.Fatalf("kept stale snapshot: %q", rows[0].Payload)
	}
}

func TestOutboxRejectedRevisionRemovesRow(t *testing.T) {
	db := outboxTestDB(t)
	_, p, _, badUpdate, _ := rejectionFixture(t, NewChangelog())
	p.outbox = db
	p.persistOutbox("brief-bad", storage.OutboxKindBrief, "yaml")
	p.pending = []BundleBrief{badUpdate}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	if got := outboxIDs(t, db); len(got) != 0 {
		t.Fatalf("rejected brief still in outbox: %v", got)
	}
}

type failingOutbox struct{ OutboxStore }

func (failingOutbox) UpsertPublishOutbox(string, string, string) (int64, error) {
	return 0, errors.New("disk full")
}

func TestOutboxWriteFailureDoesNotAcknowledgeBrief(t *testing.T) {
	_, p := newFakeFeedRepo(t)
	p.outbox = failingOutbox{}
	if err := p.Publish(outboxBriefYAML("brief-a", "A")); err == nil {
		t.Fatal("acknowledged a brief without its configured durable write")
	}
	if len(p.pending) != 0 {
		t.Fatalf("pending = %v", p.pending)
	}
}

func TestOutboxRestoresDigests(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	d := BundleDigest{ID: "daily-2026-02-20", Type: "daily_digest", Period: "2026-02-20"}
	p.bufferDigest(d)
	p.persistOutbox(d.ID, storage.OutboxKindDigest, `{"id":"daily-2026-02-20","type":"daily_digest","period":"2026-02-20"}`)

	_, fresh := newFakeFeedRepo(t)
	fresh.outbox = db
	if _, err := fresh.RestoreOutbox(); err != nil {
		t.Fatal(err)
	}
	if len(fresh.pendingDigests) != 1 || fresh.pendingDigests[0].ID != d.ID || len(fresh.pending) != 0 {
		t.Fatalf("digests = %+v briefs = %+v", fresh.pendingDigests, fresh.pending)
	}
}

func TestNewHasNoOutboxByDefault(t *testing.T) {
	_, p := newFakeFeedRepo(t)
	cli := New("o/r", testPublicKey, func() string { return "" }, p.logger)
	if cli.outbox != nil {
		t.Fatal("CLI publisher must not have an outbox")
	}
	if n, err := cli.RestoreOutbox(); n != 0 || err != nil {
		t.Fatalf("RestoreOutbox without outbox = %d, %v", n, err)
	}
	if New("o/r", testPublicKey, func() string { return "" }, p.logger, WithOutbox(outboxTestDB(t))).outbox == nil {
		t.Fatal("WithOutbox not applied")
	}
}

// upsertFailer fails UpsertPublishOutbox while fail is set.
type upsertFailer struct {
	OutboxStore
	fail bool
}

func (u *upsertFailer) UpsertPublishOutbox(id, kind, payload string) (int64, error) {
	if u.fail {
		return 0, errors.New("disk full")
	}
	return u.OutboxStore.UpsertPublishOutbox(id, kind, payload)
}

func TestOutboxFailedRepublishKeepsOlderRowUntilAcknowledged(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	store := &upsertFailer{OutboxStore: db}
	p.outbox = store
	if err := p.Publish(outboxBriefYAML("brief-a", "old")); err != nil {
		t.Fatal(err)
	}
	store.fail = true
	if err := p.Publish(outboxBriefYAML("brief-a", "new")); err == nil {
		t.Fatal("acknowledged a failed durable replacement")
	}
	if len(p.pending) != 1 || p.pending[0].Title != "old" || len(outboxIDs(t, db)) != 1 {
		t.Fatal("failed replacement changed the older queued snapshot")
	}
	p.clearOutbox(p.outboxSnapshot())
	if got := outboxIDs(t, db); len(got) != 0 {
		t.Fatalf("older row orphaned: %v", got)
	}
}

func TestOutboxRestoreDeletesInvalidRow(t *testing.T) {
	db := outboxTestDB(t)
	if _, err := db.UpsertPublishOutbox("brief-bad", storage.OutboxKindBrief, `title: "no id"`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpsertPublishOutbox("brief-a", storage.OutboxKindBrief, outboxBriefYAML("brief-a", "A")); err != nil {
		t.Fatal(err)
	}
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	n, err := p.RestoreOutbox()
	if err != nil || n != 1 {
		t.Fatalf("RestoreOutbox = %d, %v", n, err)
	}
	got := outboxIDs(t, db)
	if _, ok := got["brief-bad"]; ok || len(got) != 1 {
		t.Fatalf("invalid row kept: %v", got)
	}
}

func TestFlushIsolatesIncomingIdentityCollisions(t *testing.T) {
	// A colliding slug is repaired before first publication; only event_id
	// collisions are rejected at this stage (slug collisions in MergeBriefs are
	// covered by TestMergeBriefsIsolatesIncomingCollisionButNotExisting).
	for name, mutate := range map[string]func(b *BundleBrief, good BundleBrief){
		"event_id": func(b *BundleBrief, good BundleBrief) { b.EventID = good.EventID },
	} {
		t.Run(name, func(t *testing.T) {
			db := outboxTestDB(t)
			repo, p, key, _, good := rejectionFixture(t, NewChangelog())
			p.outbox = db
			collide := BundleBrief{ID: "brief-collide", EventID: "brief-collide", Slug: key + "-collide", Title: "Collide", PublishedAt: good.PublishedAt}
			mutate(&collide, good)
			fresh := BundleBrief{ID: "brief-fresh", EventID: "brief-fresh", Slug: key + "-fresh", Title: "Fresh", PublishedAt: good.PublishedAt}
			p.persistOutbox(collide.ID, storage.OutboxKindBrief, "yaml")
			p.pending = []BundleBrief{collide, fresh}
			if err := p.FlushSegmented(); err != nil {
				t.Fatalf("flush aborted: %v", err)
			}
			if got := p.RejectedBriefIDs(); len(got) != 1 || got[0] != "brief-collide" {
				t.Fatalf("RejectedBriefIDs = %v", got)
			}
			if got := outboxIDs(t, db); len(got) != 0 {
				t.Fatalf("rejected row kept: %v", got)
			}
			ids := map[string]bool{}
			for _, b := range repo.segment(t, key).Briefs {
				ids[b.ID] = true
			}
			if !ids["brief-fresh"] || ids["brief-collide"] {
				t.Fatalf("segment briefs = %v", ids)
			}
		})
	}
}

func TestMergeBriefsIsolatesIncomingCollisionButNotExisting(t *testing.T) {
	now := time.Now().UTC()
	a := BundleBrief{ID: "a", EventID: "a", Slug: "s-a", PublishedAt: now.Format(time.RFC3339)}
	dup := BundleBrief{ID: "b", EventID: "b", Slug: "S-A", PublishedAt: now.Format(time.RFC3339)}
	_, err := MergeBriefs([]BundleBrief{a}, []BundleBrief{dup}, now)
	var rejected *RevisionRejectedError
	if !errors.As(err, &rejected) || rejected.BriefID != "b" {
		t.Fatalf("incoming collision not typed: %v", err)
	}
	if err.Error() != `slug "S-A" already belongs to brief "a"` {
		t.Fatalf("message changed: %q", err)
	}
	_, err = MergeBriefs([]BundleBrief{a, dup}, nil, now)
	if err == nil || errors.As(err, &rejected) {
		t.Fatalf("existing-data collision must abort untyped: %v", err)
	}
}

func TestRetirementWriteFailureKeepsPreviousQueuedSnapshot(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	store := &upsertFailer{OutboxStore: db}
	p.outbox = store
	if err := p.RetireBriefForDrafts("old", "old-slug", "canonical", "draft", "canonical-draft"); err != nil {
		t.Fatal(err)
	}
	store.fail = true
	if err := p.RetireBriefForDrafts("old", "new-slug", "different", "draft", "different-draft"); err == nil {
		t.Fatal("acknowledged retirement without durable write")
	}
	if p.pendingRetirements["old"] != "old-slug" || p.retiredInFavourOf["old"] != "canonical" {
		t.Fatal("failed retirement overwrote acknowledged state")
	}
}

func TestDigestWriteFailureDoesNotAcknowledgeOrPublish(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC()
	draft := storage.Draft{ID: "digest-draft", Status: storage.StatusApproved, Score: 8, Source: "synthetic", BriefYAML: outboxBriefYAML("digest-brief", "Synthetic brief"), CreatedAt: now}
	if err := db.CreateDraft(&draft); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateDraftStatus(draft.ID, storage.StatusApproved, ""); err != nil {
		t.Fatal(err)
	}
	p.outbox = failingOutbox{}
	if err := p.PublishDigest(context.Background(), db, DigestConfig{Now: now}); err == nil {
		t.Fatal("acknowledged digest without durable write")
	}
	if len(p.pendingDigests) != 0 {
		t.Fatal("failed digest write changed pending state")
	}
	for path := range repo.files {
		if strings.HasPrefix(path, "output/digests/") {
			t.Fatal("published digest before durable enqueue")
		}
	}
}
