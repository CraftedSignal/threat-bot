package publisher

import (
	"slices"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

// restartedPublisher is a new process against the same feed repo and outbox.
func restartedPublisher(old *Publisher, db *storage.DB) *Publisher {
	return &Publisher{
		repoSlug: old.repoSlug, publicKey: old.publicKey, tokenFn: old.tokenFn,
		apiURL: old.apiURL, client: old.client, logger: old.logger,
		outbox: db, UseSegmented: true,
	}
}

func retirementRows(t *testing.T, db *storage.DB) []storage.OutboxRow {
	t.Helper()
	rows, err := db.ListPublishOutbox()
	if err != nil {
		t.Fatal(err)
	}
	var out []storage.OutboxRow
	for _, r := range rows {
		if r.Kind == storage.OutboxKindRetirement {
			out = append(out, r)
		}
	}
	return out
}

func TestRetirementSurvivesRestartAndRemovesDuplicate(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox = db
	p.UseSegmented = true
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	canonical := BundleBrief{ID: "brief-canon", EventID: "brief-canon", Slug: key + "-canon", Title: "Canon", PublishedAt: now.Format(time.RFC3339)}
	dup := BundleBrief{ID: "brief-dup", EventID: "brief-dup", Slug: key + "-dup", Title: "Dup", PublishedAt: now.Format(time.RFC3339)}
	repo.putSegment(t, key, canonical, dup)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 2}}})
	repo.putJSON(t, changelogPath, NewChangelog())

	// The crashed process queued the retirement; nothing was flushed.
	if err := p.RetireBriefForDrafts(dup.ID, dup.Slug, canonical.ID, "draft-dup", "draft-canon"); err != nil {
		t.Fatal(err)
	}
	if rows := retirementRows(t, db); len(rows) != 1 {
		t.Fatalf("retirement not persisted: %+v", rows)
	}

	fresh := restartedPublisher(p, db)
	var applied []Retirement
	fresh.retirementApplied = func(r Retirement) error { applied = append(applied, r); return nil }
	n, err := fresh.RestoreOutbox()
	if err != nil || n != 1 {
		t.Fatalf("RestoreOutbox = %d, %v; want 1 restored retirement", n, err)
	}
	if err := fresh.Flush(); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, b := range repo.segment(t, key).Briefs {
		ids = append(ids, b.ID)
	}
	if !slices.Equal(ids, []string{"brief-canon"}) {
		t.Fatalf("segment briefs = %v, want only canonical", ids)
	}
	if rows := retirementRows(t, db); len(rows) != 0 {
		t.Fatalf("outbox not emptied: %+v", rows)
	}
	want := Retirement{BriefID: "brief-dup", Slug: dup.Slug, CanonicalBriefID: "brief-canon", CanonicalDraftID: "draft-canon", DraftID: "draft-dup"}
	if len(applied) != 1 || applied[0] != want {
		t.Fatalf("retirementApplied calls = %+v, want [%+v]", applied, want)
	}
	// A third process finds nothing left to do.
	if n, err := restartedPublisher(p, db).RestoreOutbox(); err != nil || n != 0 {
		t.Fatalf("second restore = %d, %v; want 0", n, err)
	}
}

func TestRejectedCanonicalDropsRetirementRow(t *testing.T) {
	db := outboxTestDB(t)
	repo, p, key, badUpdate, good := rejectionFixture(t, NewChangelog())
	p.outbox = db
	p.UseSegmented = true
	dup := BundleBrief{ID: "brief-dup", EventID: "brief-dup", Slug: key + "-dup", Title: "Dup", PublishedAt: good.PublishedAt}
	repo.putSegment(t, key, BundleBrief{ID: "brief-bad", EventID: "brief-bad", Slug: key + "-bad", Title: "Bad", PublishedAt: good.PublishedAt, CVEs: []BundleCVE{{ID: "CVE-2026-1000"}}}, good, dup)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 3}}})
	p.pending = []BundleBrief{badUpdate}
	if err := p.RetireBriefForDrafts(dup.ID, dup.Slug, "brief-bad", "draft-dup", "draft-bad"); err != nil {
		t.Fatal(err)
	}
	if len(retirementRows(t, db)) != 1 {
		t.Fatal("retirement row missing before flush")
	}
	var applied int
	p.retirementApplied = func(Retirement) error { applied++; return nil }
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	if rows := retirementRows(t, db); len(rows) != 0 {
		t.Fatalf("dropped retirement left a row behind: %+v", rows)
	}
	if applied != 0 {
		t.Fatalf("callback ran for a dropped retirement")
	}
}

func TestDropRetirementKeepsNewerRowForSameKey(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	if err := p.RetireBriefForDrafts("brief-dup", "slug-dup", "brief-canon", "d1", "c1"); err != nil {
		t.Fatal(err)
	}
	older := retirementRows(t, db)[0]
	// A newer snapshot for the same key lands after the one this process holds.
	newerSeq, err := db.UpsertPublishOutbox(older.ID, storage.OutboxKindRetirement, older.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if newerSeq <= older.Seq {
		t.Fatalf("newer seq %d not greater than %d", newerSeq, older.Seq)
	}
	if !p.dropRetirementsFavouring("brief-canon") {
		t.Fatal("retirement not dropped from memory")
	}
	rows := retirementRows(t, db)
	if len(rows) != 1 || rows[0].Seq != newerSeq {
		t.Fatalf("newer row did not survive compare-and-delete: %+v", rows)
	}
}

func TestNonSegmentedFlushLeavesRetirementRows(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	if err := p.Publish(outboxBriefYAML("brief-a", "A")); err != nil {
		t.Fatal(err)
	}
	if err := p.RetireBriefForDrafts("brief-dup", "slug-dup", "brief-a", "d1", "c1"); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	ids := outboxIDs(t, db)
	if len(ids) != 1 || len(retirementRows(t, db)) != 1 {
		t.Fatalf("outbox after non-segmented flush = %v, want only the retirement row", ids)
	}
	if got := p.pendingRetirements["brief-dup"]; got == "" {
		t.Fatal("retirement dropped from memory by non-segmented flush")
	}
}

func TestDropRetirementsFavouringDeletesRow(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	if err := p.RetireBriefForDrafts("brief-dup", "slug-dup", "brief-canon", "d1", "c1"); err != nil {
		t.Fatal(err)
	}
	if err := p.RetireBriefForDrafts("brief-other", "slug-other", "brief-else", "d2", "c2"); err != nil {
		t.Fatal(err)
	}
	if !p.dropRetirementsFavouring("brief-canon") {
		t.Fatal("retirement not dropped")
	}
	rows := retirementRows(t, db)
	if len(rows) != 1 || rows[0].ID != retirementOutboxID("brief-other") {
		t.Fatalf("rows after drop = %+v, want only brief-other's", rows)
	}
}
