package publisher

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func briefIDs(bs []BundleBrief) []string {
	var ids []string
	for _, b := range bs {
		ids = append(ids, b.ID)
	}
	slices.Sort(ids)
	return ids
}

func captureLogs(p *Publisher) *bytes.Buffer {
	buf := &bytes.Buffer{}
	p.logger = slog.New(slog.NewTextHandler(buf, nil))
	return buf
}

// A retirement whose slug belongs to another published brief can never apply.
// It must be isolated instead of failing every flush (and every restart).
func TestPoisonRetirementIsIsolatedAndFlushContinues(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox = db
	p.UseSegmented = true
	logs := captureLogs(p)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	owner := BundleBrief{ID: "brief-owner", EventID: "brief-owner", Slug: key + "-owner", Title: "Owner", PublishedAt: now.Format(time.RFC3339)}
	repo.putSegment(t, key, owner)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	repo.putJSON(t, changelogPath, NewChangelog())

	// brief-gone is not published, but its slug belongs to brief-owner.
	if err := p.RetireBriefForDrafts("brief-gone", owner.Slug, owner.ID, "draft-gone", "draft-owner"); err != nil {
		t.Fatal(err)
	}
	fresh := BundleBrief{ID: "brief-new", EventID: "brief-new", Slug: key + "-new", Title: "New", PublishedAt: now.Format(time.RFC3339)}
	p.pending = []BundleBrief{fresh}

	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("poison retirement failed the flush: %v", err)
	}
	if got := briefIDs(repo.segment(t, key).Briefs); !slices.Equal(got, []string{"brief-new", "brief-owner"}) {
		t.Fatalf("segment briefs = %v", got)
	}
	if rows := retirementRows(t, db); len(rows) != 0 {
		t.Fatalf("poison retirement row survived: %+v", rows)
	}
	if n := strings.Count(logs.String(), "retirement rejected and dropped"); n != 1 {
		t.Fatalf("error logged %d times, want once:\n%s", n, logs)
	}
	for _, want := range []string{"level=ERROR", "brief_id=brief-gone", "canonical_id=brief-owner"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log lacks %q:\n%s", want, logs)
		}
	}
}

func TestRetirementRejectedErrorIsTyped(t *testing.T) {
	base := errors.New("boom")
	var err error = &RetirementRejectedError{BriefID: "b", Err: base}
	var target *RetirementRejectedError
	if !errors.As(err, &target) || !errors.Is(err, base) {
		t.Fatal("RetirementRejectedError must work with errors.As and errors.Is")
	}
}

// Retiring a duplicate whose canonical is neither published nor pending would
// delete public content with nothing replacing it.
func TestRetirementWithMissingCanonicalIsDropped(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox = db
	p.UseSegmented = true
	logs := captureLogs(p)
	var applied int
	p.retirementApplied = func(Retirement) error { applied++; return nil }
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	dup := BundleBrief{ID: "brief-dup", EventID: "brief-dup", Slug: key + "-dup", Title: "Dup", PublishedAt: now.Format(time.RFC3339)}
	repo.putSegment(t, key, dup)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	repo.putJSON(t, changelogPath, NewChangelog())

	if err := p.RetireBriefForDrafts(dup.ID, dup.Slug, "brief-ghost", "draft-dup", "draft-ghost"); err != nil {
		t.Fatal(err)
	}
	other := BundleBrief{ID: "brief-other", EventID: "brief-other", Slug: key + "-other", Title: "Other", PublishedAt: now.Format(time.RFC3339)}
	p.pending = []BundleBrief{other}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	if got := briefIDs(repo.segment(t, key).Briefs); !slices.Equal(got, []string{"brief-dup", "brief-other"}) {
		t.Fatalf("duplicate was removed without a canonical: %v", got)
	}
	if rows := retirementRows(t, db); len(rows) != 0 {
		t.Fatalf("row survived: %+v", rows)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "canonical_id=brief-ghost") {
		t.Fatalf("missing ERROR log:\n%s", logs)
	}
	if applied != 0 {
		t.Fatal("callback ran for a dropped retirement")
	}
}

// A canonical that is only pending (same flush) is fine.
func TestRetirementWithPendingCanonicalStillApplies(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox = db
	p.UseSegmented = true
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	dup := BundleBrief{ID: "brief-dup", EventID: "brief-dup", Slug: key + "-dup", Title: "Dup", PublishedAt: now.Format(time.RFC3339)}
	repo.putSegment(t, key, dup)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	repo.putJSON(t, changelogPath, NewChangelog())
	canon := BundleBrief{ID: "brief-canon", EventID: "brief-canon", Slug: key + "-canon", Title: "Canon", PublishedAt: now.Format(time.RFC3339)}
	p.pending = []BundleBrief{canon}
	if err := p.RetireBriefForDrafts(dup.ID, dup.Slug, canon.ID, "d", "c"); err != nil {
		t.Fatal(err)
	}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	if got := briefIDs(repo.segment(t, key).Briefs); !slices.Equal(got, []string{"brief-canon"}) {
		t.Fatalf("segment briefs = %v", got)
	}
}

// Restore must see every restored canonical regardless of outbox order: a
// retirement queued before its (unrestorable) canonical is still dropped.
func TestRestoreOrdersRetirementsAfterBriefs(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = db
	p.UseSegmented = true
	if err := p.RetireBriefForDrafts("brief-dup", "dup", "brief-bad", "d", "c"); err != nil {
		t.Fatal(err)
	}
	// Written after the retirement (higher seq), and cannot be restored.
	if _, err := db.UpsertPublishOutbox("brief-bad", storage.OutboxKindBrief, "{not a brief"); err != nil {
		t.Fatal(err)
	}
	fresh := restartedPublisher(p, db)
	if _, err := fresh.RestoreOutbox(); err != nil {
		t.Fatal(err)
	}
	if len(fresh.pendingRetirements) != 0 {
		t.Fatalf("retirement of an unrestorable canonical was restored: %v", fresh.pendingRetirements)
	}
	if rows := retirementRows(t, db); len(rows) != 0 {
		t.Fatalf("retirement row survived: %+v", rows)
	}
}

// The callback is idempotent and must be retried: a failing callback keeps the
// row so the next start runs it again.
func TestFailedRetirementCallbackKeepsRowForNextStart(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox = db
	p.UseSegmented = true
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	canon := BundleBrief{ID: "brief-canon", EventID: "brief-canon", Slug: key + "-canon", Title: "Canon", PublishedAt: now.Format(time.RFC3339)}
	dup := BundleBrief{ID: "brief-dup", EventID: "brief-dup", Slug: key + "-dup", Title: "Dup", PublishedAt: now.Format(time.RFC3339)}
	repo.putSegment(t, key, canon, dup)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 2}}})
	repo.putJSON(t, changelogPath, NewChangelog())
	if err := p.RetireBriefForDrafts(dup.ID, dup.Slug, canon.ID, "draft-dup", "draft-canon"); err != nil {
		t.Fatal(err)
	}

	failing := restartedPublisher(p, db)
	failing.retirementApplied = func(Retirement) error { return errors.New("db locked") }
	if _, err := failing.RestoreOutbox(); err != nil {
		t.Fatal(err)
	}
	if err := failing.Flush(); err != nil {
		t.Fatal(err)
	}
	if rows := retirementRows(t, db); len(rows) != 1 {
		t.Fatalf("row cleared although the callback failed: %+v", rows)
	}

	var applied []Retirement
	next := restartedPublisher(p, db)
	next.retirementApplied = func(r Retirement) error { applied = append(applied, r); return nil }
	if n, err := next.RestoreOutbox(); err != nil || n != 1 {
		t.Fatalf("RestoreOutbox = %d, %v", n, err)
	}
	if err := next.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].DraftID != "draft-dup" {
		t.Fatalf("callback not retried: %+v", applied)
	}
	if rows := retirementRows(t, db); len(rows) != 0 {
		t.Fatalf("row survived a successful callback: %+v", rows)
	}
}
