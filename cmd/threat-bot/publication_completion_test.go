package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func publicationStateDB(t *testing.T) (*storage.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateDraft(&storage.Draft{ID: "draft-one", Status: storage.StatusPending, BriefYAML: "id: brief-one", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertRumourCandidate(&storage.RumourCandidate{ClaimKey: "claim-one", Status: "below_gate", SourceIDs: []string{"source-one"}}); err != nil {
		t.Fatal(err)
	}
	return db, path
}

func TestCommittedDraftCompletionAfterRestartIsIdempotent(t *testing.T) {
	db, path := publicationStateDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	meta := publisher.DraftPublication{DraftID: "draft-one", ClaimKey: "claim-one"}
	if err := finishCommittedDraft(db, meta); err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft("draft-one")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := db.GetRumourCandidate("claim-one")
	if err != nil {
		t.Fatal(err)
	}
	if draft.Status != storage.StatusApproved || claim.Status != "published" {
		t.Fatalf("completion state draft=%s claim=%s", draft.Status, claim.Status)
	}
	reviewed := *draft.ReviewedAt
	if err := finishCommittedDraft(db, meta); err != nil {
		t.Fatal(err)
	}
	again, err := db.GetDraft("draft-one")
	if err != nil {
		t.Fatal(err)
	}
	if !again.ReviewedAt.Equal(reviewed) {
		t.Fatal("replayed completion overwrote review timestamp")
	}
}

func TestCommittedDraftCompletionPreservesRejectedOrMissingDraft(t *testing.T) {
	for _, id := range []string{"draft-one", "missing"} {
		t.Run(id, func(t *testing.T) {
			db, _ := publicationStateDB(t)
			defer db.Close()
			if err := db.UpdateDraftStatus("draft-one", storage.StatusRejected, "manual review"); err != nil {
				t.Fatal(err)
			}
			if err := finishCommittedDraft(db, publisher.DraftPublication{DraftID: id, ClaimKey: "claim-one"}); err == nil {
				t.Fatal("unpublishable draft completion succeeded")
			}
			d, err := db.GetDraft("draft-one")
			if err != nil {
				t.Fatal(err)
			}
			c, err := db.GetRumourCandidate("claim-one")
			if err != nil {
				t.Fatal(err)
			}
			if d.Status != storage.StatusRejected || d.RejectReason != "manual review" || c.Status == "published" {
				t.Fatalf("rejected state changed: draft=%+v claim=%+v", d, c)
			}
		})
	}
}

type failingClaimCompletion struct {
	*storage.DB
	fail bool
}

func (d *failingClaimCompletion) MarkRumourCandidatePublished(key string) error {
	if d.fail {
		return errors.New("claim write unavailable")
	}
	return d.DB.MarkRumourCandidatePublished(key)
}

func TestCommittedDraftCompletionRetriesPartialDatabaseFailure(t *testing.T) {
	db, _ := publicationStateDB(t)
	defer db.Close()
	store := &failingClaimCompletion{DB: db, fail: true}
	meta := publisher.DraftPublication{DraftID: "draft-one", ClaimKey: "claim-one"}
	if err := finishCommittedDraft(store, meta); err == nil {
		t.Fatal("claim database failure was swallowed")
	}
	before, err := db.GetDraft("draft-one")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := db.GetRumourCandidate("claim-one")
	if err != nil {
		t.Fatal(err)
	}
	if before.Status != storage.StatusApproved || claim.Status == "published" {
		t.Fatalf("unexpected partial state: draft=%s claim=%s", before.Status, claim.Status)
	}
	store.fail = false
	if err := finishCommittedDraft(store, meta); err != nil {
		t.Fatal(err)
	}
	after, err := db.GetDraft("draft-one")
	if err != nil {
		t.Fatal(err)
	}
	claim, err = db.GetRumourCandidate("claim-one")
	if err != nil {
		t.Fatal(err)
	}
	if claim.Status != "published" || !after.ReviewedAt.Equal(*before.ReviewedAt) {
		t.Fatal("retry did not finish claim idempotently")
	}
}

func TestIdlePollRecoversIntentsAndRetriesQueuedPublication(t *testing.T) {
	db, _ := publicationStateDB(t)
	defer db.Close()
	processed, flushes := 0, 0
	process := func(context.Context, []scraper.RawItem) error { processed++; return nil }
	flush := func() error {
		flushes++
		if flushes == 1 {
			return errors.New("concurrent ref update")
		}
		return finishCommittedDraft(db, publisher.DraftPublication{DraftID: "draft-one", ClaimKey: "claim-one"})
	}
	if err := processPolledItems(context.Background(), nil, process, flush); err == nil {
		t.Fatal("failed idle flush was swallowed")
	}
	draft, err := db.GetDraft("draft-one")
	if err != nil {
		t.Fatal(err)
	}
	if draft.Status != storage.StatusPending {
		t.Fatal("failed flush approved queued draft")
	}
	if err := processPolledItems(context.Background(), nil, process, flush); err != nil {
		t.Fatal(err)
	}
	draft, err = db.GetDraft("draft-one")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := db.GetRumourCandidate("claim-one")
	if err != nil {
		t.Fatal(err)
	}
	if draft.Status != storage.StatusApproved || claim.Status != "published" {
		t.Fatal("idle retry did not finish committed publication")
	}
	if processed != 2 || flushes != 2 {
		t.Fatalf("idle work processed=%d flushes=%d", processed, flushes)
	}
	if err := processPolledItems(context.Background(), []scraper.RawItem{{SourceID: "new-item"}}, process, flush); err != nil {
		t.Fatal(err)
	}
	if processed != 3 || flushes != 2 {
		t.Fatal("new-item batch gained an extra flush")
	}
	if err := processPolledItems(context.Background(), nil, process, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDraftPreflightRespectsModerationWithoutCompletingState(t *testing.T) {
	for _, status := range []string{storage.StatusPending, storage.StatusApproved, storage.StatusRejected, "unknown"} {
		t.Run(status, func(t *testing.T) {
			db, _ := publicationStateDB(t)
			defer db.Close()
			if err := db.UpdateDraftStatus("draft-one", status, "review decision"); err != nil {
				t.Fatal(err)
			}
			allowed, err := draftMayPublish(db, publisher.DraftPublication{DraftID: "draft-one", ClaimKey: "claim-one"})
			wantAllowed := status == storage.StatusPending || status == storage.StatusApproved
			if allowed != wantAllowed || (err != nil) != (status == "unknown") {
				t.Fatalf("allowed=%v error=%v status=%s", allowed, err, status)
			}
			draft, err := db.GetDraft("draft-one")
			if err != nil {
				t.Fatal(err)
			}
			claim, err := db.GetRumourCandidate("claim-one")
			if err != nil {
				t.Fatal(err)
			}
			if draft.Status != status || claim.Status == "published" {
				t.Fatal("preflight changed publication state")
			}
		})
	}
	db, _ := publicationStateDB(t)
	if allowed, err := draftMayPublish(db, publisher.DraftPublication{DraftID: "missing"}); err == nil || allowed {
		t.Fatal("missing draft did not fail closed")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if allowed, err := draftMayPublish(db, publisher.DraftPublication{DraftID: "draft-one"}); err == nil || allowed {
		t.Fatal("database outage did not fail closed")
	}
}

type noPublicationHTTP struct{}

func (noPublicationHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected GitHub request for rejected draft")
}

func TestServicePublisherDropsRejectedQueuedDraftBeforeGit(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = noPublicationHTTP{}
	t.Cleanup(func() { http.DefaultTransport = original })
	db, _ := publicationStateDB(t)
	defer db.Close()
	pub := newServicePublisher(&config.Config{}, func() string { return "" }, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, db)
	pub.UseSegmented = true
	if err := pub.PublishDraft("id: brief-one\nslug: 2026-11-one\ntitle: One\nsummary: Summary\ncontent: A security notice records suspicious host activity for analyst review.\nseverity: high\npublished_at: 2026-11-13T12:00:00Z\n", "draft-one", "claim-one"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateDraftStatus("draft-one", storage.StatusRejected, "manual review"); err != nil {
		t.Fatal(err)
	}
	if err := pub.Flush(); err != nil {
		t.Fatalf("rejected queued draft reached Git instead of eviction: %v", err)
	}
	rows, err := db.ListPublishOutbox()
	if err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft("draft-one")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := db.GetRumourCandidate("claim-one")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || draft.Status != storage.StatusRejected || claim.Status == "published" {
		t.Fatalf("rejection not preserved: rows=%d draft=%s claim=%s", len(rows), draft.Status, claim.Status)
	}
}
