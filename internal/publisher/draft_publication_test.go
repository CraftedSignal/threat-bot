package publisher

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDraftReceiptFailureRetainsCompletionOnlyState(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	store := &upsertFailer{OutboxStore: db}
	p.outbox, p.UseSegmented = store, true
	completed := 0
	WithDraftPublished(func(DraftPublication) error { completed++; return nil })(p)
	if err := p.PublishDraft(outboxBriefYAML("brief-a", "A"), "draft-a", ""); err != nil {
		t.Fatal(err)
	}
	interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
		if req.Method == http.MethodPatch {
			store.fail = true
		}
		return false
	})
	if err := p.Flush(); err == nil {
		t.Fatal("receipt persistence failure was hidden")
	}
	if repo.refUpdates != 1 || len(p.pending) != 0 || !p.pendingDrafts["brief-a"].Committed || completed != 0 {
		t.Fatal("known committed phase or callback ordering lost on receipt failure")
	}
	store.fail = false
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	if repo.refUpdates != 1 || completed != 1 || len(outboxIDs(t, db)) != 0 {
		t.Fatal("receipt retry republished content or failed completion")
	}
}

func TestDraftCompletionRetryDoesNotRepublishStaleBrief(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox, p.UseSegmented = db, true
	WithDraftPublished(func(DraftPublication) error { return errors.New("database unavailable") })(p)
	if err := p.PublishDraft(outboxBriefYAML("brief-a", "Original"), "draft-a", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err == nil {
		t.Fatal("expected post-commit completion failure")
	}
	if repo.refUpdates != 1 || len(p.pending) != 0 {
		t.Fatal("known committed content remained queued for publication")
	}
	segment := repo.segment(t, "2026-02")
	segment.Briefs[0].Title = "Concurrent newer revision"
	repo.putSegment(t, "2026-02", segment.Briefs...)
	before := cloneFakeFiles(repo.files)
	WithDraftPublished(func(DraftPublication) error { return nil })(p)
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	if repo.refUpdates != 1 || !maps.EqualFunc(before, repo.files, bytes.Equal) {
		t.Fatal("completion retry rewrote concurrent public content")
	}
	if len(outboxIDs(t, db)) != 0 {
		t.Fatal("completion-only retry left a durable row")
	}
}

func TestDraftOutboxRemainsReadableAsLegacyBrief(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox, p.UseSegmented = db, true
	WithDraftPublished(func(DraftPublication) error { return nil })(p)
	if err := p.PublishDraft(outboxBriefYAML("brief-a", "A"), "private-draft-identity", "private-claim-identity"); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListPublishOutbox()
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	// prepareBrief has the same YAML entry point as the previous runtime.
	brief, err := p.prepareBrief(rows[0].Payload)
	if err != nil || brief.ID != "brief-a" {
		t.Fatalf("legacy brief parse=%+v,%v", brief, err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	for path, raw := range repo.files {
		if bytes.Contains(raw, []byte("private-draft-identity")) || bytes.Contains(raw, []byte("private-claim-identity")) || bytes.Contains(raw, []byte("threat-bot-draft-publication")) {
			t.Fatalf("private queue metadata leaked into %s", path)
		}
	}
}

func TestDraftPreflightEvictsRejectedSharedSnapshot(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox, p.UseSegmented = db, true
	WithDraftPublishable(func(d DraftPublication) (bool, error) { return d.DraftID != "rejected-draft", nil })(p)
	var completed []string
	WithDraftPublished(func(d DraftPublication) error { completed = append(completed, d.DraftID); return nil })(p)
	for _, d := range []struct{ id, draft string }{{"shared", "older-allowed-draft"}, {"shared", "rejected-draft"}, {"other", "other-draft"}} {
		if err := p.PublishDraft(outboxBriefYAML(d.id, d.id), d.draft, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	segment := repo.segment(t, "2026-02")
	if len(segment.Briefs) != 1 || segment.Briefs[0].ID != "other" || len(completed) != 1 || completed[0] != "other-draft" {
		t.Fatalf("briefs=%+v completed=%v", segment.Briefs, completed)
	}
	if len(outboxIDs(t, db)) != 0 {
		t.Fatal("evicted rejected snapshot remained queued")
	}
}

func TestDraftPreflightReadFailureKeepsQueue(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox, p.UseSegmented = db, true
	WithDraftPublishable(func(DraftPublication) (bool, error) { return false, errors.New("database unavailable") })(p)
	if err := p.PublishDraft(outboxBriefYAML("brief-a", "A"), "draft-a", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err == nil || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("flush err=%v", err)
	}
	if len(p.pending) != 1 || len(outboxIDs(t, db)) != 1 || len(repo.requests) != 0 {
		t.Fatal("failed preflight changed queue or contacted Git")
	}
}

func TestDraftPublicationRejectsFailedDurableEnqueue(t *testing.T) {
	db := outboxTestDB(t)
	_, p := newFakeFeedRepo(t)
	p.outbox = failingOutbox{OutboxStore: db}
	if err := p.PublishDraft(outboxBriefYAML("brief-a", "A"), "draft-a", "claim-a"); err == nil {
		t.Fatal("acknowledged a draft without durable queue metadata")
	}
	if len(p.pending) != 0 || len(p.pendingDrafts) != 0 {
		t.Fatal("failed durable enqueue changed pending state")
	}
	_, fresh := newFakeFeedRepo(t)
	fresh.outbox = db
	if n, err := fresh.RestoreOutbox(); err != nil || n != 0 {
		t.Fatalf("restore=%d,%v", n, err)
	}
}

func TestPublicationFailedReplacementKeepsDurableSnapshot(t *testing.T) {
	for _, draft := range []bool{false, true} {
		t.Run(fmt.Sprint("draft=", draft), func(t *testing.T) {
			db := outboxTestDB(t)
			_, p := newFakeFeedRepo(t)
			p.outbox = db
			publish := func(title, draftID string) error {
				if draft {
					return p.PublishDraft(outboxBriefYAML("brief-a", title), draftID, "")
				}
				return p.Publish(outboxBriefYAML("brief-a", title))
			}
			if err := publish("Old", "old-draft"); err != nil {
				t.Fatal(err)
			}
			p.outbox = failingOutbox{OutboxStore: db}
			if err := publish("New", "new-draft"); err == nil {
				t.Fatal("acknowledged a failed durable replacement")
			}
			if len(p.pending) != 1 || p.pending[0].Title != "Old" {
				t.Fatal("failed replacement changed the pending snapshot")
			}
			_, fresh := newFakeFeedRepo(t)
			fresh.outbox = db
			if _, err := fresh.RestoreOutbox(); err != nil {
				t.Fatal(err)
			}
			if len(fresh.pending) != 1 || fresh.pending[0].Title != "Old" {
				t.Fatal("failed replacement lost the durable snapshot")
			}
			if draft && (len(fresh.pendingDrafts["brief-a"].Drafts) != 1 || fresh.pendingDrafts["brief-a"].Drafts[0].DraftID != "old-draft") {
				t.Fatal("failed replacement changed completion metadata")
			}
		})
	}
}

func TestDraftPublicationCompletionSurvivesFailedFlushAndRestart(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox, p.UseSegmented = db, true
	completed := []DraftPublication{}
	complete := func(draft DraftPublication) error { completed = append(completed, draft); return nil }
	WithDraftPublished(complete)(p)
	if err := p.PublishDraft(outboxBriefYAML("brief-a", "A"), "draft-a", "claim-a"); err != nil {
		t.Fatal(err)
	}
	repo.racePut[manifestPath] = []byte(`{"version":"concurrent"}`)
	if err := p.Flush(); err == nil {
		t.Fatal("expected conflicting flush")
	}
	if len(completed) != 0 || len(outboxIDs(t, db)) != 1 {
		t.Fatal("failed flush completed or lost the draft")
	}

	fresh := New(p.repoSlug, p.publicKey, p.tokenFn, p.logger, WithOutbox(db), WithDraftPublished(complete))
	fresh.apiURL = p.apiURL
	fresh.UseSegmented = true
	if n, err := fresh.RestoreOutbox(); err != nil || n != 1 {
		t.Fatalf("restore=%d,%v", n, err)
	}
	if err := fresh.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(completed) != 1 || completed[0].DraftID != "draft-a" || completed[0].ClaimKey != "claim-a" {
		t.Fatalf("completed=%+v", completed)
	}
	if len(outboxIDs(t, db)) != 0 || len(fresh.pending) != 0 {
		t.Fatal("successful completion retained queued draft")
	}
	if err := fresh.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(completed) != 1 {
		t.Fatal("empty flush repeated completion")
	}
}

func TestDraftPublicationCompletionFailureReplaysWithoutDuplicateBrief(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox, p.UseSegmented = db, true
	WithDraftPublished(func(DraftPublication) error { return errors.New("database unavailable") })(p)
	if err := p.PublishDraft(outboxBriefYAML("brief-a", "A"), "draft-a", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err == nil {
		t.Fatal("expected database completion failure")
	}
	if repo.refUpdates != 1 || len(outboxIDs(t, db)) != 1 || len(p.pending) != 0 {
		t.Fatal("post-commit database failure lost retry state")
	}
	completed := 0
	fresh := New(p.repoSlug, p.publicKey, p.tokenFn, p.logger, WithOutbox(db), WithDraftPublished(func(d DraftPublication) error { completed++; return nil }))
	fresh.apiURL = p.apiURL
	fresh.UseSegmented = true
	if _, err := fresh.RestoreOutbox(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Flush(); err != nil {
		t.Fatal(err)
	}
	if completed != 1 || len(outboxIDs(t, db)) != 0 {
		t.Fatal("replayed completion did not finish")
	}
	segment := repo.segment(t, "2026-02")
	if len(segment.Briefs) != 1 || segment.Briefs[0].ID != "brief-a" {
		t.Fatalf("replayed brief duplicated public content: %+v", segment.Briefs)
	}
}

func TestDraftPublicationNeverCompletesRejectedRevision(t *testing.T) {
	_, p, _, badUpdate, _ := rejectionFixture(t, NewChangelog())
	badUpdate.Summary = "A rejected change"
	badUpdate.Severity = "high"
	p.UseSegmented = true
	completed := 0
	WithDraftPublished(func(DraftPublication) error { completed++; return nil })(p)
	raw, err := yaml.Marshal(badUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.PublishDraft(string(raw), "rejected-draft", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	if completed != 0 {
		t.Fatal("rejected revision was approved")
	}
}
