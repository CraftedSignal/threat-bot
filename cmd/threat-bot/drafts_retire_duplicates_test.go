package main

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

type duplicateRetirementPublisherFake struct {
	published []string
	retired   map[string]string
	flushes   int
	flushErr  error
	drafts    map[string][2]string
}

func (f *duplicateRetirementPublisherFake) Publish(raw string) error {
	f.published = append(f.published, raw)
	return nil
}

func (f *duplicateRetirementPublisherFake) RetireBrief(id, slug string) error {
	if f.retired == nil {
		f.retired = make(map[string]string)
	}
	f.retired[id] = slug
	return nil
}

func (f *duplicateRetirementPublisherFake) RetireBriefForDrafts(id, slug, _, draftID, canonicalDraftID string) error {
	if f.drafts == nil {
		f.drafts = make(map[string][2]string)
	}
	f.drafts[id] = [2]string{draftID, canonicalDraftID}
	return f.RetireBrief(id, slug)
}

func (f *duplicateRetirementPublisherFake) Flush() error {
	f.flushes++
	return f.flushErr
}

func TestDraftsRetireDuplicatesPublishesCanonicalAndRejectsDuplicates(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	drafts := []*storage.Draft{
		{ID: "canonical-row", Status: storage.StatusApproved, BriefYAML: "id: brief-canonical\nslug: canonical\ntitle: Canonical\npublished_at: 2026-10-17T00:00:00Z\n", CreatedAt: now},
		{ID: "duplicate-one-row", Status: storage.StatusApproved, BriefYAML: "id: brief-duplicate-one\nslug: duplicate-one\ntitle: Duplicate one\npublished_at: 2026-10-18T00:00:00Z\n", CreatedAt: now},
		{ID: "duplicate-two-row", Status: storage.StatusApproved, BriefYAML: "id: brief-duplicate-two\nslug: duplicate-two\ntitle: Duplicate two\npublished_at: 2026-10-19T00:00:00Z\n", CreatedAt: now},
	}
	for _, draft := range drafts {
		if err := db.CreateDraft(draft); err != nil {
			t.Fatal(err)
		}
	}
	fake := &duplicateRetirementPublisherFake{}
	args := []string{
		"--canonical-id", "canonical-row",
		"--duplicate-id", "duplicate-one-row",
		"--duplicate-id", "duplicate-two-row",
		"--apply", "--operator", "codex", "--reason", "same ConnectWise incident",
	}
	var out bytes.Buffer
	if err := runDraftsRetireDuplicates(db, fake, args, &out); err != nil {
		t.Fatal(err)
	}
	if len(fake.published) != 1 || !strings.Contains(fake.published[0], "id: brief-canonical") {
		t.Fatalf("published = %#v", fake.published)
	}
	if fake.flushes != 1 || fake.retired["brief-duplicate-one"] != "duplicate-one" || fake.retired["brief-duplicate-two"] != "duplicate-two" {
		t.Fatalf("flushes=%d retired=%#v", fake.flushes, fake.retired)
	}
	if fake.drafts["brief-duplicate-one"] != [2]string{"duplicate-one-row", "canonical-row"} {
		t.Fatalf("retirement draft IDs = %v", fake.drafts)
	}
	for _, id := range []string{"duplicate-one-row", "duplicate-two-row"} {
		draft, err := db.GetDraft(id)
		if err != nil {
			t.Fatal(err)
		}
		if draft.Status != storage.StatusRejected || !strings.Contains(draft.RejectReason, "same ConnectWise incident") {
			t.Fatalf("duplicate %s status=%s reason=%q", id, draft.Status, draft.RejectReason)
		}
	}
	canonical, _ := db.GetDraft("canonical-row")
	if canonical.Status != storage.StatusApproved {
		t.Fatalf("canonical status = %s", canonical.Status)
	}
}

func TestDraftsRetireDuplicatesPreviewDoesNotMutate(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, draft := range []*storage.Draft{
		{ID: "canonical", Status: storage.StatusApproved, BriefYAML: "id: canonical\nslug: canonical\ntitle: Canonical\npublished_at: 2026-10-17T00:00:00Z\n", CreatedAt: time.Now()},
		{ID: "duplicate", Status: storage.StatusApproved, BriefYAML: "id: duplicate\nslug: duplicate\ntitle: Duplicate\npublished_at: 2026-10-18T00:00:00Z\n", CreatedAt: time.Now()},
	} {
		if err := db.CreateDraft(draft); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := runDraftsRetireDuplicates(db, nil, []string{"--canonical-id", "canonical", "--duplicate-id", "duplicate"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Preview only") {
		t.Fatalf("preview output = %s", out.String())
	}
	duplicate, _ := db.GetDraft("duplicate")
	if duplicate.Status != storage.StatusApproved {
		t.Fatalf("preview changed duplicate status to %s", duplicate.Status)
	}
}

func TestFinishRestoredRetirementConsolidatesIdempotently(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	for _, d := range []*storage.Draft{
		{ID: "canon-row", Status: storage.StatusApproved, BriefYAML: "id: brief-canon\nslug: canon\ntitle: C\n", CreatedAt: now},
		{ID: "dup-row", Status: storage.StatusApproved, BriefYAML: "id: brief-dup\nslug: dup\ntitle: D\n", CreatedAt: now},
	} {
		if err := db.CreateDraft(d); err != nil {
			t.Fatal(err)
		}
	}
	r := publisher.Retirement{BriefID: "brief-dup", Slug: "dup", CanonicalBriefID: "brief-canon", CanonicalDraftID: "canon-row", DraftID: "dup-row"}
	for i := 0; i < 2; i++ { // the second run must be a no-op, not an error
		if err := finishRestoredRetirement(db, r); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	dup, err := db.GetDraft("dup-row")
	if err != nil || dup.Status != storage.StatusRejected {
		t.Fatalf("duplicate draft = %+v, %v; want rejected", dup, err)
	}
	canon, _ := db.GetDraft("canon-row")
	if canon.Status != storage.StatusApproved {
		t.Fatalf("canonical draft status = %s", canon.Status)
	}
}

func TestServicePublisherFinishesRestoredRetirement(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	crashed := newServicePublisher(&config.Config{}, func() string { return "" }, logger, nil, db)
	if err := crashed.RetireBriefForDrafts("brief-dup", "dup", "brief-canon", "dup-row", "canon-row"); err != nil {
		t.Fatal(err)
	}
	restarted := newServicePublisher(&config.Config{}, func() string { return "" }, logger, nil, db)
	n, err := restarted.RestoreOutbox()
	if err != nil || n != 1 {
		t.Fatalf("RestoreOutbox = %d, %v; flushRestored needs a nonzero count to flush", n, err)
	}
}
