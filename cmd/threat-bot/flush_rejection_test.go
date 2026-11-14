package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

type rejectingAmendPublisher struct {
	amendPublisherFake
	rejected []string
}

func (f *rejectingAmendPublisher) RejectedBriefIDs() []string { return f.rejected }

func TestDraftAmendFailsWhenPublisherRejectedTheBrief(t *testing.T) {
	db := setupAmendDraft(t)
	file := writeAmendFile(t, amendRevisedYAML)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(amendOriginalYAML)))
	proposedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(amendRevisedYAML)))
	pub := &rejectingAmendPublisher{rejected: []string{"brief-1"}}
	var output bytes.Buffer
	err := runDraftsAmend(db, pub, []string{
		"--id", amendDraftID, "--file", file, "--apply",
		"--expect-sha256", hash, "--expect-proposed-sha256", proposedHash,
		"--backup-dir", filepath.Join(t.TempDir(), "backups"),
		"--operator", "analyst@example.com", "--reason", "Correct product mapping",
	}, &output)
	if err == nil {
		t.Fatal("expected error for a rejected brief")
	}
	draft, gerr := db.GetDraft(amendDraftID)
	if gerr != nil || draft.BriefYAML != amendOriginalYAML {
		t.Fatalf("stored draft must stay unchanged: %+v, %v", draft, gerr)
	}
	if strings.Contains(output.String(), "Published saved") {
		t.Fatalf("must not claim success: %q", output.String())
	}
}

type rejectingRetirementPublisher struct {
	duplicateRetirementPublisherFake
	rejected []string
}

func (f *rejectingRetirementPublisher) RejectedBriefIDs() []string { return f.rejected }

func TestDraftsRetireDuplicatesFailsWhenCanonicalRejected(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, d := range []*storage.Draft{
		{ID: "canonical-row", Status: storage.StatusApproved, BriefYAML: "id: brief-canonical\nslug: canonical\ntitle: Canonical\npublished_at: 2026-10-17T00:00:00Z\n", CreatedAt: time.Now()},
		{ID: "duplicate-row", Status: storage.StatusApproved, BriefYAML: "id: brief-duplicate\nslug: duplicate\ntitle: Duplicate\npublished_at: 2026-10-18T00:00:00Z\n", CreatedAt: time.Now()},
	} {
		if err := db.CreateDraft(d); err != nil {
			t.Fatal(err)
		}
	}
	fake := &rejectingRetirementPublisher{rejected: []string{"brief-canonical"}}
	var out bytes.Buffer
	err = runDraftsRetireDuplicates(db, fake, []string{
		"--canonical-id", "canonical-row", "--duplicate-id", "duplicate-row",
		"--apply", "--operator", "op", "--reason", "same incident",
	}, &out)
	if err == nil {
		t.Fatal("expected error for a rejected canonical brief")
	}
	dup, _ := db.GetDraft("duplicate-row")
	if dup.Status != storage.StatusApproved {
		t.Fatalf("duplicate status = %s, must stay approved", dup.Status)
	}
}

func TestDraftsRetireDuplicatesIgnoresUnrelatedRejection(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, d := range []*storage.Draft{
		{ID: "canonical-row", Status: storage.StatusApproved, BriefYAML: "id: brief-canonical\nslug: canonical\ntitle: Canonical\npublished_at: 2026-10-17T00:00:00Z\n", CreatedAt: time.Now()},
		{ID: "duplicate-row", Status: storage.StatusApproved, BriefYAML: "id: brief-duplicate\nslug: duplicate\ntitle: Duplicate\npublished_at: 2026-10-18T00:00:00Z\n", CreatedAt: time.Now()},
	} {
		if err := db.CreateDraft(d); err != nil {
			t.Fatal(err)
		}
	}
	fake := &rejectingRetirementPublisher{rejected: []string{"brief-unrelated"}}
	var out bytes.Buffer
	if err := runDraftsRetireDuplicates(db, fake, []string{
		"--canonical-id", "canonical-row", "--duplicate-id", "duplicate-row",
		"--apply", "--operator", "op", "--reason", "same incident",
	}, &out); err != nil {
		t.Fatal(err)
	}
}
