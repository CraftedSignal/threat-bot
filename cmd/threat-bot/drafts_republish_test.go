package main

import (
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestRepublishDraftIDsLimitsRecoveryWindowAndExclusion(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	for _, draft := range []storage.Draft{
		{ID: "old", Status: storage.StatusApproved, CreatedAt: now.Add(-3 * time.Hour)},
		{ID: "recent", Status: storage.StatusApproved, CreatedAt: now.Add(-time.Hour)},
		{ID: "excluded", Status: storage.StatusApproved, CreatedAt: now.Add(-30 * time.Minute)},
		{ID: "pending", Status: storage.StatusPending, CreatedAt: now},
	} {
		if err := db.CreateDraft(&draft); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := republishDraftIDs(db, now.Add(-2*time.Hour), "excluded", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "recent" {
		t.Fatalf("selected drafts = %v, want [recent]", ids)
	}
}

func TestRepublishDraftIDsSelectsOneApprovedDraft(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	for _, draft := range []storage.Draft{
		{ID: "target", Status: storage.StatusApproved, CreatedAt: now.Add(-24 * time.Hour)},
		{ID: "other", Status: storage.StatusApproved, CreatedAt: now},
		{ID: "pending", Status: storage.StatusPending, CreatedAt: now},
	} {
		if err := db.CreateDraft(&draft); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := republishDraftIDs(db, time.Time{}, "", "target")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "target" {
		t.Fatalf("selected drafts = %v, want [target]", ids)
	}
	if _, err := republishDraftIDs(db, time.Time{}, "", "pending"); err == nil {
		t.Fatal("expected exact republish of a pending draft to fail")
	}
}
