package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSourcePublicationUpdateRollsBackWithIntentFailure(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "draft.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.CreateDraft(&Draft{ID: "canonical", Status: StatusApproved, BriefYAML: "original", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER fail_publication_intent BEFORE INSERT ON publication_intents BEGIN SELECT RAISE(FAIL,'intent disk failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateDraftYAMLWithPublication("canonical", "new", true, false); err == nil {
		t.Fatal("intent failure silently accepted")
	}
	draft, err := db.GetDraft("canonical")
	if err != nil || draft.BriefYAML != "original" {
		t.Fatalf("YAML committed without recoverable publication: %+v %v", draft, err)
	}
	intents, err := db.ListPublicationIntents()
	if err != nil || len(intents) != 0 {
		t.Fatalf("partial intent transaction: %+v %v", intents, err)
	}
}

func TestSourcePublicationUpdatePreservesPendingCompletionAndClaim(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "draft.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.CreateDraftWithPublication(&Draft{ID: "canonical", Status: StatusPending, BriefYAML: "original", CreatedAt: time.Now()}, "claim-key"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateDraftYAMLWithPublication("canonical", "tagged", true, false); err != nil {
		t.Fatal(err)
	}
	intents, err := db.ListPublicationIntents()
	if err != nil || len(intents) != 1 || !intents[0].CompleteDraft || intents[0].ClaimKey != "claim-key" || intents[0].BriefYAML != "tagged" {
		t.Fatalf("metadata update lost completion receipt: %+v %v", intents, err)
	}
	if err := db.DeletePublicationIntent("canonical", "original"); err != nil {
		t.Fatal(err)
	}
	intents, _ = db.ListPublicationIntents()
	if len(intents) != 1 {
		t.Fatal("stale acknowledgement removed newer source publication")
	}
}
