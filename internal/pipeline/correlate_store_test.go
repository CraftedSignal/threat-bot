package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

// Runs read stored correlation summaries instead of re-parsing every draft's
// YAML; a draft is parsed again only after its YAML changes.
func TestCorrelatorRunReusesStoredSummaries(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	drafts := map[string]string{
		"a": "title: First APT29 brief\nthreat_actor: APT29\ntags: [phishing]\n",
		"b": "title: Second APT29 brief\nthreat_actor: apt29\ntags: [espionage]\n",
		"c": "title: Unrelated brief\ntags: [ransomware]\n",
	}
	for id, y := range drafts {
		if err := db.CreateDraft(&storage.Draft{ID: id, Status: storage.StatusApproved, Source: "s", BriefYAML: y, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	c := NewCorrelator(db, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	updated, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 2 {
		t.Fatalf("first run re-tagged %d briefs, want a and b", len(updated))
	}
	// The re-tagged drafts are parsed once more; after that nothing changes.
	if updated, err = c.Run(context.Background()); err != nil || len(updated) != 0 {
		t.Fatalf("second run re-tagged %d briefs (err %v), want none", len(updated), err)
	}
	for s, err := range db.ApprovedDraftCorrelationsSince(now.AddDate(0, 0, -1)) {
		if err != nil {
			t.Fatal(err)
		}
		if s.Summary == "" {
			t.Errorf("draft %s has no stored correlation summary after two runs", s.ID)
		}
	}

	// A stored summary is what the next run correlates on: one naming APT29
	// for c, while c's YAML still names no actor, gets c tagged.
	summary, err := encodeCorrelationSummary(correlationBrief{ThreatActor: "APT29", Tags: []string{"ransomware"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDraftCorrelation("c", drafts["c"], summary); err != nil {
		t.Fatal(err)
	}
	if updated, err = c.Run(context.Background()); err != nil || len(updated) != 1 {
		t.Fatalf("run after storing c's summary re-tagged %d briefs (err %v), want c", len(updated), err)
	}
}

func TestCorrelatorDoesNotChangeApprovedDraftWhenPublicationRejectsTags(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	drafts := map[string]string{
		"a": "title: First APT29 brief\nthreat_actor: APT29\ntags: [phishing]\n",
		"b": "title: Second APT29 brief\nthreat_actor: apt29\ntags: [espionage]\n",
	}
	for id, raw := range drafts {
		if err := db.CreateDraft(&storage.Draft{ID: id, Status: storage.StatusApproved, Source: "s", BriefYAML: raw, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	c := NewCorrelator(db, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.validatePublication = func(string) error { return errors.New("publication contract rejected candidate") }
	updated, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 0 {
		t.Fatalf("rejected candidates returned for publication: %d", len(updated))
	}
	for id, original := range drafts {
		draft, err := db.GetDraft(id)
		if err != nil || draft == nil {
			t.Fatalf("load %s: %v", id, err)
		}
		if draft.BriefYAML != original {
			t.Fatalf("rejected candidate changed approved draft %s: %s", id, draft.BriefYAML)
		}
	}
}

func TestDecodeCorrelationSummaryRejectsOtherVersions(t *testing.T) {
	if _, ok := decodeCorrelationSummary("x", `{"v":0,"threat_actor":"APT29"}`); ok {
		t.Error("summary from another version was accepted")
	}
	if _, ok := decodeCorrelationSummary("x", ""); ok {
		t.Error("missing summary was accepted")
	}
	stored, err := encodeCorrelationSummary(correlationBrief{ThreatActor: "APT29", TechniqueIDs: []string{"T1059"}})
	if err != nil {
		t.Fatal(err)
	}
	b, ok := decodeCorrelationSummary("x", stored)
	if !ok || b.ID != "x" || b.ThreatActor != "APT29" || len(b.TechniqueIDs) != 1 {
		t.Errorf("round trip = %+v, %v", b, ok)
	}
}
