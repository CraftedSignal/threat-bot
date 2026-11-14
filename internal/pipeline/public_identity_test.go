package pipeline

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

func TestEnsureUniqueDraftIdentityDisambiguatesSameDayCollisionDeterministically(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	created := time.Date(2026, 10, 21, 16, 7, 10, 0, time.UTC)
	original := `id: brief-2026-10-21-mozilla-vulnerabilities
slug: 2026-10-mozilla-vulnerabilities
title: Existing Mozilla advisory
published_at: "2026-10-21T16:07:10Z"
`
	if err := db.CreateDraft(&storage.Draft{ID: "existing", Status: storage.StatusApproved, BriefYAML: original, CreatedAt: created}); err != nil {
		t.Fatal(err)
	}
	p := New(Config{DB: db, Logger: slog.Default()})
	candidate := strings.Replace(original, "Existing Mozilla advisory", "Independent Mozilla advisory", 1)
	item := scraper.RawItem{SourceID: "anssi:CERTFR-2026-AVI-1346", Source: "anssi"}

	first, err := p.ensureUniqueDraftIdentity(candidate, item)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.ensureUniqueDraftIdentity(candidate, item)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("identity collision repair must be deterministic")
	}
	var got map[string]any
	if err := yaml.Unmarshal([]byte(first), &got); err != nil {
		t.Fatal(err)
	}
	if got["id"] == "brief-2026-10-21-mozilla-vulnerabilities" || got["slug"] == "2026-10-mozilla-vulnerabilities" {
		t.Fatalf("collision was not disambiguated: %#v", got)
	}
	if !strings.HasPrefix(got["id"].(string), "brief-2026-10-21-mozilla-vulnerabilities-") ||
		!strings.HasPrefix(got["slug"].(string), "2026-10-mozilla-vulnerabilities-") {
		t.Fatalf("repaired identity lost its readable base: %#v", got)
	}
}
