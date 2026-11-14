package pipeline

import (
	"log/slog"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestNormalizeContentHash_IgnoresWhitespaceAndCase(t *testing.T) {
	a := NormalizeContentHash("Title Here", "Hello   World\n\nfoo")
	b := NormalizeContentHash("title here", "hello world foo")
	if a != b {
		t.Fatalf("expected whitespace/case-insensitive hash equality: %q vs %q", a, b)
	}
	if NormalizeContentHash("x", "one") == NormalizeContentHash("y", "one") {
		t.Fatal("different titles should hash differently")
	}
}

func TestCheckPreExtraction_LiteralDuplicateSkipped(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	title := "Widespread Phishing Campaign Targets Regional Banks"
	body := "Attackers registered lookalike domains and sent credential-harvesting " +
		"emails to staff at several regional banks, then used the stolen logins " +
		"to initiate fraudulent wire transfers over the following days."

	// Seed an existing brief from source A with this content hash.
	seed := storage.ContentIndexEntry{
		ContentHash: NormalizeContentHash(title, body),
		DraftID:     "draft-A",
		SourceID:    "bleepingcomputer:1",
		Source:      "bleepingcomputer",
		CreatedAt:   time.Now(),
	}
	if err := db.IndexContent(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Same content, DIFFERENT source (syndicated republication) → skip.
	item := scraper.RawItem{
		SourceID: "therecord:9",
		Source:   "therecord",
		Title:    title,
		Content:  body,
	}
	decision, _, entries := dedup.CheckPreExtraction(item)
	if decision != DedupSkip {
		t.Fatalf("want DedupSkip for literal duplicate, got %d", decision)
	}
	if len(entries) == 0 || entries[0].DraftID != "draft-A" {
		t.Fatalf("want matched entry draft-A, got %+v", entries)
	}
}

func TestNormalizeSourceURL_CanonicalizesTrackingAndScheme(t *testing.T) {
	a := NormalizeSourceURL("http://Example.com:80//research/case/?utm_source=newsletter&b=2&a=1#frag")
	b := NormalizeSourceURL("https://example.com/research/case?a=1&b=2")
	if a != b {
		t.Fatalf("expected canonical URLs equal:\n%q\n%q", a, b)
	}
	if SourceURLHash(a) != SourceURLHash(b) {
		t.Fatal("expected canonical URL hashes equal")
	}
}

func TestCheckPreExtraction_NormalizedSourceURLMerges(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	seed := storage.ContentIndexEntry{
		SourceURLHash: SourceURLHash("https://example.com/threats/case-study?utm_campaign=x"),
		DraftID:       "draft-url",
		SourceID:      "feed:old",
		Source:        "vendor-blog",
		CreatedAt:     time.Now(),
	}
	if err := db.IndexContent(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	item := scraper.RawItem{
		SourceID: "feed:new",
		Source:   "vendor-blog",
		Title:    "Updated case study",
		URL:      "http://example.com/threats/case-study/",
		Content:  "Different body text is fine because the normalized source URL is the same article.",
	}
	decision, _, entries := dedup.CheckPreExtraction(item)
	if decision != DedupMerge {
		t.Fatalf("want DedupMerge for normalized source URL, got %d", decision)
	}
	if len(entries) == 0 || entries[0].DraftID != "draft-url" {
		t.Fatalf("want matched entry draft-url, got %+v", entries)
	}
}

func TestCheckPreExtraction_SameSourceURLAndSourceIDSkips(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	seed := storage.ContentIndexEntry{
		SourceURLHash: SourceURLHash("https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/"),
		DraftID:       "draft-clickonce",
		SourceID:      "crowdstrike:part-one",
		Source:        "crowdstrike",
		CreatedAt:     time.Now(),
	}
	if err := db.IndexContent(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	item := scraper.RawItem{
		SourceID: "crowdstrike:part-one",
		Source:   "crowdstrike",
		Title:    "Abuse of Microsoft ClickOnce Technology Explained, Part 1",
		URL:      "https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/?utm_source=rss",
		Content:  "CrowdStrike details ClickOnce internals and abuse mechanics.",
	}
	decision, _, entries := dedup.CheckPreExtraction(item)
	if decision != DedupSkip {
		t.Fatalf("want DedupSkip for same source URL and source ID, got %d", decision)
	}
	if len(entries) == 0 || entries[0].DraftID != "draft-clickonce" {
		t.Fatalf("want matched entry draft-clickonce, got %+v", entries)
	}
}

func TestIndexContent_IndexesReferenceURLAliases(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := &Pipeline{db: db, logger: slog.Default()}

	item := scraper.RawItem{
		SourceID: "crowdstrike:feed-guid",
		Source:   "crowdstrike",
		Title:    "New Abuse of ClickOnce Technology: Understanding Internals",
		URL:      "https://feed.example.com/crowdstrike/clickonce-part-one",
		Content:  "CrowdStrike details ClickOnce internals.",
	}
	briefYAML := `
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
`
	p.indexContent("draft-clickonce", item, nil, nil, briefYAML)

	hits, err := db.FindBySourceURLHash(SourceURLHash("https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/?utm_campaign=x"))
	if err != nil {
		t.Fatalf("find by source URL hash: %v", err)
	}
	if len(hits) == 0 || hits[0].DraftID != "draft-clickonce" {
		t.Fatalf("want reference URL alias indexed for draft-clickonce, got %+v", hits)
	}
}
