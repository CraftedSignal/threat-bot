package pipeline

import (
	"log/slog"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// correctedIOUringYAML is the io_uring brief after its editorial correction:
// it cites only its own exploit source. Merged NVD items were removed, but
// their index rows were written while the draft still cited them.
const correctedIOUringYAML = ioUringBriefYAML + `references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KUZEYARDABULUT-CVE-2024-0582&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-05T10:27:57Z"
    level: L2
    sources:
      - editorial-correction
    summary: removed separate vulnerabilities merged in error
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2024-0582
`

const (
	removedNVDURL  = "https://nvd.nist.gov/vuln/detail/CVE-2026-99218"
	ownExploitURL  = "https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KUZEYARDABULUT-CVE-2024-0582"
	updateLogURL   = "https://www.cve.org/CVERecord?id=CVE-2024-0582"
	removedNVDBody = "In the Linux kernel, the following vulnerability has been resolved: coredump: hold RCU while releasing parked threads, so a racing exit cannot free the task early."
)

func newCitationTestDedup(t *testing.T) (*storage.DB, *Deduplicator) {
	t.Helper()
	db := mustOpenTestDB(t)
	t.Cleanup(func() { db.Close() })
	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-io-uring", Status: storage.StatusApproved, Source: "sploitus",
		BriefYAML: correctedIOUringYAML, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return db, NewDeduplicator(db, slog.Default())
}

func indexRows(t *testing.T, db *storage.DB, rows ...storage.ContentIndexEntry) {
	t.Helper()
	for _, row := range rows {
		row.DraftID, row.CreatedAt = "draft-io-uring", time.Now()
		if err := db.IndexContent(&row); err != nil {
			t.Fatal(err)
		}
	}
}

func removedNVDItem() scraper.RawItem {
	return scraper.RawItem{
		SourceID: "nvd:CVE-2026-99218", Source: "nvd", Title: "CVE-2026-99218",
		URL: removedNVDURL, Content: removedNVDBody,
	}
}

func routesToIOUring(entries []storage.ContentIndexEntry) bool {
	for _, e := range entries {
		if e.DraftID == "draft-io-uring" {
			return true
		}
	}
	return false
}

// A replayed NVD item that a correction removed from the brief must be
// processed again, not skipped as the duplicate it no longer is.
func TestCheckPreExtraction_IgnoresURLRowsItsDraftNoLongerCites(t *testing.T) {
	db, dedup := newCitationTestDedup(t)
	indexRows(t, db,
		storage.ContentIndexEntry{SourceURLHash: SourceURLHash(removedNVDURL), SourceID: "nvd:CVE-2026-99218", Source: "nvd"},
		// The draft's other sources were indexed with an alias for every URL
		// it cited at the time.
		storage.ContentIndexEntry{SourceURLHash: SourceURLHash(removedNVDURL), SourceID: "nvd:CVE-2026-99224", Source: "nvd"},
	)

	decision, _, entries := dedup.CheckPreExtraction(removedNVDItem())
	if decision == DedupSkip || decision == DedupMerge || routesToIOUring(entries) {
		t.Fatalf("decision %d entries %+v: the removed item still routes to the corrected brief", decision, entries)
	}
}

// The same rows still apply while the draft cites the URL.
func TestCheckPreExtraction_SkipsAnItemItsDraftStillCites(t *testing.T) {
	db, dedup := newCitationTestDedup(t)
	indexRows(t, db, storage.ContentIndexEntry{SourceURLHash: SourceURLHash(ownExploitURL), SourceID: "sploitus:KITPLOIT", Source: "sploitus"})

	item := scraper.RawItem{SourceID: "sploitus:KITPLOIT", Source: "sploitus", Title: "CVE-2024-0582 exploit", URL: ownExploitURL, Content: "A proof of concept for CVE-2024-0582."}
	if decision, _, entries := dedup.CheckPreExtraction(item); decision != DedupSkip || !routesToIOUring(entries) {
		t.Fatalf("decision %d entries %+v, want the brief's own source skipped as a duplicate", decision, entries)
	}
}

// Identical content from another source is a republication of the indexed
// item only while the draft still cites that item.
func TestCheckPreExtraction_IgnoresContentRowsItsDraftNoLongerCites(t *testing.T) {
	db, dedup := newCitationTestDedup(t)
	indexRows(t, db, storage.ContentIndexEntry{
		ContentHash: NormalizeContentHash("CVE-2026-99218", removedNVDBody), SourceURLHash: SourceURLHash(removedNVDURL),
		SourceID: "nvd:CVE-2026-99218", Source: "nvd",
	})

	syndicated := scraper.RawItem{SourceID: "cccs:av26-1108", Source: "cccs", Title: "CVE-2026-99218", URL: "https://cyber.gc.ca/en/alerts-advisories/av26-1108", Content: removedNVDBody}
	if decision, _, entries := dedup.CheckPreExtraction(syndicated); decision == DedupSkip || routesToIOUring(entries) {
		t.Fatalf("decision %d entries %+v: a copy of the removed item still routes to the corrected brief", decision, entries)
	}
}

// A merge that adds nothing citable records the source only in the update
// log. Its rows stay live as long as the log names the URL.
func TestCheckPreExtraction_KeepsRowsTheUpdateLogCites(t *testing.T) {
	db, dedup := newCitationTestDedup(t)
	body := "MITRE published the record for CVE-2024-0582, a use-after-free in io_uring buffer ring unregistration that lets a local user escalate privileges."
	indexRows(t, db, storage.ContentIndexEntry{
		ContentHash: NormalizeContentHash("CVE-2024-0582", body), SourceURLHash: SourceURLHash(updateLogURL),
		SourceID: "cve-org:CVE-2024-0582", Source: "cve-org",
	})

	syndicated := scraper.RawItem{SourceID: "mirror:1", Source: "mirror", Title: "CVE-2024-0582", URL: "https://mirror.example/CVE-2024-0582", Content: body}
	if decision, _, entries := dedup.CheckPreExtraction(syndicated); decision != DedupSkip || !routesToIOUring(entries) {
		t.Fatalf("decision %d entries %+v, want the republication skipped", decision, entries)
	}
}

// A merge that adds nothing at all records the corroborating source in the
// draft's validation notes and still indexes the item. Its rows stay live, so
// a literal copy of it is still skipped.
func TestCheckPreExtraction_KeepsRowsOfCorroboratingSources(t *testing.T) {
	db, dedup := newCitationTestDedup(t)
	corroborating := "https://cyber.gc.ca/en/alerts-advisories/linux-security-advisory-av26-1108"
	if err := db.AppendDraftReferenceWithSource("draft-io-uring", "[corroborated] cccs "+corroborating, "cccs:av26-1108"); err != nil {
		t.Fatal(err)
	}
	body := "Linux security advisory AV26-1108: update affected kernels; the io_uring flaw CVE-2024-0582 lets a local user gain root privileges."
	indexRows(t, db, storage.ContentIndexEntry{
		ContentHash: NormalizeContentHash("Linux security advisory (AV26-1108)", body), SourceURLHash: SourceURLHash(corroborating),
		SourceID: "cccs:av26-1108", Source: "cccs",
	})

	copied := scraper.RawItem{SourceID: "mirror:av26-1108", Source: "mirror", Title: "Linux security advisory (AV26-1108)", URL: "https://mirror.example/av26-1108", Content: body}
	if decision, _, entries := dedup.CheckPreExtraction(copied); decision != DedupSkip || !routesToIOUring(entries) {
		t.Fatalf("decision %d entries %+v, want the copy of a corroborating source skipped", decision, entries)
	}
}

// A same-titled item from another source must not join a draft through a
// title row of an item the draft no longer cites.
func TestCheckPreExtraction_IgnoresTitleRowsItsDraftNoLongerCites(t *testing.T) {
	db, dedup := newCitationTestDedup(t)
	title := "Linux kernel coredump race fixed"
	indexRows(t, db, storage.ContentIndexEntry{
		TitleHash: NormalizeTitleHash(title), SourceURLHash: SourceURLHash(removedNVDURL),
		SourceID: "nvd:CVE-2026-99218", Source: "nvd",
	})

	item := scraper.RawItem{SourceID: "lwn:1", Source: "lwn", Title: title, URL: "https://lwn.net/Articles/1/", Content: "The kernel fixed a coredump race."}
	if decision, _, entries := dedup.CheckPreExtraction(item); decision == DedupSkip || decision == DedupMerge || routesToIOUring(entries) {
		t.Fatalf("decision %d entries %+v: the title of a removed item still routes to the corrected brief", decision, entries)
	}
}
