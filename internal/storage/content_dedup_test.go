package storage

import (
	"testing"
	"time"
)

func TestFindByContentHash(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	e := ContentIndexEntry{
		ContentHash: "abc123",
		DraftID:     "draft-1",
		SourceID:    "reddit:1",
		Source:      "reddit",
		CreatedAt:   time.Now(),
	}
	if err := db.IndexContent(&e); err != nil {
		t.Fatalf("index: %v", err)
	}

	got, err := db.FindByContentHash("abc123")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(got) != 1 || got[0].DraftID != "draft-1" || got[0].ContentHash != "abc123" {
		t.Fatalf("want 1 entry draft-1/abc123, got %+v", got)
	}
	if none, _ := db.FindByContentHash("nope"); len(none) != 0 {
		t.Fatalf("want 0 for unknown hash, got %d", len(none))
	}
}

func TestFindByProduct_WindowAndCVEBearing(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	fp := "capgo-fp"
	// Recent + CVE-bearing: FindByProductAndNoCVE would exclude it (has a CVE),
	// but FindByProduct must include it.
	if err := db.IndexContent(&ContentIndexEntry{
		CVEID: "CVE-2026-56081", ProductFingerprintHash: fp,
		DraftID: "draft-recent", SourceID: "ghsa:1", Source: "ghsa", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed recent: %v", err)
	}
	// Same product but well outside a 48h window → must be excluded.
	if err := db.IndexContent(&ContentIndexEntry{
		CVEID: "CVE-2020-1", ProductFingerprintHash: fp,
		DraftID: "draft-old", SourceID: "nvd:old", Source: "nvd", CreatedAt: time.Now().Add(-72 * time.Hour),
	}); err != nil {
		t.Fatalf("seed old: %v", err)
	}

	got, err := db.FindByProduct(fp, 48*time.Hour)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(got) != 1 || got[0].DraftID != "draft-recent" {
		t.Fatalf("want only draft-recent within 48h, got %+v", got)
	}
}

func TestFindByVendorCycle(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	key := "microsoft|2026-07"
	if err := db.IndexContent(&ContentIndexEntry{
		CVEID: "CVE-2026-1", VendorCycleKey: key,
		DraftID: "roundup-ms-2026-07", SourceID: "msrc:1", Source: "msrc", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := db.FindByVendorCycle(key)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(got) != 1 || got[0].DraftID != "roundup-ms-2026-07" {
		t.Fatalf("want the roundup draft, got %+v", got)
	}
	if none, _ := db.FindByVendorCycle("adobe|2026-07"); len(none) != 0 {
		t.Fatalf("want 0 for a different cycle key, got %d", len(none))
	}
}
