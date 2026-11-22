package pipeline

import "testing"

func TestDedupeExistingCVEEntriesMergesComplementaryMetadata(t *testing.T) {
	fm := map[string]any{
		"cves": []any{
			map[string]any{"id": "CVE-2026-129448", "cvss": 9.8, "kev": false},
			map[string]any{"id": "CVE-2026-129448", "kev": true, "kev_status": "true"},
		},
	}

	cleaned, changed := dedupeExistingCVEEntries(fm["cves"])
	if !changed {
		t.Fatal("duplicate existing entries were not reported as a change")
	}
	if len(cleaned) != 1 {
		t.Fatalf("got %d cleaned CVE rows, want one: %#v", len(cleaned), cleaned)
	}
	entry, ok := asStringMap(cleaned[0])
	if !ok {
		t.Fatalf("deduplicated CVE is not a map: %#v", cleaned[0])
	}
	if entry["cvss"] != 9.8 || entry["kev"] != true || entry["kev_status"] != "true" {
		t.Fatalf("deduplicating dropped structured CVE fields: %#v", entry)
	}
}

func TestDedupeExistingCVEEntriesKeepsConflictingMetadata(t *testing.T) {
	rows := []any{
		map[string]any{"id": "CVE-2026-129448", "cvss": 9.8, "kev_status": "false"},
		map[string]any{"id": "CVE-2026-129448", "cvss": 7.5, "kev_status": "false"},
	}
	cleaned, changed := dedupeExistingCVEEntries(rows)
	if changed {
		t.Fatal("conflicting CVSS rows must remain available for editorial resolution")
	}
	if len(cleaned) != 2 {
		t.Fatalf("conflicting rows were discarded: %#v", cleaned)
	}
}

func TestDedupeExistingCVEEntriesPrefersStructuredRowToBareID(t *testing.T) {
	rows := []any{"CVE-2026-129448", map[string]any{"id": "CVE-2026-129448", "cvss": 9.8}}
	cleaned, changed := dedupeExistingCVEEntries(rows)
	if !changed || len(cleaned) != 1 {
		t.Fatalf("got changed=%v rows=%#v, want one structured row", changed, cleaned)
	}
	entry, ok := asStringMap(cleaned[0])
	if !ok || entry["cvss"] != 9.8 {
		t.Fatalf("structured fields were not preserved: %#v", cleaned)
	}
}
