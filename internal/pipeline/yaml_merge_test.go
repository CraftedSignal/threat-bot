package pipeline

import "testing"

func TestMergeMapListByIdentityCompleteRepairsExistingDuplicateCVEs(t *testing.T) {
	fm := map[string]any{
		"cves": []any{
			map[string]any{"id": "CVE-2026-129448", "cvss": 9.8, "kev": false},
			map[string]any{"id": "CVE-2026-129448", "kev": true, "kev_status": "true"},
		},
	}

	changed := mergeMapListByIdentityComplete(fm, "cves", nil, []string{"id"})
	got := yamlAnyList(fm["cves"])
	if !changed {
		t.Fatal("duplicate existing entries were not reported as a change")
	}
	if len(got) != 1 {
		t.Fatalf("got %d CVE rows, want one: %#v", len(got), got)
	}
	entry, ok := asStringMap(got[0])
	if !ok {
		t.Fatalf("deduplicated CVE is not a map: %#v", got[0])
	}
	if entry["cvss"] != 9.8 || entry["kev"] != true || entry["kev_status"] != "true" {
		t.Fatalf("deduplicating dropped structured CVE fields: %#v", entry)
	}
}
