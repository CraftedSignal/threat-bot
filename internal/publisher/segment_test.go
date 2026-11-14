package publisher

import (
	"testing"
	"time"
)

func TestSegmentKeyFromDate(t *testing.T) {
	tests := []struct {
		date     string
		expected string
	}{
		{"2026-03-30T12:00:00Z", "2026-03"},
		{"2026-01-01T00:00:00Z", "2026-01"},
		{"2025-12-31T23:59:59Z", "2025-12"},
	}
	for _, tt := range tests {
		ts, _ := time.Parse(time.RFC3339, tt.date)
		key := SegmentKey(ts)
		if key != tt.expected {
			t.Errorf("SegmentKey(%s) = %s, want %s", tt.date, key, tt.expected)
		}
	}
}

func TestSegmentManifest_AddBrief(t *testing.T) {
	m := NewSegmentManifest()
	brief := BundleBrief{
		ID:          "brief-2026-03-30-test",
		PublishedAt: "2026-03-30T12:00:00Z",
	}
	m.AddBrief(brief)
	if len(m.Segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(m.Segments))
	}
	seg := m.Segments[0]
	if seg.Path != "briefs/2026-03.json" {
		t.Errorf("unexpected path: %s", seg.Path)
	}
	if seg.BriefCount != 1 {
		t.Errorf("expected 1 brief, got %d", seg.BriefCount)
	}
}

func TestSegmentManifest_MultipleBriefsOneMonth(t *testing.T) {
	m := NewSegmentManifest()
	m.AddBrief(BundleBrief{ID: "brief-1", PublishedAt: "2026-03-01T00:00:00Z"})
	m.AddBrief(BundleBrief{ID: "brief-2", PublishedAt: "2026-03-15T00:00:00Z"})
	if len(m.Segments) != 1 {
		t.Fatalf("expected 1 segment (same month), got %d", len(m.Segments))
	}
	if m.Segments[0].BriefCount != 2 {
		t.Errorf("expected 2 briefs, got %d", m.Segments[0].BriefCount)
	}
}

func TestSegmentManifest_MultipleMonths(t *testing.T) {
	m := NewSegmentManifest()
	m.AddBrief(BundleBrief{ID: "brief-1", PublishedAt: "2025-12-15T00:00:00Z"})
	m.AddBrief(BundleBrief{ID: "brief-2", PublishedAt: "2026-03-15T00:00:00Z"})
	if len(m.Segments) != 2 {
		t.Fatalf("expected 2 segments (2025-12, 2026-03), got %d", len(m.Segments))
	}
}

func TestChangelog_Append(t *testing.T) {
	cl := NewChangelog()
	cl.RecordAdd("brief-2026-03-30-test")
	cl.RecordUpdate("brief-2026-03-28-old", []string{"cves.epss", "priority"})
	if len(cl.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cl.Entries))
	}
	if len(cl.Entries[0].Changes) != 2 {
		t.Errorf("expected 2 changes, got %d", len(cl.Entries[0].Changes))
	}
}

// Legacy pre-migration manifests carry yearly entries (briefs/2024.json)
// whose briefs were redistributed into monthly segments; consumers that sync
// every listed segment then ingest each brief twice.
func TestSegmentManifest_PruneLegacySegments(t *testing.T) {
	m := NewSegmentManifest()
	m.Segments = []SegmentEntry{
		{Path: "briefs/2016.json", BriefCount: 1},
		{Path: "briefs/2024-01.json", BriefCount: 1421},
		{Path: "briefs/2024.json", BriefCount: 2559},
		{Path: "briefs/2026-07.json", BriefCount: 1110},
		{Path: "briefs/2026.json", BriefCount: 4391},
	}

	removed := m.PruneLegacySegments()

	wantRemoved := []string{"briefs/2016.json", "briefs/2024.json", "briefs/2026.json"}
	if len(removed) != len(wantRemoved) {
		t.Fatalf("removed = %v, want %v", removed, wantRemoved)
	}
	for i, path := range wantRemoved {
		if removed[i] != path {
			t.Errorf("removed[%d] = %s, want %s", i, removed[i], path)
		}
	}
	var kept []string
	for _, seg := range m.Segments {
		kept = append(kept, seg.Path)
	}
	if len(kept) != 2 || kept[0] != "briefs/2024-01.json" || kept[1] != "briefs/2026-07.json" {
		t.Errorf("kept = %v, want monthly segments only", kept)
	}
}
