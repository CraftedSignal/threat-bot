package publisher

import "testing"

func TestMigrateBundleToSegments(t *testing.T) {
	old := &BundleContent{
		Briefs: []BundleBrief{
			{ID: "brief-1", PublishedAt: "2025-12-15T00:00:00Z", Title: "2025 Brief"},
			{ID: "brief-2", PublishedAt: "2026-03-01T00:00:00Z", Title: "2026 Brief 1"},
			{ID: "brief-3", PublishedAt: "2026-03-20T00:00:00Z", Title: "2026 Brief 2"},
		},
		Digests: []BundleDigest{
			{ID: "daily-2026-03-20", Type: "daily_digest"},
		},
	}

	manifest := MigrateBundleToSegments(old)
	if len(manifest.Segments) != 2 {
		t.Fatalf("expected 2 segments (2025-12, 2026-03), got %d", len(manifest.Segments))
	}

	dec2025 := manifest.GetSegmentBriefs("2025-12")
	if len(dec2025) != 1 || dec2025[0].ID != "brief-1" {
		t.Errorf("unexpected 2025-12 briefs: %v", dec2025)
	}

	mar2026 := manifest.GetSegmentBriefs("2026-03")
	if len(mar2026) != 2 {
		t.Errorf("expected 2 2026-03 briefs, got %d", len(mar2026))
	}
}
