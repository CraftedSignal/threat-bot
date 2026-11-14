package publisher

import "time"

// MigrateBundleToSegments converts a legacy flat BundleContent into a
// SegmentManifest by distributing briefs into monthly segments based on
// their PublishedAt timestamp.
func MigrateBundleToSegments(old *BundleContent) *SegmentManifest {
	manifest := NewSegmentManifest()
	manifest.Version = "v" + time.Now().UTC().Format("20060102-150405")
	for _, brief := range old.Briefs {
		manifest.AddBrief(brief)
	}
	return manifest
}
