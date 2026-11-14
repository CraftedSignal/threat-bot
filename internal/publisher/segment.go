package publisher

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// SegmentManifest is the top-level index of all monthly brief segments.
type SegmentManifest struct {
	Version         string              `json:"version,omitempty"`
	Segments        []SegmentEntry      `json:"segments"`
	CVEMeta         *CVEMetaEntry       `json:"cve_meta,omitempty"`
	ChangelogRef    *ChangelogEntry     `json:"changelog,omitempty"`
	BriefLocations  map[string][]string `json:"brief_locations,omitempty"`
	briefsBySegment map[string][]BundleBrief
}

// SegmentEntry describes a single monthly segment file.
type SegmentEntry struct {
	Path         string `json:"path"`
	Checksum     string `json:"checksum,omitempty"`
	BriefCount   int    `json:"brief_count"`
	LastModified string `json:"last_modified,omitempty"`
}

// CVEMetaEntry points to the shared CVE metadata file.
type CVEMetaEntry struct {
	Path            string `json:"path"`
	Checksum        string `json:"checksum,omitempty"`
	LastEPSSRefresh string `json:"last_epss_refresh,omitempty"`
}

// ChangelogEntry is a reference to the changelog file.
type ChangelogEntry struct {
	Path  string `json:"path"`
	Since string `json:"since,omitempty"`
}

// SegmentContent holds the briefs and digests for a single month.
type SegmentContent struct {
	Briefs  []BundleBrief  `json:"briefs"`
	Digests []BundleDigest `json:"digests,omitempty"`
}

// CVEMetadata holds the last refresh time and a map of CVE scores keyed by CVE ID.
type CVEMetadata struct {
	LastRefresh string              `json:"last_refresh"`
	Scores      map[string]CVEScore `json:"scores"`
}

// CVEScore holds enrichment data for a single CVE.
type CVEScore struct {
	EPSS           float64 `json:"epss"`
	EPSSPercentile float64 `json:"epss_percentile"`
	CVSS           float64 `json:"cvss"`
	KEV            bool    `json:"kev,omitempty"`
}

// Changelog tracks a history of bundle mutations.
type Changelog struct {
	Entries []ChangelogVersion `json:"entries"`
}

// ChangelogVersion groups all changes that happened in a single publish run.
type ChangelogVersion struct {
	Version   string           `json:"version"`
	Timestamp string           `json:"timestamp"`
	Changes   []ChangelogDelta `json:"changes"`
}

// ChangelogDelta describes a single brief-level change.
type ChangelogDelta struct {
	Type    string   `json:"type"` // "added", "updated", "removed"
	BriefID string   `json:"brief_id"`
	Fields  []string `json:"fields,omitempty"` // populated for "updated"
}

// SegmentKey returns the YYYY-MM string for a given time, used as the segment identifier.
func SegmentKey(t time.Time) string {
	return t.UTC().Format("2006-01")
}

// segmentPath returns the relative file path for a given segment key.
func segmentPath(key string) string {
	return fmt.Sprintf("briefs/%s.json", key)
}

// NewSegmentManifest creates an empty SegmentManifest.
func NewSegmentManifest() *SegmentManifest {
	return &SegmentManifest{
		briefsBySegment: make(map[string][]BundleBrief),
	}
}

// EnsureSegment lists a monthly file even when it contains only digests.
func (m *SegmentManifest) EnsureSegment(key string) {
	path := segmentPath(key)
	for _, segment := range m.Segments {
		if segment.Path == path {
			return
		}
	}
	m.Segments = append(m.Segments, SegmentEntry{Path: path})
	sort.Slice(m.Segments, func(i, j int) bool {
		return m.Segments[i].Path < m.Segments[j].Path
	})
}

// AddBrief adds a brief to the appropriate segment, upserting its entry in Segments.
// It does NOT overwrite existing segment entries (preserving checksum/lastModified).
func (m *SegmentManifest) AddBrief(brief BundleBrief) {
	ts, err := time.Parse(time.RFC3339, brief.PublishedAt)
	if err != nil {
		ts = time.Now().UTC()
	}
	key := SegmentKey(ts)
	m.briefsBySegment[key] = append(m.briefsBySegment[key], brief)

	// Upsert into Segments so existing entries for other years are preserved.
	path := segmentPath(key)
	for i := range m.Segments {
		if m.Segments[i].Path == path {
			m.Segments[i].BriefCount = len(m.briefsBySegment[key])
			return
		}
	}
	m.Segments = append(m.Segments, SegmentEntry{
		Path:       path,
		BriefCount: len(m.briefsBySegment[key]),
	})
	sort.Slice(m.Segments, func(i, j int) bool {
		return m.Segments[i].Path < m.Segments[j].Path
	})
}

// AddBriefToSegment queues a brief for a canonical segment chosen from the
// stored identity. This prevents an incoming published_at mutation from
// routing an existing ID into a second month before MergeBriefs can reject it.
func (m *SegmentManifest) AddBriefToSegment(key string, brief BundleBrief) {
	if m.briefsBySegment == nil {
		m.briefsBySegment = make(map[string][]BundleBrief)
	}
	m.briefsBySegment[key] = append(m.briefsBySegment[key], brief)
	path := segmentPath(key)
	for i := range m.Segments {
		if m.Segments[i].Path == path {
			return
		}
	}
	m.Segments = append(m.Segments, SegmentEntry{Path: path})
	sort.Slice(m.Segments, func(i, j int) bool { return m.Segments[i].Path < m.Segments[j].Path })
}

// monthlySegmentPath matches the current segment layout (briefs/YYYY-MM.json).
var monthlySegmentPath = regexp.MustCompile(`^briefs/\d{4}-\d{2}\.json$`)

// PruneLegacySegments drops pre-migration manifest entries (yearly
// briefs/YYYY.json). Their briefs were redistributed into monthly segments,
// so consumers that sync every listed segment ingested each brief twice.
// Returns the removed paths so callers can log and clean up the files.
func (m *SegmentManifest) PruneLegacySegments() []string {
	var removed []string
	kept := m.Segments[:0]
	for _, seg := range m.Segments {
		if monthlySegmentPath.MatchString(seg.Path) {
			kept = append(kept, seg)
		} else {
			removed = append(removed, seg.Path)
		}
	}
	m.Segments = kept
	return removed
}

// GetSegmentBriefs returns all briefs for the given segment key (YYYY-MM).
func (m *SegmentManifest) GetSegmentBriefs(key string) []BundleBrief {
	return m.briefsBySegment[key]
}

// ComputeChecksum returns the SHA-256 hex digest of data.
func ComputeChecksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NewChangelog creates an empty Changelog with a single open version entry
// timestamped to now.
func NewChangelog() *Changelog {
	return &Changelog{
		Entries: []ChangelogVersion{
			{
				Version:   "1",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Changes:   []ChangelogDelta{},
			},
		},
	}
}

// currentEntry returns a pointer to the most recent (open) version entry.
// Lazily seeds an entry if the changelog was loaded with an empty
// entries array (production hit this with a freshly-initialised
// changelog.json that had `"entries": []` in it, panicking the scraper
// on first RecordUpdate).
func (cl *Changelog) currentEntry() *ChangelogVersion {
	if len(cl.Entries) == 0 {
		cl.Entries = append(cl.Entries, ChangelogVersion{
			Version:   "1",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Changes:   []ChangelogDelta{},
		})
	}
	return &cl.Entries[len(cl.Entries)-1]
}

// RecordAdd records that a new brief was added.
func (cl *Changelog) RecordAdd(briefID string) {
	cl.currentEntry().Changes = append(cl.currentEntry().Changes, ChangelogDelta{
		Type:    "added",
		BriefID: briefID,
	})
}

// RecordUpdate records that an existing brief was updated, listing which fields changed.
func (cl *Changelog) RecordUpdate(briefID string, fields []string) {
	cl.currentEntry().Changes = append(cl.currentEntry().Changes, ChangelogDelta{
		Type:    "updated",
		BriefID: briefID,
		Fields:  fields,
	})
}

// RecordRemove records that a duplicate or otherwise retired brief left the
// canonical feed.
func (cl *Changelog) RecordRemove(briefID string) {
	cl.currentEntry().Changes = append(cl.currentEntry().Changes, ChangelogDelta{
		Type:    "removed",
		BriefID: briefID,
	})
}

// Prune removes changelog entries older than maxAge and caps total entries to maxEntries.
// It operates on the Entries slice in ascending timestamp order; the newest entries are kept.
func (cl *Changelog) Prune(maxAge time.Duration, maxEntries int) {
	cutoff := time.Now().UTC().Add(-maxAge)
	kept := cl.Entries[:0]
	for _, e := range cl.Entries {
		ts, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil || ts.After(cutoff) {
			kept = append(kept, e)
		}
	}
	cl.Entries = kept

	if maxEntries > 0 && len(cl.Entries) > maxEntries {
		cl.Entries = cl.Entries[len(cl.Entries)-maxEntries:]
	}
}
