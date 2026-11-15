package publisher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PublishSTIXBundle generates paginated STIX 2.1 bundles from the last 90 days
// of briefs. It publishes:
//   - site/static/stix.json         — most recent 30 days (quick-access, always <5MB)
//   - site/static/stix/YYYY-MM.json — one bundle per calendar month in the 90-day window
//   - site/static/stix/index.json   — manifest listing available monthly bundles
//
// Hugo serves these at the configured public site under /stix*.
//
// A brief lives in the monthly segment of its publish month. Each month is
// collected, generated, validated, and staged before the next month is read.
// The enclosing Git publication exposes all staged artifacts and the index in
// one branch update, so a later source error can leave an unreachable Git blob
// but cannot publish a partial release.
type stixIndexEntry struct {
	Month          string `json:"month,omitempty"`
	Path           string `json:"path"`
	Checksum       string `json:"checksum"`
	SizeBytes      int    `json:"size_bytes"`
	ReportCount    int    `json:"report_count"`
	FirstPublished string `json:"first_published,omitempty"`
	LastPublished  string `json:"last_published,omitempty"`
	Generated      string `json:"generated"`
	SpecVersion    string `json:"spec_version"`
}

type stixIndex struct {
	Version     string           `json:"version"`
	SpecVersion string           `json:"spec_version"`
	Generated   string           `json:"generated"`
	Description string           `json:"description"`
	Rolling     stixIndexEntry   `json:"rolling"`
	Months      []stixIndexEntry `json:"months"`
}

func immutableSTIXPath(month string, data []byte) string {
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if month == "" {
		return "/stix/releases/sha256-" + digest + ".json"
	}
	return "/stix/releases/" + month + "-sha256-" + digest + ".json"
}

// removeUnreferencedSTIXReleases stages the deletion of every immutable
// release the new index does not reference. The site deploys only referenced
// releases, so the others are no longer served, and without this every
// publication grows the tree the site build checks out. Files that do not
// follow the release naming contract are left for the site build to reject.
func (p *Publisher) removeUnreferencedSTIXReleases(referenced map[string]bool) error {
	if p.publication == nil {
		return fmt.Errorf("no active Git publication")
	}
	names, err := p.listGitTreeFiles(stixDir, "releases")
	if err != nil {
		return err
	}
	removed := 0
	for _, name := range names {
		path := stixReleasesDir + "/" + name
		if referenced[name] || !stixReleaseName.MatchString(name) {
			continue
		}
		if _, staged := p.publication.staged[path]; staged {
			continue
		}
		p.publication.staged[path] = stagedGitFile{deleted: true}
		removed++
	}
	if removed > 0 {
		p.logger.Info("removing superseded stix releases", "removed", removed, "kept", len(referenced))
	}
	return nil
}

func (p *Publisher) PublishSTIXBundle() error {
	return p.withAtomicPublication("chore: publish STIX release", p.publishSTIXBundle)
}

func (p *Publisher) publishSTIXBundle() error {
	manifest, _, err := p.fetchManifest()
	if err != nil {
		return fmt.Errorf("fetching manifest for STIX export: %w", err)
	}

	now := time.Now().UTC()
	generated := now.Format("2006-01-02T15:04:05.000Z")
	monthEntries := make([]stixIndexEntry, 0, 4)
	recent30, err := p.forEachSTIXMonth(manifest, now, func(month string, briefs []BundleBrief) error {
		entry, publishErr := p.publishImmutableSTIXArtifact(month, briefs, generated)
		if publishErr != nil {
			return publishErr
		}
		monthEntries = append(monthEntries, entry)
		return nil
	})
	if err != nil {
		return err
	}

	recentCount := len(recent30)
	rollingEntry, err := p.publishImmutableSTIXArtifact("", recent30, generated)
	if err != nil {
		return err
	}
	// The rolling source is the only brief payload retained across months. Once
	// its immutable artifact is staged, publication needs index metadata only.

	indexJSON, err := json.MarshalIndent(stixIndex{
		Version: "2.0", SpecVersion: "2.1", Generated: generated,
		Description: "STIX 2.1 monthly bundles — last 90 days of threat briefs",
		Rolling:     rollingEntry, Months: monthEntries,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling STIX index: %w", err)
	}

	// Atomically switch the manifest only after every referenced byte
	// set exists and has been revalidated at its immutable path.
	indexSHA, err := p.getFileSHA("site/static/stix/index.json")
	if err != nil {
		return fmt.Errorf("checking existing STIX index: %w", err)
	}
	if err := p.putMarkdownFile("site/static/stix/index.json", indexJSON, indexSHA,
		fmt.Sprintf("chore: update STIX index (%d months)", len(monthEntries))); err != nil {
		return fmt.Errorf("uploading stix/index.json: %w", err)
	}
	referenced := map[string]bool{strings.TrimPrefix(rollingEntry.Path, "/stix/releases/"): true}
	for _, entry := range monthEntries {
		referenced[strings.TrimPrefix(entry.Path, "/stix/releases/")] = true
	}
	if err := p.removeUnreferencedSTIXReleases(referenced); err != nil {
		return fmt.Errorf("removing superseded STIX releases: %w", err)
	}

	// Refresh stable compatibility aliases from the staged immutable blobs one
	// at a time. They are intentionally not index targets, and the enclosing
	// atomic publication prevents an alias failure from exposing a partial
	// release.
	for _, entry := range monthEntries {
		if err := p.publishSTIXCompatibilityAliasFromImmutable(entry); err != nil {
			return err
		}
	}
	if err := p.publishSTIXCompatibilityAliasFromImmutable(rollingEntry); err != nil {
		return err
	}

	p.afterPublicationCommit(func() {
		p.logger.Info("stix bundles published", "months", len(monthEntries), "recent_30d", recentCount)
	})
	return nil
}

func (p *Publisher) publishImmutableSTIXArtifact(month string, briefs []BundleBrief, generated string) (stixIndexEntry, error) {
	bundleJSON, err := ExportSTIX(briefs, p.publicationSiteURL())
	if err != nil {
		if month == "" {
			return stixIndexEntry{}, fmt.Errorf("generating 30-day STIX bundle: %w", err)
		}
		return stixIndexEntry{}, fmt.Errorf("generating STIX bundle for %s: %w", month, err)
	}
	if err := ValidateSTIX(bundleJSON, len(briefs)); err != nil {
		if month == "" {
			return stixIndexEntry{}, fmt.Errorf("validating 30-day STIX bundle: %w", err)
		}
		return stixIndexEntry{}, fmt.Errorf("validating STIX bundle for %s: %w", month, err)
	}

	publicPath := immutableSTIXPath(month, bundleJSON)
	entry, err := newSTIXIndexEntry(month, publicPath, bundleJSON, briefs, generated)
	if err != nil {
		if month == "" {
			return stixIndexEntry{}, fmt.Errorf("indexing 30-day STIX bundle: %w", err)
		}
		return stixIndexEntry{}, fmt.Errorf("indexing STIX bundle for %s: %w", month, err)
	}
	repoPath := "site/static" + publicPath
	existing, _, err := p.fetchJSONFile(repoPath)
	if err != nil {
		return stixIndexEntry{}, fmt.Errorf("checking immutable STIX artifact %s: %w", repoPath, err)
	}
	if existing != nil && !bytes.Equal(existing, bundleJSON) {
		return stixIndexEntry{}, fmt.Errorf("immutable STIX path collision at %s", repoPath)
	}
	if existing == nil {
		message := fmt.Sprintf("chore: add immutable STIX artifact %s (%d briefs)", entry.Path, len(briefs))
		if err := p.putMarkdownFile(repoPath, bundleJSON, "", message); err != nil {
			concurrent, _, concurrentErr := p.fetchJSONFile(repoPath)
			if concurrentErr != nil {
				return stixIndexEntry{}, fmt.Errorf("checking immutable %s after upload race: %w", repoPath, concurrentErr)
			}
			if !bytes.Equal(concurrent, bundleJSON) {
				return stixIndexEntry{}, fmt.Errorf("uploading immutable %s: %w", repoPath, err)
			}
		}
	}
	confirmed, _, err := p.fetchJSONFile(repoPath)
	if err != nil {
		return stixIndexEntry{}, fmt.Errorf("confirming immutable STIX artifact %s: %w", repoPath, err)
	}
	if !bytes.Equal(confirmed, bundleJSON) {
		return stixIndexEntry{}, fmt.Errorf("immutable STIX artifact %s is missing or changed after upload", repoPath)
	}
	if err := ValidateSTIX(confirmed, len(briefs)); err != nil {
		return stixIndexEntry{}, fmt.Errorf("validating stored immutable STIX artifact %s: %w", repoPath, err)
	}
	return entry, nil
}

func (p *Publisher) publishSTIXCompatibilityAliasFromImmutable(entry stixIndexEntry) error {
	repoPath := "site/static" + entry.Path
	data, blobSHA, err := p.fetchJSONFile(repoPath)
	if err != nil {
		return fmt.Errorf("loading immutable STIX artifact %s for compatibility alias: %w", repoPath, err)
	}
	if data == nil {
		return fmt.Errorf("immutable STIX artifact %s is missing before compatibility alias publication", repoPath)
	}
	sum := sha256.Sum256(data)
	checksum := "sha256:" + hex.EncodeToString(sum[:])
	if len(data) != entry.SizeBytes || checksum != entry.Checksum {
		return fmt.Errorf("immutable STIX artifact %s changed before compatibility alias publication", repoPath)
	}
	if err := ValidateSTIX(data, entry.ReportCount); err != nil {
		return fmt.Errorf("validating immutable STIX artifact %s for compatibility alias: %w", repoPath, err)
	}

	aliasRepoPath := "site/static/stix.json"
	if entry.Month != "" {
		aliasRepoPath = "site/static/stix/" + entry.Month + ".json"
	}
	if p.publication != nil {
		// Both paths can name the exact same immutable Git blob. Preserve the
		// alias metadata read/conflict tracking, then reference that validated
		// identity instead of uploading and downloading the same bytes again.
		if blobSHA != gitBlobSHA(data) {
			return fmt.Errorf("immutable STIX artifact %s has an unexpected Git blob SHA", repoPath)
		}
		currentSHA, err := p.getFileSHA(aliasRepoPath)
		if err != nil {
			return fmt.Errorf("checking STIX compatibility alias %s: %w", aliasRepoPath, err)
		}
		if currentSHA != blobSHA {
			p.publication.staged[aliasRepoPath] = stagedGitFile{sha: blobSHA, size: int64(len(data))}
		}
		return nil
	}
	message := fmt.Sprintf("chore: refresh STIX compatibility alias %s (%d briefs)", aliasRepoPath, entry.ReportCount)
	if err := p.publishSTIXCompatibilityAlias(aliasRepoPath, data, message); err != nil {
		return fmt.Errorf("uploading STIX compatibility alias %s: %w", aliasRepoPath, err)
	}
	return nil
}

// publishSTIXCompatibilityAlias verifies the Git blob after every successful
// Contents API response. GitHub can return 200 while a large-file repository
// rule times out without moving the branch. Treat that as a transient write
// and retry with the branch's actual current SHA. Stale-SHA conflicts are also
// retried after a fresh lookup; other client errors remain terminal.
func (p *Publisher) publishSTIXCompatibilityAlias(path string, data []byte, message string) error {
	expectedSHA := gitBlobSHA(data)
	var lastErr error
	for attempt := 1; attempt <= putFileMaxAttempts; attempt++ {
		sha, err := p.getFileSHA(path)
		if err != nil {
			lastErr = fmt.Errorf("checking current blob: %w", err)
		} else if sha == expectedSHA {
			return nil
		} else if err := p.putMarkdownFile(path, data, sha, message); err != nil {
			lastErr = err
			if strings.Contains(err.Error(), "HTTP 4") &&
				!strings.Contains(err.Error(), "HTTP 409") &&
				!strings.Contains(err.Error(), "HTTP 429") {
				return err
			}
		} else {
			confirmed, confirmedSHA, confirmErr := p.fetchJSONFile(path)
			switch {
			case confirmErr != nil:
				lastErr = fmt.Errorf("confirming committed blob: %w", confirmErr)
			case confirmedSHA == expectedSHA || bytes.Equal(confirmed, data):
				return nil
			default:
				lastErr = fmt.Errorf("GitHub accepted the write but branch blob is %q, want %q", confirmedSHA, expectedSHA)
			}
		}
		if attempt < putFileMaxAttempts {
			if err := sleepWithContext(context.Background(), putFileRetryDelays[attempt-1]); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("committing alias after %d attempts: %w", putFileMaxAttempts, lastErr)
}

func (p *Publisher) forEachSTIXMonth(manifest *SegmentManifest, now time.Time, visit func(string, []BundleBrief) error) ([]BundleBrief, error) {
	cutoff90 := now.Add(-90 * 24 * time.Hour)
	cutoff30 := now.Add(-30 * 24 * time.Hour)
	firstMonth := SegmentKey(cutoff90)
	segmentMonths := make([]string, 0, len(manifest.Segments))
	seenSegments := make(map[string]struct{}, len(manifest.Segments))
	entriesByMonth := make(map[string]SegmentEntry, len(manifest.Segments))
	for _, segment := range manifest.Segments {
		if !monthlySegmentPath.MatchString(segment.Path) {
			continue
		}
		month := strings.TrimSuffix(strings.TrimPrefix(segment.Path, "briefs/"), ".json")
		if month < firstMonth {
			continue
		}
		if _, duplicate := seenSegments[month]; duplicate {
			return nil, fmt.Errorf("duplicate eligible STIX segment %q", segment.Path)
		}
		seenSegments[month] = struct{}{}
		entriesByMonth[month] = segment
		segmentMonths = append(segmentMonths, month)
	}
	files, err := p.listDir("output/briefs")
	if err != nil {
		return nil, fmt.Errorf("listing STIX source segments: %w", err)
	}
	for _, name := range files {
		path := "briefs/" + name
		if !monthlySegmentPath.MatchString(path) {
			continue
		}
		month := strings.TrimSuffix(name, ".json")
		if month >= firstMonth {
			if _, listed := seenSegments[month]; !listed {
				return nil, fmt.Errorf("eligible STIX source segment %q is not listed in the manifest", path)
			}
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(segmentMonths)))

	recent30 := make([]BundleBrief, 0)
	seenBriefs := make(map[string]string)
	for _, month := range segmentMonths {
		path := "output/" + segmentPath(month)
		content, _, err := p.fetchManifestSegment(entriesByMonth[month])
		if err != nil {
			return nil, fmt.Errorf("fetching eligible STIX segment %s: %w", path, err)
		}
		briefs := content.Briefs[:0]
		for _, raw := range content.Briefs {
			brief := NormalizePublicationMetadata(raw)
			published, parseErr := time.Parse(time.RFC3339Nano, brief.PublishedAt)
			if parseErr != nil {
				return nil, fmt.Errorf("brief %q in %s has invalid published_at: %w", brief.ID, path, parseErr)
			}
			if SegmentKey(published) != month {
				return nil, fmt.Errorf("brief %q published in %s is stored in segment %s", brief.ID, SegmentKey(published), month)
			}
			if published.Before(cutoff90) {
				continue
			}
			if previousMonth, duplicate := seenBriefs[brief.ID]; duplicate {
				return nil, fmt.Errorf("duplicate canonical brief id %q in STIX segments %s and %s", brief.ID, previousMonth, month)
			}
			seenBriefs[brief.ID] = month
			briefs = append(briefs, brief)
			if !published.Before(cutoff30) {
				recent30 = append(recent30, brief)
			}
		}
		if len(briefs) == 0 {
			continue
		}
		sort.Slice(briefs, func(i, j int) bool { return briefs[i].ID < briefs[j].ID })
		if err := visit(month, briefs); err != nil {
			return nil, err
		}
	}
	sort.Slice(recent30, func(i, j int) bool { return recent30[i].ID < recent30[j].ID })
	return recent30, nil
}

func newSTIXIndexEntry(month, path string, data []byte, briefs []BundleBrief, generated string) (stixIndexEntry, error) {
	sum := sha256.Sum256(data)
	entry := stixIndexEntry{
		Month: month, Path: path, Checksum: "sha256:" + hex.EncodeToString(sum[:]),
		SizeBytes: len(data), ReportCount: len(briefs), Generated: generated, SpecVersion: "2.1",
	}
	for _, brief := range briefs {
		published, _, err := normalizeSTIXTimestamp(brief.PublishedAt)
		if err != nil {
			return stixIndexEntry{}, fmt.Errorf("brief %q: %w", brief.ID, err)
		}
		if entry.FirstPublished == "" || published < entry.FirstPublished {
			entry.FirstPublished = published
		}
		if published > entry.LastPublished {
			entry.LastPublished = published
		}
	}
	return entry, nil
}
