package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/publisher"
	"gopkg.in/yaml.v3"
)

type publicIdentity struct {
	BriefID string `yaml:"brief_id"`
	Title   string `yaml:"title"`
	Date    string `yaml:"date"`
}

func main() {
	var feedDir, publicKey, repairedAtRaw, publicPathList string
	var apply bool
	flag.StringVar(&feedDir, "feed-dir", "", "path to a threat-feed checkout")
	flag.StringVar(&publicKey, "public-key", "", "hex feed encryption key")
	flag.StringVar(&repairedAtRaw, "repaired-at", "", "RFC3339 repair timestamp (defaults to now)")
	flag.StringVar(&publicPathList, "public-path-list", "", "optional newline-delimited public paths to rebuild from repaired canonical data")
	flag.BoolVar(&apply, "apply", false, "write repaired segments, manifest, and public Markdown")
	flag.Parse()
	if feedDir == "" || publicKey == "" {
		fatalf("--feed-dir and --public-key are required")
	}
	repairedAt := time.Now().UTC().Truncate(time.Second)
	if repairedAtRaw != "" {
		var err error
		repairedAt, err = time.Parse(time.RFC3339Nano, repairedAtRaw)
		if err != nil {
			fatalf("invalid --repaired-at: %v", err)
		}
	}

	manifestPath := filepath.Join(feedDir, "output", "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		fatalf("read manifest: %v", err)
	}
	var manifest publisher.SegmentManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		fatalf("decode manifest: %v", err)
	}

	segments := make(map[string]*publisher.SegmentContent, len(manifest.Segments))
	segmentFiles := make(map[string]string, len(manifest.Segments))
	for _, entry := range manifest.Segments {
		if !isMonthlySegment(entry.Path) {
			continue
		}
		path := filepath.Join(feedDir, "output", filepath.FromSlash(entry.Path))
		raw, err := os.ReadFile(path)
		if err != nil {
			fatalf("read %s: %v", entry.Path, err)
		}
		if entry.Checksum != "" && publisher.ComputeChecksum(raw) != strings.TrimPrefix(entry.Checksum, "sha256:") {
			fatalf("manifest checksum mismatch for %s", entry.Path)
		}
		var encrypted publisher.BundleManifest
		if err := json.Unmarshal(raw, &encrypted); err != nil {
			fatalf("decode %s: %v", entry.Path, err)
		}
		content, err := publisher.DecryptSegment(&encrypted, publicKey)
		if err != nil {
			fatalf("decrypt %s: %v", entry.Path, err)
		}
		if entry.BriefCount != len(content.Briefs) {
			fatalf("manifest brief count mismatch for %s: got %d, want %d", entry.Path, len(content.Briefs), entry.BriefCount)
		}
		key := strings.TrimSuffix(strings.TrimPrefix(entry.Path, "briefs/"), ".json")
		segments[key] = content
		segmentFiles[key] = path
	}

	preferences := preferredSlugOwners(feedDir, segments)
	report, err := publisher.RepairCanonicalIdentities(segments, publisher.IdentityRepairOptions{
		RepairedAt: repairedAt, PreferredSlugOwners: preferences,
	})
	if err != nil {
		fatalf("repair identities: %v", err)
	}
	result := struct {
		Apply           bool     `json:"apply"`
		RepairedAt      string   `json:"repaired_at"`
		RepairedIDs     int      `json:"repaired_ids"`
		RepairedSlugs   int      `json:"repaired_slugs"`
		ChangedSegments []string `json:"changed_segments"`
		ChangedBriefs   int      `json:"changed_briefs"`
		CollisionBriefs int      `json:"collision_briefs"`
		PreferredOwners int      `json:"preferred_public_owners"`
	}{apply, repairedAt.Format(time.RFC3339), report.RepairedIDs, report.RepairedSlugs,
		report.ChangedSegments, len(report.ChangedBriefs), len(report.CollisionBriefs), len(preferences)}
	publicBriefs := append([]publisher.BundleBrief(nil), report.CollisionBriefs...)
	if publicPathList != "" {
		requested, err := briefsForPublicPathList(publicPathList, segments)
		if err != nil {
			fatalf("resolve --public-path-list: %v", err)
		}
		publicBriefs = mergeBriefsByID(publicBriefs, requested)
	}
	if !apply {
		if _, err := renderCollisionPages(feedDir, publicBriefs); err != nil {
			fatalf("validate public Markdown repair: %v", err)
		}
		printJSON(result)
		return
	}
	renderedPages, err := renderCollisionPages(feedDir, publicBriefs)
	if err != nil {
		fatalf("validate public Markdown repair: %v", err)
	}

	now := repairedAt.UTC().Format(time.RFC3339)
	for _, key := range report.ChangedSegments {
		encrypted, err := publisher.EncryptSegment(segments[key], "1.0", now, publicKey)
		if err != nil {
			fatalf("encrypt %s: %v", key, err)
		}
		raw, err := json.Marshal(encrypted)
		if err != nil {
			fatalf("encode %s: %v", key, err)
		}
		if err := writeFile(segmentFiles[key], raw); err != nil {
			fatalf("write %s: %v", key, err)
		}
		for i := range manifest.Segments {
			if manifest.Segments[i].Path == "briefs/"+key+".json" {
				manifest.Segments[i].Checksum = publisher.ComputeChecksum(raw)
				manifest.Segments[i].BriefCount = len(segments[key].Briefs)
				manifest.Segments[i].LastModified = now
			}
		}
	}
	if len(report.ChangedSegments) > 0 {
		manifest.Version = "v" + now
		manifest.BriefLocations = make(map[string][]string)
		for _, key := range sortedKeys(segments) {
			for _, brief := range segments[key].Briefs {
				manifest.BriefLocations[brief.ID] = append(manifest.BriefLocations[brief.ID], key)
			}
		}
		manifestRaw, err = json.Marshal(&manifest)
		if err != nil {
			fatalf("encode manifest: %v", err)
		}
		if err := writeFile(manifestPath, manifestRaw); err != nil {
			fatalf("write manifest: %v", err)
		}
	}

	writtenPages := 0
	for path, content := range renderedPages {
		existing, _ := os.ReadFile(path)
		if !bytes.Equal(existing, content) {
			if err := writeFile(path, content); err != nil {
				fatalf("write public brief %s: %v", path, err)
			}
			writtenPages++
		}
	}
	printJSON(map[string]any{
		"apply": result.Apply, "repaired_at": result.RepairedAt,
		"repaired_ids": result.RepairedIDs, "repaired_slugs": result.RepairedSlugs,
		"changed_segments": result.ChangedSegments, "changed_briefs": result.ChangedBriefs,
		"collision_briefs": result.CollisionBriefs, "preferred_public_owners": result.PreferredOwners,
		"written_pages": writtenPages,
	})
}

func preferredSlugOwners(feedDir string, segments map[string]*publisher.SegmentContent) map[string]publisher.PreferredSlugOwner {
	groups := make(map[string][]publisher.BundleBrief)
	for _, content := range segments {
		for _, brief := range content.Briefs {
			slug := strings.ToLower(strings.TrimSpace(brief.Slug))
			if slug != "" {
				groups[slug] = append(groups[slug], brief)
			}
		}
	}
	preferred := make(map[string]publisher.PreferredSlugOwner)
	for slug, group := range groups {
		if len(group) < 2 {
			continue
		}
		path := filepath.Join(feedDir, "site", "content", "briefs", slug+".md")
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		identity, err := parsePublicIdentity(raw)
		if err != nil {
			continue
		}
		for _, brief := range group {
			if identity.Title == brief.Title && sameTime(identity.Date, brief.PublishedAt) && (identity.BriefID == "" || identity.BriefID == brief.ID) {
				preferred[slug] = publisher.PreferredSlugOwner{ID: brief.ID, Title: brief.Title, PublishedAt: brief.PublishedAt}
				break
			}
		}
		if _, ok := preferred[slug]; ok || identity.BriefID == "" {
			continue
		}
		matches := make([]publisher.BundleBrief, 0, 1)
		for _, brief := range group {
			if identity.BriefID == brief.ID {
				matches = append(matches, brief)
			}
		}
		if len(matches) == 1 {
			brief := matches[0]
			preferred[slug] = publisher.PreferredSlugOwner{ID: brief.ID, Title: brief.Title, PublishedAt: brief.PublishedAt}
		}
	}
	return preferred
}

func renderCollisionPages(feedDir string, briefs []publisher.BundleBrief) (map[string][]byte, error) {
	pages := make(map[string][]byte)
	owners := make(map[string]string)
	for _, brief := range briefs {
		candidatePath := filepath.Join(feedDir, "site", "content", "briefs", strings.ToLower(firstNonEmpty(brief.Slug, brief.ID))+".md")
		existing, err := os.ReadFile(candidatePath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read public brief %s: %w", candidatePath, err)
		}
		relPath, content, _, publish, err := publisher.RenderPublicBriefMarkdown(brief, existing)
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", brief.ID, err)
		}
		if !publish {
			continue
		}
		if owner, exists := owners[relPath]; exists && owner != brief.ID {
			return nil, fmt.Errorf("repaired public path %s belongs to both %s and %s", relPath, owner, brief.ID)
		}
		owners[relPath] = brief.ID
		pages[filepath.Join(feedDir, filepath.FromSlash(relPath))] = content
	}
	return pages, nil
}

func briefsForPublicPathList(path string, segments map[string]*publisher.SegmentContent) ([]publisher.BundleBrief, error) {
	byPath := make(map[string]publisher.BundleBrief)
	for _, content := range segments {
		for _, brief := range content.Briefs {
			relative := filepath.ToSlash(filepath.Join("site", "content", "briefs", strings.ToLower(firstNonEmpty(brief.Slug, brief.ID))+".md"))
			byPath[relative] = brief
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// This read-only file has no buffered writes to flush.
	defer func() { _ = file.Close() }()
	var briefs []publisher.BundleBrief
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		requested := filepath.ToSlash(strings.TrimSpace(scanner.Text()))
		if requested == "" {
			continue
		}
		brief, ok := byPath[requested]
		if !ok {
			return nil, fmt.Errorf("%s does not resolve to a canonical brief", requested)
		}
		briefs = append(briefs, brief)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return briefs, nil
}

func mergeBriefsByID(groups ...[]publisher.BundleBrief) []publisher.BundleBrief {
	seen := make(map[string]struct{})
	var merged []publisher.BundleBrief
	for _, group := range groups {
		for _, brief := range group {
			if _, exists := seen[brief.ID]; exists {
				continue
			}
			seen[brief.ID] = struct{}{}
			merged = append(merged, brief)
		}
	}
	return merged
}

func parsePublicIdentity(raw []byte) (publicIdentity, error) {
	var identity publicIdentity
	if !bytes.HasPrefix(raw, []byte("---\n")) {
		return identity, fmt.Errorf("missing YAML frontmatter")
	}
	end := bytes.Index(raw[4:], []byte("\n---"))
	if end < 0 {
		return identity, fmt.Errorf("unterminated YAML frontmatter")
	}
	err := yaml.Unmarshal(raw[4:4+end], &identity)
	return identity, err
}

func sameTime(a, b string) bool {
	if a == b {
		return true
	}
	at, aErr := time.Parse(time.RFC3339Nano, a)
	bt, bErr := time.Parse(time.RFC3339Nano, b)
	return aErr == nil && bErr == nil && at.Equal(bt)
}

func isMonthlySegment(path string) bool {
	if !strings.HasPrefix(path, "briefs/") || !strings.HasSuffix(path, ".json") {
		return false
	}
	_, err := time.Parse("2006-01", strings.TrimSuffix(strings.TrimPrefix(path, "briefs/"), ".json"))
	return err == nil
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func writeFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".identity-repair.tmp"
	if err := os.WriteFile(temporary, content, 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func printJSON(value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatalf("encode report: %v", err)
	}
	fmt.Println(string(encoded))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
