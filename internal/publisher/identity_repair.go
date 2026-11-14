package publisher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// IdentityRepairOptions controls the deterministic repair of legacy identity
// collisions. PreferredSlugOwners preserves the record currently served at a
// shared public URL when that owner can be identified from its Markdown.
type IdentityRepairOptions struct {
	RepairedAt          time.Time
	PreferredSlugOwners map[string]PreferredSlugOwner
}

// PreferredSlugOwner identifies the brief currently represented by a shared
// public path. PublishedAt and Title disambiguate legacy records that reused
// the same ID as well as the same slug.
type PreferredSlugOwner struct {
	ID          string
	Title       string
	PublishedAt string
}

// IdentityRepairReport describes the records changed by a repair. The briefs
// are returned in their repaired form so an operator can rebuild public pages.
type IdentityRepairReport struct {
	RepairedIDs     int
	RepairedSlugs   int
	ChangedSegments []string
	ChangedBriefs   []BundleBrief
	CollisionBriefs []BundleBrief
}

type identityOccurrence struct {
	segment string
	index   int
}

var datedBriefID = regexp.MustCompile(`^brief-\d{4}-\d{2}(?:-\d{2})?-(.+)$`)
var unsafeIdentityPart = regexp.MustCompile(`[^a-z0-9]+`)

// RepairCanonicalIdentities mutates a fully loaded canonical corpus so every
// ID, event ID, and non-empty slug has exactly one owner. For a shared slug it
// preserves the preferred (or newest) owner and assigns ID-derived slugs to
// the others. Reused IDs keep the record whose date matches the ID and receive
// a publication-date-derived ID for every other record.
func RepairCanonicalIdentities(segments map[string]*SegmentContent, options IdentityRepairOptions) (IdentityRepairReport, error) {
	var report IdentityRepairReport
	if options.RepairedAt.IsZero() {
		return report, fmt.Errorf("identity repair timestamp is required")
	}
	keys := sortedSegmentKeys(segments)
	original := make(map[identityOccurrence]BundleBrief)
	collisionMembers := make(map[identityOccurrence]struct{})
	markChanged := func(occ identityOccurrence) {
		if _, ok := original[occ]; ok {
			return
		}
		original[occ] = NormalizePublicationMetadata(segments[occ.segment].Briefs[occ.index])
	}

	ids := make(map[string][]identityOccurrence)
	usedIDs := make(map[string]struct{})
	for _, key := range keys {
		for i, raw := range segments[key].Briefs {
			brief := NormalizePublicationMetadata(raw)
			if strings.TrimSpace(brief.ID) == "" {
				return report, fmt.Errorf("brief at %s[%d] is missing an ID", key, i)
			}
			if err := validateRepairBrief(brief, key); err != nil {
				return report, err
			}
			occ := identityOccurrence{segment: key, index: i}
			ids[brief.ID] = append(ids[brief.ID], occ)
			usedIDs[brief.ID] = struct{}{}
		}
	}

	for _, id := range sortedOccurrenceGroupKeys(ids) {
		group := ids[id]
		if len(group) < 2 {
			continue
		}
		for _, occ := range group {
			collisionMembers[occ] = struct{}{}
		}
		keeper := chooseIDKeeper(segments, id, group)
		for _, occ := range group {
			if occ == keeper {
				continue
			}
			markChanged(occ)
			brief := NormalizePublicationMetadata(segments[occ.segment].Briefs[occ.index])
			oldID := brief.ID
			brief.ID = uniqueRepairedID(brief, usedIDs)
			if strings.TrimSpace(brief.EventID) == "" || brief.EventID == oldID {
				brief.EventID = brief.ID
			}
			segments[occ.segment].Briefs[occ.index] = brief
			usedIDs[brief.ID] = struct{}{}
			report.RepairedIDs++
		}
	}

	slugs := make(map[string][]identityOccurrence)
	usedSlugs := make(map[string]struct{})
	for _, key := range keys {
		for i, raw := range segments[key].Briefs {
			brief := NormalizePublicationMetadata(raw)
			slug := normalizedSlug(brief.Slug)
			if slug == "" {
				continue
			}
			occ := identityOccurrence{segment: key, index: i}
			slugs[slug] = append(slugs[slug], occ)
			usedSlugs[slug] = struct{}{}
		}
	}
	for _, slug := range sortedOccurrenceGroupKeys(slugs) {
		group := slugs[slug]
		if len(group) < 2 {
			continue
		}
		for _, occ := range group {
			collisionMembers[occ] = struct{}{}
		}
		keeper := chooseSlugKeeper(segments, slug, group, options.PreferredSlugOwners)
		for _, occ := range group {
			if occ == keeper {
				continue
			}
			markChanged(occ)
			brief := NormalizePublicationMetadata(segments[occ.segment].Briefs[occ.index])
			brief.Slug = uniqueRepairedSlug(brief, usedSlugs)
			segments[occ.segment].Briefs[occ.index] = brief
			usedSlugs[normalizedSlug(brief.Slug)] = struct{}{}
			report.RepairedSlugs++
		}
	}

	changedSegments := make(map[string]struct{})
	changedOccurrences := sortedOccurrences(original)
	for _, occ := range changedOccurrences {
		before := original[occ]
		after := NormalizePublicationMetadata(segments[occ.segment].Briefs[occ.index])
		beforeState, err := identityStateJSON(before)
		if err != nil {
			return report, fmt.Errorf("hashing original identity %q: %w", before.ID, err)
		}
		afterState, err := identityStateJSON(after)
		if err != nil {
			return report, fmt.Errorf("hashing repaired identity %q: %w", after.ID, err)
		}
		changedFields := changedPublicationFields(beforeState, afterState)
		if len(changedFields) == 0 {
			continue
		}
		after.Revision = before.Revision + 1
		after.RevisionHistory = append([]BundleRevision(nil), before.RevisionHistory...)
		digest := sha256.Sum256(afterState)
		after.RevisionHistory = append(after.RevisionHistory, BundleRevision{
			Revision:      after.Revision,
			At:            options.RepairedAt.UTC().Format(time.RFC3339),
			Checksum:      "sha256:" + hex.EncodeToString(digest[:]),
			Summary:       "Repaired a legacy canonical identity collision",
			ChangedFields: changedFields,
			Maintenance:   true,
		})
		segments[occ.segment].Briefs[occ.index] = after
		changedSegments[occ.segment] = struct{}{}
		report.ChangedBriefs = append(report.ChangedBriefs, after)
	}
	for key := range changedSegments {
		report.ChangedSegments = append(report.ChangedSegments, key)
	}
	sort.Strings(report.ChangedSegments)

	for _, occ := range sortedOccurrenceSet(collisionMembers) {
		report.CollisionBriefs = append(report.CollisionBriefs, NormalizePublicationMetadata(segments[occ.segment].Briefs[occ.index]))
	}
	if err := ValidateCanonicalIdentities(segments); err != nil {
		return report, fmt.Errorf("validating repaired identities: %w", err)
	}
	return report, nil
}

// ValidateCanonicalIdentities enforces the feed-wide identity contract over a
// fully loaded set of canonical monthly segments.
func ValidateCanonicalIdentities(segments map[string]*SegmentContent) error {
	ids := make(map[string]string)
	events := make(map[string]string)
	slugs := make(map[string]string)
	for _, key := range sortedSegmentKeys(segments) {
		for i, raw := range segments[key].Briefs {
			brief := NormalizePublicationMetadata(raw)
			if err := validateRepairBrief(brief, key); err != nil {
				return err
			}
			where := fmt.Sprintf("%s[%d]", key, i)
			if previous, ok := ids[brief.ID]; ok {
				return fmt.Errorf("brief ID %q occurs at %s and %s", brief.ID, previous, where)
			}
			if previous, ok := events[brief.EventID]; ok {
				return fmt.Errorf("event ID %q occurs at %s and %s", brief.EventID, previous, where)
			}
			ids[brief.ID] = where
			events[brief.EventID] = where
			if slug := normalizedSlug(brief.Slug); slug != "" {
				if previous, ok := slugs[slug]; ok {
					return fmt.Errorf("slug %q occurs at %s and %s", slug, previous, where)
				}
				slugs[slug] = where
			}
		}
	}
	return nil
}

func validateRepairBrief(brief BundleBrief, key string) error {
	published, err := time.Parse(time.RFC3339Nano, brief.PublishedAt)
	if err != nil {
		return fmt.Errorf("brief %q in segment %s has invalid published_at: %w", brief.ID, key, err)
	}
	if SegmentKey(published) != key {
		return fmt.Errorf("brief %q published in %s is stored in segment %s", brief.ID, SegmentKey(published), key)
	}
	if err := validateRevisionMetadata(brief); err != nil {
		return err
	}
	return nil
}

func chooseIDKeeper(segments map[string]*SegmentContent, id string, group []identityOccurrence) identityOccurrence {
	ordered := append([]identityOccurrence(nil), group...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a := NormalizePublicationMetadata(segments[ordered[i].segment].Briefs[ordered[i].index])
		b := NormalizePublicationMetadata(segments[ordered[j].segment].Briefs[ordered[j].index])
		aMatch := idMatchesPublishedDate(id, a.PublishedAt)
		bMatch := idMatchesPublishedDate(id, b.PublishedAt)
		if aMatch != bMatch {
			return aMatch
		}
		if a.PublishedAt != b.PublishedAt {
			return a.PublishedAt < b.PublishedAt
		}
		return occurrenceLess(ordered[i], ordered[j])
	})
	return ordered[0]
}

func chooseSlugKeeper(segments map[string]*SegmentContent, slug string, group []identityOccurrence, preferred map[string]PreferredSlugOwner) identityOccurrence {
	if wanted, ok := preferred[slug]; ok {
		for _, occ := range group {
			brief := segments[occ.segment].Briefs[occ.index]
			if wanted.Title == brief.Title && sameTimestamp(wanted.PublishedAt, brief.PublishedAt) {
				return occ
			}
		}
		for _, occ := range group {
			if segments[occ.segment].Briefs[occ.index].ID == wanted.ID {
				return occ
			}
		}
	}
	ordered := append([]identityOccurrence(nil), group...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a := NormalizePublicationMetadata(segments[ordered[i].segment].Briefs[ordered[i].index])
		b := NormalizePublicationMetadata(segments[ordered[j].segment].Briefs[ordered[j].index])
		if a.PublishedAt != b.PublishedAt {
			return a.PublishedAt > b.PublishedAt
		}
		return a.ID < b.ID
	})
	return ordered[0]
}

func uniqueRepairedID(brief BundleBrief, used map[string]struct{}) string {
	published, _ := time.Parse(time.RFC3339Nano, brief.PublishedAt)
	suffix := identitySuffix(brief.ID, brief.Title)
	base := "brief-" + published.UTC().Format("2006-01-02") + "-" + suffix
	return uniqueIdentityValue(base, brief, used)
}

func uniqueRepairedSlug(brief BundleBrief, used map[string]struct{}) string {
	base := strings.TrimPrefix(normalizedSlug(brief.ID), "brief-")
	if base == "" {
		base = identitySuffix(brief.ID, brief.Title)
	}
	return uniqueIdentityValue(base, brief, used)
}

func uniqueIdentityValue(base string, brief BundleBrief, used map[string]struct{}) string {
	if _, exists := used[base]; !exists {
		return base
	}
	digest := sha256.Sum256([]byte(brief.PublishedAt + "\x00" + brief.Title + "\x00" + strings.Join(brief.References, "\x00")))
	for width := 8; width <= len(digest)*2; width += 4 {
		candidate := base + "-" + hex.EncodeToString(digest[:])[:width]
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
	panic("sha256 identity suffix exhausted")
}

func identitySuffix(id, title string) string {
	if match := datedBriefID.FindStringSubmatch(strings.ToLower(strings.TrimSpace(id))); len(match) == 2 {
		return match[1]
	}
	value := strings.Trim(unsafeIdentityPart.ReplaceAllString(strings.ToLower(title), "-"), "-")
	if value == "" {
		return "untitled"
	}
	return value
}

func idMatchesPublishedDate(id, publishedAt string) bool {
	published, err := time.Parse(time.RFC3339Nano, publishedAt)
	return err == nil && strings.HasPrefix(id, "brief-"+published.UTC().Format("2006-01-02")+"-")
}

func identityStateJSON(brief BundleBrief) ([]byte, error) {
	brief.Revision = 0
	brief.RevisionHistory = nil
	return json.Marshal(brief)
}

func normalizedSlug(slug string) string { return strings.ToLower(strings.TrimSpace(slug)) }

func sortedSegmentKeys(segments map[string]*SegmentContent) []string {
	keys := make([]string, 0, len(segments))
	for key := range segments {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedOccurrenceGroupKeys(groups map[string][]identityOccurrence) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedOccurrences(values map[identityOccurrence]BundleBrief) []identityOccurrence {
	set := make(map[identityOccurrence]struct{}, len(values))
	for value := range values {
		set[value] = struct{}{}
	}
	return sortedOccurrenceSet(set)
}

func sortedOccurrenceSet(values map[identityOccurrence]struct{}) []identityOccurrence {
	result := make([]identityOccurrence, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return occurrenceLess(result[i], result[j]) })
	return result
}

func occurrenceLess(a, b identityOccurrence) bool {
	if a.segment != b.segment {
		return a.segment < b.segment
	}
	return a.index < b.index
}
