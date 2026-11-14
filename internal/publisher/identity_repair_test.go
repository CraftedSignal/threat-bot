package publisher

import (
	"testing"
	"time"
)

func TestRepairCanonicalIdentitiesPreservesPreferredSlugOwner(t *testing.T) {
	segments := map[string]*SegmentContent{
		"2024-01": {Briefs: []BundleBrief{
			{ID: "brief-2024-01-23-scriban-dos", Slug: "2024-01-scriban-dos", Title: "Pad functions", PublishedAt: "2024-01-23T12:00:00Z"},
			{ID: "brief-2024-01-27-scriban-dos", Slug: "2024-01-scriban-dos", Title: "LoopLimit", PublishedAt: "2024-01-27T12:00:00Z"},
			{ID: "brief-2024-01-28-unrelated", Slug: "2024-01-unrelated", Title: "Unrelated", PublishedAt: "2024-01-28T12:00:00Z"},
		}},
	}
	repairedAt := time.Date(2026, 10, 20, 14, 30, 0, 0, time.UTC)
	report, err := RepairCanonicalIdentities(segments, IdentityRepairOptions{
		RepairedAt: repairedAt,
		PreferredSlugOwners: map[string]PreferredSlugOwner{
			"2024-01-scriban-dos": {ID: "brief-2024-01-27-scriban-dos", Title: "LoopLimit", PublishedAt: "2024-01-27T12:00:00Z"},
		},
	})
	if err != nil {
		t.Fatalf("RepairCanonicalIdentities: %v", err)
	}
	if report.RepairedSlugs != 1 || report.RepairedIDs != 0 || len(report.ChangedBriefs) != 1 {
		t.Fatalf("report = %#v", report)
	}
	got := segments["2024-01"].Briefs
	if got[0].Slug != "2024-01-23-scriban-dos" {
		t.Fatalf("losing slug = %q", got[0].Slug)
	}
	if got[1].Slug != "2024-01-scriban-dos" {
		t.Fatalf("preferred owner slug = %q", got[1].Slug)
	}
	if got[0].Revision != 2 || len(got[0].RevisionHistory) != 1 {
		t.Fatalf("revision metadata = revision %d, history %#v", got[0].Revision, got[0].RevisionHistory)
	}
	revision := got[0].RevisionHistory[0]
	if revision.At != repairedAt.Format(time.RFC3339) || !revision.Maintenance {
		t.Fatalf("repair revision = %#v", revision)
	}
	if len(revision.ChangedFields) != 1 || revision.ChangedFields[0] != "slug" {
		t.Fatalf("changed fields = %#v", revision.ChangedFields)
	}
	unrelated := NormalizePublicationMetadata(got[2])
	if unrelated.Revision != 1 || len(unrelated.RevisionHistory) != 0 {
		t.Fatalf("unrelated brief changed: %#v", got[2])
	}
	if err := ValidateCanonicalIdentities(segments); err != nil {
		t.Fatalf("repaired corpus is invalid: %v", err)
	}

	again, err := RepairCanonicalIdentities(segments, IdentityRepairOptions{RepairedAt: repairedAt.Add(time.Hour)})
	if err != nil {
		t.Fatalf("second repair: %v", err)
	}
	if again.RepairedSlugs != 0 || again.RepairedIDs != 0 || len(again.ChangedBriefs) != 0 {
		t.Fatalf("second repair was not idempotent: %#v", again)
	}
}

func TestRepairCanonicalIdentitiesRepairsReusedID(t *testing.T) {
	segments := map[string]*SegmentContent{
		"2024-01": {Briefs: []BundleBrief{{
			ID: "brief-2024-01-02-yafnet-xss", Slug: "shared-yafnet-xss", Title: "Old YAFNET issue", PublishedAt: "2024-01-02T12:00:00Z",
		}}},
		"2026-05": {Briefs: []BundleBrief{{
			ID: "brief-2024-01-02-yafnet-xss", Slug: "shared-yafnet-xss", Title: "New YAFNET issue", PublishedAt: "2026-05-05T20:31:36Z",
		}}},
	}

	report, err := RepairCanonicalIdentities(segments, IdentityRepairOptions{
		RepairedAt: time.Date(2026, 10, 20, 14, 30, 0, 0, time.UTC),
		PreferredSlugOwners: map[string]PreferredSlugOwner{
			"shared-yafnet-xss": {ID: "brief-2024-01-02-yafnet-xss", Title: "New YAFNET issue", PublishedAt: "2026-05-05T20:31:36Z"},
		},
	})
	if err != nil {
		t.Fatalf("RepairCanonicalIdentities: %v", err)
	}
	if report.RepairedIDs != 1 {
		t.Fatalf("repaired IDs = %d, want 1", report.RepairedIDs)
	}
	old := segments["2024-01"].Briefs[0]
	newer := segments["2026-05"].Briefs[0]
	if old.ID != "brief-2024-01-02-yafnet-xss" {
		t.Fatalf("matching original ID changed to %q", old.ID)
	}
	if old.Slug != "2024-01-02-yafnet-xss" {
		t.Fatalf("old record retained shared public slug: %q", old.Slug)
	}
	if newer.ID != "brief-2026-05-05-yafnet-xss" || newer.EventID != newer.ID {
		t.Fatalf("new identity = id %q, event %q", newer.ID, newer.EventID)
	}
	if newer.Slug != "shared-yafnet-xss" {
		t.Fatalf("current public owner slug = %q", newer.Slug)
	}
	if newer.Revision != 2 || !newer.RevisionHistory[0].Maintenance {
		t.Fatalf("newer revision metadata = %#v", newer)
	}
	if err := ValidateCanonicalIdentities(segments); err != nil {
		t.Fatalf("repaired corpus is invalid: %v", err)
	}
}

func TestBriefActivityAtIgnoresMaintenanceRevision(t *testing.T) {
	brief := BundleBrief{
		PublishedAt: "2024-01-23T12:00:00Z",
		RevisionHistory: []BundleRevision{
			{Revision: 2, At: "2026-10-20T14:30:00Z", Maintenance: true},
		},
	}
	if got := briefActivityAt(brief); got != brief.PublishedAt {
		t.Fatalf("activity_at = %q, want publication %q", got, brief.PublishedAt)
	}
}
