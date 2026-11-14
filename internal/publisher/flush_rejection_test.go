package publisher

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// rejectionFixture publishes a segment with one brief and returns an update of
// it whose CVE set is disjoint, which MergeBriefs rejects.
func rejectionFixture(t *testing.T, changelog *Changelog) (*fakeFeedRepo, *Publisher, string, BundleBrief, BundleBrief) {
	t.Helper()
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	bad := BundleBrief{ID: "brief-bad", EventID: "brief-bad", Slug: key + "-bad", Title: "Bad", PublishedAt: now.Format(time.RFC3339), CVEs: []BundleCVE{{ID: "CVE-2026-1000"}}}
	good := BundleBrief{ID: "brief-good", EventID: "brief-good", Slug: key + "-good", Title: "Good", PublishedAt: now.Format(time.RFC3339)}
	repo.putSegment(t, key, bad, good)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 2}}})
	repo.putJSON(t, changelogPath, changelog)
	badUpdate := bad
	badUpdate.Title = "Bad rewritten"
	badUpdate.CVEs = []BundleCVE{{ID: "CVE-2026-2000"}}
	return repo, p, key, badUpdate, good
}

func TestFlushRejectionKeepsEarlierChangelogHistory(t *testing.T) {
	cl := NewChangelog()
	cl.RecordAdd("brief-bad")
	repo, p, _, badUpdate, good := rejectionFixture(t, cl)
	goodUpdate := good
	goodUpdate.Title = "Good updated"
	p.pending = []BundleBrief{badUpdate, goodUpdate}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	var got Changelog
	if err := json.Unmarshal(repo.files[changelogPath], &got); err != nil {
		t.Fatal(err)
	}
	var bad, goodDeltas []ChangelogDelta
	for _, v := range got.Entries {
		for _, c := range v.Changes {
			switch c.BriefID {
			case "brief-bad":
				bad = append(bad, c)
			case "brief-good":
				goodDeltas = append(goodDeltas, c)
			}
		}
	}
	if len(bad) != 1 || bad[0].Type != "added" {
		t.Fatalf("earlier history not preserved exactly: %#v", bad)
	}
	if len(goodDeltas) != 1 || goodDeltas[0].Type != "updated" {
		t.Fatalf("good brief delta missing: %#v", goodDeltas)
	}
}

func TestFlushRecordsRejectedBriefIDs(t *testing.T) {
	_, p, _, badUpdate, good := rejectionFixture(t, NewChangelog())
	p.pending = []BundleBrief{badUpdate, good}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	if got := p.RejectedBriefIDs(); !slices.Equal(got, []string{"brief-bad"}) {
		t.Fatalf("RejectedBriefIDs = %v", got)
	}
	p.pending = []BundleBrief{good}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	if got := p.RejectedBriefIDs(); len(got) != 0 {
		t.Fatalf("rejections not reset: %v", got)
	}
}

func TestFlushAllRejectedDoesNotCommit(t *testing.T) {
	repo, p, _, badUpdate, _ := rejectionFixture(t, NewChangelog())
	before := map[string]string{}
	for path, raw := range repo.files {
		before[path] = string(raw)
	}
	repo.requests = nil
	p.pending = []BundleBrief{badUpdate}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	if len(p.pending) != 0 {
		t.Fatalf("pending retained: %v", p.pending)
	}
	for _, req := range repo.requests {
		if req == "POST git/commits" || req == "PATCH git/refs/heads/main" {
			t.Fatalf("all-rejected flush committed: %v", repo.requests)
		}
	}
	for path, raw := range repo.files {
		if before[path] != string(raw) {
			t.Fatalf("%s rewritten", path)
		}
	}
	if got := p.RejectedBriefIDs(); !slices.Equal(got, []string{"brief-bad"}) {
		t.Fatalf("RejectedBriefIDs = %v", got)
	}
}

func TestFlushRejectedCanonicalKeepsItsRetirementsOnly(t *testing.T) {
	repo, p, key, badUpdate, good := rejectionFixture(t, NewChangelog())
	dup := BundleBrief{ID: "brief-dup", EventID: "brief-dup", Slug: key + "-dup", Title: "Dup", PublishedAt: good.PublishedAt}
	other := BundleBrief{ID: "brief-other", EventID: "brief-other", Slug: key + "-other", Title: "Other", PublishedAt: good.PublishedAt}
	repo.putSegment(t, key, BundleBrief{ID: "brief-bad", EventID: "brief-bad", Slug: key + "-bad", Title: "Bad", PublishedAt: good.PublishedAt, CVEs: []BundleCVE{{ID: "CVE-2026-1000"}}}, good, dup, other)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 4}}})
	p.pending = []BundleBrief{badUpdate}
	if err := p.RetireBriefInFavourOf(dup.ID, dup.Slug, "brief-bad"); err != nil {
		t.Fatal(err)
	}
	if err := p.RetireBrief(other.ID, other.Slug); err != nil {
		t.Fatal(err)
	}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, b := range repo.segment(t, key).Briefs {
		ids[b.ID] = true
	}
	if !ids["brief-dup"] || !ids["brief-bad"] || ids["brief-other"] {
		t.Fatalf("segment briefs = %v", ids)
	}
	if got := p.RejectedBriefIDs(); !slices.Equal(got, []string{"brief-bad"}) {
		t.Fatalf("RejectedBriefIDs = %v", got)
	}
	if len(p.pendingRetirements) != 0 {
		t.Fatalf("retirements retained: %v", p.pendingRetirements)
	}
}

func TestFlushEmptyResetsStaleRejections(t *testing.T) {
	_, p, _, _, _ := rejectionFixture(t, NewChangelog())
	p.rejectedIDs = []string{"stale"}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	if got := p.RejectedBriefIDs(); len(got) != 0 {
		t.Fatalf("stale rejections: %v", got)
	}
}
