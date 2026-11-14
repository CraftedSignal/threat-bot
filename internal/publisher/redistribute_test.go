package publisher

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Legacy yearly segments hold briefs that were never redistributed into
// monthly segments (4,642 of them in the prod feed). Consumers sync exactly
// the manifest-listed segments, so a yearly entry may only be pruned after
// every brief it holds lives in a monthly segment — and redistribution must
// not overwrite fresher monthly copies with stale yearly ones.
func TestFlushSegmentedRedistributesLegacyYearlySegments(t *testing.T) {
	encryptSegment := func(briefs []BundleBrief) string {
		enc, err := EncryptSegment(&SegmentContent{Briefs: briefs}, "v1", "2026-01-01T00:00:00Z", testPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(enc)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}

	yearlyContent := encryptSegment([]BundleBrief{
		{ID: "brief-dup", Slug: "dup", Title: "stale yearly copy", PublishedAt: "2024-01-05T10:00:00Z"},
		{ID: "brief-only", Slug: "only", Title: "lives only in yearly", PublishedAt: "2024-01-06T10:00:00Z"},
	})
	monthlyContent := encryptSegment([]BundleBrief{
		{ID: "brief-dup", Slug: "dup", Title: "fresh monthly copy", PublishedAt: "2024-01-05T10:00:00Z"},
	})

	seedManifest, err := json.Marshal(&SegmentManifest{
		Version: "v1",
		Segments: []SegmentEntry{
			{Path: "briefs/2024-01.json", BriefCount: 1},
			{Path: "briefs/2024.json", BriefCount: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	repo, p := newFakeFeedRepo(t)
	repo.files[manifestPath] = seedManifest
	yearlyRaw, err := base64.StdEncoding.DecodeString(yearlyContent)
	if err != nil {
		t.Fatal(err)
	}
	monthlyRaw, err := base64.StdEncoding.DecodeString(monthlyContent)
	if err != nil {
		t.Fatal(err)
	}
	repo.files["output/briefs/2024.json"] = yearlyRaw
	repo.files["output/briefs/2024-01.json"] = monthlyRaw
	p.pending = append(p.pending, BundleBrief{
		ID: "brief-new", Slug: "new", Title: "pending brief", PublishedAt: "2026-03-10T09:00:00Z",
	})

	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}

	if repo.requested("PUT output/briefs/2024.json") >= 0 {
		t.Error("legacy yearly segment must not be rewritten")
	}

	// The yearly-only brief must now live in its monthly segment, and the
	// fresher monthly copy of the duplicated brief must survive.
	raw, ok := repo.files["output/briefs/2024-01.json"]
	if !ok {
		t.Fatal("expected monthly segment 2024-01 to be rewritten with redistributed briefs")
	}
	var encManifest BundleManifest
	if err := json.Unmarshal(raw, &encManifest); err != nil {
		t.Fatal(err)
	}
	seg, err := DecryptSegment(&encManifest, testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]string{}
	for _, b := range seg.Briefs {
		titles[b.ID] = b.Title
	}
	if len(seg.Briefs) != 2 {
		t.Fatalf("monthly segment briefs = %d (%v), want 2", len(seg.Briefs), titles)
	}
	if titles["brief-only"] == "" {
		t.Error("yearly-only brief was not redistributed into its monthly segment")
	}
	if titles["brief-dup"] != "fresh monthly copy" {
		t.Errorf("brief-dup title = %q, stale yearly copy overwrote the monthly one", titles["brief-dup"])
	}

	// The manifest must no longer list the yearly segment.
	manifestRaw, ok := repo.files[manifestPath]
	if !ok {
		t.Fatal("expected manifest upload")
	}
	var finalManifest SegmentManifest
	if err := json.Unmarshal(manifestRaw, &finalManifest); err != nil {
		t.Fatal(err)
	}
	for _, seg := range finalManifest.Segments {
		if seg.Path == "briefs/2024.json" {
			t.Error("manifest still lists the legacy yearly segment")
		}
	}
}

// Monthly segment files can end up on disk without a manifest listing
// (briefs published while the manifest churned); consumers only sync listed
// segments, so those briefs silently vanish from the feed.
func TestFlushSegmentedListsUnlistedMonthlySegments(t *testing.T) {
	encryptSegment := func(briefs []BundleBrief) (fileB64 string, checksum string) {
		enc, err := EncryptSegment(&SegmentContent{Briefs: briefs}, "v1", "2026-01-01T00:00:00Z", testPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(enc)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw), ComputeChecksum(raw)
	}

	orphanContent, orphanChecksum := encryptSegment([]BundleBrief{
		{ID: "brief-orphan", Slug: "orphan", Title: "unlisted month", PublishedAt: "2025-11-12T10:00:00Z"},
	})

	seedManifest, err := json.Marshal(&SegmentManifest{Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}

	repo, p := newFakeFeedRepo(t)
	repo.files[manifestPath] = seedManifest
	orphanRaw, err := base64.StdEncoding.DecodeString(orphanContent)
	if err != nil {
		t.Fatal(err)
	}
	repo.files["output/briefs/2025-11.json"] = orphanRaw
	p.pending = append(p.pending, BundleBrief{
		ID: "brief-new", Slug: "new", Title: "pending brief", PublishedAt: "2026-03-10T09:00:00Z",
	})

	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}

	manifestRaw, ok := repo.files[manifestPath]
	if !ok {
		t.Fatal("expected manifest upload")
	}
	var finalManifest SegmentManifest
	if err := json.Unmarshal(manifestRaw, &finalManifest); err != nil {
		t.Fatal(err)
	}
	var orphan *SegmentEntry
	for i := range finalManifest.Segments {
		if finalManifest.Segments[i].Path == "briefs/2025-11.json" {
			orphan = &finalManifest.Segments[i]
		}
	}
	if orphan == nil {
		t.Fatalf("manifest does not list the orphan monthly segment; segments = %+v", finalManifest.Segments)
	}
	if orphan.BriefCount != 1 {
		t.Errorf("orphan brief_count = %d, want 1", orphan.BriefCount)
	}
	if orphan.Checksum != orphanChecksum {
		t.Errorf("orphan checksum = %q, want %q", orphan.Checksum, orphanChecksum)
	}
	if repo.requested("PUT output/briefs/2025-11.json") >= 0 {
		t.Error("orphan segment file must not be rewritten, only listed")
	}
}

// GitHub's contents API is eventually consistent under commit churn: the SHA
// lookup can 404 while the file exists, and the subsequent create-PUT fails
// with 422 "sha wasn't supplied". That must retry with a refetched SHA, like
// the 409 stale-SHA case (lost brief-2026-07-pcp-privesc's update in prod).
func TestPublishBriefMarkdownRetriesSHAMissing422(t *testing.T) {
	var mu sync.Mutex
	gets, puts := 0, 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "GET" {
			gets++
			if gets == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			existing := []byte("---\nbrief_id: brief-2026-07-retry-test\nevent_id: brief-2026-07-retry-test\ndate: \"2026-07-30T00:00:00Z\"\n---\n")
			fmt.Fprintf(w, `{"sha":"existing-sha","size":%d,"content":%q}`, len(existing), base64.StdEncoding.EncodeToString(existing))
			return
		}
		if r.Method == "PUT" {
			puts++
			var req contentsRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.SHA == "" {
				w.WriteHeader(http.StatusUnprocessableEntity)
				fmt.Fprint(w, `{"message":"Invalid request.\n\n\"sha\" wasn't supplied."}`)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"content":{"sha":"new-sha"}}`)
		}
	}))
	defer srv.Close()

	p := &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    http.DefaultClient,
		logger:    slog.Default(),
	}
	brief := BundleBrief{
		ID: "brief-2026-07-retry-test", Slug: "2026-07-retry-test",
		Title: "Retry Test Advisory for VendorX ProductY", Summary: "s",
		Content: "body", Severity: "high", PublishedAt: "2026-07-30T00:00:00Z",
		AffectedVendors: []string{"VendorX"}, AffectedProducts: []string{"ProductY"},
	}
	if err := p.publishBriefMarkdown(brief); err != nil {
		t.Fatalf("publishBriefMarkdown: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if puts != 2 {
		t.Fatalf("puts = %d, want 2 (422 then success with refetched sha)", puts)
	}
}
