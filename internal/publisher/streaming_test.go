package publisher

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// fakeFeedRepo serves a threat-feed repo through a minimal GitHub Contents
// API, stores every PUT back into the repo, and records the request order.
type fakeFeedRepo struct {
	mu            sync.Mutex
	files         map[string][]byte
	requests      []string
	failPut       string
	failRead      string
	omitContents  bool
	racePut       map[string][]byte
	blobs         map[string][]byte
	trees         map[string]map[string][]byte
	commits       map[string]string
	commitParents map[string]string
	snapshots     map[string]map[string][]byte
	dirTrees      map[string]fakeDirTree
	head          string
	sequence      int
	refUpdates    int
	raceRef       bool
}

func newFakeFeedRepo(t *testing.T) (*fakeFeedRepo, *Publisher) {
	t.Helper()
	repo := &fakeFeedRepo{
		files: map[string][]byte{}, racePut: map[string][]byte{}, blobs: map[string][]byte{},
		trees: map[string]map[string][]byte{}, commits: map[string]string{}, commitParents: map[string]string{},
		snapshots: map[string]map[string][]byte{}, dirTrees: map[string]fakeDirTree{}, head: "base-commit",
	}
	srv := httptest.NewServer(http.HandlerFunc(repo.serve))
	t.Cleanup(srv.Close)
	return repo, &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    http.DefaultClient,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func (r *fakeFeedRepo) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	const repoPrefix = "/repos/CraftedSignal/threat-feed/"
	endpoint := strings.TrimPrefix(req.URL.Path, repoPrefix)
	if !strings.HasPrefix(req.URL.Path, repoPrefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if endpoint == "git/ref/heads/main" && req.Method == http.MethodGet {
		treeSHA := "tree-" + r.head
		r.snapshots[r.head] = cloneFakeFiles(r.files)
		r.trees[treeSHA] = cloneFakeFiles(r.files)
		r.commits[r.head] = treeSHA
		r.requests = append(r.requests, "GET git/ref/heads/main")
		json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": r.head}})
		return
	}
	if strings.HasPrefix(endpoint, "git/commits/") && req.Method == http.MethodGet {
		sha := strings.TrimPrefix(endpoint, "git/commits/")
		r.requests = append(r.requests, "GET git/commits/"+sha)
		treeSHA, ok := r.commits[sha]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"sha": sha, "tree": map[string]string{"sha": treeSHA}})
		return
	}
	if endpoint == "git/blobs" && req.Method == http.MethodPost {
		path := req.Header.Get("X-Threat-Bot-Path")
		r.requests = append(r.requests, "PUT "+path)
		if path == r.failPut {
			w.WriteHeader(http.StatusConflict)
			return
		}
		var body struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Encoding != "base64" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		content, err := base64.StdEncoding.DecodeString(body.Content)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sha := gitBlobSHA(content)
		r.blobs[sha] = append([]byte(nil), content...)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"sha": sha})
		return
	}
	if strings.HasPrefix(endpoint, "git/blobs/") && req.Method == http.MethodGet {
		sha := strings.TrimPrefix(endpoint, "git/blobs/")
		r.requests = append(r.requests, "GET git/blobs/"+sha)
		content, ok := r.blobs[sha]
		if !ok {
			for _, candidate := range r.files {
				if gitBlobSHA(candidate) == sha {
					content, ok = candidate, true
					break
				}
			}
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(content)
		return
	}
	if strings.HasPrefix(endpoint, "git/trees/") && req.Method == http.MethodGet {
		sha := strings.TrimPrefix(endpoint, "git/trees/")
		r.requests = append(r.requests, "GET git/trees/"+sha)
		if req.URL.Query().Get("recursive") == "1" {
			files, ok := r.trees[sha]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"sha": sha, "tree": fakeRecursiveTree(files), "truncated": false})
			return
		}
		dir, ok := r.dirTrees[sha]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		type treeEntry struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
		}
		entries := []treeEntry{}
		for name, content := range dir.files {
			if rest, ok := strings.CutPrefix(name, dir.path+"/"); ok && !strings.Contains(rest, "/") {
				entries = append(entries, treeEntry{Path: rest, Mode: "100644", Type: "blob", SHA: gitBlobSHA(content)})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"sha": sha, "tree": entries, "truncated": false})
		return
	}
	if endpoint == "git/trees" && req.Method == http.MethodPost {
		var body struct {
			BaseTree string `json:"base_tree"`
			Tree     []struct {
				Path string  `json:"path"`
				SHA  *string `json:"sha"`
			} `json:"tree"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		files := cloneFakeFiles(r.trees[body.BaseTree])
		for _, entry := range body.Tree {
			if entry.SHA == nil {
				if _, exists := files[entry.Path]; !exists {
					w.WriteHeader(http.StatusUnprocessableEntity)
					return
				}
				delete(files, entry.Path)
				continue
			}
			blob, ok := r.blobs[*entry.SHA]
			if !ok {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			files[entry.Path] = append([]byte(nil), blob...)
		}
		r.sequence++
		sha := fmt.Sprintf("tree-%d", r.sequence)
		r.trees[sha] = files
		r.requests = append(r.requests, "POST git/trees")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"sha": sha})
		return
	}
	if endpoint == "git/commits" && req.Method == http.MethodPost {
		var body struct {
			Tree    string   `json:"tree"`
			Parents []string `json:"parents"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || len(body.Parents) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.sequence++
		sha := fmt.Sprintf("commit-%d", r.sequence)
		r.commits[sha] = body.Tree
		r.commitParents[sha] = body.Parents[0]
		r.requests = append(r.requests, "POST git/commits")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"sha": sha})
		return
	}
	if endpoint == "git/refs/heads/main" && req.Method == http.MethodPatch {
		var body struct {
			SHA   string `json:"sha"`
			Force bool   `json:"force"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.requests = append(r.requests, "PATCH git/refs/heads/main")
		if body.Force {
			http.Error(w, "forced ref updates are forbidden", http.StatusBadRequest)
			return
		}
		if r.raceRef || len(r.racePut) > 0 {
			r.raceRef = false
			for path, content := range r.racePut {
				r.files[path] = append([]byte(nil), content...)
				delete(r.racePut, path)
			}
			r.head = "concurrent-commit"
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"message":"Update is not a fast forward"}`))
			return
		}
		if !body.Force && r.commitParents[body.SHA] != r.head {
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"message":"Update is not a fast forward"}`))
			return
		}
		treeSHA, ok := r.commits[body.SHA]
		if !ok {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		r.files = cloneFakeFiles(r.trees[treeSHA])
		r.head = body.SHA
		r.snapshots[r.head] = cloneFakeFiles(r.files)
		r.refUpdates++
		json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": r.head}})
		return
	}

	if !strings.HasPrefix(endpoint, "contents/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	path := strings.TrimPrefix(endpoint, "contents/")
	r.requests = append(r.requests, req.Method+" "+path)
	if req.Method == http.MethodGet && path == r.failRead {
		w.WriteHeader(http.StatusConflict)
		return
	}

	if req.Method == http.MethodPut {
		if path == r.failPut {
			w.WriteHeader(http.StatusConflict)
			return
		}
		var body contentsRequest
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		content, err := base64.StdEncoding.DecodeString(body.Content)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if raced, ok := r.racePut[path]; ok {
			r.files[path] = append([]byte(nil), raced...)
			delete(r.racePut, path)
		}
		existing, exists := r.files[path]
		if exists && body.SHA != gitBlobSHA(existing) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if !exists && body.SHA != "" {
			w.WriteHeader(http.StatusConflict)
			return
		}
		r.files[path] = content
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"content":{"sha":"new-sha"}}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	source := r.files
	if ref := req.URL.Query().Get("ref"); ref != "" {
		if snapshot, ok := r.snapshots[ref]; ok {
			source = snapshot
		}
	}
	if content, ok := source[path]; ok {
		encoded := base64.StdEncoding.EncodeToString(content)
		if r.omitContents {
			encoded = ""
		}
		json.NewEncoder(w).Encode(map[string]any{
			"sha":     gitBlobSHA(content),
			"size":    len(content),
			"content": encoded,
		})
		return
	}
	// Like GitHub, a directory listing names subdirectories with their tree
	// SHA and stops at 1,000 entries.
	var listing []map[string]string
	subdirs := map[string]bool{}
	names := make([]string, 0, len(source))
	for name := range source {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rest, ok := strings.CutPrefix(name, path+"/")
		if !ok {
			continue
		}
		if subdir, _, nested := strings.Cut(rest, "/"); nested {
			if !subdirs[subdir] {
				subdirs[subdir] = true
				r.sequence++
				sha := fmt.Sprintf("dir-tree-%d", r.sequence)
				r.dirTrees[sha] = fakeDirTree{path: path + "/" + subdir, files: cloneFakeFiles(source)}
				listing = append(listing, map[string]string{"name": subdir, "type": "dir", "sha": sha})
			}
			continue
		}
		listing = append(listing, map[string]string{"name": rest, "type": "file", "sha": gitBlobSHA(source[name])})
	}
	if listing == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(listing) > 1000 {
		listing = listing[:1000]
	}
	json.NewEncoder(w).Encode(listing)
}

// fakeDirTree is a directory tree the fake handed out in a listing: the files
// of the snapshot it was listed from, read below path.
type fakeDirTree struct {
	path  string
	files map[string][]byte
}

// fakeRecursiveTree includes directory identities so tests can detect changed
// directory listings as well as changed file bytes at an immutable tree.
func fakeRecursiveTree(files map[string][]byte) []map[string]string {
	entries := []map[string]string{}
	dirs := map[string]map[string][]byte{}
	for path, content := range files {
		entries = append(entries, map[string]string{"path": path, "mode": "100644", "type": "blob", "sha": gitBlobSHA(content)})
		for slash := strings.LastIndex(path, "/"); slash >= 0; slash = strings.LastIndex(path[:slash], "/") {
			dir := path[:slash]
			if dirs[dir] == nil {
				dirs[dir] = map[string][]byte{}
			}
			dirs[dir][path[slash+1:]] = content
		}
	}
	for path, files := range dirs {
		raw, _ := json.Marshal(files)
		entries = append(entries, map[string]string{"path": path, "mode": "040000", "type": "tree", "sha": gitBlobSHA(raw)})
	}
	return entries
}

func cloneFakeFiles(source map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(source))
	for path, content := range source {
		cloned[path] = append([]byte(nil), content...)
	}
	return cloned
}

func (r *fakeFeedRepo) putJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	r.files[path] = raw
}

func (r *fakeFeedRepo) putSegment(t *testing.T, key string, briefs ...BundleBrief) {
	t.Helper()
	enc, err := EncryptSegment(&SegmentContent{Briefs: briefs}, "v1", "2026-01-01T00:00:00Z", testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r.putJSON(t, "output/"+segmentPath(key), enc)
}

func (r *fakeFeedRepo) segment(t *testing.T, key string) *SegmentContent {
	t.Helper()
	var enc BundleManifest
	if err := json.Unmarshal(r.files["output/"+segmentPath(key)], &enc); err != nil {
		t.Fatal(err)
	}
	content, err := DecryptSegment(&enc, testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func (r *fakeFeedRepo) manifest(t *testing.T) SegmentManifest {
	t.Helper()
	var m SegmentManifest
	if err := json.Unmarshal(r.files[manifestPath], &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (r *fakeFeedRepo) requested(req string) int {
	return slices.Index(r.requests, req)
}

func TestPublishedBriefExistsReadsCanonicalSegmentIdentity(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	brief := BundleBrief{
		ID:          "brief-canonical",
		EventID:     "event-canonical",
		Slug:        "canonical-slug",
		PublishedAt: "2026-10-21T07:47:00Z",
	}
	repo.putSegment(t, "2026-10", brief)
	repo.putJSON(t, manifestPath, &SegmentManifest{
		Version:  "v1",
		Segments: []SegmentEntry{{Path: segmentPath("2026-10"), BriefCount: 1}},
	})

	exists, err := p.PublishedBriefExists(brief.ID)
	if err != nil {
		t.Fatalf("PublishedBriefExists(%q) error = %v", brief.ID, err)
	}
	if !exists {
		t.Fatalf("PublishedBriefExists(%q) = false, want true", brief.ID)
	}
	exists, err = p.PublishedBriefExists("brief-missing")
	if err != nil {
		t.Fatalf("PublishedBriefExists(missing) error = %v", err)
	}
	if exists {
		t.Fatal("PublishedBriefExists(missing) = true, want false")
	}
}

// epssCacheServing returns an EPSS cache whose refresh downloads csv.
func epssCacheServing(t *testing.T, csv string) *scraper.EPSSCache {
	t.Helper()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(csv)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return scraper.NewEPSSCache(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(gz.Bytes())), Header: http.Header{}, Request: req}, nil
	})}, db)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func decryptCVEMetadata(t *testing.T, raw []byte) CVEMetadata {
	t.Helper()
	var enc BundleManifest
	if err := json.Unmarshal(raw, &enc); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(enc.Content)
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveKey(testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	n := gcm.NonceSize()
	plaintext, err := gcm.Open(nil, ciphertext[:n], ciphertext[n:], nil)
	if err != nil {
		t.Fatal(err)
	}
	var meta CVEMetadata
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

// The EPSS refresh walks the whole feed, so it must stage one changed segment
// before fetching the next instead of holding every segment at once.
func TestRefreshEPSSUploadsEachChangedSegmentBeforeFetchingTheNext(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.putSegment(t, "2026-08", BundleBrief{ID: "a", PublishedAt: "2026-08-03T10:00:00Z", CVEs: []BundleCVE{{ID: "CVE-2026-0001", EPSS: 0.1, CVSS: 9.8}}})
	repo.putSegment(t, "2026-09", BundleBrief{ID: "b", PublishedAt: "2026-09-03T10:00:00Z", CVEs: []BundleCVE{{ID: "CVE-2026-0002", EPSS: 0.2, CVSS: 5.0}}})
	repo.putSegment(t, "2026-10", BundleBrief{ID: "c", PublishedAt: "2026-10-03T10:00:00Z", CVEs: []BundleCVE{{ID: "CVE-2026-0003", EPSS: 0.3, CVSS: 7.5}}})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{
		{Path: "briefs/2026-08.json", BriefCount: 1},
		{Path: "briefs/2026-09.json", BriefCount: 1},
		{Path: "briefs/2026-10.json", BriefCount: 1},
	}})
	cache := epssCacheServing(t, "#model_version:v2025.03.14\ncve,epss,percentile\n"+
		"CVE-2026-0001,0.9,0.99\nCVE-2026-0002,0.2,0.5\nCVE-2026-0003,0.8,0.97\n")

	if err := p.RefreshEPSS(cache, scraper.NewKEVCatalog(), EPSSRefreshConfig{MinScoreDelta: 0.01}, p.logger); err != nil {
		t.Fatal(err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	put08, get09 := repo.requested("PUT output/briefs/2026-08.json"), repo.requested("GET output/briefs/2026-09.json")
	if put08 < 0 || get09 < 0 || put08 > get09 {
		t.Errorf("changed segment 2026-08 must be uploaded before 2026-09 is fetched; requests: %v", repo.requests)
	}
	if repo.requested("PUT output/briefs/2026-09.json") >= 0 {
		t.Error("unchanged segment 2026-09 was rewritten")
	}
	if repo.refUpdates != 1 {
		t.Fatalf("EPSS release advanced the branch %d times, want 1", repo.refUpdates)
	}
	if got := repo.segment(t, "2026-10").Briefs[0].CVEs[0].EPSS; got != 0.8 {
		t.Errorf("2026-10 CVE EPSS = %v, want 0.8", got)
	}

	// The CVE index still covers every segment, unchanged ones included.
	meta := decryptCVEMetadata(t, repo.files[cveMetadataPath])
	want := map[string]float64{"CVE-2026-0001": 0.9, "CVE-2026-0002": 0.2, "CVE-2026-0003": 0.8}
	if len(meta.Scores) != len(want) {
		t.Errorf("CVE metadata has %d scores, want %d: %v", len(meta.Scores), len(want), meta.Scores)
	}
	for cve, epss := range want {
		if meta.Scores[cve].EPSS != epss {
			t.Errorf("CVE metadata %s EPSS = %v, want %v", cve, meta.Scores[cve].EPSS, epss)
		}
	}

	m := repo.manifest(t)
	if m.CVEMeta == nil || m.CVEMeta.Checksum == "" {
		t.Error("manifest does not point at the rebuilt CVE metadata")
	}
	for _, seg := range m.Segments {
		if changed := seg.Path != "briefs/2026-09.json"; changed != (seg.Checksum != "") {
			t.Errorf("segment %s checksum = %q after refresh", seg.Path, seg.Checksum)
		}
	}
}

func TestRefreshEPSSFailureLeavesBranchUnchanged(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.putSegment(t, "2026-10", BundleBrief{ID: "a", PublishedAt: "2026-10-03T10:00:00Z", CVEs: []BundleCVE{{ID: "CVE-2026-0001", EPSS: 0.1, CVSS: 9.8}}})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: "briefs/2026-10.json", BriefCount: 1}}})
	before := cloneFakeFiles(repo.files)
	repo.failPut = manifestPath
	cache := epssCacheServing(t, "#model_version:v2025.03.14\ncve,epss,percentile\nCVE-2026-0001,0.9,0.99\n")

	if err := p.RefreshEPSS(cache, scraper.NewKEVCatalog(), EPSSRefreshConfig{MinScoreDelta: 0.01}, p.logger); err == nil {
		t.Fatal("expected EPSS manifest staging failure")
	}
	if repo.refUpdates != 0 {
		t.Fatalf("failed EPSS release advanced the branch %d times", repo.refUpdates)
	}
	if !maps.EqualFunc(repo.files, before, bytes.Equal) {
		t.Fatal("failed EPSS release changed branch-visible files")
	}
}

func countSTIXReports(t *testing.T, raw []byte) int {
	t.Helper()
	var bundle struct {
		Objects []struct {
			Type string `json:"type"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, o := range bundle.Objects {
		if o.Type == "report" {
			n++
		}
	}
	return n
}

// Only segments that can hold briefs from the last 90 days are fetched.
func TestPublishSTIXBundleFetchesOnlyWindowSegments(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC()
	recent, older, old := now.Add(-2*24*time.Hour), now.Add(-60*24*time.Hour), now.Add(-200*24*time.Hour)
	recentKey, olderKey, oldKey := SegmentKey(recent), SegmentKey(older), SegmentKey(old)
	repo.putSegment(t, oldKey, BundleBrief{ID: "old", Title: "old", PublishedAt: old.Format(time.RFC3339)})
	repo.putSegment(t, olderKey, BundleBrief{ID: "older", Title: "older", PublishedAt: older.Format(time.RFC3339)})
	repo.putSegment(t, recentKey, BundleBrief{ID: "recent", Title: "recent", PublishedAt: recent.Format(time.RFC3339)})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{
		{Path: segmentPath(oldKey), BriefCount: 1}, {Path: segmentPath(olderKey), BriefCount: 1}, {Path: segmentPath(recentKey), BriefCount: 1},
	}})

	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatal(err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.requested("GET output/"+segmentPath(oldKey)) >= 0 {
		t.Errorf("segment %s is outside the 90-day window but was fetched", oldKey)
	}
	for key, want := range map[string]int{recentKey: 1, olderKey: 1} {
		raw, ok := repo.files[fmt.Sprintf("site/static/stix/%s.json", key)]
		if !ok {
			t.Errorf("no STIX bundle for %s", key)
			continue
		}
		if got := countSTIXReports(t, raw); got != want {
			t.Errorf("STIX bundle %s has %d reports, want %d", key, got, want)
		}
	}
	if _, ok := repo.files[fmt.Sprintf("site/static/stix/%s.json", oldKey)]; ok {
		t.Errorf("STIX bundle published for %s, outside the window", oldKey)
	}
	if got := countSTIXReports(t, repo.files["site/static/stix.json"]); got != 1 {
		t.Errorf("30-day STIX bundle has %d reports, want 1", got)
	}
	var index struct {
		Version     string `json:"version"`
		SpecVersion string `json:"spec_version"`
		Generated   string `json:"generated"`
		Rolling     struct {
			Path           string `json:"path"`
			Checksum       string `json:"checksum"`
			SizeBytes      int    `json:"size_bytes"`
			ReportCount    int    `json:"report_count"`
			FirstPublished string `json:"first_published"`
			LastPublished  string `json:"last_published"`
			Generated      string `json:"generated"`
			SpecVersion    string `json:"spec_version"`
		} `json:"rolling"`
		Months []struct {
			Month          string `json:"month"`
			Path           string `json:"path"`
			Checksum       string `json:"checksum"`
			SizeBytes      int    `json:"size_bytes"`
			ReportCount    int    `json:"report_count"`
			FirstPublished string `json:"first_published"`
			LastPublished  string `json:"last_published"`
			Generated      string `json:"generated"`
			SpecVersion    string `json:"spec_version"`
		} `json:"months"`
	}
	if err := json.Unmarshal(repo.files["site/static/stix/index.json"], &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Months) != 2 || index.Months[0].Month != recentKey || index.Months[1].Month != olderKey {
		t.Errorf("STIX index months = %+v, want [%s %s]", index.Months, recentKey, olderKey)
	}
	if index.Version != "2.0" || index.SpecVersion != "2.1" || index.Generated == "" {
		t.Fatalf("STIX index header = %+v", index)
	}
	assertImmutableSTIXIndexArtifact(t, repo, "", index.Rolling.Path, index.Rolling.Checksum, index.Rolling.SizeBytes, index.Rolling.ReportCount)
	if index.Rolling.SpecVersion != "2.1" || index.Rolling.Generated != index.Generated {
		t.Fatalf("rolling index entry = %+v", index.Rolling)
	}
	for _, entry := range index.Months {
		assertImmutableSTIXIndexArtifact(t, repo, entry.Month, entry.Path, entry.Checksum, entry.SizeBytes, entry.ReportCount)
		if entry.SpecVersion != "2.1" || entry.Generated != index.Generated || entry.FirstPublished == "" || entry.LastPublished == "" {
			t.Fatalf("month index entry = %+v", entry)
		}
	}
	rollingPUT := repo.requested("PUT site/static" + index.Rolling.Path)
	indexPUT := repo.requested("PUT site/static/stix/index.json")
	aliasRead := repo.requested("GET site/static/stix.json")
	treePOST := repo.requested("POST git/trees")
	if rollingPUT < 0 || indexPUT < 0 || aliasRead < 0 || treePOST < 0 || (rollingPUT >= indexPUT || indexPUT >= aliasRead || aliasRead >= treePOST) {
		t.Fatalf("publication order must be immutable -> index -> alias reference -> tree; requests: %v", repo.requests)
	}
}

// STIX publication can cover several large monthly segments. Each month must
// be converted and staged before the next source segment is fetched so the
// publisher never retains the whole 90-day window or every generated bundle.
func TestPublishSTIXBundleStagesEachMonthBeforeFetchingTheNext(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC()
	recent, older := now.Add(-24*time.Hour), now.Add(-45*24*time.Hour)
	recentKey, olderKey := SegmentKey(recent), SegmentKey(older)
	repo.putSegment(t, recentKey, BundleBrief{ID: "recent", Title: "recent", PublishedAt: recent.Format(time.RFC3339)})
	repo.putSegment(t, olderKey, BundleBrief{ID: "older", Title: "older", PublishedAt: older.Format(time.RFC3339)})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{
		{Path: segmentPath(olderKey), BriefCount: 1},
		{Path: segmentPath(recentKey), BriefCount: 1},
	}})

	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatal(err)
	}

	var index stixIndex
	if err := json.Unmarshal(repo.files["site/static/stix/index.json"], &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Months) != 2 || index.Months[0].Month != recentKey || index.Months[1].Month != olderKey {
		t.Fatalf("STIX index months = %+v, want [%s %s]", index.Months, recentKey, olderKey)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	getRecent := repo.requested("GET output/" + segmentPath(recentKey))
	putRecent := repo.requested("PUT site/static" + index.Months[0].Path)
	getOlder := repo.requested("GET output/" + segmentPath(olderKey))
	putOlder := repo.requested("PUT site/static" + index.Months[1].Path)
	putIndex := repo.requested("PUT site/static/stix/index.json")
	if getRecent < 0 || putRecent < 0 || getOlder < 0 || putOlder < 0 || putIndex < 0 ||
		(getRecent >= putRecent || putRecent >= getOlder || getOlder >= putOlder || putOlder >= putIndex) {
		t.Fatalf("publication must stream month -> immutable and stage the index last; requests: %v", repo.requests)
	}
}

func assertImmutableSTIXIndexArtifact(t *testing.T, repo *fakeFeedRepo, month, path, checksum string, size, reports int) {
	t.Helper()
	hexDigest := strings.TrimPrefix(checksum, "sha256:")
	wantPath := "/stix/releases/sha256-" + hexDigest + ".json"
	if month != "" {
		wantPath = "/stix/releases/" + month + "-sha256-" + hexDigest + ".json"
	}
	if path != wantPath {
		t.Fatalf("immutable path = %q, want %q", path, wantPath)
	}
	artifact, exists := repo.files["site/static"+path]
	if !exists {
		t.Fatalf("index references missing immutable artifact %s", path)
	}
	assertSTIXIndexArtifact(t, artifact, checksum, size, reports)
}

func assertSTIXIndexArtifact(t *testing.T, artifact []byte, checksum string, size, reports int) {
	t.Helper()
	sum := sha256.Sum256(artifact)
	wantChecksum := "sha256:" + hex.EncodeToString(sum[:])
	if checksum != wantChecksum || size != len(artifact) || reports != countSTIXReports(t, artifact) {
		t.Fatalf("index metadata checksum=%q size=%d reports=%d, want checksum=%q size=%d reports=%d", checksum, size, reports, wantChecksum, len(artifact), countSTIXReports(t, artifact))
	}
}

func TestImmutableSTIXPathIsDeterministicFromExactBytes(t *testing.T) {
	data := []byte(`{"type":"bundle","objects":[]}`)
	sum := sha256.Sum256(data)
	hexDigest := hex.EncodeToString(sum[:])
	for _, tt := range []struct {
		month string
		want  string
	}{
		{want: "/stix/releases/sha256-" + hexDigest + ".json"},
		{month: "2026-10", want: "/stix/releases/2026-10-sha256-" + hexDigest + ".json"},
	} {
		if got := immutableSTIXPath(tt.month, data); got != tt.want {
			t.Fatalf("immutableSTIXPath(%q) = %q, want %q", tt.month, got, tt.want)
		}
	}
}

func seedPriorSTIXIndex(t *testing.T, repo *fakeFeedRepo) (indexBytes, aliasBytes []byte) {
	t.Helper()
	brief := NormalizePublicationMetadata(BundleBrief{ID: "prior", Title: "Prior", PublishedAt: time.Now().UTC().Add(-12 * time.Hour).Format(time.RFC3339)})
	artifact, err := ExportSTIX([]BundleBrief{brief})
	if err != nil {
		t.Fatal(err)
	}
	generated := "2026-10-20T00:00:00.000Z"
	path := testImmutableSTIXPath("", artifact)
	entry, err := newSTIXIndexEntry("", path, artifact, []BundleBrief{brief}, generated)
	if err != nil {
		t.Fatal(err)
	}
	indexBytes, err = json.Marshal(stixIndex{
		Version: "2.0", SpecVersion: "2.1", Generated: generated, Description: "prior", Rolling: entry, Months: []stixIndexEntry{},
	})
	if err != nil {
		t.Fatal(err)
	}
	repo.files["site/static"+path] = append([]byte(nil), artifact...)
	repo.files["site/static/stix/index.json"] = append([]byte(nil), indexBytes...)
	repo.files["site/static/stix.json"] = append([]byte(nil), artifact...)
	return append([]byte(nil), indexBytes...), append([]byte(nil), artifact...)
}

func testImmutableSTIXPath(month string, data []byte) string {
	sum := sha256.Sum256(data)
	hexDigest := hex.EncodeToString(sum[:])
	if month == "" {
		return "/stix/releases/sha256-" + hexDigest + ".json"
	}
	return "/stix/releases/" + month + "-sha256-" + hexDigest + ".json"
}

func putRecentSTIXSource(t *testing.T, repo *fakeFeedRepo) BundleBrief {
	t.Helper()
	brief := BundleBrief{ID: "new-release", Title: "New release", PublishedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)}
	key := SegmentKey(mustParseTime(t, brief.PublishedAt))
	repo.putSegment(t, key, brief)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	return NormalizePublicationMetadata(brief)
}

func mustParseTime(t *testing.T, raw string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func stixReleaseFiles(repo *fakeFeedRepo) []string {
	var names []string
	for path := range repo.files {
		if name, ok := strings.CutPrefix(path, "site/static/stix/releases/"); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func indexedSTIXReleases(t *testing.T, repo *fakeFeedRepo) []string {
	t.Helper()
	var index stixIndex
	if err := json.Unmarshal(repo.files["site/static/stix/index.json"], &index); err != nil {
		t.Fatal(err)
	}
	names := []string{strings.TrimPrefix(index.Rolling.Path, "/stix/releases/")}
	for _, entry := range index.Months {
		names = append(names, strings.TrimPrefix(entry.Path, "/stix/releases/"))
	}
	sort.Strings(names)
	return names
}

// Every publication adds content-addressed releases, and the site deploys
// only those the index references. Releases a new index no longer references
// are removed in the same commit, so the tree holds the current release only.
// The directory holds more files than GitHub's 1,000-entry Contents listing.
func TestPublishSTIXBundleRemovesReleasesTheIndexNoLongerReferences(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	seedPriorSTIXIndex(t, repo)
	for i := 0; i < 1001; i++ {
		repo.files[fmt.Sprintf("site/static/stix/releases/2026-07-sha256-%064x.json", i)] = []byte(`{"type":"bundle"}`)
	}
	repo.files["site/static/stix/releases/README.md"] = []byte("not a release")
	putRecentSTIXSource(t, repo)

	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatal(err)
	}
	if repo.refUpdates != 1 {
		t.Fatalf("STIX release advanced the branch %d times, want 1", repo.refUpdates)
	}
	want := append(indexedSTIXReleases(t, repo), "README.md")
	sort.Strings(want)
	if got := stixReleaseFiles(repo); !slices.Equal(got, want) {
		t.Fatalf("release files after publication = %d %v, want the indexed releases and the unknown file %v", len(got), got[:min(len(got), 5)], want)
	}
}

// A release that the new index still references stays, even though the
// previous index referenced it too.
func TestPublishSTIXBundleKeepsReleasesTheIndexStillReferences(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	putRecentSTIXSource(t, repo)
	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatal(err)
	}
	first := indexedSTIXReleases(t, repo)

	repo.files["site/static/stix/releases/sha256-"+strings.Repeat("0", 64)+".json"] = []byte(`{"type":"bundle"}`)
	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatal(err)
	}
	if got := stixReleaseFiles(repo); !slices.Equal(got, first) {
		t.Fatalf("release files after republishing unchanged content = %v, want %v", got, first)
	}
}

func TestPublishSTIXBundleFailureBeforeIndexPreservesPriorRelease(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	oldIndex, oldAlias := seedPriorSTIXIndex(t, repo)
	brief := putRecentSTIXSource(t, repo)
	month := SegmentKey(mustParseTime(t, brief.PublishedAt))
	monthData, err := ExportSTIX([]BundleBrief{brief})
	if err != nil {
		t.Fatal(err)
	}
	repo.failPut = "site/static" + testImmutableSTIXPath(month, monthData)
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected immutable artifact upload failure")
	}
	if !bytes.Equal(repo.files["site/static/stix/index.json"], oldIndex) || !bytes.Equal(repo.files["site/static/stix.json"], oldAlias) {
		t.Fatal("failure before index switch changed the prior release")
	}
}

func TestPublishSTIXBundleIndexFailureLeavesOldIndexReferentiallyValid(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	oldIndex, oldAlias := seedPriorSTIXIndex(t, repo)
	putRecentSTIXSource(t, repo)
	repo.failPut = "site/static/stix/index.json"
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected index switch failure")
	}
	if !bytes.Equal(repo.files["site/static/stix/index.json"], oldIndex) || !bytes.Equal(repo.files["site/static/stix.json"], oldAlias) {
		t.Fatal("failed index switch invalidated the prior release")
	}
	var prior stixIndex
	if err := json.Unmarshal(oldIndex, &prior); err != nil {
		t.Fatal(err)
	}
	assertImmutableSTIXIndexArtifact(t, repo, prior.Rolling.Month, prior.Rolling.Path, prior.Rolling.Checksum, prior.Rolling.SizeBytes, prior.Rolling.ReportCount)
}

func TestPublishSTIXBundleAliasFailureKeepsNewIndexValidAndRetries(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	_, oldAlias := seedPriorSTIXIndex(t, repo)
	brief := putRecentSTIXSource(t, repo)
	month := SegmentKey(mustParseTime(t, brief.PublishedAt))
	repo.failRead = "site/static/stix/" + month + ".json"
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected compatibility alias refresh failure")
	}
	var current stixIndex
	if err := json.Unmarshal(repo.files["site/static/stix/index.json"], &current); err != nil {
		t.Fatal(err)
	}
	assertImmutableSTIXIndexArtifact(t, repo, current.Rolling.Month, current.Rolling.Path, current.Rolling.Checksum, current.Rolling.SizeBytes, current.Rolling.ReportCount)
	for _, entry := range current.Months {
		assertImmutableSTIXIndexArtifact(t, repo, entry.Month, entry.Path, entry.Checksum, entry.SizeBytes, entry.ReportCount)
	}
	if !bytes.Equal(repo.files["site/static/stix.json"], oldAlias) {
		t.Fatal("rolling compatibility alias changed after earlier month alias failed")
	}
	repo.failRead = ""
	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatalf("retrying alias refresh: %v", err)
	}
	if bytes.Equal(repo.files["site/static/stix.json"], oldAlias) {
		t.Fatal("successful retry did not refresh stable rolling alias")
	}
}

func TestPublishSTIXBundleRejectsImmutablePathCollisionBeforeIndexSwitch(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	oldIndex, _ := seedPriorSTIXIndex(t, repo)
	brief := putRecentSTIXSource(t, repo)
	month := SegmentKey(mustParseTime(t, brief.PublishedAt))
	monthData, err := ExportSTIX([]BundleBrief{brief})
	if err != nil {
		t.Fatal(err)
	}
	repo.racePut["site/static"+testImmutableSTIXPath(month, monthData)] = []byte("concurrent conflicting bytes")
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected immutable artifact creation race to abort publication")
	}
	if !bytes.Equal(repo.files["site/static/stix/index.json"], oldIndex) {
		t.Fatal("immutable collision changed the index")
	}
}

func TestPublishSTIXBundleRetriesAfterConcurrentIdenticalImmutableArtifact(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	brief := putRecentSTIXSource(t, repo)
	month := SegmentKey(mustParseTime(t, brief.PublishedAt))
	monthData, err := ExportSTIX([]BundleBrief{brief})
	if err != nil {
		t.Fatal(err)
	}
	path := "site/static" + testImmutableSTIXPath(month, monthData)
	repo.racePut[path] = append([]byte(nil), monthData...)
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("concurrent branch advance must reject the first publication")
	}
	if !bytes.Equal(repo.files[path], monthData) {
		t.Fatal("identical concurrent artifact bytes changed")
	}
	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatalf("retry after identical concurrent artifact: %v", err)
	}
}

func TestPublishSTIXBundleIndexRaceCannotOverwriteConcurrentValidIndex(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	oldIndex, oldAlias := seedPriorSTIXIndex(t, repo)
	putRecentSTIXSource(t, repo)
	var concurrent stixIndex
	if err := json.Unmarshal(oldIndex, &concurrent); err != nil {
		t.Fatal(err)
	}
	concurrent.Description = "concurrent valid release"
	concurrentBytes, err := json.Marshal(concurrent)
	if err != nil {
		t.Fatal(err)
	}
	repo.racePut["site/static/stix/index.json"] = concurrentBytes
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected stale-SHA index race to abort the switch")
	}
	if !bytes.Equal(repo.files["site/static/stix/index.json"], concurrentBytes) {
		t.Fatal("publication overwrote the concurrent index")
	}
	assertImmutableSTIXIndexArtifact(t, repo, concurrent.Rolling.Month, concurrent.Rolling.Path, concurrent.Rolling.Checksum, concurrent.Rolling.SizeBytes, concurrent.Rolling.ReportCount)
	if !bytes.Equal(repo.files["site/static/stix.json"], oldAlias) {
		t.Fatal("index race refreshed aliases")
	}
}

func TestPublishSTIXBundleAliasRaceConvergesWithoutInvalidatingIndex(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	seedPriorSTIXIndex(t, repo)
	brief := putRecentSTIXSource(t, repo)
	month := SegmentKey(mustParseTime(t, brief.PublishedAt))
	monthAlias := "site/static/stix/" + month + ".json"
	repo.racePut[monthAlias] = []byte("concurrent alias bytes")
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("concurrent alias commit must reject the first publication")
	}
	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatalf("retrying after alias race: %v", err)
	}
	var current stixIndex
	if err := json.Unmarshal(repo.files["site/static/stix/index.json"], &current); err != nil {
		t.Fatal(err)
	}
	assertImmutableSTIXIndexArtifact(t, repo, current.Rolling.Month, current.Rolling.Path, current.Rolling.Checksum, current.Rolling.SizeBytes, current.Rolling.ReportCount)
	if got := string(repo.files[monthAlias]); got == "concurrent alias bytes" {
		t.Fatal("alias race did not refresh compatibility URL")
	}
}

func TestPublishSTIXBundleFailsOnUnreadableEligibleSegment(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC()
	key := SegmentKey(now.Add(-24 * time.Hour))
	repo.files["output/"+segmentPath(key)] = []byte(`{"not":"an encrypted segment"}`)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected unreadable eligible segment to abort STIX publication")
	}
	if _, uploaded := repo.files["site/static/stix.json"]; uploaded {
		t.Fatal("STIX artifacts were uploaded after source collection failed")
	}
}

func TestPublishSTIXBundleFailsWhenManifestSegmentIsMissing(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	key := SegmentKey(time.Now().UTC().Add(-24 * time.Hour))
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected missing manifest-listed segment to abort STIX publication")
	}
	if _, uploaded := repo.files["site/static/stix.json"]; uploaded {
		t.Fatal("STIX artifacts were uploaded from an incomplete source set")
	}
}

func TestPublishSTIXBundleRejectsEligibleUnlistedSegment(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC()
	listedAt := now.Add(-24 * time.Hour)
	unlistedAt := now.Add(-40 * 24 * time.Hour)
	listedKey, unlistedKey := SegmentKey(listedAt), SegmentKey(unlistedAt)
	repo.putSegment(t, listedKey, BundleBrief{ID: "listed", Title: "Listed", PublishedAt: listedAt.Format(time.RFC3339)})
	repo.putSegment(t, unlistedKey, BundleBrief{ID: "unlisted", Title: "Unlisted", PublishedAt: unlistedAt.Format(time.RFC3339)})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(listedKey), BriefCount: 1}}})
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected eligible unlisted segment to abort STIX publication")
	}
}

func TestPublishSTIXBundleVerifiesManifestCountAndChecksum(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Add(-24 * time.Hour)
	key := SegmentKey(now)
	repo.putSegment(t, key, BundleBrief{ID: "one", Title: "one", PublishedAt: now.Format(time.RFC3339)})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{
		Path: segmentPath(key), BriefCount: 2, Checksum: "bad-checksum",
	}}})
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected manifest metadata mismatch to abort STIX publication")
	}
}

func TestPublishSTIXBundleRejectsDuplicateCanonicalBriefIDs(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC()
	recent, older := now.Add(-2*24*time.Hour), now.Add(-40*24*time.Hour)
	recentKey, olderKey := SegmentKey(recent), SegmentKey(older)
	repo.putSegment(t, recentKey, BundleBrief{ID: "duplicate", Title: "recent", PublishedAt: recent.Format(time.RFC3339)})
	repo.putSegment(t, olderKey, BundleBrief{ID: "duplicate", Title: "older", PublishedAt: older.Format(time.RFC3339)})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(recentKey), BriefCount: 1}, {Path: segmentPath(olderKey), BriefCount: 1}}})
	if err := p.PublishSTIXBundle(); err == nil {
		t.Fatal("expected duplicate canonical brief ID to abort publication")
	}
}

func TestFlushSegmentedPropagatesSTIXPublicationFailure(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC()
	currentKey := SegmentKey(now)
	brokenKey := SegmentKey(now.Add(-40 * 24 * time.Hour))
	repairAt := now.Add(-40 * 24 * time.Hour)
	repo.putSegment(t, brokenKey, BundleBrief{ID: "existing", Title: "Existing", PublishedAt: repairAt.Format(time.RFC3339)})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(brokenKey), BriefCount: 1}}})
	repo.failRead = "site/static/stix.json"
	p.pending = []BundleBrief{{ID: "new", Slug: "new", Title: "New", PublishedAt: now.Format(time.RFC3339)}}
	if err := p.FlushSegmented(); err == nil {
		t.Fatal("expected segmented flush to return STIX publication failure")
	}
	if _, ok := repo.files["output/"+segmentPath(currentKey)]; ok {
		t.Fatal("failed release exposed its encrypted segment before downstream STIX completed")
	}
	if repo.refUpdates != 0 {
		t.Fatalf("failed release advanced the branch %d time(s)", repo.refUpdates)
	}
	if len(p.pending) != 1 {
		t.Fatalf("pending briefs cleared after STIX failure: %#v", p.pending)
	}
	repo.failRead = ""
	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("retry after repairing STIX source failed: %v", err)
	}
	if len(p.pending) != 0 {
		t.Fatalf("pending briefs retained after successful STIX retry: %#v", p.pending)
	}
	if repo.refUpdates != 1 {
		t.Fatalf("successful release advanced the branch %d times, want 1", repo.refUpdates)
	}
}

func TestFlushSegmentedRetiresDuplicateFromEveryPublicArtifact(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	canonical := BundleBrief{ID: "brief-connectwise-original", EventID: "brief-connectwise-original", Slug: "2026-10-connectwise-m365-compromise", Title: "ConnectWise compromise", PublishedAt: now.Format(time.RFC3339)}
	duplicate := BundleBrief{ID: "brief-storm-0940", EventID: "brief-storm-0940", Slug: "2026-10-storm-0940-artex", Title: "Storm-0940 duplicate", PublishedAt: now.Format(time.RFC3339)}
	repo.putSegment(t, key, canonical, duplicate)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 2}}})
	repo.putJSON(t, changelogPath, NewChangelog())
	duplicatePath := publicMarkdownPath(duplicate)
	repo.files[duplicatePath] = []byte("duplicate page")
	if err := p.RetireBrief(duplicate.ID, duplicate.Slug); err != nil {
		t.Fatal(err)
	}
	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("retire duplicate: %v", err)
	}
	segment := repo.segment(t, key)
	if len(segment.Briefs) != 1 || segment.Briefs[0].ID != canonical.ID {
		t.Fatalf("segment briefs = %#v, want only canonical", segment.Briefs)
	}
	manifest := repo.manifest(t)
	if manifest.Segments[0].BriefCount != 1 {
		t.Fatalf("manifest brief count = %d, want 1", manifest.Segments[0].BriefCount)
	}
	if _, exists := manifest.BriefLocations[duplicate.ID]; exists {
		t.Fatalf("retired brief still indexed: %#v", manifest.BriefLocations)
	}
	if _, exists := repo.files[duplicatePath]; exists {
		t.Fatalf("duplicate Markdown %s still exists", duplicatePath)
	}
	if len(p.pendingRetirements) != 0 {
		t.Fatalf("retirement queue retained after successful flush: %#v", p.pendingRetirements)
	}
	var changelog Changelog
	if err := json.Unmarshal(repo.files[changelogPath], &changelog); err != nil {
		t.Fatal(err)
	}
	foundRemove := false
	for _, version := range changelog.Entries {
		for _, change := range version.Changes {
			foundRemove = foundRemove || change.Type == "removed" && change.BriefID == duplicate.ID
		}
	}
	if !foundRemove {
		t.Fatalf("changelog did not record retirement: %#v", changelog)
	}
}

func TestFlushSegmentedTreatsAlreadyAbsentRetirementAsIdempotent(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	canonical := BundleBrief{
		ID: "brief-2026-10-21-emudhra-intermediate-key-compromise", EventID: "brief-2026-10-21-emudhra-intermediate-key-compromise",
		Slug: "2026-10-emudhra-intermediate-key-compromise", Title: "eMudhra intermediate key compromise", PublishedAt: now.Format(time.RFC3339),
	}
	repo.putSegment(t, key, canonical)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	repo.putJSON(t, changelogPath, NewChangelog())
	retired := BundleBrief{ID: "brief-2026-10-21-emudhra-ca-keys", Slug: "2026-10-emudhra-ca-keys"}
	retiredPath := publicMarkdownPath(retired)
	p.pending = []BundleBrief{canonical}
	if err := p.RetireBrief(retired.ID, retired.Slug); err != nil {
		t.Fatal(err)
	}

	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("retry retirement after the brief is already absent: %v", err)
	}
	segment := repo.segment(t, key)
	if len(segment.Briefs) != 1 || segment.Briefs[0].ID != canonical.ID {
		t.Fatalf("segment briefs = %#v, want only canonical", segment.Briefs)
	}
	if _, exists := repo.files[retiredPath]; exists {
		t.Fatalf("stale duplicate Markdown %s still exists", retiredPath)
	}
	var changelog Changelog
	if err := json.Unmarshal(repo.files[changelogPath], &changelog); err != nil {
		t.Fatal(err)
	}
	for _, version := range changelog.Entries {
		for _, change := range version.Changes {
			if change.Type == "removed" && change.BriefID == retired.ID {
				t.Fatalf("already-absent retirement emitted a second removal: %#v", changelog)
			}
		}
	}
}

func TestFlushSegmentedRejectsAlreadyAbsentRetirementUsingLiveSlug(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	live := BundleBrief{
		ID: "brief-live", EventID: "brief-live", Slug: "live-brief",
		Title: "Live brief", PublishedAt: now.Format(time.RFC3339),
	}
	repo.putSegment(t, key, live)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	repo.putJSON(t, changelogPath, NewChangelog())
	livePath := publicMarkdownPath(live)
	repo.files[livePath] = []byte("live page")
	if err := p.RetireBrief("brief-already-absent", live.Slug); err != nil {
		t.Fatal(err)
	}

	// The poison retirement is isolated: it is dropped, the flush succeeds
	// and the live brief's Markdown is untouched.
	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("poison retirement failed the flush: %v", err)
	}
	if _, exists := repo.files[livePath]; !exists {
		t.Fatalf("dropped retirement removed live Markdown %s", livePath)
	}
	if len(p.pendingRetirements) != 0 {
		t.Fatalf("poison retirement not dropped: %#v", p.pendingRetirements)
	}
}

func TestFlushSegmentedRejectsAlreadyAbsentRetirementUsingSameReleaseSlug(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Truncate(time.Second)
	live := BundleBrief{
		ID: "brief-new-live", EventID: "brief-new-live", Slug: "same-release-live-brief",
		Title: "New live brief", PublishedAt: now.Format(time.RFC3339),
	}
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1"})
	repo.putJSON(t, changelogPath, NewChangelog())
	repo.files[publicMarkdownPath(live)] = []byte("pre-existing page at the requested slug")
	p.pending = []BundleBrief{live}
	if err := p.RetireBrief("brief-already-absent", live.Slug); err != nil {
		t.Fatal(err)
	}

	// The retirement is dropped; the brief owning the slug still publishes.
	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("poison retirement failed the flush: %v", err)
	}
	if repo.refUpdates == 0 {
		t.Fatal("flush with a dropped retirement did not publish the brief")
	}
	if len(p.pending) != 0 || len(p.pendingRetirements) != 0 {
		t.Fatalf("pending state not cleared: briefs=%#v retirements=%#v", p.pending, p.pendingRetirements)
	}
}

func TestFlushSegmentedUsesCanonicalSlugForExistingRetirement(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	canonical := BundleBrief{
		ID: "brief-canonical", EventID: "brief-canonical", Slug: "canonical",
		Title: "Canonical", PublishedAt: now.Format(time.RFC3339),
	}
	duplicate := BundleBrief{
		ID: "brief-duplicate", EventID: "brief-duplicate", Slug: "feed-canonical-duplicate-slug",
		Title: "Duplicate", PublishedAt: now.Format(time.RFC3339),
	}
	repo.putSegment(t, key, canonical, duplicate)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 2}}})
	repo.putJSON(t, changelogPath, NewChangelog())
	duplicatePath := publicMarkdownPath(duplicate)
	repo.files[duplicatePath] = []byte("duplicate page")
	if err := p.RetireBrief(duplicate.ID, "stale-local-slug"); err != nil {
		t.Fatal(err)
	}

	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("retire duplicate with stale local slug: %v", err)
	}
	if _, exists := repo.files[duplicatePath]; exists {
		t.Fatalf("canonical duplicate Markdown %s still exists", duplicatePath)
	}
}

func TestFlushSegmentedDisambiguatesNewSlugCollisionBeforePublication(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Truncate(time.Second)
	key := SegmentKey(now)
	sharedSlug := now.Format("2006-01") + "-scriban-dos"
	existing := BundleBrief{
		ID: "brief-" + now.Format("2006-01-02") + "-existing", Slug: sharedSlug,
		Title: "Existing", PublishedAt: now.Add(-time.Hour).Format(time.RFC3339),
	}
	repo.putSegment(t, key, existing)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	newID := "brief-" + now.Format("2006-01-02") + "-new"
	p.pending = []BundleBrief{{ID: newID, Slug: sharedSlug, Title: "New", PublishedAt: now.Format(time.RFC3339)}}

	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("FlushSegmented: %v", err)
	}
	briefs := repo.segment(t, key).Briefs
	if len(briefs) != 2 {
		t.Fatalf("brief count = %d, want 2", len(briefs))
	}
	if briefs[0].Slug != sharedSlug {
		t.Fatalf("existing slug changed to %q", briefs[0].Slug)
	}
	if briefs[1].Slug != strings.TrimPrefix(newID, "brief-") {
		t.Fatalf("new slug = %q, want ID-derived disambiguation", briefs[1].Slug)
	}
}

func TestFlushSegmentedCoalescesSameIDBeforeSlugRepair(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Truncate(time.Second)
	key := SegmentKey(now)
	sharedSlug := now.Format("2006-01") + "-virtualenv-command-injection"
	existing := BundleBrief{
		ID: "brief-" + now.Format("2006-01-02") + "-existing", Slug: sharedSlug,
		Title: "Existing", PublishedAt: now.Add(-time.Hour).Format(time.RFC3339),
	}
	repo.putSegment(t, key, existing)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	newID := "brief-" + now.Format("2006-01-02") + "-virtualenv-command-injection"
	p.bufferBrief(BundleBrief{ID: newID, Slug: sharedSlug, Title: "First snapshot", PublishedAt: now.Format(time.RFC3339)})
	p.bufferBrief(BundleBrief{ID: newID, Slug: sharedSlug, Title: "Latest snapshot", PublishedAt: now.Format(time.RFC3339)})

	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("FlushSegmented: %v", err)
	}
	briefs := repo.segment(t, key).Briefs
	if len(briefs) != 2 {
		t.Fatalf("brief count = %d, want 2", len(briefs))
	}
	if briefs[1].Title != "Latest snapshot" {
		t.Fatalf("published title = %q, want latest snapshot", briefs[1].Title)
	}
	if briefs[1].Slug != strings.TrimPrefix(newID, "brief-") {
		t.Fatalf("new slug = %q, want ID-derived disambiguation", briefs[1].Slug)
	}
}

func TestFlushSegmentedPreservesCanonicalSlugOnLaterCollidingUpdate(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Truncate(time.Second)
	key := SegmentKey(now)
	requestedSlug := now.Format("2006-01") + "-virtualenv-command-injection"
	canonicalSlug := now.Format("2006-01-02") + "-virtualenv-command-injection"
	targetID := "brief-" + canonicalSlug
	repo.putSegment(t, key,
		BundleBrief{ID: "brief-existing", Slug: requestedSlug, Title: "Existing owner", PublishedAt: now.Add(-time.Hour).Format(time.RFC3339)},
		BundleBrief{ID: targetID, Slug: canonicalSlug, Title: "First publication", PublishedAt: now.Format(time.RFC3339)},
	)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 2}}})
	p.pending = []BundleBrief{{ID: targetID, Slug: requestedSlug, Title: "Later update", PublishedAt: now.Format(time.RFC3339)}}

	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("FlushSegmented: %v", err)
	}
	briefs := repo.segment(t, key).Briefs
	for _, brief := range briefs {
		if brief.ID == targetID {
			if brief.Title != "Later update" || brief.Slug != canonicalSlug {
				t.Fatalf("updated brief = %#v, want latest content with canonical slug %q", brief, canonicalSlug)
			}
			return
		}
	}
	t.Fatalf("updated brief %q not found", targetID)
}

func TestFlushSegmentedPublishesMergedRevisionMetadata(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Truncate(time.Second)
	key := SegmentKey(now)
	existing := BundleBrief{ID: "brief-1", Slug: "brief-1", Title: "Old", Content: "The security notice records suspicious process activity for analyst review.", PublishedAt: now.Format(time.RFC3339)}
	repo.putSegment(t, key, existing)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}}})
	p.pending = []BundleBrief{{ID: "brief-1", Slug: "brief-1", Title: "Corrected", Content: existing.Content, PublishedAt: existing.PublishedAt}}
	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	md := string(repo.files["site/content/briefs/brief-1.md"])
	if !strings.Contains(md, "revision: 2") || !strings.Contains(md, "revision_history:") {
		t.Fatalf("Markdown did not use canonical merged snapshot:\n%s", md)
	}
}

func TestFlushSegmentedRejectsIdentityMovedAcrossMonths(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-40 * 24 * time.Hour)
	oldKey := SegmentKey(old)
	repo.putSegment(t, oldKey, BundleBrief{ID: "brief-1", EventID: "event-1", Slug: "brief-1", Title: "Old", PublishedAt: old.Format(time.RFC3339)})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(oldKey), BriefCount: 1}}})
	p.pending = []BundleBrief{{ID: "brief-1", EventID: "event-1", Slug: "brief-1", Title: "Moved", PublishedAt: now.Format(time.RFC3339)}}
	// The moved snapshot is a per-brief revision rejection: it is dropped
	// from the release instead of aborting it.
	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("cross-month identity mutation must be isolated, got %v", err)
	}
	if len(p.pending) != 0 {
		t.Fatalf("rejected snapshot retained in pending: %#v", p.pending)
	}
	if got := repo.segment(t, oldKey).Briefs; len(got) != 1 || got[0].Title != "Old" {
		t.Fatalf("published version changed: %#v", got)
	}
	if _, exists := repo.files["output/"+segmentPath(SegmentKey(now))]; exists {
		t.Fatal("identity mutation created a second monthly segment copy")
	}
}

// A flush only holds the segments it rewrites, so it must not replace the
// feed-wide CVE metadata index with one built from those segments alone.
func TestFlushSegmentedKeepsCVEMetadataIndex(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	now := time.Now().UTC()
	key := SegmentKey(now)
	repo.putSegment(t, key, BundleBrief{ID: "existing", Title: "existing", PublishedAt: now.Format(time.RFC3339)})
	repo.files[cveMetadataPath] = []byte(`{"content":"index"}`)
	repo.putJSON(t, manifestPath, &SegmentManifest{
		Version:  "v1",
		Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 1}},
		CVEMeta:  &CVEMetaEntry{Path: cveMetadataPath, Checksum: "index-checksum"},
	})
	p.pending = append(p.pending, BundleBrief{ID: "new", Title: "new", PublishedAt: now.Format(time.RFC3339),
		CVEs: []BundleCVE{{ID: "CVE-2026-0004", EPSS: 0.4}}})

	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.requested("PUT "+cveMetadataPath) >= 0 {
		t.Error("flush rewrote the CVE metadata index")
	}
	if m := repo.manifest(t); m.CVEMeta == nil || m.CVEMeta.Checksum != "index-checksum" {
		t.Errorf("manifest CVE metadata entry = %+v, want the existing index", m.CVEMeta)
	}
	if got := len(repo.segment(t, key).Briefs); got != 2 {
		t.Errorf("segment %s has %d briefs after flush, want 2", key, got)
	}
}

// A pre-existing duplicate ID is ambiguous under the append-only identity
// contract. Publication must stop before rewriting either copy; an operator
// can then reconcile the historical corruption explicitly.
func TestFlushSegmentedRejectsDuplicateBriefAcrossMonths(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	old := BundleBrief{ID: "brief-moved", Slug: "brief-moved", Title: "old copy", PublishedAt: "2024-01-30T10:00:00Z"}
	neighbor := BundleBrief{ID: "brief-neighbor", Slug: "brief-neighbor", Title: "keep me", PublishedAt: "2024-01-31T10:00:00Z"}
	digest := BundleDigest{ID: "digest-keep", PublishedAt: "2024-01-31T10:00:00Z"}
	enc, err := EncryptSegment(&SegmentContent{Briefs: []BundleBrief{old, neighbor}, Digests: []BundleDigest{digest}}, "v1", "2026-01-01T00:00:00Z", testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	repo.putJSON(t, "output/briefs/2024-01.json", enc)
	repo.putSegment(t, "2025-11", BundleBrief{ID: old.ID, Slug: old.Slug, Title: "another stale copy", PublishedAt: "2025-11-30T10:00:00Z"})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{
		{Path: "briefs/2024-01.json", BriefCount: 2},
		{Path: "briefs/2025-11.json", BriefCount: 1},
	}})
	p.pending = append(p.pending, BundleBrief{ID: old.ID, Slug: old.Slug, Title: "corrected copy", PublishedAt: "2026-04-08T10:00:00Z"})

	if err := p.FlushSegmented(); err == nil || !strings.Contains(err.Error(), "duplicate canonical brief id") {
		t.Fatalf("FlushSegmented error = %v, want duplicate canonical ID", err)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	oldSegment := repo.segment(t, "2024-01")
	if len(oldSegment.Briefs) != 2 || oldSegment.Briefs[0].Title != "old copy" {
		t.Errorf("old segment briefs changed after rejection: %+v", oldSegment.Briefs)
	}
	if len(oldSegment.Digests) != 1 || oldSegment.Digests[0].ID != digest.ID {
		t.Errorf("old segment digests = %+v, want preserved digest", oldSegment.Digests)
	}
	if stale := repo.segment(t, "2025-11"); len(stale.Briefs) != 1 || stale.Briefs[0].Title != "another stale copy" {
		t.Errorf("second old segment changed after rejection: %+v", stale.Briefs)
	}
	if _, created := repo.files["output/briefs/2026-04.json"]; created {
		t.Fatal("rejected identity mutation created a new segment")
	}
}

func TestFlushSegmentedDoesNotIndexMissingListedSegment(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.putJSON(t, manifestPath, &SegmentManifest{
		Version:  "v1",
		Segments: []SegmentEntry{{Path: "briefs/2024-01.json", BriefCount: 1}},
	})
	p.pending = append(p.pending, BundleBrief{
		ID: "brief-corrected", Slug: "brief-corrected", Title: "corrected", PublishedAt: "2026-04-08T10:00:00Z",
	})

	if err := p.FlushSegmented(); err == nil || !strings.Contains(err.Error(), "briefs/2024-01.json") {
		t.Fatalf("FlushSegmented error = %v, want missing indexed segment", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.requested("PUT "+manifestPath) >= 0 {
		t.Fatal("manifest was published from an incomplete brief index")
	}
}

func TestFlushSegmentedDoesNotReplaceManifestAfterFetchError(t *testing.T) {
	var puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/git/ref/heads/main") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"object":{"sha":"base-commit"}}`))
			return
		}
		if strings.HasSuffix(req.URL.Path, "/git/commits/base-commit") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"tree":{"sha":"base-tree"}}`))
			return
		}
		if req.Method == http.MethodPut {
			puts.Add(1)
			w.WriteHeader(http.StatusCreated)
			return
		}
		if strings.HasSuffix(req.URL.Path, "/output/manifest.json") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	p := &Publisher{
		repoSlug: "CraftedSignal/threat-feed", publicKey: testPublicKey,
		tokenFn: func() string { return "test-token" }, apiURL: srv.URL,
		client: http.DefaultClient, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	p.pending = append(p.pending, BundleBrief{ID: "brief-new", Slug: "new", PublishedAt: "2026-04-08T10:00:00Z"})

	if err := p.FlushSegmented(); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("FlushSegmented error = %v, want manifest fetch failure", err)
	}
	if got := puts.Load(); got != 0 {
		t.Errorf("uploaded %d files after manifest fetch failed, want none", got)
	}
	if len(p.pending) != 1 {
		t.Error("pending brief was dropped after failed flush")
	}
}

func TestFlushSegmentedMigratesLegacyBundleWhenManifestMissing(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	legacy := BundleBrief{ID: "brief-legacy", Slug: "legacy", Title: "legacy", PublishedAt: "2024-01-30T10:00:00Z"}
	legacyDigest := BundleDigest{ID: "digest-legacy", PublishedAt: "2025-11-30T10:00:00Z"}
	encrypted, err := Encrypt(&BundleContent{Briefs: []BundleBrief{legacy}, Digests: []BundleDigest{legacyDigest}}, "v1", "2026-01-01T00:00:00Z", testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	repo.putJSON(t, bundlePath, encrypted)
	p.pending = append(p.pending, BundleBrief{ID: "brief-new", Slug: "new", Title: "new", PublishedAt: "2026-04-08T10:00:00Z"})

	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if old := repo.segment(t, "2024-01"); len(old.Briefs) != 1 || old.Briefs[0].ID != legacy.ID {
		t.Errorf("migrated month = %+v, want legacy brief", old.Briefs)
	}
	if got := repo.manifest(t).BriefLocations[legacy.ID]; !slices.Equal(got, []string{"2024-01"}) {
		t.Errorf("legacy brief location = %v, want [2024-01]", got)
	}
	if digestMonth := repo.segment(t, "2025-11"); len(digestMonth.Digests) != 1 || digestMonth.Digests[0].ID != legacyDigest.ID {
		t.Errorf("migrated digest month = %+v, want legacy digest", digestMonth.Digests)
	}
	foundDigestMonth := false
	for _, entry := range repo.manifest(t).Segments {
		foundDigestMonth = foundDigestMonth || entry.Path == "briefs/2025-11.json"
	}
	if !foundDigestMonth {
		t.Fatal("manifest omitted migrated digest-only month")
	}
}

func TestFlushSegmentedListsDigestOnlyMonth(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	p.pendingDigests = append(p.pendingDigests, BundleDigest{ID: "digest-only", PublishedAt: "2024-01-30T10:00:00Z"})
	p.pending = append(p.pending, BundleBrief{ID: "brief-new", Slug: "new", PublishedAt: "2026-04-08T10:00:00Z"})

	if err := p.FlushSegmented(); err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	content := repo.segment(t, "2024-01")
	if len(content.Digests) != 1 || content.Digests[0].ID != "digest-only" {
		t.Errorf("segment digests = %+v, want digest-only", content.Digests)
	}
	found := false
	for _, segment := range repo.manifest(t).Segments {
		if segment.Path == "briefs/2024-01.json" {
			found = true
			if segment.BriefCount != 0 || segment.Checksum == "" {
				t.Errorf("digest-only segment entry = %+v", segment)
			}
		}
	}
	if !found {
		t.Fatal("manifest omitted digest-only month")
	}
}

type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func TestFlushSegmentedIsolatesRejectedRevision(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	handler := &recordingHandler{}
	p.logger = slog.New(handler)
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	key := SegmentKey(now)
	published := now.Format(time.RFC3339)
	bad := BundleBrief{ID: "brief-bad", EventID: "brief-bad", Slug: key + "-bad", Title: "Bad", PublishedAt: published, CVEs: []BundleCVE{{ID: "CVE-2026-1000"}}}
	good := BundleBrief{ID: "brief-good", EventID: "brief-good", Slug: key + "-good", Title: "Good", PublishedAt: published}
	repo.putSegment(t, key, bad, good)
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath(key), BriefCount: 2}}})
	repo.putJSON(t, changelogPath, NewChangelog())

	badUpdate := bad
	badUpdate.Title = "Bad rewritten"
	badUpdate.CVEs = []BundleCVE{{ID: "CVE-2026-2000"}}
	goodUpdate := good
	goodUpdate.Title = "Good updated"
	p.pending = []BundleBrief{badUpdate, goodUpdate}

	if err := p.FlushSegmented(); err != nil {
		t.Fatalf("FlushSegmented: %v", err)
	}
	if len(p.pending) != 0 {
		t.Fatalf("pending retained: %#v", p.pending)
	}
	titles := map[string]string{}
	for _, b := range repo.segment(t, key).Briefs {
		titles[b.ID] = b.Title
	}
	if titles["brief-good"] != "Good updated" {
		t.Fatalf("valid brief not published: %#v", titles)
	}
	if titles["brief-bad"] != "Bad" {
		t.Fatalf("rejected brief was modified: %#v", titles)
	}
	for path, raw := range repo.files {
		if strings.Contains(string(raw), "Bad rewritten") || (strings.Contains(path, "brief-bad") && strings.HasPrefix(path, "site/")) {
			t.Fatalf("rejected brief leaked into %s", path)
		}
	}
	var changelog Changelog
	if err := json.Unmarshal(repo.files[changelogPath], &changelog); err != nil {
		t.Fatal(err)
	}
	for _, v := range changelog.Entries {
		for _, c := range v.Changes {
			if c.BriefID == "brief-bad" {
				t.Fatalf("rejected brief in changelog: %#v", c)
			}
		}
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	found := false
	for _, r := range handler.records {
		if r.Level == slog.LevelError && r.Message == "brief revision rejected" {
			found = true
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == "brief_id" && a.Value.String() != "brief-bad" {
					t.Errorf("brief_id = %v", a.Value)
				}
				return true
			})
		}
	}
	if !found {
		t.Fatal("missing ERROR record 'brief revision rejected'")
	}
}
