package publisher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestBlobCacheRetainsCurrentFeedWorkingSetBetweenPasses(t *testing.T) {
	_, p := newFakeFeedRepo(t)
	dir := t.TempDir()
	WithBlobCache(dir)(p)
	// Four independent 80 MiB artifacts fit the deployed working set. A fifth
	// must evict the oldest before writing, leaving headroom on a 512 MiB volume.
	data := make([]byte, 80<<20)
	var shas []string
	for i := range 5 {
		data[0] = byte(i)
		sha := gitBlobSHA(data)
		if err := p.cacheDownloadedBlob(sha, int64(len(data)), data); err != nil {
			t.Fatal(err)
		}
		shas = append(shas, sha)
		if i == 3 {
			for _, cached := range shas {
				if got := p.blobCache.get(cached, int64(len(data))); got == nil {
					t.Fatal("current feed working set was evicted before the next pass")
				}
			}
		}
	}
	if got := p.blobCache.get(shas[0], int64(len(data))); got != nil {
		t.Fatal("cache did not evict the oldest artifact before exceeding its budget")
	}
	for _, sha := range shas[1:] {
		if got := p.blobCache.get(sha, int64(len(data))); got == nil {
			t.Fatal("cache lost an artifact from the current feed working set")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > 384<<20 {
		t.Fatalf("cache retained %d bytes beyond its deployed budget", total)
	}
}

func TestBlobCacheStagedReadsAvoidDownload(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	WithBlobCache(t.TempDir())(p)
	err := p.withAtomicPublication("cached staged bytes", func() error {
		if _, err := p.stageGitFile("output/new.json", []byte(`{"new":true}`)); err != nil {
			return err
		}
		for range 2 {
			raw, _, err := p.fetchJSONFile("output/new.json")
			if err != nil || string(raw) != `{"new":true}` {
				return fmt.Errorf("staged bytes = %q, %v", raw, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range repo.requests {
		if strings.HasPrefix(request, "GET git/blobs/") {
			t.Fatalf("staged bytes were downloaded: %v", repo.requests)
		}
	}
	if repo.refUpdates != 1 || string(repo.files["output/new.json"]) != `{"new":true}` {
		t.Fatal("cache changed atomic publication result")
	}
}

func TestBlobCacheWarmAcrossPublicationsKeepsMetadataAndChangedSHA(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.omitContents = true
	cacheDir := t.TempDir()
	WithBlobCache(cacheDir)(p)
	const path = "output/cached.json"
	repo.files[path] = []byte(`{"version":1}`)
	read := func(want string) {
		t.Helper()
		if err := p.withAtomicPublication("read pinned bytes", func() error {
			raw, _, err := p.fetchJSONFile(path)
			if err != nil || string(raw) != want {
				return fmt.Errorf("read = %q, %v; want %q", raw, err, want)
			}
			if _, tracked := p.publication.readPaths[path]; !tracked {
				return fmt.Errorf("cached read was absent from conflict read set")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	read(`{"version":1}`)
	read(`{"version":1}`)
	WithBlobCache(cacheDir)(p) // A new cache instance can use the same disk bytes.
	read(`{"version":1}`)
	repo.files[path] = []byte(`{"version":2}`)
	read(`{"version":2}`)
	delete(repo.files, path)
	raw, sha, err := p.fetchJSONFile(path)
	if err != nil || raw != nil || sha != "" {
		t.Fatalf("deleted file was hidden by cache: %q, %q, %v", raw, sha, err)
	}
	metadata, blobs := 0, 0
	for _, request := range repo.requests {
		if request == "GET "+path {
			metadata++
		}
		if strings.HasPrefix(request, "GET git/blobs/") {
			blobs++
		}
	}
	if metadata != 5 || blobs != 2 {
		t.Fatalf("metadata reads = %d, blob downloads = %d; want 5 and 2", metadata, blobs)
	}
}

func TestBlobCacheCorruptionFallsBackToDownload(t *testing.T) {
	for _, damage := range []string{"same-size", "truncated"} {
		t.Run(damage, func(t *testing.T) {
			repo, p := newFakeFeedRepo(t)
			repo.omitContents = true
			dir := t.TempDir()
			WithBlobCache(dir)(p)
			const path = "output/cached.json"
			repo.files[path] = []byte(`{"valid":true}`)
			_, sha, err := p.fetchJSONFile(path)
			if err != nil {
				t.Fatal(err)
			}
			broken := []byte("x")
			if damage == "same-size" {
				broken = bytes.Repeat([]byte("x"), len(repo.files[path]))
			}
			if err := os.WriteFile(filepath.Join(dir, sha+".blob"), broken, 0600); err != nil {
				t.Fatal(err)
			}
			raw, _, err := p.fetchJSONFile(path)
			if err != nil || string(raw) != `{"valid":true}` {
				t.Fatalf("corrupt cache read = %q, %v", raw, err)
			}
			downloads := 0
			for _, request := range repo.requests {
				if strings.HasPrefix(request, "GET git/blobs/") {
					downloads++
				}
			}
			if downloads != 2 {
				t.Fatalf("downloads = %d, want corrupted entry refetched", downloads)
			}
		})
	}
}

func TestBlobCacheRejectsInvalidDownloadedBytes(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		size int64
	}{
		{"wrong SHA", "BAD!", 4},
		{"wrong size", "good", 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(test.data))
			}))
			defer srv.Close()
			p := testPublisher(srv)
			WithBlobCache(t.TempDir())(p)
			if _, err := p.fetchBlob(gitBlobSHA([]byte("good")), test.size); err == nil {
				t.Fatal("invalid downloaded bytes were accepted")
			}
		})
	}
}

func TestBlobCacheRejectsWrongUploadSHA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"sha": gitBlobSHA([]byte("wrong bytes"))})
	}))
	defer srv.Close()
	p := testPublisher(srv)
	WithBlobCache(t.TempDir())(p)
	p.publication = &gitPublication{staged: make(map[string]stagedGitFile)}
	if _, err := p.stageGitFile("output/file.json", []byte("intended bytes")); err == nil {
		t.Fatal("upload response with the wrong SHA was accepted")
	}
	if len(p.publication.staged) != 0 {
		t.Fatal("invalid upload was staged")
	}
}

func TestBlobCacheUnavailableDirectoryKeepsRemoteReadWorking(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.omitContents = true
	dir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(dir, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	WithBlobCache(dir)(p)
	repo.files["output/remote.json"] = []byte(`{"remote":true}`)
	for range 2 {
		raw, _, err := p.fetchJSONFile("output/remote.json")
		if err != nil || string(raw) != `{"remote":true}` {
			t.Fatalf("cache filesystem error broke authoritative read: %q, %v", raw, err)
		}
	}
}

func TestBlobDiskCacheBoundsAndConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	const budget int64 = 48
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			// Separate cache instances exercise the shared directory lock.
			cache := &blobDiskCache{dir: dir, maxBytes: budget}
			data := []byte(fmt.Sprintf("blob payload %02d", i))
			if err := cache.put(gitBlobSHA(data), data); err != nil {
				t.Errorf("cache write: %v", err)
			}
		})
	}
	wg.Wait()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	retained := 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
		if strings.HasSuffix(entry.Name(), ".blob") {
			retained++
			sha := strings.TrimSuffix(entry.Name(), ".blob")
			if raw := (&blobDiskCache{dir: dir, maxBytes: budget}).get(sha, info.Size()); raw == nil {
				t.Fatalf("concurrent write left corrupt bytes for %s", sha)
			}
		}
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("temporary cache file left behind: %s", entry.Name())
		}
	}
	if total > budget || retained == 0 || retained == 20 {
		t.Fatalf("cache retained %d blobs, %d bytes with %d byte budget", retained, total, budget)
	}
}

func TestBlobDiskCacheSkipsOversizeAndInvalidEntries(t *testing.T) {
	dir := t.TempDir()
	cache := &blobDiskCache{dir: dir, maxBytes: 4}
	data := []byte("larger than cache")
	if err := cache.put(gitBlobSHA(data), data); err != nil {
		t.Fatal(err)
	}
	if raw := cache.get(gitBlobSHA(data), int64(len(data))); raw != nil {
		t.Fatal("oversize blob consumed cache space")
	}
	if err := cache.put("../../escape", []byte("bad")); err == nil {
		t.Fatal("invalid cache key was accepted")
	}
	if err := cache.put(gitBlobSHA([]byte("good")), []byte("BAD!")); err == nil {
		t.Fatal("bytes with the wrong SHA were cached")
	}
}

func TestSTIXAtomicAliasesReuseImmutableBlobUpload(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	WithBlobCache(t.TempDir())(p)
	putRecentSTIXSource(t, repo)
	if err := p.PublishSTIXBundle(); err != nil {
		t.Fatal(err)
	}
	var index stixIndex
	if err := json.Unmarshal(repo.files["site/static/stix/index.json"], &index); err != nil {
		t.Fatal(err)
	}
	for _, entry := range append(index.Months, index.Rolling) {
		alias := "site/static/stix.json"
		if entry.Month != "" {
			alias = "site/static/stix/" + entry.Month + ".json"
		}
		if !bytes.Equal(repo.files[alias], repo.files["site/static"+entry.Path]) {
			t.Fatalf("alias %s differs from immutable artifact", alias)
		}
		for _, request := range repo.requests {
			if request == "PUT "+alias {
				t.Fatalf("alias reuploaded identical blob: %v", repo.requests)
			}
		}
	}
	if repo.refUpdates != 1 {
		t.Fatalf("release used %d branch updates, want 1", repo.refUpdates)
	}
}
