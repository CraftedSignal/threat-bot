package publisher

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func testPublisher(srv *httptest.Server) *Publisher {
	return &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    srv.Client(),
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// The streamed upload must carry exactly json.Marshal(manifest), and the
// returned checksum must be the checksum of those bytes.
func TestPutFileUploadsTheMarshaledManifest(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"content":{"sha":"new-sha"}}`))
	}))
	defer srv.Close()
	p := testPublisher(srv)

	enc, err := EncryptSegment(&SegmentContent{Briefs: []BundleBrief{
		{ID: "a", Title: `Escapes <&> and "quotes"`, PublishedAt: "2026-10-18T09:00:00Z"},
	}}, "1.0", "2026-10-18T09:00:00Z", testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(enc)
	if err != nil {
		t.Fatal(err)
	}

	message := `chore: a message mentioning "content":"" itself`
	checksum, err := p.putFile("output/briefs/2026-10.json", enc, "old-sha", message)
	if err != nil {
		t.Fatal(err)
	}

	var req contentsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("request body is not valid JSON: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("uploaded file differs from json.Marshal(manifest): %d vs %d bytes", len(got), len(want))
	}
	if checksum != ComputeChecksum(want) {
		t.Errorf("checksum = %s, want %s", checksum, ComputeChecksum(want))
	}
	if req.Message != message || req.SHA != "old-sha" || req.Author.Name != "threat-bot" || req.Author.Email != "threat-bot@users.noreply.github.com" {
		t.Errorf("request fields = %+v", req)
	}
}

func TestContentsPayloadOmitsEmptySHA(t *testing.T) {
	data := []byte{0, 1, 2, 0xff, '"', '\\'}
	payload, err := contentsPayload("chore: new file", "", len(data), writeBytes(data))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if _, ok := fields["sha"]; ok {
		t.Error("payload carries a sha for a new file")
	}
	got, err := base64.StdEncoding.DecodeString(fields["content"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content = %v, want %v", got, data)
	}
}

// Segments over 1MB come without inline content. They must be read as the
// blob of the SHA the next upload uses as its precondition: the branch
// download_url is CDN-cached, and right after a flush it served the previous
// version, which the next flush then merged into and overwrote newer briefs.
func TestFetchSegmentReadsLargeSegmentsByBlobSHA(t *testing.T) {
	encode := func(briefs []BundleBrief) []byte {
		t.Helper()
		enc, err := EncryptSegment(&SegmentContent{Briefs: briefs}, "1.0", "2026-10-18T09:00:00Z", testPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		file, err := json.Marshal(enc)
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	big := strings.Repeat("x", 2<<20)
	stale := encode([]BundleBrief{{ID: "a", Title: big, PublishedAt: "2026-10-18T09:00:00Z"}})
	current := []BundleBrief{
		{ID: "a", Title: big, PublishedAt: "2026-10-18T09:00:00Z"},
		{ID: "b", Title: "added by the previous flush", PublishedAt: "2026-10-18T09:05:00Z"},
	}
	file := encode(current)

	var blobReads, cdnReads atomic.Int32
	size := int64(len(file))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/CraftedSignal/threat-feed/git/blobs/current-sha":
			if r.Header.Get("Accept") != "application/vnd.github.raw+json" {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			blobReads.Add(1)
			w.Write(file)
		case "/cdn/segment":
			cdnReads.Add(1)
			w.Write(stale)
		default:
			fmt.Fprintf(w, `{"sha":"current-sha","size":%d,"content":"","download_url":%q}`, size, "http://"+r.Host+"/cdn/segment")
		}
	}))
	defer srv.Close()
	p := testPublisher(srv)

	got, sha, err := p.fetchSegment("output/briefs/2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	if sha != "current-sha" || !reflect.DeepEqual(got.Briefs, current) {
		t.Errorf("fetched sha %q and %d briefs, want current-sha and the current %d", sha, len(got.Briefs), len(current))
	}
	if cdnReads.Load() != 0 {
		t.Error("fetch read the CDN-cached download_url")
	}

	// A file the API reports as over the limit is refused before downloading.
	size = maxFeedFileBytes + 1
	if _, _, err := p.fetchSegment("output/briefs/2026-10.json"); err == nil {
		t.Error("fetched a segment reported as over the size limit")
	}
	if n := blobReads.Load(); n != 1 {
		t.Errorf("blob reads = %d, want only the first fetch to download", n)
	}
}

func TestReadFeedFileStopsAtTheLimit(t *testing.T) {
	data := strings.Repeat("a", 50)
	for _, size := range []int64{50, 0, 10} { // exact, unknown, understated
		got, err := readFeedFile(strings.NewReader(data), size, 64)
		if err != nil || string(got) != data {
			t.Errorf("size %d: got %d bytes, err %v", size, len(got), err)
		}
	}
	if _, err := readFeedFile(strings.NewReader(strings.Repeat("a", 65)), 10, 64); err == nil {
		t.Error("download past the limit was accepted")
	}
}
