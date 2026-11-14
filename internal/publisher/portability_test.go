package publisher

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicationUsesConfiguredBranchAndAuthorForReadsAndWrites(t *testing.T) {
	var readRef, patchPath, refPath string
	var author commitAuthor
	var contents map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/contents/") && r.Method == "GET":
			readRef = r.URL.Query().Get("ref")
			_, _ = io.WriteString(w, `{"sha":"file","content":"e30=","encoding":"base64"}`)
		case strings.Contains(r.URL.Path, "/contents/") && r.Method == "PUT":
			_ = json.NewDecoder(r.Body).Decode(&contents)
			w.WriteHeader(201)
		case strings.Contains(r.URL.Path, "/git/ref/heads/"):
			refPath = r.URL.Path
			_, _ = io.WriteString(w, `{"object":{"sha":"base"}}`)
		case strings.HasSuffix(r.URL.Path, "/git/commits/base"):
			_, _ = io.WriteString(w, `{"tree":{"sha":"base-tree"}}`)
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			_, _ = io.WriteString(w, `{"sha":"tree"}`)
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			var payload struct {
				Author commitAuthor `json:"author"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			author = payload.Author
			_, _ = io.WriteString(w, `{"sha":"commit"}`)
		case strings.Contains(r.URL.Path, "/git/refs/heads/"):
			patchPath = r.URL.Path
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	p := New("owner/feed", testPublicKey, func() string { return "test" }, slog.New(slog.NewTextHandler(io.Discard, nil)), WithPublicationSettings(PublicationSettings{SiteURL: "https://example.org/intel", Branch: "release/feed#1", AuthorName: "Feed Writer", AuthorEmail: "writer@example.org"}))
	p.apiURL = srv.URL
	p.client = srv.Client()
	if _, _, err := p.fetchJSONFile("output/test.json"); err != nil {
		t.Fatal(err)
	}
	if readRef != "release/feed#1" {
		t.Errorf("read ref=%q", readRef)
	}
	if err := p.putJSONFile("output/test.json", map[string]bool{"ok": true}, "", "test"); err != nil {
		t.Fatal(err)
	}
	if contents["branch"] != "release/feed#1" {
		t.Errorf("contents branch=%v", contents["branch"])
	}
	a, _ := contents["author"].(map[string]any)
	if a["name"] != "Feed Writer" || a["email"] != "writer@example.org" {
		t.Errorf("contents author=%v", a)
	}
	tx, err := p.beginGitPublication("test")
	if err != nil {
		t.Fatal(err)
	}
	tx.staged["output/test.json"] = stagedGitFile{sha: "blob"}
	if err := p.commitGitPublicationAttempt(tx); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(refPath, "/release/feed#1") || !strings.HasSuffix(patchPath, "/release/feed#1") {
		t.Errorf("wrong refs: %q, %q", refPath, patchPath)
	}
	if author.Name != "Feed Writer" || author.Email != "writer@example.org" {
		t.Errorf("author=%+v", author)
	}
}

func TestSTIXUsesConfiguredSiteWithoutChangingIDs(t *testing.T) {
	brief := BundleBrief{ID: "portable-brief", Slug: "portable-brief", Title: "Portable brief", PublishedAt: "2026-10-01T00:00:00Z", Lastmod: "2026-10-01T00:00:00Z"}
	first, err := ExportSTIX([]BundleBrief{brief}, "https://one.example/site")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExportSTIX([]BundleBrief{brief}, "https://two.example/feed/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(second), "https://two.example/feed/briefs/portable-brief/") {
		t.Fatal("STIX omitted configured canonical URL")
	}
	var a, b struct {
		Objects []struct{ Type, ID string } `json:"objects"`
	}
	if err = json.Unmarshal(first, &a); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(second, &b); err != nil {
		t.Fatal(err)
	}
	if len(a.Objects) != len(b.Objects) {
		t.Fatal("changed object count")
	}
	for i := range a.Objects {
		if a.Objects[i] != b.Objects[i] {
			t.Fatal("site URL changed stable object identities")
		}
	}
}
