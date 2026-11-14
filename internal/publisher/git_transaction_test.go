package publisher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAtomicPublicationHidesStagedWritesUntilRefAdvance(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.files["output/existing.json"] = []byte(`{"old":true}`)

	err := p.withAtomicPublication("test: atomic release", func() error {
		if err := p.putJSONFile("output/new.json", map[string]bool{"new": true}, "", "ignored inner message"); err != nil {
			return err
		}
		if _, visible := repo.files["output/new.json"]; visible {
			t.Fatal("staged file became branch-visible before ref advance")
		}
		raw, _, err := p.fetchJSONFile("output/new.json")
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, []byte(`{"new":true}`)) {
			t.Fatalf("staged read = %q", raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repo.files["output/new.json"], []byte(`{"new":true}`)) {
		t.Fatalf("committed file = %q", repo.files["output/new.json"])
	}
	if repo.refUpdates != 1 {
		t.Fatalf("ref updates = %d, want 1", repo.refUpdates)
	}
}

func TestAtomicPublicationRejectsConcurrentRefAdvance(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.files["output/existing.json"] = []byte(`{"old":true}`)
	repo.racePut["output/existing.json"] = []byte(`{"concurrent":true}`)

	err := p.withAtomicPublication("test: conflicting release", func() error {
		return p.putJSONFile("output/existing.json", map[string]bool{"old": false}, "", "ignored")
	})
	if err == nil {
		t.Fatal("expected non-fast-forward ref update to fail")
	}
	if !bytes.Equal(repo.files["output/existing.json"], []byte(`{"concurrent":true}`)) {
		t.Fatalf("conflicting release changed branch bytes: %q", repo.files["output/existing.json"])
	}
	if repo.refUpdates != 0 {
		t.Fatalf("conflicting release advanced the branch %d time(s)", repo.refUpdates)
	}
}

func TestAtomicPublicationRebasesUnrelatedConcurrentCommit(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusUnprocessableEntity} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			repo, p := newFakeFeedRepo(t)
			repo.files["go.mod"] = []byte("old source")
			patches := 0
			interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
				if req.Method != http.MethodPatch {
					return false
				}
				patches++
				if patches != 1 {
					return false
				}
				repo.mu.Lock()
				repo.files["go.mod"] = []byte("concurrent source")
				repo.head = "concurrent-source-commit"
				repo.mu.Unlock()
				w.WriteHeader(status)
				w.Write([]byte(`{"message":"Update is not a fast forward"}`))
				return true
			})
			callbacks, renders := 0, 0
			err := p.withAtomicPublication("test: complete batch", func() error {
				renders++
				p.afterPublicationCommit(func() {
					callbacks++
					if string(repo.files["output/manifest.json"]) != `{"brief":"new"}` || string(repo.files["output/brief.json"]) != `{"id":"new"}` {
						t.Error("callback ran before the complete batch became visible")
					}
				})
				if err := p.putJSONFile("output/brief.json", map[string]string{"id": "new"}, "", "ignored"); err != nil {
					return err
				}
				return p.putJSONFile("output/manifest.json", map[string]string{"brief": "new"}, "", "ignored")
			})
			if err != nil {
				t.Fatal(err)
			}
			if string(repo.files["go.mod"]) != "concurrent source" || string(repo.files["output/brief.json"]) != `{"id":"new"}` || string(repo.files["output/manifest.json"]) != `{"brief":"new"}` {
				t.Fatalf("publication lost concurrent source or batch contents: %q", repo.files)
			}
			if repo.commitParents[repo.head] != "concurrent-source-commit" {
				t.Fatalf("publication parent = %q", repo.commitParents[repo.head])
			}
			if callbacks != 1 || renders != 1 || patches != 2 || repo.refUpdates != 1 {
				t.Fatalf("callbacks=%d renders=%d patches=%d commits=%d", callbacks, renders, patches, repo.refUpdates)
			}
			if got := countPublicationRequests(repo, "PUT output/brief.json"); got != 1 {
				t.Fatalf("uploaded brief blob %d times", got)
			}
		})
	}
}

func TestAtomicPublicationBoundsRefConflictsWithoutCallbacks(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	patches, callbacks := 0, 0
	interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
		if req.Method != http.MethodPatch {
			return false
		}
		patches++
		repo.mu.Lock()
		repo.files["README.md"] = []byte(fmt.Sprint(patches))
		repo.head = fmt.Sprintf("concurrent-%d", patches)
		repo.mu.Unlock()
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message":"Update is not a fast forward"}`))
		return true
	})
	err := p.withAtomicPublication("test: bounded conflict", func() error {
		p.afterPublicationCommit(func() { callbacks++ })
		return p.putJSONFile("output/new.json", map[string]bool{"new": true}, "", "ignored")
	})
	if err == nil {
		t.Fatal("expected exhausted publication conflict")
	}
	if patches != 3 || callbacks != 0 || repo.refUpdates != 0 {
		t.Fatalf("patches=%d callbacks=%d commits=%d", patches, callbacks, repo.refUpdates)
	}
	if _, ok := repo.files["output/new.json"]; ok {
		t.Fatal("exhausted publication became visible")
	}
	if string(repo.files["README.md"]) != "3" {
		t.Fatal("concurrent changes were lost")
	}
}

func TestAtomicPublicationPreservesConcurrentCreateAndDeleteEdits(t *testing.T) {
	for _, deleting := range []bool{false, true} {
		t.Run(fmt.Sprint("delete=", deleting), func(t *testing.T) {
			repo, p := newFakeFeedRepo(t)
			const path = "output/brief.json"
			if deleting {
				repo.files[path] = []byte("old brief")
			}
			repo.racePut[path] = []byte("concurrent brief")
			callbacks := 0
			err := p.withAtomicPublication("test: changed path", func() error {
				p.afterPublicationCommit(func() { callbacks++ })
				if deleting {
					return p.stageGitDelete(path)
				}
				_, err := p.stageGitFile(path, []byte("staged brief"))
				return err
			})
			if err == nil || callbacks != 0 || repo.refUpdates != 0 {
				t.Fatalf("err=%v callbacks=%d commits=%d", err, callbacks, repo.refUpdates)
			}
			if string(repo.files[path]) != "concurrent brief" {
				t.Fatal("lost concurrently created/edited brief")
			}
		})
	}
}

func TestAtomicPublicationRejectsTruncatedConflictCheck(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.racePut["README.md"] = []byte("concurrent source")
	interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
		if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/git/trees/") {
			json.NewEncoder(w).Encode(map[string]any{"sha": "ignored", "tree": []any{}, "truncated": true})
			return true
		}
		return false
	})
	err := p.withAtomicPublication("test: truncated check", func() error {
		return p.putJSONFile("output/new.json", map[string]bool{"new": true}, "", "ignored")
	})
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("err=%v, want truncated comparison failure", err)
	}
	if repo.refUpdates != 0 {
		t.Fatal("published without complete path comparison")
	}
}

func TestAtomicPublicationRejectsChangedRootRead(t *testing.T) {
	for _, dir := range []string{"", ".", "/"} {
		t.Run(fmt.Sprintf("root=%q", dir), func(t *testing.T) {
			repo, p := newFakeFeedRepo(t)
			repo.racePut["README.md"] = []byte("concurrent source")
			err := p.withAtomicPublication("test: root dependency", func() error {
				if _, err := p.readDir(dir); err != nil {
					return err
				}
				return p.putJSONFile("output/new.json", map[string]bool{"new": true}, "", "ignored")
			})
			if err == nil {
				t.Fatal("published after root listing changed")
			}
			if repo.refUpdates != 0 {
				t.Fatal("changed root read was ignored")
			}
		})
	}
}

func TestAtomicPublicationRejectsIncompleteTreeComparison(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.racePut["README.md"] = []byte("concurrent source")
	interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
		const prefix = "/repos/CraftedSignal/threat-feed/git/trees/"
		if req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, prefix) {
			json.NewEncoder(w).Encode(map[string]string{"sha": strings.TrimPrefix(req.URL.Path, prefix)})
			return true
		}
		return false
	})
	err := p.withAtomicPublication("test: incomplete metadata", func() error {
		return p.putJSONFile("output/new.json", map[string]bool{"new": true}, "", "ignored")
	})
	if err == nil {
		t.Fatal("publication trusted incomplete comparison metadata")
	}
	if repo.refUpdates != 0 {
		t.Fatal("publication advanced without a complete path comparison")
	}
}

func TestAtomicPublicationDoesNotRetryOtherRefFailures(t *testing.T) {
	for _, tc := range []struct {
		status  int
		message string
	}{
		{http.StatusUnauthorized, "Bad credentials"},
		{http.StatusForbidden, "Resource not accessible by integration"},
		{http.StatusUnprocessableEntity, "Validation Failed"},
		{http.StatusConflict, "Git Repository is empty."},
	} {
		t.Run(fmt.Sprint(tc.status)+tc.message, func(t *testing.T) {
			repo, p := newFakeFeedRepo(t)
			patches, callbacks := 0, 0
			interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
				if req.Method != http.MethodPatch {
					return false
				}
				patches++
				w.WriteHeader(tc.status)
				json.NewEncoder(w).Encode(map[string]string{"message": tc.message})
				return true
			})
			err := p.withAtomicPublication("test: permanent failure", func() error {
				p.afterPublicationCommit(func() { callbacks++ })
				return p.putJSONFile("output/new.json", map[string]bool{"new": true}, "", "ignored")
			})
			if err == nil || patches != 1 || callbacks != 0 || countPublicationRequests(repo, "GET git/ref/heads/main") != 1 {
				t.Fatalf("err=%v patches=%d callbacks=%d requests=%v", err, patches, callbacks, repo.requests)
			}
		})
	}
}

func TestFlushConflictPreservesQueuedBriefAndConcurrentManifest(t *testing.T) {
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox, p.UseSegmented = db, true
	concurrent := []byte(`{"version":"concurrent"}`)
	repo.racePut[manifestPath] = concurrent
	if err := p.Publish(outboxBriefYAML("queued-brief", "Queued")); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err == nil {
		t.Fatal("expected touched manifest conflict")
	}
	if string(repo.files[manifestPath]) != string(concurrent) {
		t.Fatal("concurrent manifest was overwritten")
	}
	if len(p.pending) != 1 || len(outboxIDs(t, db)) != 1 {
		t.Fatal("conflicting publication lost its pending/outbox brief")
	}
	if published, pushed := p.NewestPublicBrief(); !published.IsZero() || !pushed.IsZero() {
		t.Fatal("failed publication updated success cache")
	}
	if repo.refUpdates != 0 {
		t.Fatal("conflicting batch was partially published")
	}
}

func interceptPublicationAPI(t *testing.T, repo *fakeFeedRepo, p *Publisher, intercept func(http.ResponseWriter, *http.Request) bool) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if intercept(w, req) {
			return
		}
		repo.serve(w, req)
	}))
	t.Cleanup(srv.Close)
	p.apiURL = srv.URL
}

func countPublicationRequests(repo *fakeFeedRepo, want string) int {
	n := 0
	for _, req := range repo.requests {
		if strings.TrimSpace(req) == want {
			n++
		}
	}
	return n
}

func TestAtomicPublicationReadsUnstagedFilesFromPinnedBase(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	repo.files["output/existing.json"] = []byte(`{"version":1}`)
	var fetched []byte

	err := p.withAtomicPublication("test: pinned read", func() error {
		repo.mu.Lock()
		repo.files["output/existing.json"] = []byte(`{"version":2}`)
		repo.head = "concurrent-commit"
		repo.mu.Unlock()

		var err error
		fetched, _, err = p.fetchJSONFile("output/existing.json")
		if err != nil {
			return err
		}
		return p.putJSONFile("output/new.json", map[string]bool{"new": true}, "", "ignored")
	})
	if err == nil {
		t.Fatal("expected pinned-base release to reject the concurrent branch advance")
	}
	if !bytes.Equal(fetched, []byte(`{"version":1}`)) {
		t.Fatalf("pinned read = %q, want base version", fetched)
	}
}

func TestAtomicPublicationRejectsDeleteOverStagedWrite(t *testing.T) {
	repo, p := newFakeFeedRepo(t)
	path := "site/content/briefs/live.md"
	repo.files[path] = []byte("old live page")

	err := p.withAtomicPublication("test: conflicting staged operations", func() error {
		if _, err := p.stageGitFile(path, []byte("new live page")); err != nil {
			return err
		}
		return p.stageGitDelete(path)
	})
	if err == nil {
		t.Fatal("expected delete to reject overwriting a staged write")
	}
	if !bytes.Equal(repo.files[path], []byte("old live page")) {
		t.Fatalf("conflicting staged operations changed branch bytes: %q", repo.files[path])
	}
	if repo.refUpdates != 0 {
		t.Fatalf("conflicting staged operations advanced the branch %d time(s)", repo.refUpdates)
	}
}
