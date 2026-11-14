package publisher

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestPublicationMetadataReadsRetryBadGateway(t *testing.T) {
	for _, kind := range []string{"file SHA", "directory", "JSON file"} {
		t.Run(kind, func(t *testing.T) {
			withFastPutFileRetries(t)
			repo, p := newFakeFeedRepo(t)
			repo.files["output/briefs/2026-02.json"] = []byte(`{"briefs":[]}`)
			attempts := 0
			interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
				attempts++
				if attempts != 1 {
					return false
				}
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("<!DOCTYPE html><html>Unicorn upstream failure</html>"))
				return true
			})
			switch kind {
			case "file SHA":
				sha, err := p.getFileSHA("output/briefs/2026-02.json")
				if err != nil || sha == "" {
					t.Fatalf("sha=%q err=%v", sha, err)
				}
			case "directory":
				entries, err := p.readDir("output/briefs")
				if err != nil || len(entries) != 1 || entries[0].Name != "2026-02.json" {
					t.Fatalf("entries=%v err=%v", entries, err)
				}
			case "JSON file":
				raw, sha, err := p.fetchJSONFile("output/briefs/2026-02.json")
				if err != nil || sha == "" || !bytes.Equal(raw, []byte(`{"briefs":[]}`)) {
					t.Fatalf("raw=%q sha=%q err=%v", raw, sha, err)
				}
			}
			if attempts != 2 {
				t.Fatalf("attempts=%d", attempts)
			}
		})
	}
}

func TestPublicationMetadataReadBoundsFailuresAndNormalizesHTML(t *testing.T) {
	withFastPutFileRetries(t)
	repo, p := newFakeFeedRepo(t)
	attempts := 0
	interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
		attempts++
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<!DOCTYPE html><html>" + strings.Repeat("upstream page ", 1000) + "</html>"))
		return true
	})
	_, _, err := p.fetchJSONFile("output/manifest.json")
	if err == nil || attempts != 3 {
		t.Fatalf("err=%v attempts=%d", err, attempts)
	}
	if !strings.Contains(err.Error(), "HTTP 502") || strings.Contains(err.Error(), "<") || len(err.Error()) > 200 {
		t.Fatalf("unbounded/non-normalized upstream error: %s", err)
	}
}

func TestPublicationMetadataReadDoesNotRetryPermanentStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			repo, p := newFakeFeedRepo(t)
			attempts := 0
			interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
				attempts++
				w.WriteHeader(status)
				w.Write([]byte(`{"message":"request rejected"}`))
				return true
			})
			raw, sha, err := p.fetchJSONFile("output/manifest.json")
			if status == http.StatusNotFound {
				if err != nil || raw != nil || sha != "" {
					t.Fatalf("404 semantics changed: %q %q %v", raw, sha, err)
				}
			} else if err == nil {
				t.Fatal("permanent error was hidden")
			}
			if attempts != 1 {
				t.Fatalf("status%d retried%d times", status, attempts)
			}
		})
	}
}

func TestSegmentReadFailureKeepsPublicationQueued(t *testing.T) {
	withFastPutFileRetries(t)
	db := outboxTestDB(t)
	repo, p := newFakeFeedRepo(t)
	p.outbox, p.UseSegmented = db, true
	repo.putSegment(t, "2026-02", BundleBrief{ID: "existing", Slug: "existing", Title: "Existing", PublishedAt: "2026-02-19T10:00:00Z"})
	repo.putJSON(t, manifestPath, &SegmentManifest{Version: "v1", Segments: []SegmentEntry{{Path: segmentPath("2026-02"), BriefCount: 1}}})
	if err := p.PublishDraft(outboxBriefYAML("brief-a", "A"), "draft-a", ""); err != nil {
		t.Fatal(err)
	}
	completed, attempts := 0, 0
	WithDraftPublished(func(DraftPublication) error { completed++; return nil })(p)
	interceptPublicationAPI(t, repo, p, func(w http.ResponseWriter, req *http.Request) bool {
		if !strings.HasSuffix(req.URL.Path, "/contents/output/briefs/2026-02.json") {
			return false
		}
		attempts++
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<!DOCTYPE html><html>Unicorn</html>"))
		return true
	})
	if err := p.Flush(); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("flush err=%v", err)
	}
	if attempts != 3 || len(p.pending) != 1 || len(outboxIDs(t, db)) != 1 || completed != 0 || repo.refUpdates != 0 {
		t.Fatalf("attempts=%d pending=%d callbacks=%d refs=%d", attempts, len(p.pending), completed, repo.refUpdates)
	}
}
