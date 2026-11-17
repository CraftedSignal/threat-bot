package pipeline

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

const refreshRetryArticle = "Confirmed advisory evidence for the saved candidate."

type refreshRetryFixture struct {
	db       *storage.DB
	path     string
	item     scraper.RawItem
	logs     bytes.Buffer
	fetches  int
	fetchErr error
}

func newRefreshRetryFixture(t *testing.T, merge bool) *refreshRetryFixture {
	t.Helper()
	f := &refreshRetryFixture{path: filepath.Join(t.TempDir(), "refresh.db"), fetchErr: errors.New("upstream unavailable")}
	var err error
	f.db, err = storage.Open(f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	// A public numeric address avoids DNS even in the URL safety preflight;
	// the HTTP transport below supplies every response without network access.
	f.item = scraper.RawItem{SourceID: "nvd:refresh-outage", Source: "nvd", Title: "Vendor advisory", URL: "https://93.184.216.34/advisory", Content: "Original source summary.", NeedsFullArticle: true}
	p := f.pipeline()
	saved := f.item
	saved.Revision = saved.ContentRevision()
	saved.Content += "\n\n---\n\n" + refreshRetryArticle
	saved.Enriched, saved.NeedsFullArticle = true, false
	state := processingCandidate{Item: saved, BriefYAML: validWindowsPathBriefYAML, ReviewHold: true, Issues: []string{"saved editorial review"}}
	if merge {
		state.MergeDraftID = "existing-draft"
		state.MergeAttempts = 2
	}
	if err := p.saveCandidate(p.processingInputKey(f.item), state, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := f.db.RecordGroundingAttempt(f.item.SourceID); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *refreshRetryFixture) pipeline() *Pipeline {
	p := New(Config{DB: f.db, Logger: slog.New(slog.NewJSONHandler(&f.logs, nil))})
	p.enricher.client = &http.Client{Transport: enrichRoundTrip(func(*http.Request) (*http.Response, error) {
		f.fetches++
		if f.fetchErr != nil {
			return nil, f.fetchErr
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader("<html><body>" + refreshRetryArticle + "</body></html>"))}, nil
	})}
	return p
}

func (f *refreshRetryFixture) checkpoint(t *testing.T) *storage.ProcessingCheckpoint {
	t.Helper()
	cp, err := f.db.GetProcessingCheckpoint(f.item.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("saved candidate lost: cp=%v err=%v", cp, err)
	}
	return cp
}

func TestSourceRefreshOutageBacksOffDurably(t *testing.T) {
	for _, merge := range []bool{false, true} {
		name := "standalone"
		if merge {
			name = "merge"
		}
		t.Run(name, func(t *testing.T) {
			f := newRefreshRetryFixture(t, merge)
			before := f.checkpoint(t)
			p := f.pipeline()
			if err := p.Process(context.Background(), []scraper.RawItem{f.item}); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(f.logs.String(), `"msg":"pipeline error"`) || p.Decisions(time.Hour).Failed != 0 {
				t.Fatalf("retained refresh outage paged as a failed pipeline: %s", f.logs.String())
			}
			for _, field := range []string{`"msg":"source evidence refresh deferred"`, `"level":"WARN"`, `"source":"nvd"`, `"error_class":"source_unavailable"`, `"retry_at":`} {
				if !strings.Contains(f.logs.String(), field) {
					t.Fatalf("missing refresh diagnostic %s: %s", field, f.logs.String())
				}
			}
			if err := f.db.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			f.db, err = storage.Open(f.path)
			if err != nil {
				t.Fatal(err)
			}
			p = f.pipeline()
			available, terminal, _ := p.batchItemReady(context.Background(), f.item)
			if !available || !terminal {
				t.Fatal("readiness did not defer a backed-off source without fetching")
			}
			for range 3 {
				if err := p.Process(context.Background(), []scraper.RawItem{f.item}); err != nil {
					t.Fatal(err)
				}
			}
			if f.fetches != 1 {
				t.Fatalf("outage fetched %d times before retry deadline, want 1", f.fetches)
			}
			after := f.checkpoint(t)
			if after.InputKey != before.InputKey || !after.RetryAt.Equal(before.RetryAt) {
				t.Fatal("source-fetch outage changed grounding retry identity or deadline")
			}
			var state processingCandidate
			if err := yaml.Unmarshal([]byte(after.Payload), &state); err != nil {
				t.Fatal(err)
			}
			if !state.ReviewHold || state.BriefYAML != validWindowsPathBriefYAML || state.Item.Content != f.item.Content+"\n\n---\n\n"+refreshRetryArticle {
				t.Fatal("source-fetch outage changed saved work or editorial disposition")
			}
			if merge && (state.MergeDraftID != "existing-draft" || state.MergeAttempts != 2) {
				t.Fatal("source-fetch outage reset merge candidate or budget")
			}
			if attempts, err := f.db.RecordGroundingAttempt(f.item.SourceID); err != nil || attempts != 3 {
				t.Fatalf("grounding budget changed: attempts=%d err=%v", attempts, err)
			}
			if seen, err := f.db.HasSeen(f.item.SourceID); err != nil || seen {
				t.Fatalf("unavailable source consumed: seen=%v err=%v", seen, err)
			}
		})
	}
}

func TestChangedSourceInputBypassesRefreshBackoff(t *testing.T) {
	f := newRefreshRetryFixture(t, false)
	p := f.pipeline()
	_ = p.processItem(context.Background(), f.item)
	changed := f.item
	changed.Content += " Corrected vendor scope."
	_ = p.processItem(context.Background(), changed)
	_ = f.pipeline().processItem(context.Background(), changed)
	for range 3 {
		_ = f.pipeline().processItem(context.Background(), f.item)
		_ = f.pipeline().processItem(context.Background(), changed)
	}
	if f.fetches != 2 {
		t.Fatalf("changed input must probe once then defer: fetches=%d want 2", f.fetches)
	}
}

func TestSourceRefreshRecoversAfterDurableDeadline(t *testing.T) {
	f := newRefreshRetryFixture(t, false)
	p := f.pipeline()
	_ = p.processItem(context.Background(), f.item)
	cp := f.checkpoint(t)
	var saved struct {
		RefreshRetries map[string]time.Time
	}
	if err := yaml.Unmarshal([]byte(cp.Payload), &saved); err != nil {
		t.Fatal(err)
	}
	key := p.processingInputKey(f.item)
	retryAt := saved.RefreshRetries[key]
	if retryAt.Before(time.Now().Add(14*time.Minute)) || retryAt.After(time.Now().Add(16*time.Minute)) {
		t.Fatalf("refresh retry not persisted with configured delay: %v", retryAt)
	}
	var payload map[string]any
	if err := yaml.Unmarshal([]byte(cp.Payload), &payload); err != nil {
		t.Fatal(err)
	}
	payload["refreshretries"] = map[string]time.Time{key: time.Now().Add(-time.Second)}
	b, err := yaml.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	cp.Payload = string(b)
	if err := f.db.PutProcessingCheckpoint(*cp); err != nil {
		t.Fatal(err)
	}
	f.fetchErr = nil
	if err := f.pipeline().processItem(context.Background(), f.item); err != nil {
		t.Fatalf("source did not recover after backoff: %v", err)
	}
	if f.fetches != 2 {
		t.Fatalf("recovery fetches=%d want 2", f.fetches)
	}
	saved.RefreshRetries = nil
	if err := yaml.Unmarshal([]byte(f.checkpoint(t).Payload), &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.RefreshRetries[key].IsZero() {
		t.Fatal("successful refresh retained its outage deadline")
	}
}

func TestSourceRefreshCheckpointFailureRemainsOperational(t *testing.T) {
	f := newRefreshRetryFixture(t, false)
	control, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if _, err := control.Exec(`CREATE TRIGGER fail_refresh_checkpoint BEFORE INSERT ON processing_checkpoints BEGIN SELECT RAISE(ABORT, 'refresh retry persistence unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	p := f.pipeline()
	if err := p.Process(context.Background(), []scraper.RawItem{f.item}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.logs.String(), "refresh retry persistence unavailable") || !strings.Contains(f.logs.String(), `"msg":"pipeline error"`) || p.Decisions(time.Hour).Failed != 1 {
		t.Fatalf("checkpoint persistence failure was hidden: %s", f.logs.String())
	}
}
