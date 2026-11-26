package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// paidWorkLLM fails the test on any model call.
type paidWorkLLM struct {
	t     *testing.T
	calls *int
}

func (m paidWorkLLM) Generate(context.Context, string, string) (string, error) {
	*m.calls++
	m.t.Errorf("source revision paid for model generation")
	return "", errors.New("unexpected model call")
}

func (m paidWorkLLM) GenerateJSON(_ context.Context, _, system string, _ any) error {
	*m.calls++
	m.t.Errorf("source revision paid for a model stage: %.60s", system)
	return errors.New("unexpected model call")
}

func (m paidWorkLLM) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	return m.GenerateJSON(ctx, prompt, system, out)
}

// Batch-capable, so prefetch planning runs for real; it never has answers.
type paidWorkPrefetcher struct{ paidWorkLLM }

func (paidWorkPrefetcher) Prefetch(context.Context, []llm.Request) {}
func (paidWorkPrefetcher) Cached(llm.Request, any) bool            { return false }

const revisionSourceID = "nvd:CVE-2026-4242"

// briefedRevisionFixture indexes revision "old" of an NVD record as the source
// of an approved canonical brief, exactly as indexContent records it.
func briefedRevisionFixture(t *testing.T) (*storage.DB, scraper.RawItem, *int, *int, *Pipeline) {
	t.Helper()
	db := mustOpenTestDB(t)
	t.Cleanup(func() { db.Close() })
	original := scraper.RawItem{
		SourceID: revisionSourceID, Source: "nvd", Revision: "old",
		Title:    "CVE-2026-4242 — WidgetServer permits attachment deletion through an administrator rename operation.",
		URL:      "https://nvd.nist.gov/vuln/detail/CVE-2026-4242",
		Content:  "WidgetServer permits attachment deletion through an administrator rename operation.\nCVSS v3.1 Base Score: 8.1",
		Metadata: map[string]string{"cve": "CVE-2026-4242", "cvss": "8.1", "vuln_status": "Awaiting Analysis"},
	}
	if err := db.CreateDraft(&storage.Draft{ID: "canonical", Status: storage.StatusApproved, Source: "nvd", SourceIDs: `["` + revisionSourceID + `"]`, BriefYAML: recoveryBase + recoveryNarrative, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{CVEID: "CVE-2026-4242", DraftID: "canonical", SourceID: revisionSourceID, Source: "nvd", ContentHash: NormalizeContentHash(original.Title, original.Content), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSeenRevision(revisionSourceID, "nvd", original.Title, "old"); err != nil {
		t.Fatal(err)
	}
	calls, fetches := 0, 0
	p := New(Config{DB: db, LLMClient: paidWorkPrefetcher{paidWorkLLM{t: t, calls: &calls}}, QualityThreshold: 1, RetryBackoff: -time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	p.enricher.client = &http.Client{Transport: enrichRoundTrip(func(*http.Request) (*http.Response, error) {
		fetches++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader("<html><body>Vendor advisory text.</body></html>"))}, nil
	})}
	revised := original
	revised.Revision = ""
	revised.UpdatedAt = time.Now()
	revised.Metadata = map[string]string{"cve": "CVE-2026-4242", "cvss": "8.1", "vuln_status": "Analyzed", "vendor_advisory_urls": `["https://93.184.216.34/advisory"]`}
	return db, revised, &calls, &fetches, p
}

// NVD revises records for status, reference and analysis metadata. A revision
// that keeps the title and text its brief was built from cannot change that
// brief, so it completes without fetching pages or paying for a rebuild.
func TestUnchangedSourceRevisionCompletesWithoutWork(t *testing.T) {
	db, revised, calls, fetches, p := briefedRevisionFixture(t)
	if err := p.processItem(context.Background(), revised); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 || *fetches != 0 {
		t.Fatalf("unchanged revision paid for work: model calls=%d fetches=%d", *calls, *fetches)
	}
	if seen, err := db.HasSeenRevision(revised.SourceID, revised.ContentRevision()); err != nil || !seen {
		t.Fatalf("unchanged revision left pending: seen=%v err=%v", seen, err)
	}
	if _, held, err := db.PipelineQuarantineReason(revised.SourceID); err != nil || held {
		t.Fatalf("unchanged revision created review noise: held=%v err=%v", held, err)
	}
}

// A changed revision of an already-briefed source can only end in an editorial
// hold: the canonical narrative is never replaced automatically. Hold it before
// paying for quality, extraction, assembly and grounding, and keep it free on
// re-delivery.
func TestChangedSourceRevisionIsHeldBeforeModelWork(t *testing.T) {
	db, revised, calls, fetches, p := briefedRevisionFixture(t)
	revised.Content = "WidgetServer permits attachment deletion by unauthenticated users.\nCVSS v3.1 Base Score: 9.8"
	if err := p.processItem(context.Background(), revised); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("held revision paid for %d model calls", *calls)
	}
	after, err := db.GetDraft("canonical")
	if err != nil || after.BriefYAML != recoveryBase+recoveryNarrative {
		t.Fatalf("source revision changed the canonical brief without review: %v", err)
	}
	if seen, err := db.HasSeenRevision(revised.SourceID, revised.ContentRevision()); err != nil || seen {
		t.Fatalf("held revision consumed: seen=%v err=%v", seen, err)
	}
	reason, held, err := db.PipelineQuarantineReason(revised.SourceID)
	if err != nil || !held || !strings.Contains(reason, "canonical") || !strings.Contains(reason, "source revision") {
		t.Fatalf("missing editorial hold: %q %v", reason, err)
	}
	cp, err := db.GetProcessingCheckpoint(revised.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("hold not durable: %v", err)
	}
	var state processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
		t.Fatal(err)
	}
	if !state.ReviewHold || state.RebuildDraftID != "canonical" || !strings.Contains(state.BriefYAML, "unauthenticated") {
		t.Fatalf("hold lacks the revised evidence or target: hold=%v target=%q", state.ReviewHold, state.RebuildDraftID)
	}
	before := *fetches
	for range 3 {
		if err := p.processItem(context.Background(), revised); err != nil {
			t.Fatal(err)
		}
	}
	if *calls != 0 || *fetches != before {
		t.Fatalf("held revision repeated work on re-delivery: model calls=%d fetches=%d->%d", *calls, before, *fetches)
	}
}

func TestSourceRevisionsNeedNoBatchWork(t *testing.T) {
	for _, changed := range []bool{false, true} {
		_, revised, calls, fetches, p := briefedRevisionFixture(t)
		if changed {
			revised.Content = "WidgetServer permits attachment deletion by unauthenticated users."
		}
		revised.Revision = revised.ContentRevision()
		ready, terminal, extraction := p.batchItemReady(context.Background(), revised)
		if !ready || !terminal || extraction != nil {
			t.Fatalf("changed=%v: revision waits for batch model results: ready=%v terminal=%v", changed, ready, terminal)
		}
		plan := p.planPrefetch(context.Background(), []scraper.RawItem{revised})
		if len(plan.qualityRequests) != 0 || len(plan.extractionRequests) != 0 || len(plan.candidates) != 0 {
			t.Fatalf("changed=%v: prefetch planned paid batch work for a source revision", changed)
		}
		if *calls != 0 || *fetches != 0 {
			t.Fatalf("changed=%v: readiness or planning did work: calls=%d fetches=%d", changed, *calls, *fetches)
		}
	}
}
