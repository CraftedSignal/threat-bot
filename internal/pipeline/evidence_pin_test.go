package pipeline

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// pinnedHoldFixture saves a held candidate whose evidence came from a complete
// refresh, then serves a different page on every later fetch, like rotating
// page chrome or changing social reply counts.
func pinnedHoldFixture(t *testing.T, complete bool) *refreshRetryFixture {
	t.Helper()
	f := newRefreshRetryFixture(t, false)
	f.fetchErr = nil
	cp := f.checkpoint(t)
	var state processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
		t.Fatal(err)
	}
	state.PinnedInput = ""
	if complete {
		state.PinnedInput = f.item.EvidenceRevision()
	}
	if err := f.pipeline().saveCandidate(cp.InputKey, state, cp.RetryAt); err != nil {
		t.Fatal(err)
	}
	return f
}

func rotatingArticle(f *refreshRetryFixture) *Pipeline {
	p := f.pipeline()
	p.enricher.client = &http.Client{Transport: enrichRoundTrip(func(*http.Request) (*http.Response, error) {
		f.fetches++
		body := "<html><body>" + refreshRetryArticle + " Trending now: item " + time.Now().Format(time.RFC3339Nano) + "</body></html>"
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	return p
}

func TestHeldCandidateReusesPinnedEvidenceForUnchangedInput(t *testing.T) {
	f := pinnedHoldFixture(t, true)
	before := f.checkpoint(t)
	for range 3 {
		if err := rotatingArticle(f).Process(context.Background(), []scraper.RawItem{f.item}); err != nil {
			t.Fatal(err)
		}
	}
	if f.fetches != 0 {
		t.Fatalf("unchanged input re-fetched third-party evidence %d times", f.fetches)
	}
	if strings.Contains(f.logs.String(), "rebuilding candidate") || strings.Contains(f.logs.String(), "source enrichment unavailable") {
		t.Fatalf("pinned evidence was replaced: %s", f.logs.String())
	}
	after := f.checkpoint(t)
	if after.Payload != before.Payload || after.InputKey != before.InputKey {
		t.Fatal("held candidate changed although its source input did not")
	}
	if attempts, err := f.db.RecordGroundingAttempt(f.item.SourceID); err != nil || attempts != 3 {
		t.Fatalf("grounding budget reset by unchanged input: attempts=%d err=%v", attempts, err)
	}
}

func TestChangedSourceRevisionStillRefreshesPinnedEvidence(t *testing.T) {
	f := pinnedHoldFixture(t, true)
	p := rotatingArticle(f)
	if _, ok := p.pinnedSourceEvidence(f.item); !ok {
		t.Fatal("unchanged input was not pinned")
	}
	// A feed that only bumps its modification time supplied no new evidence.
	touched := f.item
	touched.UpdatedAt = time.Now()
	if _, ok := p.pinnedSourceEvidence(touched); !ok {
		t.Fatal("a modification-time-only revision discarded pinned evidence")
	}
	changed := f.item
	changed.Content = "Original source summary, corrected by the vendor."
	if _, ok := p.pinnedSourceEvidence(changed); ok {
		t.Fatal("a new source revision reused evidence pinned to the old revision")
	}
	refreshed, err := p.refreshSourceEvidence(context.Background(), changed)
	if err != nil || f.fetches != 1 || !strings.Contains(refreshed.Content, "corrected by the vendor") {
		t.Fatalf("changed input not refreshed: fetches=%d err=%v content=%q", f.fetches, err, refreshed.Content)
	}
}

// Checkpoints written before pinning carry no completeness record. They keep
// the previous refresh behavior once, then pin after a matching refresh.
func TestLegacyCheckpointPinsAfterAMatchingRefresh(t *testing.T) {
	f := pinnedHoldFixture(t, false)
	p := f.pipeline()
	for range 3 {
		if err := p.Process(context.Background(), []scraper.RawItem{f.item}); err != nil {
			t.Fatal(err)
		}
	}
	if f.fetches != 1 {
		t.Fatalf("legacy candidate fetched %d times, want one confirming refresh", f.fetches)
	}
	var state processingCandidate
	if err := yaml.Unmarshal([]byte(f.checkpoint(t).Payload), &state); err != nil {
		t.Fatal(err)
	}
	if state.PinnedInput != f.item.EvidenceRevision() || !state.ReviewHold {
		t.Fatalf("confirmed evidence not pinned: pinned=%q hold=%v", state.PinnedInput, state.ReviewHold)
	}
}

func TestIncompleteEvidenceIsRetriedNotPinned(t *testing.T) {
	f := pinnedHoldFixture(t, false)
	f.fetchErr = context.DeadlineExceeded
	if err := f.pipeline().Process(context.Background(), []scraper.RawItem{f.item}); err != nil {
		t.Fatal(err)
	}
	if f.fetches != 1 || !strings.Contains(f.logs.String(), "source evidence refresh deferred") {
		t.Fatalf("incomplete evidence was pinned: fetches=%d logs=%s", f.fetches, f.logs.String())
	}
}

func criticalQualityFixture(t *testing.T) (*storage.DB, *qualityMockLLM, *Pipeline, scraper.RawItem) {
	t.Helper()
	db := mustOpenTestDB(t)
	t.Cleanup(func() { db.Close() })
	model := &qualityMockLLM{score: QualityScore{Credibility: 4, Actionability: 1, Novelty: 3}}
	pipe := New(Config{DB: db, LLMClient: model, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{
		SourceID: "oss-security:php-notice", Source: "oss-security",
		Title: "Upcoming Critical PHP Security Release", URL: "https://seclists.org/oss-sec/2026/q4/266",
		Content:     strings.Repeat("The vendor reports two critical vulnerabilities and an upcoming security release. ", 10),
		PublishedAt: time.Now(),
		Enriched:    true,
	}
	return db, model, pipe, item
}

// A retained critical disclosure waits for a durable deadline. Re-delivery
// from the intake queue must not re-score identical evidence every cycle.
func TestCriticalQualityRetentionWaitsForItsRetryDeadline(t *testing.T) {
	db, model, pipe, item := criticalQualityFixture(t)
	for range 5 {
		if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
			t.Fatal(err)
		}
	}
	if model.calls != 1 {
		t.Fatalf("quality model called %d times before the retry deadline, want 1", model.calls)
	}
	if seen, err := db.HasSeen(item.SourceID); err != nil || seen {
		t.Fatalf("critical disclosure consumed: seen=%v err=%v", seen, err)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("retention deadline not durable: cp=%v err=%v", cp, err)
	}
	if delay := time.Until(cp.RetryAt); delay < 10*time.Minute || delay > 20*time.Minute {
		t.Fatalf("first retention delay=%s, want the configured retry backoff", delay)
	}

	cp.RetryAt = time.Now().Add(-time.Second)
	if err := db.PutProcessingCheckpoint(*cp); err != nil {
		t.Fatal(err)
	}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if model.calls != 2 {
		t.Fatalf("expired retention deadline did not re-score once: calls=%d", model.calls)
	}
	next, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || next == nil {
		t.Fatalf("second retention not durable: cp=%v err=%v", next, err)
	}
	if delay := time.Until(next.RetryAt); delay < 25*time.Minute {
		t.Fatalf("second retention delay=%s did not back off", delay)
	}
}

func TestCriticalQualityRetentionEndsAfterItsWindow(t *testing.T) {
	db, model, pipe, item := criticalQualityFixture(t)
	item.PublishedAt = time.Now().Add(-73 * time.Hour)
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if seen, err := db.HasSeen(item.SourceID); err != nil || !seen || model.calls != 1 {
		t.Fatalf("expired critical window still retained: seen=%v calls=%d err=%v", seen, model.calls, err)
	}
}

// YAML decodes nil maps and slices as empty ones. Social and Sigma items carry
// such fields; their pinned evidence must still be recognised exactly.
func TestPinnedEvidenceSurvivesCheckpointEncodingOfOptionalCollections(t *testing.T) {
	for name, item := range map[string]scraper.RawItem{
		"social": {SourceID: "public-web-social-search:1", Source: "public-web-social-search", Title: "Post", URL: "https://93.184.216.34/post", Content: "Claim text.",
			Discovery: &scraper.DiscoveryContext{Platform: "x", OriginalURL: "https://93.184.216.34/post", ContextComplete: true}},
		"sigma": {SourceID: "sigma-hq:rule", Source: "sigma-hq", Title: "Rule", URL: "https://93.184.216.34/rule", Content: "title: Rule",
			SigmaRule: &scraper.SigmaRule{Title: "Rule"}},
		"metadata": {SourceID: "nvd:CVE-2026-0001", Source: "nvd", Title: "CVE", URL: "https://93.184.216.34/cve", Content: "Description.",
			Metadata: map[string]string{"cve": "CVE-2026-0001", "vendor_advisory_urls": `["https://93.184.216.34/a"]`}},
	} {
		t.Run(name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			p := New(Config{DB: db, Logger: quietLogger()})
			item.Revision = item.ContentRevision()
			enriched := item
			enriched.Content += "\n\n---\n\nFetched evidence."
			enriched.Enriched = true
			state := processingCandidate{Item: enriched, BriefYAML: validWindowsPathBriefYAML, ReviewHold: true, PinnedInput: item.EvidenceRevision()}
			if err := p.saveCandidate(p.processingInputKey(item), state, time.Time{}); err != nil {
				t.Fatal(err)
			}
			pinned, ok := p.pinnedSourceEvidence(item)
			if !ok {
				t.Fatal("checkpoint encoding defeated evidence pinning")
			}
			if p.processingKey(pinned) != p.processingKey(enriched) {
				t.Fatal("pinned evidence differs from the evidence the candidate was built from")
			}
		})
	}
}
