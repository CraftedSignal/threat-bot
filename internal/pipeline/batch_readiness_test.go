package pipeline

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// The provider is blocked by a channel, not a timing guess. All model answers
// are fixtures; only the normal independent grounding path may run live.
type readinessClient struct {
	shutdownStageLLM
	cache           pipelinePrefetchFake
	started         chan struct{}
	release         chan struct{}
	onWait          func()
	onBatch         func(context.Context, []llm.Request)
	onRelease       func()
	onConsume       func(llm.Request)
	pendingStage    string
	pendingRequests []llm.Request
	responses       map[string]string
}

func (f *readinessClient) Cached(r llm.Request, out any) bool { return f.cache.Cached(r, out) }
func (f *readinessClient) Release() {
	if f.onRelease != nil {
		f.onRelease()
	}
	f.cache.Release()
}
func (f *readinessClient) Prefetch(ctx context.Context, requests []llm.Request) {
	if f.onBatch != nil {
		f.onBatch(ctx, requests)
	}
	if f.onWait != nil {
		f.onWait()
	}
	if f.started != nil {
		close(f.started)
		f.started = nil
	}
	if f.release != nil {
		select {
		case <-ctx.Done():
			return
		case <-f.release:
		}
	}
	f.cache.Prefetch(ctx, requests)
	f.cache.mu.Lock()
	defer f.cache.mu.Unlock()
	for _, r := range requests {
		if text := f.responses[r.Metadata.SourceID+":"+r.Metadata.Stage]; text != "" {
			f.cache.answers[r] = text
		}
		if r.Metadata.Stage == f.pendingStage {
			delete(f.cache.answers, r)
			f.pendingRequests = append(f.pendingRequests, r)
		}
	}
}

func TestPrefetchSubmitsAndAdvancesWhileReadyGroundingIsBlocked(t *testing.T) {
	p, f, checks := newReadinessPipeline(t)
	pending, ready := batchItem("pending"), readySigma("ready")
	qualityStarted, extractionStarted := make(chan struct{}), make(chan struct{})
	allowQuality, allowGrounding := make(chan struct{}), make(chan struct{})
	groundingStarted := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.onBatch = func(ctx context.Context, requests []llm.Request) {
		if requests[0].Metadata.Stage == "quality" {
			close(qualityStarted)
			select {
			case <-allowQuality:
			case <-ctx.Done():
			}
		} else {
			close(extractionStarted)
		}
	}
	oldJSON := f.generateJSON
	f.generateJSON = func(ctx context.Context, prompt, system string, out any) error {
		if system == groundingSystem && llm.CallMetadataFromContext(ctx).SourceID == ready.SourceID {
			select {
			case <-qualityStarted:
			case <-ctx.Done():
				return ctx.Err()
			}
			close(groundingStarted)
			close(allowQuality)
			select {
			case <-allowGrounding:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return oldJSON(ctx, prompt, system, out)
	}
	done := make(chan error, 1)
	go func() { done <- p.Process(ctx, []scraper.RawItem{pending, ready}) }()
	select {
	case <-extractionStarted:
		// First grounding is still blocked: child must advance the dependent wave.
		select {
		case <-groundingStarted:
		default:
			t.Error("extraction did not overlap ready grounding")
		}
		close(allowGrounding)
	case <-ctx.Done():
		t.Error("dependent extraction stalled behind ready grounding")
	}
	if err := <-done; err != nil {
		t.Fatalf("process=%v", err)
	}
	if f.cache.live != 0 || len(f.cache.batches) != 2 {
		t.Fatalf("duplicate or missing inference: live=%d batches=%d", f.cache.live, len(f.cache.batches))
	}
	for _, item := range []scraper.RawItem{pending, ready} {
		if seen, _ := p.db.HasSeen(item.SourceID); !seen {
			t.Errorf("late result not consumed: %s", item.SourceID)
		}
	}
	if err := p.Process(context.Background(), []scraper.RawItem{pending, ready}); err != nil {
		t.Fatal(err)
	}
	if len(f.cache.batches) != 2 || *checks != 2 {
		t.Fatalf("late answers consumed more than once: batches=%d checks=%d", len(f.cache.batches), *checks)
	}
}

func TestPrefetchWorkerUsesImmutableEligibilitySnapshot(t *testing.T) {
	p, f, _ := newReadinessPipeline(t)
	p.sourceConfidence = map[string]float64{"weighted": 1}
	p.quality.threshold = 3.5
	started, release := make(chan struct{}), make(chan struct{})
	f.onBatch = func(ctx context.Context, requests []llm.Request) {
		if requests[0].Metadata.Stage == "quality" {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}
	plan := p.planPrefetch(context.Background(), []scraper.RawItem{batchItem("weighted")})
	done := make(chan struct{})
	go func() { defer close(done); plan.run(context.Background()) }()
	<-started
	// Parent state may change while provider orchestration continues. Only
	// scalar snapshot values may determine its second wave.
	p.sourceConfidence["weighted"] = 0
	p.quality.threshold = 5
	close(release)
	<-done
	if len(f.cache.batches) != 2 || f.cache.batches[1][0].Metadata.Stage != "extraction" {
		t.Fatalf("worker read mutable eligibility: %+v", f.cache.batches)
	}
}

func TestCancellationJoinsPrefetchBeforeReleasingAnswers(t *testing.T) {
	p, f, _ := newReadinessPipeline(t)
	entered, cancelObserved, allowExit := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var active atomic.Bool
	f.onBatch = func(ctx context.Context, _ []llm.Request) {
		active.Store(true)
		close(entered)
		<-ctx.Done()
		close(cancelObserved)
		<-allowExit
		active.Store(false)
	}
	f.onRelease = func() {
		if active.Load() {
			t.Error("prefetch answers released before child joined")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.generateJSON = func(ctx context.Context, _, _ string, _ any) error { <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { done <- p.Process(ctx, []scraper.RawItem{batchItem("pending"), readySigma("ready")}) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("prefetch never started")
	}
	cancel()
	<-cancelObserved
	select {
	case err := <-done:
		close(allowExit)
		t.Errorf("Process returned before child completed: %v", err)
		return
	default:
	}
	close(allowExit)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	if active.Load() || f.cache.released != 1 {
		t.Fatalf("worker leaked/released twice: active=%v releases=%d", active.Load(), f.cache.released)
	}
}

func (f *readinessClient) GenerateStructured(ctx context.Context, prompt, system string, schema *llm.Schema, out any) error {
	if system == groundingClaimsSystem {
		return llm.DecodeStructured(`{"issues":[]}`, out)
	}
	return f.shutdownStageLLM.GenerateStructured(ctx, prompt, system, schema, out)
}
func (f *readinessClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	if system == qualitySystemPrompt || system == extractionSystemPrompt {
		req := llm.Request{Prompt: prompt, System: system, JSON: true}
		if f.onConsume != nil {
			f.onConsume(req)
		}
		f.cache.mu.Lock()
		for _, pending := range f.pendingRequests {
			if pending.Prompt == prompt && pending.System == system {
				f.cache.mu.Unlock()
				return &llm.PendingBatchError{}
			}
		}
		f.cache.mu.Unlock()
		return f.cache.GenerateJSON(ctx, prompt, system, out)
	}
	return f.shutdownStageLLM.GenerateJSON(ctx, prompt, system, out)
}

func newReadinessPipeline(t *testing.T) (*Pipeline, *readinessClient, *int) {
	t.Helper()
	db, err := storage.Open(t.TempDir() + "/readiness.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	checks := new(int)
	f := &readinessClient{cache: pipelinePrefetchFake{answers: map[llm.Request]string{}}}
	f.shutdownStageLLM = shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			return strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1), nil
		},
		generateJSON: func(_ context.Context, _, system string, out any) error {
			if system == groundingSystem {
				*checks++
				out.(*GroundingResult).Grounded = true
				return nil
			}
			return errors.New("unexpected live factual call")
		},
	}
	p := New(Config{DB: db, LLMClient: f, QualityThreshold: 1, Logger: quietLogger()})
	return p, f, checks
}

func readySigma(id string) scraper.RawItem {
	item := batchItem(id)
	item.Source = "cisa-kev"
	item.SigmaRule = &scraper.SigmaRule{Title: "Rule"}
	return item
}

func TestReadyCandidateCompletesBeforePendingProviderWait(t *testing.T) {
	p, f, checks := newReadinessPipeline(t)
	pub := &readinessPublisher{recoveryPublisher: recoveryPublisher{fail: true}, published: make(chan struct{})}
	p.publisher, p.autoPublish = pub, true
	pending, ready := batchItem("pending"), readySigma("ready")
	if _, err := p.db.RecordGroundingAttempt(pending.SourceID); err != nil {
		t.Fatal(err)
	}
	f.started, f.release = make(chan struct{}), make(chan struct{})
	started, release := f.started, f.release
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Process(ctx, []scraper.RawItem{pending, ready}) }()
	<-started
	<-pub.published
	// Prefetch cannot proceed, so publication progress must precede the wait.
	seen, err := p.db.HasSeen(ready.SourceID)
	if err != nil || !seen || *checks != 1 {
		t.Errorf("ready candidate blocked: seen=%v checks=%d err=%v", seen, *checks, err)
	}
	if intents, err := p.db.ListPublicationIntents(); err != nil || len(intents) != 1 || !intents[0].CompleteDraft {
		t.Errorf("ready grounded publication not retained: %+v %v", intents, err)
	}
	if counts := p.Decisions(time.Hour); counts.Processed != 1 || counts.Failed != 0 {
		t.Errorf("readiness miss started processing: %+v", counts)
	}
	if seen, _ := p.db.HasSeen(pending.SourceID); seen {
		t.Error("pending source consumed by readiness probe")
	}
	if cp, err := p.db.GetProcessingCheckpoint(pending.SourceID); err != nil || cp != nil {
		t.Errorf("probe changed pending candidate: %+v %v", cp, err)
	}
	if attempts, err := p.db.RecordGroundingAttempt(pending.SourceID); err != nil || attempts != 2 {
		t.Errorf("probe cleared or charged attempt budget: %d %v", attempts, err)
	}
	if reason, quarantined, err := p.db.PipelineQuarantineReason(pending.SourceID); err != nil || quarantined {
		t.Errorf("probe quarantined source: %q %v", reason, err)
	}
	queued, err := p.db.NextIngestionCandidates(10)
	if err != nil || len(queued) != 1 || queued[0].SourceID != pending.SourceID {
		t.Errorf("pending payload not durably retained: %+v %v", queued, err)
	}
	cancel()
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

type readinessPublisher struct {
	recoveryPublisher
	flushes                int
	skipFlushSignals       int
	published, flushed     chan struct{}
	publishOnce, flushOnce sync.Once
}

func (p *readinessPublisher) PublishDraft(s, id, key string) error {
	err := p.recoveryPublisher.PublishDraft(s, id, key)
	if p.published != nil {
		p.publishOnce.Do(func() { close(p.published) })
	}
	return err
}
func (p *readinessPublisher) Flush() error {
	p.flushes++
	if p.flushed != nil && p.flushes > p.skipFlushSignals {
		p.flushOnce.Do(func() { close(p.flushed) })
	}
	return nil
}

func TestRecoveredOutboxFlushesBeforePendingProviderWait(t *testing.T) {
	p, f, _ := newReadinessPipeline(t)
	pub := &readinessPublisher{}
	p.publisher, p.autoPublish = pub, true
	if err := p.db.CreateDraftWithPublication(&storage.Draft{ID: "recovered", Source: "prior", Status: storage.StatusPending, BriefYAML: "retained publication", CreatedAt: time.Now()}, ""); err != nil {
		t.Fatal(err)
	}
	f.onWait = func() {
		if pub.drafts != 1 || pub.flushes == 0 {
			t.Errorf("validated outbox blocked: drafts=%d flushes=%d", pub.drafts, pub.flushes)
		}
	}
	if err := p.Process(context.Background(), []scraper.RawItem{batchItem("rejected")}); err != nil {
		t.Fatal(err)
	}
}

func TestKnownBatchConflictsPreserveSourcePrecedence(t *testing.T) {
	p, _, _ := newReadinessPipeline(t)
	first, second := batchItem("first"), readySigma("second")
	first.Title, second.Title = "CVE-2026-4242 vendor notice", "CVE-2026-4242 later coverage"
	ctx := context.WithValue(context.Background(), sourceRefreshMemoKey{}, sourceRefreshMemo{})
	ready, waiting := p.readyBatchItems(ctx, []scraper.RawItem{first, second})
	if len(ready) != 0 || len(waiting) != 2 || waiting[0].SourceID != first.SourceID {
		t.Fatalf("known conflict reordered: ready=%+v waiting=%+v", ready, waiting)
	}
}

func TestBatchIntakeIsIdempotentAndDoesNotAdvanceWatermarks(t *testing.T) {
	p, _, _ := newReadinessPipeline(t)
	item := batchItem("retained")
	watermark := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if err := p.db.SaveScraperState(item.Source, watermark, "prior"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := p.retainBatchItems([]scraper.RawItem{item}); err != nil {
			t.Fatal(err)
		}
	}
	queued, err := p.db.NextIngestionCandidates(10)
	if err != nil || len(queued) != 1 {
		t.Fatalf("duplicate intake: %+v %v", queued, err)
	}
	got := decodeRetainedItem(t, queued[0].Payload)
	if got.Content != item.Content || got.Revision != item.ContentRevision() || got.Enriched {
		t.Fatalf("intake retained transient evidence: %+v", got)
	}
	state, err := p.db.GetScraperState(item.Source)
	if err != nil || state.Cursor != "prior" || !state.LastPoll.Equal(watermark) {
		t.Fatalf("intake advanced watermark: %+v %v", state, err)
	}
}

func TestUnknownPendingIdentityMergesIntoReadyCanonicalAfterRecovery(t *testing.T) {
	p, f, checks := newReadinessPipeline(t)
	pending, ready := batchItem("pending-related"), readySigma("ready-related")
	pending.Source, pending.Title, pending.URL = "vendor-blog", "New Windows attack telemetry", "https://vendor.example/attack"
	pending.Content += " CVE-2026-4242 uses malicious domain command.attacker.example. A public proof-of-concept exploit is now available for this vulnerability."
	ready.Title, ready.URL = "CVE-2026-4242 Windows process evidence", "https://vendor.example/detection"
	ready.Content += " CVE-2026-4242 has Windows process creation telemetry."
	brief := strings.Replace(actionablePathBrief, "content: Review Windows", "content: For CVE-2026-4242, review Windows", 1)
	brief = strings.Replace(brief, "title: Windows Path Detection", "title: CVE-2026-4242 Windows Path Detection", 1)
	brief = "affected_vendors: [Microsoft]\naffected_products: [Windows]\n" + strings.Replace(brief, "content: For CVE-2026-4242, review Windows process creation telemetry for the binary path described by the source.", "content: |\n  For CVE-2026-4242, review Windows process creation telemetry for the binary path described by the source.\n\n  ## Recommendation\n  Consult the vendor advisory and apply its remediation to affected Windows installations.", 1)
	p.cveVerifier.cache["CVE-2026-4242"] = &CVEMeta{Exists: true, CVSS: 7.5, CachedAt: time.Now(), Verification: CVEVerification{Status: "verified", Source: "fixture", CheckedAt: time.Now()}}
	assemblies := 0
	f.generate = func(ctx context.Context, _, _ string) (string, error) {
		if llm.CallMetadataFromContext(ctx).Stage == "assembly" {
			assemblies++
			return brief, nil
		}
		return "For CVE-2026-4242, review Windows process creation telemetry and command.attacker.example.", nil
	}
	previousJSON := f.generateJSON
	f.generateJSON = func(ctx context.Context, prompt, system string, out any) error {
		if system == mergeRelevanceSystemPrompt {
			return json.Unmarshal([]byte(`{"merge":true,"reference_relevant":true,"poc_relevant":false,"cves":["CVE-2026-4242"],"iocs":[{"type":"domain","value":"command.attacker.example"}]}`), out)
		}
		return previousJSON(ctx, prompt, system, out)
	}
	f.responses = map[string]string{pending.SourceID + ":extraction": `{"summary":"CVE-2026-4242 attack telemetry","cves":["CVE-2026-4242"],"iocs":[{"type":"domain","value":"command.attacker.example"}]}`}
	// First round loses its context while the paid provider is blocked.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pub := &readinessPublisher{flushed: make(chan struct{}), skipFlushSignals: 1}
	p.publisher, p.autoPublish = pub, true
	f.release = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- p.Process(ctx, []scraper.RawItem{pending, ready}) }()
	select {
	case <-pub.flushed:
	case <-ctx.Done():
		t.Fatal("unknown pending identity blocked ready candidate")
	}
	readyAssemblies := assemblies
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("first round=%v", err)
	}
	queued, err := p.db.NextIngestionCandidates(10)
	if err != nil || len(queued) != 1 {
		t.Fatalf("pending payload lost: %+v %v", queued, err)
	}
	retained := decodeRetainedItem(t, queued[0].Payload)
	// New Pipeline, no upstream item: consume only durable intake and the eventual result.
	f.release = nil
	restarted := New(Config{DB: p.db, LLMClient: f, QualityThreshold: 1, Logger: quietLogger()})
	restarted.cveVerifier, restarted.cveEnricher = p.cveVerifier, p.cveEnricher
	if err := restarted.Process(context.Background(), []scraper.RawItem{retained}); err != nil {
		t.Fatal(err)
	}
	if got := countCompletionDrafts(t, p.db); got != 1 || readyAssemblies == 0 || assemblies != readyAssemblies {
		t.Fatalf("duplicate canonical: drafts=%d assemblies=%d ready=%d", got, assemblies, readyAssemblies)
	}
	entries, err := p.db.FindByCVE("CVE-2026-4242")
	if err != nil || len(entries) == 0 {
		t.Fatalf("missing canonical identity: %+v %v", entries, err)
	}
	draft, err := p.db.GetDraft(entries[0].DraftID)
	if err != nil || !strings.Contains(draft.BriefYAML, "command.attacker.example") || !strings.Contains(draft.BriefYAML, ready.URL) || !strings.Contains(draft.BriefYAML, pending.URL) {
		t.Fatalf("merge lost material fact/source: %+v %v", draft, err)
	}
	if *checks < 1 {
		t.Fatalf("ready candidate did not independently ground: %d", *checks)
	}
	if seen, _ := p.db.HasSeenRevision(retained.SourceID, retained.ContentRevision()); !seen {
		t.Fatal("eventual result not consumed")
	}
	if err := restarted.Process(context.Background(), []scraper.RawItem{retained}); err != nil {
		t.Fatal(err)
	}
	if assemblies != readyAssemblies {
		t.Fatal("consumed result assembled twice")
	}
}

func TestReadyCheckpointStillGroundsBeforeProviderWait(t *testing.T) {
	p, f, checks := newReadinessPipeline(t)
	item := readySigma("checkpoint-ready")
	state := processingCandidate{Item: item, BriefYAML: actionablePathBrief, Score: 5, Confidence: 1}
	if err := p.saveCandidate(p.processingInputKey(item), state, time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.generate = func(context.Context, string, string) (string, error) {
		t.Error("ready checkpoint repeated assembly")
		return "", errors.New("unexpected assembly")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pub := &readinessPublisher{flushed: make(chan struct{}), skipFlushSignals: 1}
	p.publisher, p.autoPublish = pub, true
	f.release = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- p.Process(ctx, []scraper.RawItem{batchItem("pending"), item}) }()
	select {
	case <-pub.flushed:
	case <-ctx.Done():
		t.Fatal("checkpoint blocked behind provider")
	}
	if seen, _ := p.db.HasSeen(item.SourceID); !seen || *checks != 1 {
		t.Errorf("saved candidate bypassed/delayed grounding: seen=%v checks=%d", seen, *checks)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReadinessAndPrefetchReuseBoundedArticleRefresh(t *testing.T) {
	p, _, _ := newReadinessPipeline(t)
	requests := 0
	p.enricher.client = &http.Client{Transport: batchRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<p>" + strings.Repeat("Concrete process creation evidence. ", 30) + "</p>")), Header: http.Header{}}, nil
	})}
	pending, ready := batchItem("rejected"), readySigma("ready")
	pending.Content, pending.URL = "Thin source summary", "https://example.com/pending"
	ready.Content, ready.URL = "Thin rule summary", "https://example.com/ready"
	if err := p.Process(context.Background(), []scraper.RawItem{pending, ready}); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("readiness/prefetch/consumption repeated article HTTP: %d", requests)
	}
	// A new chunk/context must fetch source evidence again; no cross-round memo.
	if _, err := p.refreshSourceEvidence(context.Background(), ready); err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Fatalf("source refresh escaped its chunk: %d", requests)
	}
}

type readinessStatusProvider func(context.Context, string) (scraper.SocialStatus, error)

func (f readinessStatusProvider) FetchStatus(ctx context.Context, id string) (scraper.SocialStatus, error) {
	return f(ctx, id)
}

func TestPendingSocialRefreshReusesExactBatchPrompts(t *testing.T) {
	for _, pendingStage := range []string{"", "quality", "extraction"} {
		t.Run("pending-"+pendingStage, func(t *testing.T) {
			p, f, _ := newReadinessPipeline(t)
			f.pendingStage = pendingStage
			const social = "Stable independent social evidence names concrete process telemetry."
			calls, articles := 0, 0
			p.socialProvider = readinessStatusProvider(func(_ context.Context, id string) (scraper.SocialStatus, error) {
				calls++
				return scraper.SocialStatus{ID: id, URL: "https://x.com/i/status/123", Author: "researcher", Text: social}, nil
			})
			p.enricher.client = &http.Client{Transport: batchRoundTrip(func(*http.Request) (*http.Response, error) {
				articles++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<p>" + strings.Repeat("Article evidence with concrete Windows process telemetry. ", 20) + "</p>")), Header: http.Header{}}, nil
			})}
			item := batchItem("social-pending")
			item.URL = "https://x.com/i/status/123"
			item.NeedsFullArticle = true
			item.Discovery = &scraper.DiscoveryContext{Platform: "x", OriginalURL: item.URL, DiscoveryURL: item.URL}
			var consumed []llm.Request
			f.onConsume = func(r llm.Request) { consumed = append(consumed, r) }
			if err := p.Process(context.Background(), []scraper.RawItem{item}); err != nil {
				t.Fatal(err)
			}
			if calls != 2 || articles != 1 {
				t.Errorf("source refresh counts social=%d article=%d", calls, articles)
			}
			if len(consumed) == 0 {
				t.Fatal("no consumption requests exercised")
			}
			for _, actual := range consumed {
				matches := false
				for _, batch := range f.cache.batches {
					for _, submitted := range batch {
						if actual.System == submitted.System && actual.Prompt == submitted.Prompt {
							matches = true
						}
					}
				}
				if !matches {
					t.Errorf("consumption prompt misses submitted batch for system=%q, social copies=%d", actual.System[:min(30, len(actual.System))], strings.Count(actual.Prompt, social))
				}
				if strings.Count(actual.Prompt, social) != 1 {
					t.Errorf("social evidence repeated in paid prompt: %d", strings.Count(actual.Prompt, social))
				}
			}
			if f.cache.live != 0 {
				t.Fatalf("unchanged social evidence bought %d duplicate online calls", f.cache.live)
			}
		})
	}
}

func TestChangedPendingSocialEvidenceStillRefreshes(t *testing.T) {
	p, _, _ := newReadinessPipeline(t)
	calls := 0
	p.socialProvider = readinessStatusProvider(func(_ context.Context, id string) (scraper.SocialStatus, error) {
		calls++
		text := "Earlier fetched social evidence."
		if calls > 1 {
			text = "Corrected current social evidence."
		}
		return scraper.SocialStatus{ID: id, Text: text}, nil
	})
	item := batchItem("social-correction")
	item.URL = "https://x.com/i/status/123"
	item.Revision = item.ContentRevision()
	chunk := []scraper.RawItem{item}
	memo := sourceRefreshMemo{}
	ctx := context.WithValue(context.Background(), sourceRefreshMemoKey{}, memo)
	p.planPrefetch(ctx, chunk)
	clear(memo)
	refreshed, err := p.refreshSourceEvidence(ctx, chunk[0])
	if err != nil || calls != 2 || !strings.Contains(refreshed.Content, "Corrected current social evidence.") || strings.Contains(refreshed.Content, "Earlier fetched social evidence.") {
		t.Fatalf("pending refresh retained obsolete social text: %q calls=%d err=%v", refreshed.Content, calls, err)
	}
}

func TestIngestionBackpressureStillDrainsRetainedReadyWork(t *testing.T) {
	for _, freshCount := range []int{1, prefetchChunkSize} {
		t.Run(fmt.Sprint(freshCount), func(t *testing.T) {
			_, f, _ := newReadinessPipeline(t)
			path := t.TempDir() + "/backpressure.db"
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			p := New(Config{DB: db, LLMClient: f, QualityThreshold: 1, Logger: quietLogger()})
			ready := readySigma("retained-ready")
			if err := p.retainBatchItems([]scraper.RawItem{ready}); err != nil {
				t.Fatal(err)
			}
			// Exercise the real durable byte-budget branch without allocating a
			// 128MiB fixture payload. This retained row accounts for the full cap.
			conn, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Exec("UPDATE ingestion_candidates SET payload_bytes=? WHERE source_id=?", storage.MaxIngestionQueueBytes, ready.SourceID); err != nil {
				t.Fatal(err)
			}
			watermark := time.Now().Add(-time.Hour).UTC()
			if err := db.SaveScraperState("incoming", watermark, "prior"); err != nil {
				t.Fatal(err)
			}
			var items []scraper.RawItem
			for i := 0; i < freshCount; i++ {
				item := batchItem(fmt.Sprintf("unadmitted-%d", i))
				item.Source = "incoming"
				items = append(items, item)
			}
			items = append(items, ready)
			if err := p.Process(context.Background(), items); err != nil {
				t.Errorf("backpressure aborted drainage: %v", err)
			}
			if seen, _ := db.HasSeen(ready.SourceID); !seen {
				t.Error("retained ready work did not drain")
			}
			for _, item := range items[:freshCount] {
				if seen, _ := db.HasSeen(item.SourceID); seen {
					t.Errorf("unretained source consumed: %s", item.SourceID)
				}
			}
			if f.cache.live != 0 || len(f.cache.batches) != 0 {
				t.Errorf("unadmitted work bought inference: live=%d batches=%d", f.cache.live, len(f.cache.batches))
			}
			state, err := db.GetScraperState("incoming")
			if err != nil || state.Cursor != "prior" || !state.LastPoll.Equal(watermark) {
				t.Errorf("backpressure advanced cursor: %+v %v", state, err)
			}
			if queued, err := db.NextIngestionCandidates(10); err != nil || len(queued) != 0 {
				t.Errorf("queue not drained: %+v %v", queued, err)
			}
		})
	}
}

func TestLowValueLookingCVEUpdateRemainsInBatchOrder(t *testing.T) {
	p, f, _ := newReadinessPipeline(t)
	const id = "CVE-2026-4242"
	brief := "cves: [CVE-2026-4242]\naffected_products: [Widget]\n" + strings.Replace(actionablePathBrief, "content: Review Windows process creation telemetry for the binary path described by the source.", "content: |\n  Widget permits file deletion through attachment renaming.\n\n  ## Recommendation\n  Consult the vendor advisory and apply remediation to affected installations.", 1)
	if err := p.db.CreateDraft(&storage.Draft{ID: "existing", Source: "nvd", Status: storage.StatusApproved, BriefYAML: brief, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := p.db.IndexContent(&storage.ContentIndexEntry{CVEID: id, DraftID: "existing", SourceID: "nvd:original", Source: "nvd", CVEContext: `{"has_exploit":false,"has_patch":false,"active_exploitation":false}`, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	first, update := batchItem("first-update"), batchItem("redos-update")
	first.Title = id + " public exploit"
	update.Title = id + " ReDoS public exploit"
	first.Content += " A public proof-of-concept exploit is available."
	update.Content += " A public proof-of-concept exploit is available."
	if decision, _, _ := p.dedup.checkPreExtraction(update, false); decision != DedupUpdate {
		t.Fatalf("fixture is not a meaningful existing-CVE update: %v", decision)
	}
	if isLowValueItem(update) == "" {
		t.Fatal("fixture does not cover the low-value wording")
	}
	ctx := context.WithValue(context.Background(), sourceRefreshMemoKey{}, sourceRefreshMemo{})
	ready, waiting := p.readyBatchItems(ctx, []scraper.RawItem{first, update})
	if len(ready) != 0 || len(waiting) != 2 || waiting[1].SourceID != update.SourceID {
		t.Fatalf("uncached update falsely terminal/reordered: ready=%+v waiting=%+v", ready, waiting)
	}
	p.planPrefetch(ctx, waiting).run(ctx)
	if len(f.cache.batches) != 2 || len(f.cache.batches[0]) != 2 || len(f.cache.batches[1]) != 2 {
		t.Fatalf("updates bypassed normal quality/extraction batches: %+v", f.cache.batches)
	}
	if _, _, err := p.quality.Evaluate(ctx, update); err != nil {
		t.Fatal(err)
	}
	if _, err := p.extractor.Extract(ctx, update); err != nil {
		t.Fatal(err)
	}
	if f.cache.live != 0 {
		t.Fatalf("update bought %d duplicate online calls", f.cache.live)
	}
}

type outboxOnlyPublisher struct {
	db       *storage.DB
	attempts int
	fail     bool
}

func (p *outboxOnlyPublisher) Publish(payload string) error {
	_, err := p.db.UpsertPublishOutbox("prior", storage.OutboxKindBrief, payload)
	return err
}
func (p *outboxOnlyPublisher) Flush() error {
	p.attempts++
	if p.fail {
		return errors.New("prior feed flush failed")
	}
	rows, err := p.db.ListPublishOutbox()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := p.db.DeletePublishOutboxIfSeq(row.ID, row.Seq); err != nil {
			return err
		}
	}
	return nil
}

func TestOutboxWithoutDatabaseIntentRetriesBeforeProviderWait(t *testing.T) {
	p, f, _ := newReadinessPipeline(t)
	pub := &outboxOnlyPublisher{db: p.db, fail: true}
	if err := pub.Publish("already validated durable publication"); err != nil {
		t.Fatal(err)
	}
	if err := pub.Flush(); err == nil {
		t.Fatal("fixture did not retain failed outbox flush")
	}
	pub.fail = false
	p.publisher, p.autoPublish = pub, true
	if intents, err := p.db.ListPublicationIntents(); err != nil || len(intents) != 0 {
		t.Fatalf("fixture has DB publication intents: %+v %v", intents, err)
	}
	f.onBatch = func(context.Context, []llm.Request) {
		if rows, err := p.db.ListPublishOutbox(); err != nil || len(rows) != 0 || pub.attempts < 2 {
			t.Errorf("existing publisher outbox blocked behind provider: rows=%+v attempts=%d err=%v", rows, pub.attempts, err)
		}
	}
	if err := p.Process(context.Background(), []scraper.RawItem{batchItem("rejected")}); err != nil {
		t.Fatal(err)
	}
}

// The fake advances logical provider time without sleeping. The metric is the
// provider dependency removed before first ready grounding, not a production
// wall-clock estimate or a claim about cheaper inference.
func BenchmarkReadyBatchProgress(b *testing.B) {
	for _, barrier := range []bool{true, false} {
		name := "ready-pass"
		if barrier {
			name = "whole-chunk-barrier"
		}
		b.Run(name, func(b *testing.B) {
			var totalWaits int
			for i := 0; i < b.N; i++ {
				db, err := storage.Open(b.TempDir() + "/progress.db")
				if err != nil {
					b.Fatal(err)
				}
				var completedWaits atomic.Int64
				beforeReady := int64(-1)
				groundingReached := make(chan struct{})
				f := &readinessClient{cache: pipelinePrefetchFake{answers: map[llm.Request]string{}}}
				f.onBatch = func(ctx context.Context, _ []llm.Request) {
					if !barrier {
						select {
						case <-groundingReached:
						case <-ctx.Done():
							return
						}
					}
					completedWaits.Add(1)
				}
				f.shutdownStageLLM = shutdownStageLLM{
					generate: func(context.Context, string, string) (string, error) { return actionablePathBrief, nil },
					generateJSON: func(_ context.Context, _, system string, out any) error {
						if system == groundingSystem {
							beforeReady = completedWaits.Load()
							close(groundingReached)
							out.(*GroundingResult).Grounded = true
							return nil
						}
						return errors.New("unexpected inference")
					},
				}
				p := New(Config{DB: db, LLMClient: f, QualityThreshold: 1, Logger: quietLogger()})
				items := []scraper.RawItem{batchItem("rejected"), readySigma("ready")}
				if barrier {
					p.prefetchItems(context.Background(), items)
					for _, item := range items {
						if err := p.processItem(context.Background(), item); err != nil {
							b.Fatal(err)
						}
					}
				} else if err := p.Process(context.Background(), items); err != nil {
					b.Fatal(err)
				}
				if beforeReady < 0 {
					b.Fatal("ready candidate did not ground")
				}
				totalWaits += int(beforeReady)
				db.Close()
			}
			b.ReportMetric(float64(totalWaits)/float64(b.N), "provider-waits/ready")
		})
	}
}

func TestCachedQualityRejectionProgressesBeforePendingWait(t *testing.T) {
	p, f, _ := newReadinessPipeline(t)
	pending, rejected := batchItem("pending"), batchItem("cached-rejected")
	f.cache.answers[qualityBatchRequest(rejected)] = `{"credibility":5,"actionability":1,"novelty":5}`
	pub := &readinessPublisher{flushed: make(chan struct{}), skipFlushSignals: 1}
	p.publisher, p.autoPublish = pub, true
	f.release = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Process(ctx, []scraper.RawItem{pending, rejected}) }()
	select {
	case <-pub.flushed:
	case <-ctx.Done():
		t.Fatal("cached rejection blocked behind provider")
	}
	if seen, _ := p.db.HasSeen(rejected.SourceID); !seen {
		t.Error("cached quality rejection not consumed")
	}
	if seen, _ := p.db.HasSeen(pending.SourceID); seen {
		t.Error("pending source consumed")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, batch := range f.cache.batches {
		for _, r := range batch {
			if r.Metadata.SourceID == rejected.SourceID {
				t.Errorf("already rejected source bought batch inference: %+v", r.Metadata)
			}
		}
	}
	if f.cache.live != 0 {
		t.Fatalf("unexpected inference=%d", f.cache.live)
	}
}

// Retained intake serializes the raw source revision, not refreshed evidence.
func decodeRetainedItem(t *testing.T, payload string) scraper.RawItem {
	t.Helper()
	var item scraper.RawItem
	if err := json.Unmarshal([]byte(payload), &item); err != nil {
		t.Fatal(err)
	}
	return item
}
