package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

type pipelinePrefetchFake struct {
	cancel   context.CancelFunc
	batches  [][]llm.Request
	answers  map[llm.Request]string
	live     int
	released int
}

func (f *pipelinePrefetchFake) Prefetch(ctx context.Context, reqs []llm.Request) {
	if ctx.Err() != nil {
		return
	}
	f.batches = append(f.batches, append([]llm.Request(nil), reqs...))
	if f.cancel != nil {
		f.cancel()
	}
	for _, r := range reqs {
		if strings.Contains(r.Prompt, "missing-answer") {
			continue
		}
		text := `{"credibility":5,"actionability":5,"novelty":5}`
		if strings.Contains(r.Prompt, "rejected") {
			text = `{"credibility":5,"actionability":1,"novelty":5}`
		}
		if strings.Contains(r.Prompt, "weighted") {
			text = `{"credibility":4,"actionability":4,"novelty":4}`
		}
		if r.System == extractionSystemPrompt {
			text = `{"summary":"extracted"}`
		}
		f.answers[r] = text
	}
}
func (f *pipelinePrefetchFake) Cached(r llm.Request, out any) bool {
	text, ok := f.answers[r]
	// Model lookup is by wire request; schema and attribution metadata are not prompt data.
	if !ok {
		for key, value := range f.answers {
			if key.Prompt == r.Prompt && key.System == r.System && key.JSON == r.JSON {
				text, ok = value, true
				break
			}
		}
	}
	return ok && json.Unmarshal([]byte(text), out) == nil
}
func (f *pipelinePrefetchFake) Release() { f.released++; clear(f.answers) }
func (f *pipelinePrefetchFake) Generate(context.Context, string, string) (string, error) {
	f.live++
	return "", fmt.Errorf("unexpected live call")
}
func (f *pipelinePrefetchFake) GenerateJSON(_ context.Context, prompt, system string, out any) error {
	if f.Cached(llm.Request{Prompt: prompt, System: system, JSON: true}, out) {
		return nil
	}
	f.live++
	return fmt.Errorf("unexpected live call")
}
func batchTestPipeline(t *testing.T) (*Pipeline, *pipelinePrefetchFake) {
	t.Helper()
	db := mustOpenTestDB(t)
	t.Cleanup(func() { db.Close() })
	f := &pipelinePrefetchFake{answers: map[llm.Request]string{}}
	p := New(Config{DB: db, LLMClient: f, QualityThreshold: 3.5, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), SourceConfidence: map[string]float64{"weighted": 0}})
	return p, f
}
func batchItem(id string) scraper.RawItem {
	return scraper.RawItem{SourceID: id, Title: id, Source: id, Content: strings.Repeat("Observed credential theft and persistence. ", 30)}
}

func TestPipelinePrefetchOnlyExtractsQualifiedItems(t *testing.T) {
	p, f := batchTestPipeline(t)
	p.db.MarkSeen("seen", "seen", "seen")
	corroborationOnly := batchItem("corroboration-only")
	corroborationOnly.CorroborationOnly = true
	items := []scraper.RawItem{batchItem("qualified"), batchItem("rejected"), batchItem("weighted"), batchItem("missing-answer"), batchItem("seen"), {SourceID: "thin", Content: "short"}, batchItem("cisa-kev"), batchItem("sigma"), corroborationOnly}
	items[7].SigmaRule = &scraper.SigmaRule{ID: "sigma"}
	p.prefetchItems(context.Background(), items)
	if f.live != 0 {
		t.Fatalf("prefetch made %d live calls", f.live)
	}
	if len(f.batches) != 2 {
		t.Fatalf("got %d batches, want quality then extraction", len(f.batches))
	}
	if len(f.batches[0]) != 5 || len(f.batches[1]) != 2 {
		t.Fatalf("batch sizes = %d, %d", len(f.batches[0]), len(f.batches[1]))
	}
	for _, r := range f.batches[1] {
		if !strings.Contains(r.Prompt, "Title: qualified\n") && !strings.Contains(r.Prompt, "Title: cisa-kev\n") {
			t.Fatalf("unqualified extraction: %s", r.Prompt)
		}
	}
	for _, batch := range f.batches {
		for _, r := range batch {
			if strings.Contains(r.Prompt, "Title: corroboration-only\n") {
				t.Fatalf("unmatched corroboration-only item was prefetched: %s", r.Prompt)
			}
		}
	}
	for _, item := range items[:4] {
		seen, err := p.db.HasSeen(item.SourceID)
		if err != nil || seen {
			t.Fatalf("prefetch consumed %s: %v %v", item.SourceID, seen, err)
		}
	}
	var result ExtractionResult
	if err := p.extractor.client.GenerateJSON(context.Background(), extractionRequest(items[0]).Prompt, extractionSystemPrompt, &result); err != nil || result.Summary != "extracted" {
		t.Fatalf("cache not reused: %+v %v", result, err)
	}
}
func TestPipelineProcessUsesBatchCacheAndReleasesIt(t *testing.T) {
	p, f := batchTestPipeline(t)
	if err := p.Process(context.Background(), []scraper.RawItem{batchItem("rejected")}); err != nil {
		t.Fatal(err)
	}
	seen, err := p.db.HasSeen("rejected")
	if err != nil || !seen {
		t.Fatalf("rejected item not processed: %v %v", seen, err)
	}
	if f.live != 0 || f.released != 1 || len(f.answers) != 0 {
		t.Fatalf("live=%d releases=%d answers=%d", f.live, f.released, len(f.answers))
	}
}
func TestPipelinePrefetchRespectsCancellation(t *testing.T) {
	p, f := batchTestPipeline(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.prefetchItems(ctx, []scraper.RawItem{batchItem("qualified")})
	if len(f.batches) != 0 {
		t.Fatal("submitted batch after cancellation")
	}
}

func TestPipelineProcessBoundsBatchChunks(t *testing.T) {
	p, f := batchTestPipeline(t)
	items := make([]scraper.RawItem, prefetchChunkSize+1)
	for i := range items {
		items[i] = batchItem(fmt.Sprintf("rejected-%d", i))
	}
	if err := p.Process(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 2 || len(f.batches[0]) != prefetchChunkSize || len(f.batches[1]) != 1 || f.released != 2 || f.live != 0 {
		t.Fatalf("batches=%v releases=%d live=%d", len(f.batches), f.released, f.live)
	}
}

func TestPipelinePrefetchDoesNotBoostDraftScore(t *testing.T) {
	p, _ := batchTestPipeline(t)
	draft := &storage.Draft{ID: "existing", Score: 3, Status: storage.StatusPending, BriefYAML: `id: existing
cves: [CVE-2026-12345]
summary: WidgetOS vulnerability notice.
affected_products: [WidgetOS]
content: |
  The advisory identifies CVE-2026-12345 in WidgetOS and describes its affected installations.
  ## Recommendation
  Inventory WidgetOS deployments and apply the vendor advisory's remediation.
`, CreatedAt: time.Now()}
	if err := p.db.CreateDraft(draft); err != nil {
		t.Fatal(err)
	}
	if err := p.db.IndexContent(&storage.ContentIndexEntry{CVEID: "CVE-2026-12345", DraftID: draft.ID, Source: "nvd", SourceID: "prior", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	item := batchItem("corroborating")
	item.Title = "CVE-2026-12345 advisory"
	item.Source = "ghsa"
	p.prefetchItems(context.Background(), []scraper.RawItem{item})
	got, err := p.db.GetDraft(draft.ID)
	if err != nil || got.Score != 3 {
		t.Fatalf("prefetch changed draft: %+v %v", got, err)
	}
	if err := p.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	got, err = p.db.GetDraft(draft.ID)
	if err != nil || got.Score != 3.5 {
		t.Fatalf("want exactly one boost: %+v %v", got, err)
	}
}

type batchFlushFake struct{ flushed int }

func (p *batchFlushFake) Publish(string) error { return nil }
func (p *batchFlushFake) Flush() error         { p.flushed++; return nil }
func TestPipelineBatchCancellationFlushesPublications(t *testing.T) {
	p, f := batchTestPipeline(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	pub := &batchFlushFake{}
	p.publisher = pub
	p.autoPublish = true
	if err := p.Process(ctx, []scraper.RawItem{batchItem("rejected")}); err != context.Canceled {
		t.Fatalf("error=%v", err)
	}
	if pub.flushed != 1 || f.released != 1 {
		t.Fatalf("flushes=%d released=%d", pub.flushed, f.released)
	}
}

type batchRoundTrip func(*http.Request) (*http.Response, error)

func (f batchRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestPipelineBatchEnrichmentDoesNotRetainArticlesInInput(t *testing.T) {
	p, _ := batchTestPipeline(t)
	p.enricher.client = &http.Client{Transport: batchRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<p>" + strings.Repeat("text ", 500) + "</p>")), Header: http.Header{}}, nil
	})}
	items := []scraper.RawItem{{SourceID: "rejected", Title: "rejected", Source: "nvd", URL: "https://example.com/article", Content: strings.Repeat("summary ", 20)}}
	original := items[0].Content
	if err := p.Process(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	if items[0].Enriched || items[0].Content != original {
		t.Fatal("enriched article retained by caller's input slice")
	}
}

// Invalid model scoring must not pass the quality gate or enter the durable LLM cache.
func TestQualityScoreRejectsInvalidLLMValues(t *testing.T) {
	for _, score := range []*QualityScore{{Credibility: 6, Actionability: 5, Novelty: 5}, {Credibility: 5, Actionability: 0, Novelty: 5}, {Credibility: 5, Actionability: 5, Novelty: 1e100}} {
		if err := score.ValidateLLMResponse(); err == nil {
			t.Fatalf("accepted invalid quality score: %+v", score)
		}
	}
	if err := (&QualityScore{Credibility: 5, Actionability: 3, Novelty: 1}).ValidateLLMResponse(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractionRejectsInvalidCachedIdentifiers(t *testing.T) {
	for _, ex := range []*ExtractionResult{{CVEs: []string{"CVE-not-an-id"}}, {Techniques: []string{"TA0001"}}, {IOCs: []ExtractedIOC{{Type: "campaign", Value: "name"}}}} {
		if err := ex.ValidateLLMResponse(); err == nil {
			t.Fatalf("accepted invalid extraction: %+v", ex)
		}
	}
	if err := (&ExtractionResult{CVEs: []string{"CVE-2026-12345"}, Techniques: []string{"T1059.003"}, IOCs: []ExtractedIOC{{Type: "domain", Value: "malicious.example"}}}).ValidateLLMResponse(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractionRejectsEmptyModelErrorObject(t *testing.T) {
	var ex ExtractionResult
	if err := json.Unmarshal([]byte(`{"error":"unsupported request"}`), &ex); err != nil {
		t.Fatal(err)
	}
	if err := ex.ValidateLLMResponse(); err == nil {
		t.Fatal("unknown error object would be cached as empty successful extraction")
	}
	if err := (&ExtractionResult{Summary: "This item contains no concrete threat indicators."}).ValidateLLMResponse(); err != nil {
		t.Fatal(err)
	}
}
