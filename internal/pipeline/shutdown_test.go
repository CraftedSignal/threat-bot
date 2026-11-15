package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

type shutdownTestLLM struct {
	generate     func(context.Context) (string, error)
	generateJSON func(context.Context) error
}

func (c shutdownTestLLM) Generate(ctx context.Context, _, _ string) (string, error) {
	return c.generate(ctx)
}

func (c shutdownTestLLM) GenerateJSON(ctx context.Context, _, _ string, _ any) error {
	return c.generateJSON(ctx)
}

type shutdownTestPublisher struct {
	flushes   int
	publishes int
}

func (p *shutdownTestPublisher) Publish(string) error {
	p.publishes++
	return nil
}
func (p *shutdownTestPublisher) Flush() error {
	p.flushes++
	return nil
}

type shutdownStageLLM struct {
	generate     func(context.Context, string, string) (string, error)
	generateJSON func(context.Context, string, string, any) error
}

func (c shutdownStageLLM) Generate(ctx context.Context, prompt, system string) (string, error) {
	return c.generate(ctx, prompt, system)
}

func (c shutdownStageLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	return c.generateJSON(ctx, prompt, system, out)
}

func shutdownPipelineItem(id, source string) scraper.RawItem {
	return scraper.RawItem{
		SourceID: id,
		Source:   source,
		Title:    "Credential theft campaign with persistence",
		Content:  strings.Repeat("Observed credential theft and persistence with concrete detection evidence. ", 20),
	}
}

func TestPipelineStopsWithoutErrorLogOrSeenMutationOnShutdown(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := shutdownTestLLM{
		generate: func(context.Context) (string, error) {
			return "", errors.New("unexpected text generation")
		},
		generateJSON: func(callCtx context.Context) error {
			cancel()
			return fmt.Errorf("provider request interrupted: %w", callCtx.Err())
		},
	}
	var logs bytes.Buffer
	pub := &shutdownTestPublisher{}
	pipe := New(Config{
		DB:               db,
		LLMClient:        client,
		QualityThreshold: 3.5,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
		Publisher:        pub,
		AutoPublish:      true,
	})
	item := shutdownPipelineItem("shutdown-quality", "test-feed")

	if err := pipe.Process(ctx, []scraper.RawItem{item}); !errors.Is(err, context.Canceled) {
		t.Fatalf("process error = %v, want context cancellation; logs=%s", err, logs.String())
	}
	if out := logs.String(); strings.Contains(out, `"level":"ERROR"`) {
		t.Fatalf("shutdown cancellation was logged as an error: %s", out)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Fatal("shutdown-canceled item was marked seen")
	}
	if failed := pipe.Decisions(time.Hour).Failed; failed != 0 {
		t.Fatalf("shutdown cancellation recorded %d pipeline failures", failed)
	}
	if pub.flushes != 1 {
		t.Fatalf("shutdown flushes = %d, want 1", pub.flushes)
	}
}

func TestPipelineDoesNotQuarantineBriefGenerationCanceledByShutdown(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	generateCalls := 0
	client := shutdownTestLLM{
		generate: func(callCtx context.Context) (string, error) {
			generateCalls++
			cancel()
			return "", fmt.Errorf("brief request interrupted: %w", callCtx.Err())
		},
		generateJSON: func(context.Context) error {
			return errors.New("unexpected JSON generation")
		},
	}
	var logs bytes.Buffer
	pub := &shutdownTestPublisher{}
	pipe := New(Config{
		DB:               db,
		LLMClient:        client,
		QualityThreshold: 3.5,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
		Publisher:        pub,
		AutoPublish:      true,
	})
	item := shutdownPipelineItem("shutdown-yaml-repair", "cisa-kev")
	item.SigmaRule = &scraper.SigmaRule{Title: "Credential theft detection", Detection: map[string]any{"condition": "selection"}}

	if err := pipe.Process(ctx, []scraper.RawItem{item}); !errors.Is(err, context.Canceled) {
		t.Fatalf("process error = %v, want context cancellation; logs=%s", err, logs.String())
	}
	if generateCalls != 1 {
		t.Fatalf("LLM calls = %d, want the interrupted brief call only", generateCalls)
	}
	out := logs.String()
	if strings.Contains(out, `"level":"ERROR"`) || strings.Contains(out, "quarantined malformed brief") {
		t.Fatalf("shutdown-canceled generation was logged as failure/quarantine: %s", out)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Fatal("shutdown-canceled generation was quarantined and marked seen")
	}
	if pub.flushes != 1 {
		t.Fatalf("shutdown flushes = %d, want 1", pub.flushes)
	}
}

func TestPipelineKeepsChildCancellationAsOperationalError(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()

	client := shutdownTestLLM{
		generate: func(context.Context) (string, error) {
			return "", errors.New("unexpected text generation")
		},
		generateJSON: func(context.Context) error {
			return fmt.Errorf("child request interrupted: %w", context.Canceled)
		},
	}
	var logs bytes.Buffer
	pipe := New(Config{
		DB:               db,
		LLMClient:        client,
		QualityThreshold: 3.5,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	item := shutdownPipelineItem("child-cancel", "test-feed")

	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatalf("process returned per-item error: %v", err)
	}
	if out := logs.String(); !strings.Contains(out, `"level":"ERROR"`) || !strings.Contains(out, `"msg":"pipeline error"`) {
		t.Fatalf("child cancellation was not logged as a pipeline error: %s", out)
	}
	if failed := pipe.Decisions(time.Hour).Failed; failed != 1 {
		t.Fatalf("child cancellation recorded %d failures, want 1", failed)
	}
}

func TestPipelineStopsBeforePublishWhenGroundingIsCanceledByShutdown(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			return validWindowsPathBriefYAML, nil
		},
		generateJSON: func(callCtx context.Context, _, system string, _ any) error {
			if system != groundingSystem {
				return fmt.Errorf("unexpected JSON generation for system %q", system)
			}
			cancel()
			return fmt.Errorf("grounding interrupted: %w", callCtx.Err())
		},
	}
	var logs bytes.Buffer
	pub := &shutdownTestPublisher{}
	pipe := New(Config{
		DB:               db,
		LLMClient:        client,
		QualityThreshold: 3.5,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
		Publisher:        pub,
		AutoPublish:      true,
	})
	item := shutdownPipelineItem("shutdown-grounding", "cisa-kev")
	item.SigmaRule = &scraper.SigmaRule{Title: "Credential theft detection", Detection: map[string]any{"condition": "selection"}}

	if err := pipe.Process(ctx, []scraper.RawItem{item}); !errors.Is(err, context.Canceled) {
		t.Fatalf("process error = %v, want context cancellation; logs=%s", err, logs.String())
	}
	if out := logs.String(); strings.Contains(out, "grounding check failed") || strings.Contains(out, `"level":"ERROR"`) {
		t.Fatalf("shutdown-canceled grounding was logged as a failure: %s", out)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if seen || pub.publishes != 0 {
		t.Fatalf("shutdown grounding mutation: seen=%v publishes=%d", seen, pub.publishes)
	}
	if pub.flushes != 1 {
		t.Fatalf("shutdown flushes = %d, want 1", pub.flushes)
	}
}

func TestPipelineStopsBeforePublishWhenRuleRepairIsCanceledByShutdown(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := shutdownStageLLM{
		generate: func(callCtx context.Context, _, system string) (string, error) {
			switch system {
			case briefSystemPrompt, compactAdvisorySystemPrompt:
				return repairBrief, nil
			case ruleRepairSystemPrompt:
				cancel()
				return "", fmt.Errorf("rule repair interrupted: %w", callCtx.Err())
			default:
				return "", fmt.Errorf("unexpected text generation for system %q", system)
			}
		},
		generateJSON: func(context.Context, string, string, any) error {
			return errors.New("unexpected JSON generation")
		},
	}
	var logs bytes.Buffer
	pub := &shutdownTestPublisher{}
	pipe := New(Config{
		DB:               db,
		LLMClient:        client,
		QualityThreshold: 3.5,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
		Publisher:        pub,
		AutoPublish:      true,
	})
	item := shutdownPipelineItem("shutdown-rule-repair", "cisa-kev")
	item.SigmaRule = &scraper.SigmaRule{Title: "Credential theft detection", Detection: map[string]any{"condition": "selection"}}

	if err := pipe.Process(ctx, []scraper.RawItem{item}); !errors.Is(err, context.Canceled) {
		t.Fatalf("process error = %v, want context cancellation; logs=%s", err, logs.String())
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if seen || pub.publishes != 0 {
		t.Fatalf("shutdown rule-repair mutation: seen=%v publishes=%d", seen, pub.publishes)
	}
	if pub.flushes != 1 {
		t.Fatalf("shutdown flushes = %d, want 1", pub.flushes)
	}
}

func TestPipelineStopsBeforeMergeWhenRelevanceIsCanceledByShutdown(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()

	const originalYAML = `id: brief-existing
slug: 2026-10-existing
title: Existing threat brief
summary: Existing brief
severity: high
published_at: "2026-10-19T08:00:00Z"
content: Existing detection context.
rules:
  - title: Existing detection
    logsource: {category: process_creation, product: windows}
    detection:
      selection: {Image|endswith: '\\tool.exe'}
      condition: selection
`
	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-existing", Status: storage.StatusApproved, Source: "original", BriefYAML: originalYAML, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	item := shutdownPipelineItem("shutdown-merge-relevance", "new-source")
	item.URL = "https://research.example/shared-report"
	if err := db.IndexContent(&storage.ContentIndexEntry{
		DraftID: "draft-existing", SourceID: "original:1", Source: "original", SourceURLHash: SourceURLHash(item.URL), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			return "", errors.New("unexpected text generation")
		},
		generateJSON: func(callCtx context.Context, _, system string, out any) error {
			switch system {
			case extractionSystemPrompt:
				extraction, ok := out.(*ExtractionResult)
				if !ok {
					return fmt.Errorf("extraction output type = %T", out)
				}
				extraction.AffectedVendors = []string{"Acme"}
				extraction.AffectedProducts = []string{"WidgetServer"}
				return nil
			case mergeRelevanceSystemPrompt:
				cancel()
				return fmt.Errorf("merge relevance interrupted: %w", callCtx.Err())
			default:
				return fmt.Errorf("unexpected JSON generation for system %q", system)
			}
		},
	}
	var logs bytes.Buffer
	pub := &shutdownTestPublisher{}
	pipe := New(Config{
		DB:               db,
		LLMClient:        client,
		QualityThreshold: 3.5,
		Logger:           slog.New(slog.NewJSONHandler(&logs, nil)),
		Publisher:        pub,
		AutoPublish:      true,
	})

	if err := pipe.Process(ctx, []scraper.RawItem{item}); !errors.Is(err, context.Canceled) {
		t.Fatalf("process error = %v, want context cancellation; logs=%s", err, logs.String())
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft("draft-existing")
	if err != nil {
		t.Fatal(err)
	}
	if seen || draft == nil || draft.BriefYAML != originalYAML || pub.publishes != 0 {
		t.Fatalf("shutdown merge mutation: seen=%v draft_changed=%v publishes=%d", seen, draft == nil || draft.BriefYAML != originalYAML, pub.publishes)
	}
	if pub.flushes != 1 {
		t.Fatalf("shutdown flushes = %d, want 1", pub.flushes)
	}
}

func TestRuleRepairKeepsChildCancellationAsFallbackNote(t *testing.T) {
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			return "", fmt.Errorf("child repair interrupted: %w", context.Canceled)
		},
		generateJSON: func(context.Context, string, string, any) error {
			return errors.New("unexpected JSON generation")
		},
	}

	repaired, notes, err := NewBriefAssembler(client).RepairRules(context.Background(), repairBrief)
	if err != nil {
		t.Fatalf("child cancellation became service shutdown: %v", err)
	}
	if repaired != repairBrief || len(notes) != 1 || !strings.Contains(notes[0], "repair call failed") {
		t.Fatalf("child cancellation fallback: changed=%v notes=%q", repaired != repairBrief, notes)
	}
}

func TestMergeRelevanceDefersOnChildCancellation(t *testing.T) {
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			return "", errors.New("unexpected text generation")
		},
		generateJSON: func(context.Context, string, string, any) error {
			return fmt.Errorf("child relevance interrupted: %w", context.Canceled)
		},
	}
	p := &Pipeline{llmClient: client, logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
	extraction := &ExtractionResult{AffectedProducts: []string{"WidgetServer"}}

	got, decision, err := p.assessDraftMergeRelevance(context.Background(), map[string]any{
		"title":             "WidgetServer vulnerability",
		"affected_products": []any{"WidgetServer"},
	}, extraction, scraper.RawItem{SourceID: "child-relevance", Title: "WidgetServer update"})
	if !errors.Is(err, errMergeRelevanceUnavailable) {
		t.Fatalf("child cancellation did not defer relevance check: %v", err)
	}
	if decision.Merge || decision.ReferenceRelevant || decision.POCRelevant || got != nil {
		t.Fatalf("child cancellation accepted a merge: decision=%+v extraction=%+v", decision, got)
	}
}
