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

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// Waiting for a paid remote batch is the designed way to avoid duplicate
// inference. It defers the item; it is not a failed pipeline run.
func TestPendingBatchWorkDefersWithoutFailingThePipeline(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) {
		return validWindowsPathBriefYAML, nil
	}, generateJSON: func(_ context.Context, _, system string, out any) error {
		if system == extractionSystemPrompt {
			return fmt.Errorf("batch recovery: %w", &llm.PendingBatchError{Keys: []string{"paid"}})
		}
		if q, ok := out.(*QualityScore); ok {
			*q = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
		}
		return nil
	}}
	var logs bytes.Buffer
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	item := scraper.RawItem{SourceID: "batch:deferred", Source: "cisa", Title: "Vendor notice", Content: strings.Repeat("Concrete process telemetry evidence. ", 20), Enriched: true}
	if err := p.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), `"msg":"pipeline error"`) || p.Decisions(time.Hour).Failed != 0 {
		t.Fatalf("pending batch work reported as a pipeline failure: %s", logs.String())
	}
	for _, field := range []string{`"msg":"item deferred while paid batch work is pending"`, `"level":"WARN"`, `"source":"cisa"`, `"error_class":"batch_pending"`} {
		if !strings.Contains(logs.String(), field) {
			t.Fatalf("missing deferral diagnostic %s: %s", field, logs.String())
		}
	}
	if seen, _ := db.HasSeen(item.SourceID); seen {
		t.Fatal("deferred item consumed")
	}
}

// Genuine processing failures still surface as pipeline errors.
func TestProcessingFailureStillReportsPipelineError(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client := shutdownStageLLM{generateJSON: func(_ context.Context, _, system string, out any) error {
		return errors.New("provider rejected request")
	}}
	var logs bytes.Buffer
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	item := scraper.RawItem{SourceID: "batch:failed", Source: "cisa", Title: "Vendor notice", Content: strings.Repeat("Concrete process telemetry evidence. ", 20), Enriched: true}
	if err := p.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"msg":"pipeline error"`) || p.Decisions(time.Hour).Failed != 1 {
		t.Fatalf("operational failure no longer reported: %s", logs.String())
	}
}

// An unusable optional indicator must not make an otherwise usable extraction
// unprocessable: the model repeats it for the same source on every retry.
func TestExtractionDropsUnusableIndicatorsInsteadOfRejectingTheItem(t *testing.T) {
	ex := &ExtractionResult{Summary: "Mitsubishi Electric CNC series improper input validation.", AffectedVendors: []string{"Mitsubishi Electric"},
		IOCs: []ExtractedIOC{{Type: "other", Value: "CNC series"}, {Type: "domain", Value: "malicious.example"}, {Type: "ip", Value: "  "}}}
	if err := ex.ValidateLLMResponse(); err != nil {
		t.Fatalf("usable extraction rejected for an unusable indicator: %v", err)
	}
	if len(ex.IOCs) != 1 || ex.IOCs[0].Value != "malicious.example" {
		t.Fatalf("unusable indicators kept or usable ones dropped: %+v", ex.IOCs)
	}
	onlyUnusable := &ExtractionResult{IOCs: []ExtractedIOC{{Type: "other", Value: "CNC series"}}}
	if err := onlyUnusable.ValidateLLMResponse(); err == nil {
		t.Fatal("extraction with nothing usable accepted")
	}
}
