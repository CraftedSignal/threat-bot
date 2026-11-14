package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// TestFirstRunCLIProcess executes the real CLI in a separate process. It runs
// only when explicitly selected by the fixture smoke test below.
func TestFirstRunCLIProcess(t *testing.T) {
	if os.Getenv("THREAT_BOT_TEST_CLI") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"threat-bot"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("threat-bot", flag.ExitOnError)
	main()
	os.Exit(0)
}

func fixtureCLI(path string, args ...string) ([]byte, error) {
	commandArgs := []string{"-test.run=^TestFirstRunCLIProcess$", "--", "-config", path}
	commandArgs = append(commandArgs, args...)
	cmd := exec.Command(os.Args[0], commandArgs...)
	cmd.Env = append(os.Environ(), "THREAT_BOT_TEST_CLI=1", "GITHUB_TOKEN=", "THREAT_BOT_CONFIG=")
	return cmd.CombinedOutput()
}

// This exercises real parsing, source scheduling, pipeline validation, SQLite,
// and a fresh CLI process after close. Only source/model answers are fixtures;
// the test does not call a provider, enrichment API, or publishing service.
func TestFirstRunFixtureCreatesDraftAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "threat-bot.db")
	body := fmt.Sprintf("db:\n  path: %q\nllm: {provider: ollama, endpoint: 'http://127.0.0.1:1', model: fixture}\npipeline: {auto_publish: false, quality_threshold: 3.5, source_confidence: {fixture: 1}}\n", dbPath)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := fixtureCLI(path, "config", "validate"); err != nil {
		t.Fatalf("validation: %v\n%s", err, output)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("offline validation created a database")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	runner := scraper.NewRunner(db, logger, 24*time.Hour)
	runner.RegisterWithInterval(fixtureSource{}, time.Hour)
	items, err := runner.PollAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("fixture items=%d", len(items))
	}
	model := &fixtureLLM{}
	pipe := pipeline.New(pipeline.Config{DB: db, LLMClient: model, QualityThreshold: cfg.Pipeline.QualityThreshold, SourceConfidence: cfg.Pipeline.SourceConfidence, AutoPublish: cfg.Pipeline.AutoPublish, Logger: logger})
	if err := processPolledItems(context.Background(), items, pipe.Process, nil); err != nil {
		t.Fatal(err)
	}
	var draftID string
	count := 0
	for draft, err := range db.DraftsWithStatus(storage.StatusPending) {
		if err != nil {
			t.Fatal(err)
		}
		draftID = draft.ID
		count++
	}
	if count != 1 || model.calls < 3 {
		t.Fatalf("drafts=%d model calls=%d\n%s", count, model.calls, logs.String())
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"drafts", "list"}, {"drafts", "show", draftID}} {
		output, err := fixtureCLI(path, args...)
		if err != nil {
			t.Fatalf("restart CLI: %v\n%s", err, output)
		}
		if !bytes.Contains(output, []byte("Fixture Widget security notice")) {
			t.Fatalf("draft missing after restart: %s", output)
		}
	}
	reopened, err := storage.Open(cfg.DB.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	seen, err := reopened.HasSeen("fixture:notice")
	if err != nil || !seen {
		t.Fatalf("seen state lost: %v %v", seen, err)
	}
}

type fixtureSource struct{}

func (fixtureSource) Name() string { return "fixture" }
func (fixtureSource) Poll(context.Context, time.Time) ([]scraper.RawItem, error) {
	return []scraper.RawItem{{Source: "fixture", SourceID: "fixture:notice", URL: "https://example.invalid/notice", Title: "Fixture Widget security notice", Content: strings.Repeat("Fixture Widget installations require an inventory review. ", 40), PublishedAt: time.Now().UTC(), Enriched: true}}, nil
}

type fixtureLLM struct{ calls int }

func (*fixtureLLM) Generate(context.Context, string, string) (string, error) {
	return "", errors.New("unexpected unstructured model request")
}
func (f *fixtureLLM) GenerateJSON(_ context.Context, _, _ string, out any) error {
	f.calls++
	switch out.(type) {
	case *pipeline.QualityScore:
		return json.Unmarshal([]byte(`{"credibility":5,"actionability":5,"novelty":5,"summary":"Synthetic fixture"}`), out)
	case *pipeline.ExtractionResult:
		return json.Unmarshal([]byte(`{"summary":"Fixture Widget requires an inventory review","affected_vendors":["Fixture"],"affected_products":["Widget"]}`), out)
	default:
		return fmt.Errorf("unexpected fixture JSON request %T", out)
	}
}
func (f *fixtureLLM) GenerateStructured(_ context.Context, _, _ string, schema *llm.Schema, out any) error {
	f.calls++
	if _, ok := schema.Properties["issues"]; ok {
		return json.Unmarshal([]byte(`{"issues":[]}`), out)
	}
	if _, ok := schema.Properties["id"]; !ok {
		return fmt.Errorf("unexpected fixture structured request %T", out)
	}
	return json.Unmarshal([]byte(`{"id":"brief-2026-11-14-fixture-widget","slug":"2026-11-14-fixture-widget","title":"Fixture Widget security notice","summary":"Fixture Widget installations require an inventory review.","severity":"medium","content":"## Overview\nFixture Widget installations require an inventory review.\n\n## Recommendation\nInventory Fixture Widget installations.","affected_vendors":["Fixture"],"affected_products":["Widget"],"references":["https://example.invalid/notice"],"action_plan":{"immediate_actions":[{"action":"Inventory Fixture Widget installations.","evidence":"Fixture Widget installations require an inventory review."}]}}`), out)
}

var _ llm.Client = (*fixtureLLM)(nil)
