package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/eval"
	"github.com/craftedsignal/threat-bot/internal/llm"
)

func main() {
	dataset := flag.String("dataset", "internal/eval/testdata/single_label.json", "TRAM dataset path")
	out := flag.String("out", "output/eval-report.json", "report output path")
	configPath := flag.String("config", "config.yaml", "config file path")
	record := flag.Bool("record", false, "record LLM fixtures to internal/eval/testdata/fixtures.json")
	flag.Parse()

	client, err := buildLLMClient(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build llm client:", err)
		os.Exit(1)
	}

	recs, err := eval.LoadDataset(*dataset)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load dataset:", err)
		os.Exit(1)
	}
	docs := eval.GroupByDoc(recs)

	ctx := context.Background()

	if *record {
		rec := eval.NewRecordingClient(client)
		eval.Run(ctx, docs, eval.ExtractorPredict(rec), eval.BaseTechniqueID)
		fixturesPath := filepath.Join("internal", "eval", "testdata", "fixtures.json")
		if err := writeJSON(fixturesPath, rec.Fixtures()); err != nil {
			fmt.Fprintln(os.Stderr, "write fixtures:", err)
			os.Exit(1)
		}
		fmt.Println("recorded fixtures ->", fixturesPath)
		return
	}

	predict := eval.ExtractorPredict(client)
	base, exact := runEvaluation(ctx, docs, predict)

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}
	if err := writeJSON(*out, map[string]any{"base": base, "exact": exact}); err != nil {
		fmt.Fprintln(os.Stderr, "write report:", err)
		os.Exit(1)
	}
	fmt.Printf("docs=%d  base macroF1=%.3f microF1=%.3f  exact macroF1=%.3f microF1=%.3f\n",
		base.Docs, base.MacroF1, base.MicroF1, exact.MacroF1, exact.MicroF1)
	fmt.Println("report ->", *out)
}

func runEvaluation(ctx context.Context, docs []eval.EvalDoc, predict eval.PredictFunc) (eval.Report, eval.Report) {
	results := eval.CollectPredictions(ctx, docs, predict)
	base := eval.Score(results, eval.BaseTechniqueID)
	exact := eval.Score(results, func(s string) string { return s })
	return base, exact
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// buildLLMClient loads config and constructs the primary extraction LLM
// client, mirroring cmd/threat-bot's newLLMClient provider switch.
func buildLLMClient(path string) (llm.Client, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	c := cfg.LLM
	if err := c.Validate(true); err != nil {
		return nil, err
	}
	switch c.Provider {
	case "vertexai":
		client, err := llm.NewVertexAIClient(c.Project, c.Location, c.Model)
		if err != nil {
			return nil, err
		}
		return client, nil
	case "ollama":
		return llm.NewOllamaClient(c.Endpoint, c.Model), nil
	default:
		return nil, fmt.Errorf("llm.provider must be ollama or vertexai")
	}
}
