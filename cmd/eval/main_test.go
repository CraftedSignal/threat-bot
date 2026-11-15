package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/eval"
)

func TestBuildLLMClientValidatesBeforeProviderSetup(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"unknown provider", "llm: {provider: typo, model: fixture}", "llm.provider"},
		{"missing provider", "llm: {model: fixture}", "llm.provider"},
		{"missing Ollama model", "llm: {provider: ollama}", "llm.model"},
		{"missing Vertex model", "llm: {provider: vertexai, project: fixture, location: fixture}", "llm.model"},
		{"incomplete Vertex", "llm: {provider: vertexai, model: fixture}", "llm.project"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(dir, "missing-credentials.json"))
			client, err := buildLLMClient(path)
			if err == nil || client != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("configuration did not fail before provider setup: client=%T err=%v", client, err)
			}
		})
	}
}

func TestEvalCLIProcess(t *testing.T) {
	if os.Getenv("THREAT_BOT_TEST_EVAL_CLI") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"eval"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("eval", flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestEvalRejectsInvalidProviderBeforeLoadingDataset(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("llm: {provider: typo, model: fixture}"), 0600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "output", "report.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestEvalCLIProcess$", "--", "-config", configPath, "-dataset", filepath.Join(dir, "missing.json"), "-out", outputPath)
	cmd.Env = append(os.Environ(), "THREAT_BOT_TEST_EVAL_CLI=1")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "llm.provider") {
		t.Fatalf("invalid config did not fail first: %v %s", err, output)
	}
	if _, err := os.Stat(filepath.Dir(outputPath)); !os.IsNotExist(err) {
		t.Fatalf("invalid config created output directory: %v", err)
	}
}

func TestRunEvaluationPredicts149DocumentsOnce(t *testing.T) {
	docs := make([]eval.EvalDoc, 149)
	for i := range docs {
		docs[i] = eval.EvalDoc{GoldTechniques: []string{"T1059.001"}}
	}
	calls := 0
	base, exact := runEvaluation(context.Background(), docs, func(context.Context, eval.EvalDoc) ([]string, error) {
		calls++
		return []string{"T1059.003"}, nil
	})
	if calls != 149 {
		t.Fatalf("prediction calls = %d, want 149", calls)
	}
	if base.Docs != 149 || base.MicroF1 != 1 || base.MacroF1 != 1 {
		t.Fatalf("base = %+v", base)
	}
	if exact.Docs != 149 || exact.MicroF1 != 0 || exact.MacroF1 != 0 {
		t.Fatalf("exact = %+v", exact)
	}
}

// CPU work stands in for inference without network access or paid calls. The
// calls/op metric is the useful cost evidence; ns/op is a local simulation.
func BenchmarkEvaluation149Documents(b *testing.B) {
	docs := make([]eval.EvalDoc, 149)
	for i := range docs {
		docs[i] = eval.EvalDoc{GoldTechniques: []string{"T1059.001"}}
	}
	for _, shared := range []bool{false, true} {
		name := "LegacyTwoPasses"
		if shared {
			name = "SharedPredictions"
		}
		b.Run(name, func(b *testing.B) {
			calls := 0
			digest := [32]byte{}
			predict := func(context.Context, eval.EvalDoc) ([]string, error) {
				calls++
				for i := 0; i < 100; i++ {
					digest = sha256.Sum256(digest[:])
				}
				return []string{"T1059.001"}, nil
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if shared {
					runEvaluation(context.Background(), docs, predict)
				} else {
					eval.Run(context.Background(), docs, predict, eval.BaseTechniqueID)
					eval.Run(context.Background(), docs, predict, func(s string) string { return s })
				}
			}
			b.ReportMetric(float64(calls)/float64(b.N), "calls/op")
		})
	}
}
