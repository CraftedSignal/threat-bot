package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
