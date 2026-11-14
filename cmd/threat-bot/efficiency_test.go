package main

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEfficiencyInvalidRecoveryDoesNotCreateDatabase(t *testing.T) {
	for _, args := range [][]string{
		{"--abandon", "--reconcile-job=job", "--keys=key", "--expected-ref=ref"},
		{"--abandon"},
		{"--keys=key", "--expected-ref=ref"},
		{"--abandon", "--keys=one,,two", "--expected-ref=ref"},
		{"--reconcile-job=job", "--keys=key", "--expected-ref=ref"},
	} {
		t.Run(strconv.Quote(args[0]), func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "should-not-exist.db")
			cfgPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(cfgPath, []byte("db:\n  path: "+strconv.Quote(dbPath)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := flagConfig
			flagConfig = cfgPath
			t.Cleanup(func() { flagConfig = previous })
			if err := runEfficiency(args, io.Discard); err == nil {
				t.Fatal("invalid recovery request succeeded")
			}
			if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
				t.Fatalf("invalid recovery touched database: %v", err)
			}
		})
	}
}

func TestEfficiencyReconcilePreflightBeforeDatabase(t *testing.T) {
	for _, job := range []string{"not-a-resource", "projects/example/locations/eu/batchPredictionJobs/1"} {
		t.Run(job, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(dir, "missing-adc.json"))
			dbPath := filepath.Join(dir, "should-not-exist.db")
			cfgPath := filepath.Join(dir, "config.yaml")
			cfg := "db:\n  path: " + strconv.Quote(dbPath) + "\nllm:\n  provider: vertexai\n  project: example\n  location: eu\n  model: fixture-model\n  batch:\n    bucket: example-fixture-bucket\n"
			if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := flagConfig
			flagConfig = cfgPath
			t.Cleanup(func() { flagConfig = previous })
			err := runEfficiency([]string{"--reconcile-job=" + job, "--keys=key", "--expected-ref=ref"}, io.Discard)
			if err == nil {
				t.Fatal("reconciliation unexpectedly succeeded without credentials")
			}
			if job == "not-a-resource" && !strings.Contains(err.Error(), "full resource name") {
				t.Fatalf("job syntax must fail before credential lookup: %v", err)
			}
			if strings.Contains(err.Error(), "poll interval") {
				t.Fatalf("recovery must get timing defaults while new batching is disabled: %v", err)
			}
			if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
				t.Fatalf("failed reconciliation preflight touched database: %v", err)
			}
		})
	}
}
