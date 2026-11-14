package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// Defaults to read-only reporting. Recovery mutations require exact request
// keys and the observed reference; reconciliation verifies remote ownership.
func runEfficiency(args []string, w io.Writer) error {
	flags := flag.NewFlagSet("efficiency", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	since := flags.Duration("since", 24*time.Hour, "processing history window")
	keys := flags.String("keys", "", "comma-separated exact request keys")
	expected := flags.String("expected-ref", "", "observed batch reference for compare-and-swap")
	job := flags.String("reconcile-job", "", "confirmed Vertex remote job name")
	abandon := flags.Bool("abandon", false, "retain unknown-work tombstone; never authorizes re-inference")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *since <= 0 {
		return fmt.Errorf("usage: efficiency [--since 24h] [--keys KEYS --expected-ref REF (--reconcile-job JOB | --abandon)]")
	}
	if *abandon && *job != "" {
		return fmt.Errorf("choose reconcile-job or abandon")
	}
	recovery := *abandon || *job != ""
	var requestKeys []string
	if recovery {
		if *keys == "" || *expected == "" {
			return fmt.Errorf("batch recovery requires keys and expected-ref")
		}
		requestKeys = strings.Split(*keys, ",")
		for i := range requestKeys {
			requestKeys[i] = strings.TrimSpace(requestKeys[i])
			if requestKeys[i] == "" {
				return fmt.Errorf("empty request key")
			}
		}
	} else if *keys != "" || *expected != "" {
		return fmt.Errorf("keys/expected-ref require a recovery action")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.ValidateFor("efficiency"); err != nil {
		return err
	}
	var runner *llm.VertexBatch
	if *job != "" {
		if err := llm.ValidateBatchJobResourceName(*job); err != nil {
			return err
		}
		if cfg.LLM.Provider != "vertexai" {
			return fmt.Errorf("batch reconciliation requires vertexai")
		}
		if err := cfg.LLM.Validate(true); err != nil {
			return err
		}
		if strings.TrimSpace(cfg.LLM.Batch.Bucket) == "" {
			return fmt.Errorf("batch reconciliation requires llm.batch.bucket")
		}
		runner, err = llm.NewVertexBatch(cfg.LLM.Project, cfg.LLM.Location, cfg.LLM.Model, cfg.LLM.Batch.Bucket, cfg.LLM.Batch.PollInterval, cfg.LLM.Batch.MaxWait, slog.Default())
		if err != nil {
			return err
		}
	}
	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if recovery {
		if *abandon {
			err = llm.AbandonBatchJob(db, requestKeys, *expected)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			err = runner.WithJobStore(db).ReconcileBatchJob(ctx, requestKeys, *expected, *job)
		}
		if err != nil {
			return err
		}
	}
	summary, err := db.ProcessingSummary(time.Now().Add(-*since))
	if err != nil {
		return err
	}
	refs, err := db.ListBatchJobReferences()
	if err != nil {
		return err
	}
	type jobState struct {
		storage.BatchJobReference
		State string `json:"state"`
	}
	jobs := make([]jobState, 0, len(refs))
	for _, r := range refs {
		jobs = append(jobs, jobState{r, llm.BatchJobReferenceState(r.Reference)})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Processing storage.ProcessingSummary `json:"processing"`
		BatchJobs  []jobState                `json:"batch_jobs"`
	}{summary, jobs})
}
