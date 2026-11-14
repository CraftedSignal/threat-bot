package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// The storage lookup must expose the old checkpoint even when a delivery clock
// or policy changes. The pipeline decides whether to rekey, resume or rebuild.
func TestCheckpointCompatibilityRemainsPipelineOwned(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		hold, backoff, timestamp, evidence, policy bool
	}{
		{name: "editorial hold", hold: true},
		{name: "timestamp rekeys editorial hold", hold: true, timestamp: true},
		{name: "retry backoff", backoff: true},
		{name: "timestamp rekeys without losing backoff", backoff: true, timestamp: true},
		{name: "source change releases editorial hold", hold: true, evidence: true},
		{name: "policy change releases editorial hold", hold: true, policy: true},
		{name: "source change invalidates backoff", backoff: true, evidence: true},
		{name: "policy change invalidates backoff", backoff: true, policy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			calls := 0
			freshWork := errors.New("fresh quality evaluation requested")
			client := shutdownStageLLM{
				generate: func(context.Context, string, string) (string, error) { t.Fatal("unexpected assembly"); return "", nil },
				generateJSON: func(_ context.Context, _, system string, _ any) error {
					if system != qualitySystemPrompt {
						t.Fatalf("unexpected stage %q", system)
					}
					calls++
					return freshWork
				},
			}
			cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger()}
			p := New(cfg)
			item := scraper.RawItem{SourceID: "checkpoint:source", Source: "research", Title: "Concrete source evidence", Content: strings.Repeat("Concrete source evidence about administrator rename operations. ", 4), Enriched: true}
			item.Revision = item.ContentRevision()
			retry := time.Time{}
			if tc.backoff {
				retry = time.Now().Add(time.Hour).UTC()
			}
			state := processingCandidate{Item: item, BriefYAML: "saved independently grounded candidate", ReviewHold: tc.hold}
			if err := p.saveCandidate(p.processingInputKey(item), state, retry); err != nil {
				t.Fatal(err)
			}
			incoming := item
			incoming.Revision = ""
			if tc.timestamp {
				incoming.UpdatedAt = time.Now().UTC()
			}
			if tc.evidence {
				incoming.Content += " The vendor corrected the affected operation."
			}
			if tc.policy {
				cfg.ProcessingPolicy = "revised grounding policy"
			}
			// A fresh pipeline instance exercises the persisted state, not local
			// references to the original candidate.
			p = New(cfg)
			err := p.processItem(context.Background(), incoming)
			if tc.evidence || tc.policy {
				if !errors.Is(err, freshWork) || calls != 1 {
					t.Fatalf("changed evidence/policy reused stale saved work: calls=%d err=%v", calls, err)
				}
				if cp, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || cp != nil {
					t.Fatalf("invalidated checkpoint retained: %+v %v", cp, err)
				}
				return
			}
			if err != nil || calls != 0 {
				t.Fatalf("unchanged saved work repeated AI calls: calls=%d err=%v", calls, err)
			}
			cp, err := db.GetProcessingCheckpoint(item.SourceID)
			if err != nil || cp == nil || cp.InputKey != p.processingInputKey(incoming) || !cp.RetryAt.Equal(retry) {
				t.Fatalf("resume/rekey lost stored input or backoff: %+v %v", cp, err)
			}
		})
	}
}
