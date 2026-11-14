package pipeline

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// Break caught: a secondary incident aggregator must never become the sole
// source for a new public brief when dedup cannot find a canonical incident.
func TestPipelineSkipsUnmatchedCorroborationOnlyItemBeforeLLM(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llmCalls := 0
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			llmCalls++
			return "", fmt.Errorf("LLM must not be called")
		},
		generateJSON: func(context.Context, string, string, any) error {
			llmCalls++
			return fmt.Errorf("LLM must not be called")
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{
		SourceID:          "pwn-watch:new-incident:2026-10-23T08:00:00Z",
		Source:            "pwn-watch",
		Title:             "A new incident known only to an aggregator",
		URL:               "https://pwn.watch/i/new-incident",
		Content:           strings.Repeat("Structured secondary-source incident context. ", 10),
		PublishedAt:       time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC),
		CorroborationOnly: true,
	}

	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if llmCalls != 0 {
		t.Fatalf("LLM calls = %d, want zero", llmCalls)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("unmatched corroboration item was not marked seen")
	}
	for _, status := range []string{storage.StatusPending, storage.StatusApproved} {
		for draft, err := range db.DraftsWithStatus(status) {
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("unexpected %s draft %s", status, draft.ID)
		}
	}
}
