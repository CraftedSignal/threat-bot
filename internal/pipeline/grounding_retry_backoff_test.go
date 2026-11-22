package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// Fixed retry delays buy another repair/recheck for every held source on each
// polling cycle. The saved candidate must retain increasing delays even after
// restart, before another provider call is made.
func TestGroundingRetriesBackOffDurablyAcrossRestarts(t *testing.T) {
	for _, failure := range []string{"rejected", "unavailable"} {
		t.Run(failure, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			assemblies, calls := 0, 0
			client := shutdownStageLLM{
				generate: func(_ context.Context, _, system string) (string, error) {
					calls++
					if !strings.HasPrefix(system, groundingRepairSystemPrompt) {
						assemblies++
					}
					return validWindowsPathBriefYAML, nil
				},
				generateJSON: func(_ context.Context, _, _ string, out any) error {
					calls++
					if failure == "unavailable" {
						return errors.New("provider unavailable")
					}
					*out.(*GroundingResult) = GroundingResult{Issues: []string{"unsupported claim"}}
					return nil
				},
			}
			cfg := Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: quietLogger()}
			item := scraper.RawItem{SourceID: "backoff:" + failure, Source: "cisa-kev", Title: "Vendor notice", Content: strings.Repeat("Confirmed vendor notice. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
			if failure == "rejected" {
				start := time.Now()
				if err := New(cfg).processItem(context.Background(), item); err != nil {
					t.Fatal(err)
				}
				cp, err := db.GetProcessingCheckpoint(item.SourceID)
				if err != nil || cp == nil || cp.RetryAt.Before(start.Add(15*time.Minute)) {
					t.Fatalf("first rejection was not retained with backoff: checkpoint=%+v err=%v", cp, err)
				}
				before := calls
				if err := New(cfg).processItem(context.Background(), item); err != nil || calls != before {
					t.Fatalf("retry spent work before backoff: err=%v calls=%d/%d", err, calls, before)
				}
				cp.RetryAt = time.Now().Add(-time.Second)
				if err := db.PutProcessingCheckpoint(*cp); err != nil {
					t.Fatal(err)
				}
				if err := New(cfg).processItem(context.Background(), item); err != nil {
					t.Fatal(err)
				}
				if calls != before || assemblies != 1 {
					t.Fatalf("repeated rejection bought more paid work: calls=%d/%d assemblies=%d", calls, before, assemblies)
				}
				if _, quarantined, err := db.PipelineQuarantineReason(item.SourceID); err != nil || !quarantined {
					t.Fatalf("repeated rejection not quarantined: quarantined=%v err=%v", quarantined, err)
				}
				return
			}
			for attempt, delay := range []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour} {
				start := time.Now()
				err := New(cfg).processItem(context.Background(), item)
				if failure == "rejected" && err != nil || failure == "unavailable" && err == nil {
					t.Fatalf("unexpected %s outcome on attempt %d: %v", failure, attempt+1, err)
				}
				cp, err := db.GetProcessingCheckpoint(item.SourceID)
				if err != nil || cp == nil {
					t.Fatalf("missing retained candidate: %v", err)
				}
				if cp.RetryAt.Before(start.Add(delay)) || cp.RetryAt.After(time.Now().Add(delay)) {
					t.Fatalf("attempt %d scheduled delay %s, want %s", attempt+1, cp.RetryAt.Sub(start), delay)
				}
				before := calls
				if err := New(cfg).processItem(context.Background(), item); err != nil {
					t.Fatal(err)
				}
				if calls != before {
					t.Fatal("restart spent paid work before the durable retry became due")
				}
				if seen, _ := db.HasSeen(item.SourceID); seen {
					t.Fatal("backoff consumed an ungrounded source")
				}
				cp.RetryAt = time.Now().Add(-time.Second)
				if err := db.PutProcessingCheckpoint(*cp); err != nil {
					t.Fatal(err)
				}
			}
			if assemblies != 1 {
				t.Fatalf("backoff rebuilt retained work: assemblies=%d", assemblies)
			}
			_ = New(cfg).processItem(context.Background(), item)
			if _, quarantined, _ := db.PipelineQuarantineReason(item.SourceID); !quarantined {
				t.Fatal("backoff removed the existing five-attempt quarantine limit")
			}
		})
	}
}

func TestGroundingRetryDelayBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		base    time.Duration
		attempt int
		want    time.Duration
	}{
		{"cap", 15 * time.Minute, 100, 2 * time.Hour},
		{"non power of two", 50 * time.Minute, 3, 2 * time.Hour},
		{"long configured delay", 4 * time.Hour, 100, 4 * time.Hour},
		{"maximum configured duration", time.Duration(1<<63 - 1), 100, time.Duration(1<<63 - 1)},
		{"explicit immediate retries", 0, 100, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Pipeline{retryBackoff: tc.base}
			if got := p.groundingRetryDelay(tc.attempt); got != tc.want {
				t.Fatalf("retry delay=%s want=%s", got, tc.want)
			}
		})
	}
}
