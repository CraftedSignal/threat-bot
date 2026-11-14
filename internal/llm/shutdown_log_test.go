package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// recordHandler records the level of every log record.
type recordHandler struct {
	mu     sync.Mutex
	levels []slog.Level
	msgs   []string
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.levels = append(h.levels, r.Level)
	h.msgs = append(h.msgs, r.Message)
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordHandler) has(level slog.Level) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, l := range h.levels {
		if l == level {
			return true
		}
	}
	return false
}

func TestPrefetchShutdownLogsInfoNotWarn(t *testing.T) {
	h := &recordHandler{}
	runner := &fakeRunner{err: fmt.Errorf("waiting for batch job x: %w", context.Canceled)}
	c := newPrefetchClient(&fakeLive{}, runner, 500, slog.New(h))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Prefetch(ctx, []Request{{Prompt: "p", JSON: true}})
	if h.has(slog.LevelWarn) || h.has(slog.LevelError) {
		t.Fatalf("shutdown logged above info: %v %v", h.levels, h.msgs)
	}
	if !h.has(slog.LevelInfo) {
		t.Fatalf("expected an info record, got %v", h.msgs)
	}
}

func TestPrefetchFailureWithLiveContextStillWarns(t *testing.T) {
	h := &recordHandler{}
	runner := &fakeRunner{err: errors.New("batch job x ended JOB_STATE_CANCELLED")}
	c := newPrefetchClient(&fakeLive{}, runner, 500, slog.New(h))
	c.Prefetch(context.Background(), []Request{{Prompt: "p", JSON: true}})
	if !h.has(slog.LevelWarn) {
		t.Fatalf("expected a warning, got %v %v", h.levels, h.msgs)
	}
}

func TestBatchCancelOnShutdownLogsInfoNotWarn(t *testing.T) {
	api := &fakeBatchAPI{states: []string{"JOB_STATE_RUNNING"}}
	batch, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	h := &recordHandler{}
	batch.logger = slog.New(h)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	batch.cancel(ctx, fakeJobName)
	if h.has(slog.LevelWarn) {
		t.Fatalf("shutdown cancel warned: %v", h.msgs)
	}
	if !api.cancelled {
		t.Fatal("job not cancelled")
	}
}

func TestBatchCancelWithLiveContextStillWarns(t *testing.T) {
	api := &fakeBatchAPI{states: []string{"JOB_STATE_RUNNING"}}
	batch, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	h := &recordHandler{}
	batch.logger = slog.New(h)
	batch.cancel(context.Background(), fakeJobName)
	if !h.has(slog.LevelWarn) {
		t.Fatalf("expected a warning, got %v", h.msgs)
	}
}
