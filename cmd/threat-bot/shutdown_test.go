package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestHandleLoopErrorStopsSilentlyForShutdownCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	err := fmt.Errorf("processing interrupted: %w", context.Canceled)

	if !handleLoopError(ctx, logger, "pipeline error", err) {
		t.Fatal("handleLoopError returned false, want shutdown stop")
	}
	if logs.Len() != 0 {
		t.Fatalf("shutdown cancellation was logged: %q", logs.String())
	}
}

func TestHandleLoopErrorPreservesOperationalErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	err := errors.New("feed unavailable")

	if handleLoopError(ctx, logger, "poll error", err) {
		t.Fatal("handleLoopError returned true for an operational error")
	}
	got := logs.String()
	if !strings.Contains(got, "level=ERROR") || !strings.Contains(got, `msg="poll error"`) || !strings.Contains(got, `error="feed unavailable"`) {
		t.Fatalf("operational error log = %q", got)
	}
}

func TestHandleLoopErrorDoesNotHideChildCancellation(t *testing.T) {
	ctx := context.Background()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	if handleLoopError(ctx, logger, "pipeline error", context.Canceled) {
		t.Fatal("handleLoopError returned true while the service context is still active")
	}
	if got := logs.String(); !strings.Contains(got, "level=ERROR") || !strings.Contains(got, `error="context canceled"`) {
		t.Fatalf("child cancellation log = %q", got)
	}
}
