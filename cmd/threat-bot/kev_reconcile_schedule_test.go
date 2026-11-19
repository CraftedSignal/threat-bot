package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
)

func TestKEVReconcileScheduleDrainsBacklogAndLogsOnlyChanges(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	var schedule kevReconcileSchedule
	start := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	if !schedule.due(start) {
		t.Fatal("first pass must run as soon as the service starts")
	}

	schedule.completed(start, pipeline.ExploitationReconcileResult{Updated: 50, Held: 97, More: true}, logger)
	if schedule.due(start.Add(9*time.Minute)) || !schedule.due(start.Add(kevReconcileBacklogInterval)) {
		t.Fatal("a backlog must be drained every 10 minutes")
	}
	schedule.completed(start, pipeline.ExploitationReconcileResult{Held: 97}, logger)
	if schedule.due(start.Add(59*time.Minute)) || !schedule.due(start.Add(kevReconcileInterval)) {
		t.Fatal("without a backlog the pass must run hourly")
	}
	if got := strings.Count(logs.String(), "exploitation reconciliation pass"); got != 1 {
		t.Fatalf("an unchanged pass was logged: %d summaries\n%s", got, logs.String())
	}
	schedule.completed(start, pipeline.ExploitationReconcileResult{Held: 96}, logger)
	if got := strings.Count(logs.String(), "exploitation reconciliation pass"); got != 2 {
		t.Fatalf("a changed review count was not logged:\n%s", logs.String())
	}
}
