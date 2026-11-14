package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
)

// starvationRun is one invocation of checkBriefStarvation against fixed counts.
type starvationRun struct {
	counts       pipeline.DecisionCounts
	startedAt    time.Time
	lastNewItems time.Time
}

// afterAFullWindow is a run past the startup grace period with items seen
// recently, the state in which the check is allowed to speak.
func afterAFullWindow(counts pipeline.DecisionCounts) starvationRun {
	return starvationRun{
		counts:       counts,
		startedAt:    time.Now().Add(-briefStarvationWindow - time.Hour),
		lastNewItems: time.Now().Add(-10 * time.Minute),
	}
}

// check runs the check and returns the log records it wrote, in order.
func (r starvationRun) check(t *testing.T, throttle *starvationThrottle) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	var window time.Duration
	checkBriefStarvation(func(w time.Duration) pipeline.DecisionCounts {
		window = w
		return r.counts
	}, r.startedAt, r.lastNewItems, throttle, logger)

	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		records = append(records, rec)
	}
	if len(records) > 0 && window != briefStarvationWindow {
		t.Fatalf("counts read over %s, want the %s starvation window", window, briefStarvationWindow)
	}
	return records
}

func requireOneRecord(t *testing.T, records []map[string]any, level, msg string) map[string]any {
	t.Helper()
	if len(records) != 1 {
		t.Fatalf("got %d log records %v, want one %s %q", len(records), records, level, msg)
	}
	if records[0]["level"] != level || records[0]["msg"] != msg {
		t.Fatalf("got %v %q, want %s %q", records[0]["level"], records[0]["msg"], level, msg)
	}
	return records[0]
}

func requireCounts(t *testing.T, rec map[string]any, want pipeline.DecisionCounts) {
	t.Helper()
	got := map[string]any{
		"processed":           float64(want.Processed),
		"passed_quality":      float64(want.PassedQuality),
		"drafts":              float64(want.Drafts),
		"merged":              float64(want.Merged),
		"rejected_ungrounded": float64(want.RejectedUngrounded),
		"failed":              float64(want.Failed),
	}
	for key, value := range got {
		if rec[key] != value {
			t.Errorf("log field %s = %v, want %v", key, rec[key], value)
		}
	}
}

// A quiet stretch where nothing cleared the quality gate is not starvation,
// however many items arrived and were scored.
func TestBriefStarvationQuietWhenNothingClearedQualityGate(t *testing.T) {
	counts := pipeline.DecisionCounts{Processed: 80}
	rec := requireOneRecord(t, afterAFullWindow(counts).check(t, &starvationThrottle{}), "INFO", "quiet period")
	requireCounts(t, rec, counts)
}

// The 2026-10-18 pattern: items cleared the gate, some were rejected as
// ungrounded, others merged into existing drafts, and no new draft was needed.
func TestBriefStarvationQuietWhenQualityPassesWereMerged(t *testing.T) {
	counts := pipeline.DecisionCounts{Processed: 30, PassedQuality: 9, Merged: 2, RejectedUngrounded: 7}
	rec := requireOneRecord(t, afterAFullWindow(counts).check(t, &starvationThrottle{}), "INFO", "quiet period")
	requireCounts(t, rec, counts)
}

// Items cleared the quality gate and none became a draft or merged into one.
func TestBriefStarvationErrorsWhenQualityPassesProduceNothing(t *testing.T) {
	counts := pipeline.DecisionCounts{Processed: 12, PassedQuality: 5, RejectedUngrounded: 3, Failed: 2}
	rec := requireOneRecord(t, afterAFullWindow(counts).check(t, &starvationThrottle{}), "ERROR", "brief production starvation")
	requireCounts(t, rec, counts)
}

func TestBriefStarvationSilentWhenDraftsWereCreated(t *testing.T) {
	counts := pipeline.DecisionCounts{Processed: 12, PassedQuality: 5, Drafts: 1, RejectedUngrounded: 4}
	if records := afterAFullWindow(counts).check(t, &starvationThrottle{}); len(records) != 0 {
		t.Fatalf("got log records %v, want none while drafts are being created", records)
	}
}

func TestBriefStarvationLogsOncePerWindowPerSeverity(t *testing.T) {
	quiet := afterAFullWindow(pipeline.DecisionCounts{Processed: 40})
	broken := afterAFullWindow(pipeline.DecisionCounts{Processed: 40, PassedQuality: 4})
	var throttle starvationThrottle

	requireOneRecord(t, quiet.check(t, &throttle), "INFO", "quiet period")
	if records := quiet.check(t, &throttle); len(records) != 0 {
		t.Fatalf("repeated quiet period logged again: %v", records)
	}

	// A quiet period must not hold back the error that follows it.
	requireOneRecord(t, broken.check(t, &throttle), "ERROR", "brief production starvation")
	if records := broken.check(t, &throttle); len(records) != 0 {
		t.Fatalf("repeated starvation logged again: %v", records)
	}

	// Once the window has passed both may speak again.
	throttle.lastError = time.Now().Add(-briefStarvationWindow - time.Minute)
	throttle.lastQuiet = throttle.lastError
	requireOneRecord(t, broken.check(t, &throttle), "ERROR", "brief production starvation")
	requireOneRecord(t, quiet.check(t, &throttle), "INFO", "quiet period")
}

func TestBriefStarvationWaitsForAFullWindowOfNewItems(t *testing.T) {
	broken := pipeline.DecisionCounts{Processed: 12, PassedQuality: 5}

	justStarted := afterAFullWindow(broken)
	justStarted.startedAt = time.Now().Add(-time.Hour)

	noItemsYet := afterAFullWindow(broken)
	noItemsYet.lastNewItems = time.Time{}

	staleItems := afterAFullWindow(broken)
	staleItems.lastNewItems = time.Now().Add(-briefStarvationWindow - time.Minute)

	for name, run := range map[string]starvationRun{
		"counts do not span a window yet": justStarted,
		"no items have arrived":           noItemsYet,
		"no items arrived in the window":  staleItems,
	} {
		if records := run.check(t, &starvationThrottle{}); len(records) != 0 {
			t.Errorf("%s: got log records %v, want none", name, records)
		}
	}
}
