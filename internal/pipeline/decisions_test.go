package pipeline

import (
	"testing"
	"time"
)

// fakeClock is a settable clock for decisionLog.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestDecisionLog() (*decisionLog, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)}
	return &decisionLog{now: clock.now}, clock
}

func TestDecisionLogSumsOnlyTheTrailingWindow(t *testing.T) {
	log, clock := newTestDecisionLog()

	// 7h ago: a draft and a processed item that must have aged out of a 6h window.
	clock.advance(-7 * time.Hour)
	log.record(outcomeProcessed)
	log.record(outcomeDraft)

	// 3h ago: a quality pass that was rejected as ungrounded.
	clock.advance(4 * time.Hour)
	log.record(outcomeProcessed)
	log.record(outcomePassedQuality)
	log.record(outcomeRejectedUngrounded)

	// Now: one merge and one failure.
	clock.advance(3 * time.Hour)
	log.record(outcomeProcessed)
	log.record(outcomeMerged)
	log.record(outcomeFailed)

	got := log.since(6 * time.Hour)
	want := DecisionCounts{Processed: 2, PassedQuality: 1, Merged: 1, RejectedUngrounded: 1, Failed: 1}
	if got != want {
		t.Fatalf("6h window = %+v, want %+v", got, want)
	}

	if all := log.since(8 * time.Hour); all.Drafts != 1 || all.Processed != 3 {
		t.Fatalf("8h window = %+v, want the aged-out draft and 3 processed items", all)
	}
}

func TestDecisionLogWindowIsAccurateToOneBucket(t *testing.T) {
	log, clock := newTestDecisionLog()

	log.record(outcomeDraft)
	clock.advance(6*time.Hour - time.Minute)
	if got := log.since(6 * time.Hour); got.Drafts != 1 {
		t.Fatalf("draft just inside the window = %d, want 1", got.Drafts)
	}

	// Past the window by more than one bucket the draft is gone.
	clock.advance(time.Minute + decisionBucketSpan)
	if got := log.since(6 * time.Hour); got.Drafts != 0 {
		t.Fatalf("draft a full bucket past the window = %d, want 0", got.Drafts)
	}
}

func TestDecisionLogOverwritesBucketsFromPreviousLaps(t *testing.T) {
	log, clock := newTestDecisionLog()

	log.record(outcomeDraft)
	// Exactly one lap of the ring later the same bucket is reused.
	clock.advance(decisionRetention)
	log.record(outcomeMerged)

	got := log.since(decisionRetention)
	if got.Drafts != 0 || got.Merged != 1 {
		t.Fatalf("after a full lap = %+v, want only the new merge", got)
	}
}

func TestDecisionLogClampsWindowToRetention(t *testing.T) {
	log, clock := newTestDecisionLog()

	log.record(outcomeDraft)
	clock.advance(decisionRetention - decisionBucketSpan)
	log.record(outcomeMerged)

	// An absurd window must not see buckets that survive from earlier laps.
	got := log.since(1000 * time.Hour)
	if got.Drafts != 1 || got.Merged != 1 {
		t.Fatalf("window beyond retention = %+v, want both events still inside the ring", got)
	}
	clock.advance(2 * decisionBucketSpan)
	if got := log.since(1000 * time.Hour); got.Drafts != 0 || got.Merged != 1 {
		t.Fatalf("after the oldest bucket left the ring = %+v, want only the merge", got)
	}
}

func TestDecisionLogZeroValueUsesWallClock(t *testing.T) {
	var log decisionLog
	log.record(outcomeProcessed)
	if got := log.since(time.Minute); got.Processed != 1 {
		t.Fatalf("zero-value log = %+v, want the processed item", got)
	}
}
