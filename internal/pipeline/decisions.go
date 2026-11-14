package pipeline

import (
	"sync"
	"time"
)

// DecisionCounts tallies what the pipeline did with the items it processed over
// a trailing window. The brief-starvation check reads it to tell a quiet period
// (nothing worth a brief arrived, or all of it was already covered) from a
// broken pipeline (items cleared the quality gate and nothing came out).
type DecisionCounts struct {
	Processed          int // items taken through the pipeline
	PassedQuality      int // items that cleared the quality gate
	Drafts             int // new drafts created
	Merged             int // items folded into an existing draft, corroborating duplicates included
	RejectedUngrounded int // assembled briefs dropped by the grounding check
	Failed             int // items whose processing returned an error
}

type outcome int

const (
	outcomeProcessed outcome = iota
	outcomePassedQuality
	outcomeDraft
	outcomeMerged
	outcomeRejectedUngrounded
	outcomeFailed
	outcomeKinds // number of outcomes; keep last
)

const (
	// decisionBucketSpan is the counters' resolution: a window is accurate to
	// within one bucket.
	decisionBucketSpan = 5 * time.Minute
	// decisionRetention is how far back counts are kept. Memory stays fixed at
	// decisionBuckets buckets however many items arrive.
	decisionRetention = 24 * time.Hour
	decisionBuckets   = int(decisionRetention / decisionBucketSpan)
)

// decisionLog keeps outcome counters in a ring of fixed-width time buckets, so
// a trailing window can be summed without storing the items behind it. The zero
// value is ready to use.
type decisionLog struct {
	mu      sync.Mutex
	now     func() time.Time // time.Now when nil; tests inject a clock
	buckets [decisionBuckets]decisionBucket
}

type decisionBucket struct {
	slot   int64 // decisionBucketSpan periods since the Unix epoch
	counts [outcomeKinds]int
}

func (l *decisionLog) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func slotOf(t time.Time) int64 {
	return t.UnixNano() / int64(decisionBucketSpan)
}

func (l *decisionLog) record(o outcome) {
	slot := slotOf(l.clock())

	l.mu.Lock()
	defer l.mu.Unlock()
	b := &l.buckets[slot%int64(decisionBuckets)]
	if b.slot != slot {
		// The bucket still holds a period from a previous lap of the ring.
		*b = decisionBucket{slot: slot}
	}
	b.counts[o]++
}

// since sums the outcomes recorded over the trailing window. Windows longer
// than decisionRetention are cut to it.
func (l *decisionLog) since(window time.Duration) DecisionCounts {
	now := l.clock()
	newest := slotOf(now)
	oldest := slotOf(now.Add(-window))
	if floor := newest - int64(decisionBuckets) + 1; oldest < floor {
		oldest = floor
	}

	var sum [outcomeKinds]int
	l.mu.Lock()
	for i := range l.buckets {
		b := &l.buckets[i]
		if b.slot < oldest || b.slot > newest {
			continue
		}
		for kind, n := range b.counts {
			sum[kind] += n
		}
	}
	l.mu.Unlock()

	return DecisionCounts{
		Processed:          sum[outcomeProcessed],
		PassedQuality:      sum[outcomePassedQuality],
		Drafts:             sum[outcomeDraft],
		Merged:             sum[outcomeMerged],
		RejectedUngrounded: sum[outcomeRejectedUngrounded],
		Failed:             sum[outcomeFailed],
	}
}
