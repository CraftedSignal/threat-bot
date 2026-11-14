package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	batchReviewPrefix    = "review:"
	batchAbandonedPrefix = "abandoned:"
	// BatchCreationReviewAfter bounds automatic attempts to discover an ambiguous
	// creation. Expiry moves it to manual review; it NEVER authorizes resubmission.
	BatchCreationReviewAfter = time.Hour
)

// BatchJobReconciler atomically replaces all matching references. An empty
// replacement deletes only matching records (for demonstrably unsent claims).
type BatchJobReconciler interface {
	CompareAndSwapBatchJob(requestKeys []string, expectedReference, replacementReference string) (bool, error)
}

var ErrBatchJobReferenceChanged = errors.New("batch job reference changed; inspect its current state before reconciling")

// BatchReviewError is terminal for automatic inference. It unwraps the existing
// deferred-work guard so quality fallback/extraction cannot pay for a duplicate.
type BatchReviewError struct {
	Reference string
	Reason    string
	Pending   *PendingBatchError
}

func (e *BatchReviewError) Error() string {
	return "batch job requires review (" + e.Reason + "); duplicate inference blocked"
}
func (e *BatchReviewError) Unwrap() error { return e.Pending }
func reviewRequests(reqs []Request, ref, reason string) *BatchReviewError {
	return &BatchReviewError{Reference: ref, Reason: reason, Pending: pendingRequests(reqs, nil)}
}

// BatchJobReferenceState is suitable for operational inspection/counts.
func BatchJobReferenceState(ref string) string {
	switch {
	case strings.HasPrefix(ref, batchAbandonedPrefix):
		return "abandoned"
	case strings.HasPrefix(ref, batchReviewPrefix):
		return "review_required"
	case strings.HasPrefix(ref, creationIntentPrefix):
		return "creating"
	default:
		return "remote"
	}
}
func originalBatchReference(ref string) string {
	for {
		switch {
		case strings.HasPrefix(ref, batchReviewPrefix):
			ref = strings.TrimPrefix(ref, batchReviewPrefix)
		case strings.HasPrefix(ref, batchAbandonedPrefix):
			ref = strings.TrimPrefix(ref, batchAbandonedPrefix)
		default:
			return ref
		}
	}
}
func swapBatchReference(store BatchJobStore, keys []string, expected, replacement string) error {
	if len(keys) == 0 || expected == "" {
		return fmt.Errorf("batch reconciliation requires keys and expected reference")
	}
	atomic, ok := store.(BatchJobReconciler)
	if !ok {
		return fmt.Errorf("batch reconciliation requires an atomic store")
	}
	changed, err := atomic.CompareAndSwapBatchJob(keys, expected, replacement)
	if err != nil {
		return err
	}
	if !changed {
		return ErrBatchJobReferenceChanged
	}
	return nil
}

// updateOwnedBatchReference protects operational review/abandon decisions from
// delayed responses. Legacy stores without reconciliation support cannot expose
// those concurrent operations and retain their original single-process behavior.
func updateOwnedBatchReference(store BatchJobStore, keys []string, expected, replacement string) error {
	if _, ok := store.(BatchJobReconciler); ok {
		return swapBatchReference(store, keys, expected, replacement)
	}
	if replacement == "" {
		return store.DeleteBatchJob(keys)
	}
	return store.PutBatchJob(keys, replacement)
}

// AbandonBatchJob explicitly dead-letters work while retaining its unknown-paid-
// work tombstone. It does not delete the guard or authorize another inference.
func AbandonBatchJob(store BatchJobStore, keys []string, expectedReference string) error {
	replacement := expectedReference
	if BatchJobReferenceState(replacement) != "abandoned" {
		replacement = batchAbandonedPrefix + replacement
	}
	return swapBatchReference(store, keys, expectedReference, replacement)
}

// ValidateBatchJobResourceName checks the resource shape without accessing
// credentials, storage, or the provider. Reconciliation separately verifies
// the remote job identity and its ownership of the original request.
func ValidateBatchJobResourceName(name string) error {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[1] == "" || parts[2] != "locations" || parts[3] == "" || parts[4] != "batchPredictionJobs" || parts[5] == "" {
		return fmt.Errorf("confirmed batch job must be a full resource name")
	}
	return nil
}

// ReconcileBatchJob attaches an existing, GET-verified remote job. An intent can
// only attach its own exact creation displayName; an existing job tombstone can
// only restore that same job. No model inference or provider write is performed.
func (b *VertexBatch) ReconcileBatchJob(ctx context.Context, keys []string, expectedReference, confirmedJobName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateBatchJobResourceName(confirmedJobName); err != nil {
		return err
	}
	var job batchJob
	if err := b.call(ctx, http.MethodGet, b.host()+"/v1/"+confirmedJobName, nil, true, &job); err != nil {
		return err
	}
	if job.Name != confirmedJobName {
		return fmt.Errorf("remote job identity does not match the confirmed resource")
	}
	original := originalBatchReference(expectedReference)
	if strings.HasPrefix(original, creationIntentPrefix) {
		if !matchesBatchCreationIdentity(job.DisplayName, strings.TrimPrefix(original, creationIntentPrefix)) {
			return fmt.Errorf("remote job does not match the original creation intent")
		}
	} else if original != confirmedJobName {
		return fmt.Errorf("reconciliation cannot replace an unrelated remote job")
	}
	return swapBatchReference(b.store, keys, expectedReference, job.Name)
}

func unresolvedCreationNeedsReview(id string, now time.Time) bool {
	if len(id) < 15 {
		return true
	}
	created, err := time.Parse("20060102-150405", id[:15])
	if err != nil {
		return true
	}
	return created.After(now.Add(5*time.Minute)) || now.Sub(created) >= BatchCreationReviewAfter
}
func (b *VertexBatch) requireCreationReview(ctx context.Context, ref string, reqs []Request, reason string) (map[string]string, error) {
	replacement := batchReviewPrefix + ref
	if err := swapBatchReference(b.store, b.requestKeys(reqs), ref, replacement); err != nil {
		if errors.Is(err, ErrBatchJobReferenceChanged) {
			return nil, pendingRequests(reqs, err)
		}
		b.logger.ErrorContext(ctx, "batch review state persistence failed", "reference", ref, "requests", len(reqs))
		return nil, reviewRequests(reqs, ref, "review_state_persistence_failed")
	}
	b.logger.ErrorContext(ctx, "batch creation requires manual review", "reference", replacement, "reason", reason, "requests", len(reqs))
	return nil, reviewRequests(reqs, replacement, reason)
}
