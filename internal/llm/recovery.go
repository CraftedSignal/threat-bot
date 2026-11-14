package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BatchJobStore durably associates each versioned request with its paid remote job.
// PutBatchJob and DeleteBatchJob must be transactional across the supplied keys.
type BatchJobStore interface {
	GetBatchJob(requestKey string) (jobName string, ok bool, err error)
	PutBatchJob(requestKeys []string, jobName string) error
	DeleteBatchJob(requestKeys []string) error
}

// BatchJobClaimer optionally prevents two processes from submitting the same
// requests during a rollout. Claim all keys atomically, only when all are absent.
type BatchJobClaimer interface {
	ClaimBatchJob(requestKeys []string, intent string) (bool, error)
}

// PendingBatchError prevents a second live inference while a paid remote request
// is still running or its creation outcome cannot yet be established.
type PendingBatchError struct {
	Keys  []string
	Cause error
}

func (e *PendingBatchError) Error() string {
	return "remote batch work pending; duplicate inference deferred"
}
func (e *PendingBatchError) Unwrap() error                           { return e.Cause }
func (b *VertexBatch) WithJobStore(store BatchJobStore) *VertexBatch { b.store = store; return b }

const creationIntentPrefix = "creating:"

func (b *VertexBatch) run(ctx context.Context, reqs []Request) (map[string]string, error) {
	return b.runRecoverable(ctx, reqs, true)
}
func (b *VertexBatch) recover(ctx context.Context, reqs []Request) (map[string]string, error) {
	return b.runRecoverable(ctx, reqs, false)
}
func (b *VertexBatch) runRecoverable(ctx context.Context, reqs []Request, allowCreate bool) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b.store == nil {
		if allowCreate {
			return b.runNew(ctx, reqs)
		}
		return nil, nil
	}
	ctx = withBatchCallMetadata(ctx, reqs)
	groups := map[string][]Request{}
	var fresh []Request
	var pending []string
	var errs []error
	for _, r := range reqs {
		name, ok, err := b.store.GetBatchJob(persistentRequestKey(b.model, r))
		if err != nil {
			pending = append(pending, requestKey(r.vertexRequest()))
			errs = append(errs, err)
			continue
		}
		if ok {
			groups[name] = append(groups[name], r)
		} else {
			fresh = append(fresh, r)
		}
	}
	answers := map[string]string{}
	accept := func(part map[string]string, err error) {
		for k, v := range part {
			answers[k] = v
		}
		var p *PendingBatchError
		if errors.As(err, &p) {
			pending = append(pending, p.Keys...)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	for name, rs := range groups {
		part, err := b.resume(ctx, name, rs)
		accept(part, err)
	}
	if allowCreate && len(fresh) > 0 && ctx.Err() == nil {
		part, err := b.runNew(ctx, fresh)
		accept(part, err)
	}
	if len(pending) > 0 {
		return answers, &PendingBatchError{Keys: pending, Cause: errors.Join(errs...)}
	}
	return answers, errors.Join(errs...)
}
func (b *VertexBatch) requestKeys(reqs []Request) []string {
	keys := make([]string, 0, len(reqs))
	for _, r := range reqs {
		keys = append(keys, persistentRequestKey(b.model, r))
	}
	return keys
}
func pendingRequests(reqs []Request, cause error) *PendingBatchError {
	keys := make([]string, 0, len(reqs))
	for _, r := range reqs {
		keys = append(keys, requestKey(r.vertexRequest()))
	}
	return &PendingBatchError{Keys: keys, Cause: cause}
}
func wantedRequests(reqs []Request) map[string]struct{} {
	want := map[string]struct{}{}
	for _, r := range reqs {
		want[requestKey(r.vertexRequest())] = struct{}{}
	}
	return want
}

func (b *VertexBatch) resume(ctx context.Context, name string, reqs []Request) (map[string]string, error) {
	state := BatchJobReferenceState(name)
	if state == "review_required" || state == "abandoned" {
		return nil, reviewRequests(reqs, name, state)
	}
	if strings.HasPrefix(name, creationIntentPrefix) {
		id := strings.TrimPrefix(name, creationIntentPrefix)
		job, err := b.findCreatedJob(ctx, id)
		if err != nil || job == nil {
			if unresolvedCreationNeedsReview(id, time.Now()) {
				reason := "creation_not_found"
				if err != nil {
					reason = "creation_lookup_unavailable"
				}
				return b.requireCreationReview(ctx, name, reqs, reason)
			}
			return nil, pendingRequests(reqs, err)
		}
		if err := updateOwnedBatchReference(b.store, b.requestKeys(reqs), name, job.Name); err != nil {
			return nil, pendingRequests(reqs, err)
		}
		name = job.Name
	}
	b.logger.InfoContext(ctx, "recovering remote batch job", "job", name, "requests", len(reqs))
	return b.awaitStored(ctx, name, reqs)
}
func (b *VertexBatch) awaitStored(ctx context.Context, name string, reqs []Request) (map[string]string, error) {
	waitCtx, cancel := context.WithTimeout(ctx, b.maxWait)
	defer cancel()
	ticker := time.NewTicker(b.pollInterval)
	defer ticker.Stop()
	for {
		if err := waitCtx.Err(); err != nil {
			return nil, pendingRequests(reqs, err)
		}
		var job batchJob
		if err := b.call(waitCtx, http.MethodGet, b.host()+"/v1/"+name, nil, true, &job); err != nil {
			return nil, pendingRequests(reqs, err)
		}
		switch job.State {
		case jobSucceeded, jobPartiallySucceeded, jobFailed, jobCancelled, jobExpired:
			answers := map[string]string{}
			if job.OutputInfo.GCSOutputDirectory != "" {
				var err error
				answers, err = b.collect(ctx, &job, wantedRequests(reqs))
				if err != nil {
					return answers, pendingRequests(reqs, err)
				}
			}
			// Successful associations remain until a typed, validated result is cached.
			// Terminal requests without output can safely fall back to the live model.
			var missing []string
			for _, r := range reqs {
				if _, ok := answers[requestKey(r.vertexRequest())]; !ok {
					missing = append(missing, persistentRequestKey(b.model, r))
				}
			}
			if len(missing) > 0 {
				if err := updateOwnedBatchReference(b.store, missing, name, ""); err != nil {
					return answers, pendingRequests(reqs, err)
				}
			}
			return answers, nil
		}
		select {
		case <-waitCtx.Done():
			return nil, pendingRequests(reqs, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

// A durable creation intent is written before POST. If the process exits after
// Vertex accepted creation but before its response was saved, lookup by that
// exact display name recovers it; an unknown outcome is held, never resubmitted.
const batchDisplayNamePrefix = "threat-bot-prefetch-"
const legacyBatchDisplayNamePrefix = "ti-bot-prefetch-"

func matchesBatchCreationIdentity(displayName, id string) bool {
	return displayName == batchDisplayNamePrefix+id || displayName == legacyBatchDisplayNamePrefix+id
}

func (b *VertexBatch) findCreatedJob(ctx context.Context, id string) (*batchJob, error) {
	// Legacy paid jobs must remain recoverable across the application rename.
	for _, prefix := range []string{legacyBatchDisplayNamePrefix, batchDisplayNamePrefix} {
		job, err := b.findCreatedJobByDisplayName(ctx, prefix+id)
		if err != nil || job != nil {
			return job, err
		}
	}
	return nil, nil
}

func (b *VertexBatch) findCreatedJobByDisplayName(ctx context.Context, displayName string) (*batchJob, error) {
	endpoint := fmt.Sprintf("%s/v1/projects/%s/locations/%s/batchPredictionJobs", b.host(), b.project, b.location)
	query := url.Values{"filter": {`display_name="` + displayName + `"`}, "pageSize": {"100"}}
	for {
		var page struct {
			BatchPredictionJobs []batchJob `json:"batchPredictionJobs"`
			NextPageToken       string     `json:"nextPageToken"`
		}
		if err := b.call(ctx, http.MethodGet, endpoint+"?"+query.Encode(), nil, true, &page); err != nil {
			return nil, err
		}
		for _, job := range page.BatchPredictionJobs {
			if job.DisplayName == displayName && job.Name != "" {
				return &job, nil
			}
		}
		if page.NextPageToken == "" {
			return nil, nil
		}
		query.Set("pageToken", page.NextPageToken)
	}
}

type batchCallMetadataKey struct{}

func withBatchCallMetadata(ctx context.Context, reqs []Request) context.Context {
	m := map[string]CallMetadata{}
	for _, r := range reqs {
		m[requestKey(r.vertexRequest())] = r.Metadata
	}
	return context.WithValue(ctx, batchCallMetadataKey{}, m)
}
