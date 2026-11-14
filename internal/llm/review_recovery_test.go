package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func (s *memoryJobs) CompareAndSwapBatchJob(keys []string, expected, replacement string) (bool, error) {
	for _, key := range keys {
		if s.jobs[key] != expected {
			return false, nil
		}
	}
	for _, key := range keys {
		if replacement == "" {
			delete(s.jobs, key)
		} else {
			s.jobs[key] = replacement
		}
	}
	return true, nil
}

// An old unknown creation is a visible terminal review, not an infinite silent wait.
func TestStaleUnresolvedBatchCreationRequiresDurableReview(t *testing.T) {
	lists, posts := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			lists++
			fmt.Fprint(w, `{"batchPredictionJobs":[]}`)
			return
		}
		posts++
		http.Error(w, "must not resubmit", 500)
	}))
	defer srv.Close()
	req := Request{Prompt: "claim killed before POST", JSON: true}
	key := persistentRequestKey("gemini-test", req)
	store := &memoryJobs{jobs: map[string]string{key: creationIntentPrefix + "20200101-000000-unknown"}}
	b := reviewTestBatch(srv, store)
	for range 3 {
		_, err := b.run(context.Background(), []Request{req})
		var review *BatchReviewError
		var pending *PendingBatchError
		if !errors.As(err, &review) || !errors.As(err, &pending) {
			t.Fatalf("want explicit review compatible with duplicate guard, got %v", err)
		}
	}
	if BatchJobReferenceState(store.jobs[key]) != "review_required" || lists != 2 || posts != 0 {
		t.Fatalf("review not durable: ref=%q lists=%d posts=%d", store.jobs[key], lists, posts)
	}
}

func TestBatchAbandonmentPreservesDuplicateGuard(t *testing.T) {
	req := Request{Prompt: "unknown", JSON: true, Schema: MustSchemaOf[boundedScore]()}
	key := persistentRequestKey("gemini-test", req)
	store := &combinedMemoryStore{memoryCacheStore: memoryCacheStore{values: map[string]string{}}, memoryJobs: memoryJobs{jobs: map[string]string{key: creationIntentPrefix + "20200101-000000-unknown"}}}
	original := store.jobs[key]
	if err := AbandonBatchJob(store, []string{key}, original); err != nil {
		t.Fatal(err)
	}
	if BatchJobReferenceState(store.jobs[key]) != "abandoned" {
		t.Fatalf("unknown evidence deleted: %q", store.jobs[key])
	}
	live := &jsonReplyClient{reply: `{"score":4}`}
	c := newPrefetchClient(live, &fakeRunner{}, 10, quietLogger()).WithCache("gemini-test", store)
	var out boundedScore
	err := c.GenerateJSON(context.Background(), req.Prompt, "", &out)
	var review *BatchReviewError
	if !errors.As(err, &review) || live.calls != 0 {
		t.Fatalf("abandoned work reinferred: err=%v calls=%d", err, live.calls)
	}
}

func TestBatchReconciliationVerifiesOriginalCreationIdentity(t *testing.T) {
	req := Request{Prompt: "lost response", JSON: true}
	key := persistentRequestKey("gemini-test", req)
	intent := creationIntentPrefix + "20200101-000000-known"
	store := &memoryJobs{jobs: map[string]string{key: intent}}
	display := "wrong-job"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("reconciliation mutation: %s", r.Method)
		}
		fmt.Fprintf(w, `{"name":%q,"displayName":%q,"state":"JOB_STATE_SUCCEEDED"}`, fakeJobName, display)
	}))
	defer srv.Close()
	b := reviewTestBatch(srv, store)
	if err := b.ReconcileBatchJob(context.Background(), []string{key}, intent, fakeJobName); err == nil || store.jobs[key] != intent {
		t.Fatal("attached unrelated job to unknown work")
	}
	display = "ti-bot-prefetch-20200101-000000-known"
	if err := b.ReconcileBatchJob(context.Background(), []string{key}, intent, fakeJobName); err != nil {
		t.Fatal(err)
	}
	if store.jobs[key] != fakeJobName {
		t.Fatalf("verified remote job not attached: %q", store.jobs[key])
	}
	if err := AbandonBatchJob(store, []string{key}, intent); !errors.Is(err, ErrBatchJobReferenceChanged) {
		t.Fatalf("stale operator action overwrote resolved job: %v", err)
	}
}

func TestCancelledUnsentBatchClaimReleasesOnlyOwnedIntent(t *testing.T) {
	for _, changedOwner := range []bool{false, true} {
		t.Run(fmt.Sprint("changed_owner=", changedOwner), func(t *testing.T) {
			api := &fakeBatchAPI{states: []string{jobSucceeded}}
			b, stop := newTestBatch(api, time.Millisecond, time.Second)
			defer stop()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := &cancelClaimStore{memoryJobs: memoryJobs{jobs: map[string]string{}}, cancel: cancel, changedOwner: changedOwner}
			b.WithJobStore(store)
			req := Request{Prompt: "cancel before creation", JSON: true}
			_, err := b.run(ctx, []Request{req})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			key := persistentRequestKey("gemini-test", req)
			ref, exists, _ := store.GetBatchJob(key)
			if changedOwner {
				var pending *PendingBatchError
				if !exists || ref != fakeJobName || !errors.As(err, &pending) {
					t.Fatalf("released another owner's intent: ref=%q exists=%v err=%v", ref, exists, err)
				}
			} else if exists {
				t.Fatalf("demonstrably unsent claim held indefinitely: %q", ref)
			}
			api.mu.Lock()
			defer api.mu.Unlock()
			if api.created.Model != "" || api.cancelled {
				t.Fatal("submitted or cancelled remote work after unsent cancellation")
			}
		})
	}
}

func TestDelayedCreateResponseCannotOverwriteAbandonment(t *testing.T) {
	req := Request{Prompt: "abandoned while creating", JSON: true}
	key := persistentRequestKey("gemini-test", req)
	store := &memoryJobs{jobs: map[string]string{}}
	api := &fakeBatchAPI{states: []string{jobSucceeded}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/projects/p/locations/eu/batchPredictionJobs" {
			ref := store.jobs[key]
			if err := AbandonBatchJob(store, []string{key}, ref); err != nil {
				t.Errorf("abandoning in-flight request: %v", err)
			}
		}
		api.ServeHTTP(w, r)
	}))
	defer srv.Close()
	b := reviewTestBatch(srv, store)
	_, err := b.run(context.Background(), []Request{req})
	var pending *PendingBatchError
	if !errors.As(err, &pending) || BatchJobReferenceState(store.jobs[key]) != "abandoned" {
		t.Fatalf("late provider response overwrote operator decision: ref=%q err=%v", store.jobs[key], err)
	}
}

type cancelClaimStore struct {
	memoryJobs
	cancel       context.CancelFunc
	changedOwner bool
}

func (s *cancelClaimStore) ClaimBatchJob(keys []string, intent string) (bool, error) {
	if s.changedOwner {
		intent = fakeJobName
	}
	if err := s.PutBatchJob(keys, intent); err != nil {
		return false, err
	}
	s.cancel()
	return true, nil
}

func reviewTestBatch(srv *httptest.Server, store BatchJobStore) *VertexBatch {
	return (&VertexBatch{project: "p", location: "eu", model: "gemini-test", bucket: "bkt", pollInterval: time.Millisecond, maxWait: time.Second, logger: quietLogger(), httpClient: &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}}}).WithJobStore(store)
}

func TestBatchJobPreflightRejectsMalformedNamesBeforeRemoteAccess(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	store := &memoryJobs{jobs: map[string]string{"request": fakeJobName}}
	batch := reviewTestBatch(server, store)
	if err := ValidateBatchJobResourceName(fakeJobName); err != nil {
		t.Fatalf("existing complete resource rejected: %v", err)
	}
	for _, name := range []string{"", "job-1", "projects//locations/eu/batchPredictionJobs/job-1", "projects/p/locations//batchPredictionJobs/job-1", "projects/p/locations/eu/batchPredictionJobs/", "projects/p/locations/eu/jobs/job-1", fakeJobName + "/extra"} {
		if err := ValidateBatchJobResourceName(name); err == nil {
			t.Errorf("malformed resource passed preflight: %q", name)
		}
		if err := batch.ReconcileBatchJob(context.Background(), []string{"request"}, fakeJobName, name); err == nil {
			t.Errorf("malformed resource reached reconciliation: %q", name)
		}
	}
	if requests.Load() != 0 || store.jobs["request"] != fakeJobName {
		t.Fatalf("malformed resource caused side effects: requests=%d reference=%q", requests.Load(), store.jobs["request"])
	}
}
