package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type memoryJobs struct{ jobs map[string]string }

func (s *memoryJobs) GetBatchJob(k string) (string, bool, error) {
	v, ok := s.jobs[k]
	return v, ok, nil
}
func (s *memoryJobs) PutBatchJob(keys []string, name string) error {
	for _, k := range keys {
		s.jobs[k] = name
	}
	return nil
}
func (s *memoryJobs) DeleteBatchJob(keys []string) error {
	for _, k := range keys {
		delete(s.jobs, k)
	}
	return nil
}

// A timeout/restart must recover the paid remote job instead of creating a second one.
func TestVertexBatchRecoveryAfterTimeoutDoesNotCreateOrCancelAgain(t *testing.T) {
	api := &fakeBatchAPI{states: []string{"JOB_STATE_RUNNING"}}
	batch, stop := newTestBatch(api, time.Millisecond, 150*time.Millisecond)
	store := &memoryJobs{jobs: map[string]string{}}
	batch.WithJobStore(store)
	req := Request{Prompt: "resume", JSON: true}
	_, err := batch.run(context.Background(), []Request{req})
	var pending *PendingBatchError
	if !errors.As(err, &pending) {
		stop()
		t.Fatalf("timeout did not retain pending work: %v", err)
	}
	api.mu.Lock()
	cancelled := api.cancelled
	api.states = []string{jobSucceeded}
	api.polls = 0
	api.createStatus = 500
	api.mu.Unlock()
	stop()
	if cancelled {
		t.Fatal("recoverable job cancelled instead of preserved")
	}
	restarted, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	restarted.WithJobStore(store)
	answers, err := restarted.run(context.Background(), []Request{req})
	if err != nil || answers[keyOf(req)] != `{"answer": "resume"}` {
		t.Fatalf("restart resubmitted or lost remote answer: %v %v", answers, err)
	}
}

func TestVertexBatchRecoveryBelowMinimumStillBlocksDuplicateLiveCall(t *testing.T) {
	api := &fakeBatchAPI{states: []string{"JOB_STATE_RUNNING"}}
	batch, stop := newTestBatch(api, time.Millisecond, 150*time.Millisecond)
	defer stop()
	store := &memoryJobs{jobs: map[string]string{}}
	req := Request{Prompt: "still-running", JSON: true}
	store.jobs[persistentRequestKey("gemini-test", req)] = fakeJobName
	batch.WithJobStore(store)
	live := &jsonReplyClient{reply: `{"score":4}`}
	c := newPrefetchClient(live, batch, 10, quietLogger()).WithMinPrompts(5)
	c.Prefetch(context.Background(), []Request{req})
	var score boundedScore
	if err := c.GenerateJSON(context.Background(), req.Prompt, "", &score); err == nil || live.calls != 0 {
		t.Fatalf("small recovery duplicated live: calls=%d err=%v", live.calls, err)
	}
}

// A completed but unusable result must permit a fresh live call, rather than hold forever.
func TestVertexBatchPartialResultReleasesOnlyTerminalMissingRequests(t *testing.T) {
	api := &fakeBatchAPI{states: []string{jobPartiallySucceeded}}
	batch, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	store := &memoryJobs{jobs: map[string]string{}}
	batch.WithJobStore(store)
	good := Request{Prompt: "good", JSON: true}
	bad := Request{Prompt: "FAIL", JSON: true}
	answers, err := batch.run(context.Background(), []Request{good, bad})
	if err != nil || len(answers) != 1 {
		t.Fatalf("partial results=%v err=%v", answers, err)
	}
	if _, ok, _ := store.GetBatchJob(persistentRequestKey("gemini-test", good)); !ok {
		t.Fatal("unconsumed good result lost durable association")
	}
	if _, ok, _ := store.GetBatchJob(persistentRequestKey("gemini-test", bad)); ok {
		t.Fatal("terminal missing result blocks live fallback")
	}
}

// Persisting only the returned job ID misses a crash after Vertex accepted creation.
func TestVertexBatchRecoversCreationIntentWithoutResubmitting(t *testing.T) {
	req := Request{Prompt: "accepted-before-crash", JSON: true}
	api := &fakeBatchAPI{states: []string{jobSucceeded}, uploadBody: []byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"accepted-before-crash"}]}],"generationConfig":{"responseMimeType":"application/json"}}}`)}
	api.created.OutputConfig.GCSDestination.OutputURIPrefix = "gs://bkt/output/recovered/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/projects/p/locations/eu/batchPredictionJobs" {
			if r.URL.Query().Get("filter") != `display_name="ti-bot-prefetch-intent-1"` {
				t.Errorf("creation identity filter=%q", r.URL.Query().Get("filter"))
			}
			fmt.Fprintf(w, `{"batchPredictionJobs":[{"name":%q,"displayName":"ti-bot-prefetch-intent-1","state":"JOB_STATE_SUCCEEDED"}]}`, fakeJobName)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/batchPredictionJobs") {
			t.Error("accepted creation was repeated")
			http.Error(w, "duplicate", 500)
			return
		}
		api.ServeHTTP(w, r)
	}))
	defer srv.Close()
	b := &VertexBatch{project: "p", location: "eu", model: "gemini-test", bucket: "bkt", pollInterval: time.Millisecond, maxWait: time.Second, logger: quietLogger(), httpClient: &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}}}
	store := &memoryJobs{jobs: map[string]string{persistentRequestKey("gemini-test", req): creationIntentPrefix + "intent-1"}}
	b.WithJobStore(store)
	answers, err := b.run(context.Background(), []Request{req})
	if err != nil || answers[keyOf(req)] != `{"answer": "accepted-before-crash"}` {
		t.Fatalf("intent recovery lost paid result: %v %v", answers, err)
	}
	if store.jobs[persistentRequestKey("gemini-test", req)] != fakeJobName {
		t.Fatal("recovered job ID not persisted")
	}
}

// Another process may claim these requests after our initial lookup.
func TestVertexBatchLostClaimNeverSubmitsPaidJob(t *testing.T) {
	api := &fakeBatchAPI{states: []string{jobSucceeded}}
	b, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	store := &lostClaimStore{memoryJobs: memoryJobs{jobs: map[string]string{}}}
	b.WithJobStore(store)
	_, err := b.run(context.Background(), []Request{{Prompt: "claimed elsewhere", JSON: true}})
	var pending *PendingBatchError
	if !errors.As(err, &pending) {
		t.Fatalf("lost claim allowed paid submission: %v", err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.created.Model != "" || api.cancelled {
		t.Fatal("changed another owner's job")
	}
}

type lostClaimStore struct{ memoryJobs }

func (*lostClaimStore) ClaimBatchJob([]string, string) (bool, error) { return false, nil }
