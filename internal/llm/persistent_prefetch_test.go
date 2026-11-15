package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

type boundedScore struct {
	Score int `json:"score"`
}

func (s *boundedScore) ValidateLLMResponse() error {
	if s.Score < 1 || s.Score > 5 {
		return fmt.Errorf("score outside range")
	}
	return nil
}

type jsonReplyClient struct {
	calls int
	reply string
}

func (c *jsonReplyClient) Generate(context.Context, string, string) (string, error) {
	return c.reply, nil
}
func (c *jsonReplyClient) GenerateJSON(_ context.Context, _, _ string, out any) error {
	c.calls++
	return json.Unmarshal([]byte(c.reply), out)
}
func (c *jsonReplyClient) GenerateStructured(context.Context, string, string, *Schema, any) error {
	return errors.New("unexpected structured call")
}

// Losing the outer batch memory cache must not buy the identical model request again.
func TestPersistentPrefetchSurvivesReleaseAndRestart(t *testing.T) {
	store := &memoryCacheStore{values: map[string]string{}}
	r := Request{Prompt: "private article", System: "score", JSON: true, Schema: MustSchemaOf[boundedScore]()}
	runner := &fakeRunner{answers: map[string]string{r.Prompt: `{"score":4}`}}
	live := &jsonReplyClient{reply: `{"score":3}`}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	first := newPrefetchClient(live, runner, 10, logger).WithCache("model-a", store)
	first.Prefetch(context.Background(), []Request{r})
	var score boundedScore
	if err := first.GenerateJSON(context.Background(), r.Prompt, r.System, &score); err != nil || score.Score != 4 {
		t.Fatalf("first score=%+v err=%v", score, err)
	}
	first.Release()
	second := newPrefetchClient(live, runner, 10, logger).WithCache("model-a", store)
	second.Prefetch(context.Background(), []Request{r})
	score = boundedScore{}
	if !second.Cached(r, &score) || score.Score != 4 {
		t.Fatalf("restart lost decoded response: %+v", score)
	}
	if len(runner.got) != 1 || live.calls != 0 {
		t.Fatalf("paid duplicate requests: batches=%d live=%d", len(runner.got), live.calls)
	}
	if !strings.Contains(logs.String(), `"result":"hit"`) || strings.Contains(logs.String(), r.Prompt) {
		t.Fatalf("cache telemetry missing or exposed prompt: %s", logs.String())
	}
}

func TestPrefetchReadinessReadsDurableCacheWithoutInference(t *testing.T) {
	store := &memoryCacheStore{values: map[string]string{}}
	live := &jsonReplyClient{reply: `{"score":4}`}
	r := Request{Prompt: "p", System: "s", JSON: true, Schema: MustSchemaOf[boundedScore]()}
	if err := NewCachedClient(live, "m", store).GenerateJSON(context.Background(), r.Prompt, r.System, &boundedScore{}); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	c := newPrefetchClient(live, runner, 10, quietLogger()).WithCache("m", store)
	var score boundedScore
	if !c.Cached(r, &score) || score.Score != 4 {
		t.Fatalf("durable readiness miss: %+v", score)
	}
	for key := range store.values {
		store.values[key] = `{"score":99}`
	}
	c.Release()
	unchanged := boundedScore{Score: 2}
	if c.Cached(r, &unchanged) || unchanged.Score != 2 {
		t.Fatalf("invalid durable answer accepted/mutated output: %+v", unchanged)
	}
	if live.calls != 1 || len(runner.got) != 0 {
		t.Fatalf("readiness bought inference: live=%d batches=%d", live.calls, len(runner.got))
	}
}

// A semantically corrupt entry must neither poison scoring nor partially mutate the output.
func TestPersistentJSONRejectsInvalidSemanticAnswer(t *testing.T) {
	store := &memoryCacheStore{values: map[string]string{}}
	live := &jsonReplyClient{reply: `{"score":4}`}
	c := NewCachedClient(live, "model-a", store)
	var first boundedScore
	if err := c.GenerateJSON(context.Background(), "p", "s", &first); err != nil {
		t.Fatal(err)
	}
	for key := range store.values {
		store.values[key] = `{"score":99}`
	}
	out := boundedScore{Score: 2}
	if err := c.GenerateJSON(context.Background(), "p", "s", &out); err != nil || out.Score != 4 || live.calls != 2 {
		t.Fatalf("invalid cache accepted: out=%+v calls=%d err=%v", out, live.calls, err)
	}
	live.reply = `{"score":99}`
	if err := c.GenerateJSON(context.Background(), "other", "s", &out); err == nil || out.Score != 4 {
		t.Fatalf("invalid live response accepted/mutated out=%+v err=%v", out, err)
	}
}

func TestCachedJSONCancellationWinsOverHit(t *testing.T) {
	store := &memoryCacheStore{values: map[string]string{}}
	live := &jsonReplyClient{reply: `{"score":4}`}
	c := NewCachedClient(live, "m", store)
	var out boundedScore
	if err := c.GenerateJSON(context.Background(), "p", "s", &out); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.GenerateJSON(ctx, "p", "s", &out); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cached call=%v", err)
	}
}

func TestPrefetchKeepsPartialResultsWithoutPayingLiveForPendingRequest(t *testing.T) {
	runner := &partialPendingRunner{}
	live := &jsonReplyClient{reply: `{"score":3}`}
	c := newPrefetchClient(live, runner, 10, quietLogger())
	c.Prefetch(context.Background(), []Request{{Prompt: "ready", JSON: true}, {Prompt: "pending", JSON: true}})
	var out boundedScore
	if err := c.GenerateJSON(context.Background(), "ready", "", &out); err != nil || out.Score != 4 {
		t.Fatalf("partial result discarded: %+v %v", out, err)
	}
	if err := c.GenerateJSON(context.Background(), "pending", "", &out); err == nil {
		t.Fatal("pending remote request was sent live")
	}
	if live.calls != 0 {
		t.Fatalf("live calls=%d", live.calls)
	}
}

type partialPendingRunner struct{}

func (*partialPendingRunner) run(context.Context, []Request) (map[string]string, error) {
	return map[string]string{keyOf(Request{Prompt: "ready", JSON: true}): `{"score":4}`}, &PendingBatchError{Keys: []string{keyOf(Request{Prompt: "pending", JSON: true})}}
}

// A request beyond this round's batching limit may already be running remotely.
func TestLiveFallbackChecksDurablePendingJobEvenWithoutPrefetch(t *testing.T) {
	store := &combinedMemoryStore{memoryCacheStore: memoryCacheStore{values: map[string]string{}}, memoryJobs: memoryJobs{jobs: map[string]string{}}}
	req := Request{Prompt: "pending", JSON: true, Schema: MustSchemaOf[boundedScore]()}
	store.jobs[persistentRequestKey("model-a", req)] = fakeJobName
	live := &jsonReplyClient{reply: `{"score":3}`}
	c := newPrefetchClient(live, &fakeRunner{}, 1, quietLogger()).WithCache("model-a", store)
	var out boundedScore
	if err := c.GenerateJSON(context.Background(), req.Prompt, "", &out); err == nil || live.calls != 0 {
		t.Fatalf("durable pending request duplicated live: err=%v calls=%d", err, live.calls)
	}
}

func TestReadinessMissPreservesPaidAndAmbiguousClaims(t *testing.T) {
	for _, reference := range []string{fakeJobName, creationIntentPrefix + "20261115-unknown", batchReviewPrefix + "ambiguous", batchAbandonedPrefix + "manual"} {
		t.Run(reference, func(t *testing.T) {
			store := &combinedMemoryStore{memoryCacheStore: memoryCacheStore{values: map[string]string{}}, memoryJobs: memoryJobs{jobs: map[string]string{}}}
			req := Request{Prompt: "pending", JSON: true, Schema: MustSchemaOf[boundedScore]()}
			key := persistentRequestKey("m", req)
			store.jobs[key] = reference
			live, runner := &jsonReplyClient{}, &fakeRunner{}
			c := newPrefetchClient(live, runner, 10, quietLogger()).WithCache("m", store)
			if c.Cached(req, &boundedScore{}) {
				t.Fatal("claim mistaken for completed response")
			}
			c.Release()
			if store.jobs[key] != reference {
				t.Fatalf("readiness changed claim: %q", store.jobs[key])
			}
			var pending *PendingBatchError
			if err := c.GenerateJSON(context.Background(), req.Prompt, "", &boundedScore{}); !errors.As(err, &pending) {
				t.Fatalf("claim lost duplicate guard: %v", err)
			}
			if live.calls != 0 || len(runner.got) != 0 {
				t.Fatal("readiness/restart bought duplicate inference")
			}
		})
	}
}

type combinedMemoryStore struct {
	memoryCacheStore
	memoryJobs
}
