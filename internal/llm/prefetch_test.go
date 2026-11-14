package llm

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

// fakeLive is the live model behind a PrefetchClient. It records every call.
type fakeLive struct {
	mu    sync.Mutex
	calls []Request
}

func (f *fakeLive) Generate(_ context.Context, prompt, system string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Request{Prompt: prompt, System: system})
	return "live: " + prompt, nil
}

func (f *fakeLive) GenerateJSON(_ context.Context, prompt, system string, out any) error {
	f.mu.Lock()
	f.calls = append(f.calls, Request{Prompt: prompt, System: system, JSON: true})
	f.mu.Unlock()
	return json.Unmarshal([]byte(`{"from":"live"}`), out)
}

// fakeRunner answers requests with a canned text per prompt.
type fakeRunner struct {
	answers map[string]string // by prompt
	err     error
	got     [][]Request
}

func (f *fakeRunner) run(_ context.Context, reqs []Request) (map[string]string, error) {
	f.got = append(f.got, reqs)
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]string{}
	for _, r := range reqs {
		if text, ok := f.answers[r.Prompt]; ok {
			out[keyOf(r)] = text
		}
	}
	return out, nil
}

type verdict struct {
	Score int    `json:"score"`
	Note  string `json:"note"`
}

func TestPrefetchClientServesHitsAndFallsThroughOnMiss(t *testing.T) {
	live := &fakeLive{}
	runner := &fakeRunner{answers: map[string]string{
		"scored":   "```json\n{\"score\": 4, \"note\": \"fenced\"}\n```", // fences are stripped as on the live path
		"wrapped":  `[{"score": 2}]`,                                     // so is a one-element array
		"plain":    "a plain-text answer",
		"answered": `{"score": 1}`,
	}}
	c := newPrefetchClient(live, runner, 500, quietLogger())
	c.Prefetch(context.Background(), []Request{
		{Prompt: "scored", System: "sys", JSON: true},
		{Prompt: "wrapped", System: "sys", JSON: true},
		{Prompt: "plain"},
		{Prompt: "unanswered", System: "sys", JSON: true},
		{Prompt: "answered", System: "sys", JSON: true},
	})

	var v verdict
	if err := c.GenerateJSON(context.Background(), "scored", "sys", &v); err != nil || v != (verdict{4, "fenced"}) {
		t.Fatalf("hit: v = %+v, err = %v", v, err)
	}
	v = verdict{}
	if err := c.GenerateJSON(context.Background(), "wrapped", "sys", &v); err != nil || v.Score != 2 {
		t.Fatalf("wrapped hit: v = %+v, err = %v", v, err)
	}
	if text, err := c.Generate(context.Background(), "plain", ""); err != nil || text != "a plain-text answer" {
		t.Fatalf("plain hit: %q, %v", text, err)
	}
	if len(live.calls) != 0 {
		t.Fatalf("hits reached the live model: %v", live.calls)
	}

	// A miss, a different system prompt and a different mode all go live.
	v = verdict{}
	if err := c.GenerateJSON(context.Background(), "unanswered", "sys", &v); err != nil {
		t.Fatal(err)
	}
	_ = c.GenerateJSON(context.Background(), "scored", "another system", &v)
	_, _ = c.Generate(context.Background(), "scored", "sys")
	if len(live.calls) != 3 {
		t.Fatalf("live calls = %v, want the miss, the other system prompt and the other mode", live.calls)
	}
}

func TestPrefetchClientRunnerFailureLeavesEverythingLive(t *testing.T) {
	live := &fakeLive{}
	c := newPrefetchClient(live, &fakeRunner{err: errors.New("job failed")}, 500, quietLogger())
	c.Prefetch(context.Background(), []Request{{Prompt: "p", JSON: true}})

	var v verdict
	if err := c.GenerateJSON(context.Background(), "p", "", &v); err != nil || len(live.calls) != 1 {
		t.Fatalf("err = %v, live calls = %v; want the prompt answered live", err, live.calls)
	}
}

func TestPrefetchClientMalformedAnswerGoesLiveAndLeavesOutUntouched(t *testing.T) {
	live := &fakeLive{}
	runner := &fakeRunner{answers: map[string]string{"p": `{"score": "not a number", "note": "half"}`}}
	c := newPrefetchClient(live, runner, 500, quietLogger())
	c.Prefetch(context.Background(), []Request{{Prompt: "p", JSON: true}})

	if c.Cached(Request{Prompt: "p", JSON: true}, &verdict{}) {
		t.Error("Cached reported a hit for an answer that does not decode")
	}
	var out verdict
	if err := c.GenerateJSON(context.Background(), "p", "", &out); err != nil || len(live.calls) != 1 {
		t.Fatalf("err = %v, live calls = %v; want the prompt answered live", err, live.calls)
	}
	if out != (verdict{}) {
		t.Fatalf("out = %+v, want nothing kept from the malformed answer", out)
	}

	// The failed decode must not leave half an answer in out.
	partial := verdict{}
	if err := decodeInto(`{"score": "x", "note": "half"}`, &partial); err == nil || partial != (verdict{}) {
		t.Fatalf("decodeInto left %+v behind after %v", partial, err)
	}
}

func TestPrefetchClientCachedNeverCallsLive(t *testing.T) {
	live := &fakeLive{}
	runner := &fakeRunner{answers: map[string]string{"scored": `{"score": 3}`}}
	c := newPrefetchClient(live, runner, 500, quietLogger())
	c.Prefetch(context.Background(), []Request{{Prompt: "scored", JSON: true}, {Prompt: "missing", JSON: true}})

	var v verdict
	if !c.Cached(Request{Prompt: "scored", JSON: true}, &v) || v.Score != 3 {
		t.Fatalf("Cached(scored) = %+v", v)
	}
	if c.Cached(Request{Prompt: "missing", JSON: true}, &v) {
		t.Error("Cached reported a hit for a request the batch did not answer")
	}
	if len(live.calls) != 0 {
		t.Errorf("Cached reached the live model: %v", live.calls)
	}
}

func TestPrefetchClientReleaseClearsTheCache(t *testing.T) {
	live := &fakeLive{}
	runner := &fakeRunner{answers: map[string]string{"p": `{"score": 5}`}}
	c := newPrefetchClient(live, runner, 500, quietLogger())
	c.Prefetch(context.Background(), []Request{{Prompt: "p", JSON: true}})
	c.Release()

	var v verdict
	if err := c.GenerateJSON(context.Background(), "p", "", &v); err != nil || len(live.calls) != 1 {
		t.Fatalf("err = %v, live calls = %v; want the released answer gone", err, live.calls)
	}
}

func TestPrefetchClientSendsAtMostMaxPrompts(t *testing.T) {
	runner := &fakeRunner{answers: map[string]string{"a": `{}`, "b": `{}`, "c": `{}`}}
	live := &fakeLive{}
	c := newPrefetchClient(live, runner, 2, quietLogger())
	c.Prefetch(context.Background(), []Request{{Prompt: "a", JSON: true}, {Prompt: "b", JSON: true}, {Prompt: "c", JSON: true}})

	if len(runner.got) != 1 || len(runner.got[0]) != 2 {
		t.Fatalf("batch carried %v, want the first 2 requests", runner.got)
	}
	var v verdict
	_ = c.GenerateJSON(context.Background(), "c", "", &v)
	if len(live.calls) != 1 {
		t.Fatalf("the request over max_prompts did not run live: %v", live.calls)
	}
}

func TestPrefetchClientKeepsAnswersFromSuccessiveBatches(t *testing.T) {
	runner := &fakeRunner{answers: map[string]string{"first": `{"score": 1}`, "second": `{"score": 2}`}}
	live := &fakeLive{}
	c := newPrefetchClient(live, runner, 500, quietLogger())
	c.Prefetch(context.Background(), []Request{{Prompt: "first", JSON: true}})
	c.Prefetch(context.Background(), []Request{{Prompt: "second", JSON: true}})

	var v verdict
	for _, p := range []string{"first", "second"} {
		if !c.Cached(Request{Prompt: p, JSON: true}, &v) {
			t.Errorf("answer to %q was lost", p)
		}
	}
}

func TestRequestKeyIgnoresEncodingAndSeparatesFields(t *testing.T) {
	base := Request{Prompt: "ab", System: "c", JSON: true}
	if keyOf(base) != keyOf(Request{Prompt: "ab", System: "c", JSON: true}) {
		t.Error("equal requests have different keys")
	}
	for name, other := range map[string]Request{
		"prompt":       {Prompt: "a", System: "c", JSON: true},
		"system":       {Prompt: "ab", System: "d", JSON: true},
		"mode":         {Prompt: "ab", System: "c"},
		"field border": {Prompt: "a", System: "bc", JSON: true},
	} {
		if keyOf(base) == keyOf(other) {
			t.Errorf("requests differing in %s share a key", name)
		}
	}
}

// A handful of prompts is not worth a batch job: the job queues for minutes
// and can outlive max_wait, while live calls answer at once.
func TestPrefetchClientRunsSmallSetsLive(t *testing.T) {
	live := &fakeLive{}
	runner := &fakeRunner{answers: map[string]string{"a": "x"}}
	c := newPrefetchClient(live, runner, 500, quietLogger()).WithMinPrompts(5)

	c.Prefetch(context.Background(), []Request{{Prompt: "a"}, {Prompt: "b"}, {Prompt: "c"}, {Prompt: "d"}})
	if len(runner.got) != 0 {
		t.Fatalf("batch ran for 4 prompts: %v", runner.got)
	}

	c.Prefetch(context.Background(), []Request{{Prompt: "a"}, {Prompt: "b"}, {Prompt: "c"}, {Prompt: "d"}, {Prompt: "e"}})
	if len(runner.got) != 1 {
		t.Fatalf("batch runs = %d, want 1 for 5 prompts", len(runner.got))
	}
}

func (f *fakeLive) GenerateStructured(ctx context.Context, prompt, system string, _ *Schema, out any) error {
	return f.GenerateJSON(ctx, prompt, system, out)
}
