package llm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type structuredCacheClient struct {
	response string
	err      error
	calls    int
}

func (c *structuredCacheClient) Generate(context.Context, string, string) (string, error) {
	return "", errors.New("unexpected plain generation")
}
func (c *structuredCacheClient) GenerateJSON(_ context.Context, _, _ string, out any) error {
	c.calls++
	return json.Unmarshal([]byte(c.response), out)
}
func (c *structuredCacheClient) GenerateStructured(_ context.Context, _, _ string, _ *Schema, out any) error {
	c.calls++
	if c.err != nil {
		return c.err
	}
	return DecodeStructured(c.response, out)
}

func generationContext(stage string) context.Context {
	return WithCallMetadata(context.Background(), CallMetadata{Stage: stage})
}

func TestStructuredGenerationCacheSurvivesRestart(t *testing.T) {
	for _, stage := range []string{"assembly"} {
		t.Run(stage, func(t *testing.T) {
			store := &memoryCacheStore{values: map[string]string{}}
			live := &structuredCacheClient{response: `{"name":"original","where":["one"]}`}
			schema := MustSchemaOf[schemaInner]()
			var first schemaInner
			if err := NewCachedClient(live, "m", store).GenerateStructured(generationContext(stage), "p", "s", schema, &first); err != nil {
				t.Fatal(err)
			}
			first.Where[0] = "caller mutation"
			var second schemaInner
			if err := NewCachedClient(live, "m", store).GenerateStructured(generationContext(stage), "p", "s", schema, &second); err != nil {
				t.Fatal(err)
			}
			if live.calls != 1 || second.Name != "original" || len(second.Where) != 1 || second.Where[0] != "one" {
				t.Fatalf("generation was bought again or cache aliased caller: calls=%d value=%+v", live.calls, second)
			}
		})
	}
}

func TestStructuredVerdictsAlwaysRunLive(t *testing.T) {
	for _, stage := range []string{"", "grounding", "grounding_recheck", "grounding_repair", "rule_repair", "claim_evidence_grounding", "merge_relevance", "quality", "validation", "assembly_verdict"} {
		t.Run(stage, func(t *testing.T) {
			store := &memoryCacheStore{values: map[string]string{}}
			live := &structuredCacheClient{response: `{"score":4}`}
			client := NewCachedClient(live, "m", store)
			for range 2 {
				var score boundedScore
				if err := client.GenerateStructured(generationContext(stage), "p", "s", MustSchemaOf[boundedScore](), &score); err != nil {
					t.Fatal(err)
				}
			}
			if live.calls != 2 || len(store.values) != 0 {
				t.Fatalf("factual verdict memoized: calls=%d cache entries=%d", live.calls, len(store.values))
			}
		})
	}
}

func TestStructuredGenerationCacheKeysAllInputsAndMode(t *testing.T) {
	store := &memoryCacheStore{values: map[string]string{}}
	live := &structuredCacheClient{response: `{"score":4}`}
	schema := MustSchemaOf[boundedScore]()
	changedSchema := MustSchemaOf[boundedScore]()
	changedSchema.Description = "different response contract"
	ctx := generationContext("assembly")
	for _, tc := range []struct {
		model, prompt, system string
		schema                *Schema
	}{
		{"m", "p", "s", schema},
		{"other", "p", "s", schema},
		{"m", "other", "s", schema},
		{"m", "p", "other", schema},
		{"m", "p", "s", changedSchema},
	} {
		for range 2 {
			var out boundedScore
			if err := NewCachedClient(live, tc.model, store).GenerateStructured(ctx, tc.prompt, tc.system, tc.schema, &out); err != nil {
				t.Fatal(err)
			}
		}
	}
	if live.calls != 5 {
		t.Fatalf("distinct requests shared answers or repeated: calls=%d want5", live.calls)
	}
	// An unconstrained JSON answer may not stand in for a constrained answer.
	var out boundedScore
	client := NewCachedClient(live, "fresh", store)
	if err := client.GenerateJSON(ctx, "p", "s", &out); err != nil {
		t.Fatal(err)
	}
	if err := client.GenerateStructured(ctx, "p", "s", schema, &out); err != nil {
		t.Fatal(err)
	}
	if live.calls != 7 {
		t.Fatalf("constrained generation reused plain JSON: calls=%d want7", live.calls)
	}
}

func TestStructuredGenerationCacheRejectsInvalidArtifact(t *testing.T) {
	for _, corrupt := range []string{`{"score":99}`, `{"score":"4"}`, "```json\n{\"score\":4}\n```"} {
		t.Run(corrupt, func(t *testing.T) {
			store := &memoryCacheStore{values: map[string]string{}}
			live := &structuredCacheClient{response: `{"score":4}`}
			client := NewCachedClient(live, "m", store)
			ctx := generationContext("assembly")
			var out boundedScore
			if err := client.GenerateStructured(ctx, "p", "s", MustSchemaOf[boundedScore](), &out); err != nil {
				t.Fatal(err)
			}
			if len(store.values) != 1 {
				t.Fatalf("successful generation not durable: entries=%d", len(store.values))
			}
			for key := range store.values {
				store.values[key] = corrupt
			}
			if err := client.GenerateStructured(ctx, "p", "s", MustSchemaOf[boundedScore](), &out); err != nil || out.Score != 4 || live.calls != 2 {
				t.Fatalf("invalid cache artifact accepted: calls=%d out=%+v err=%v", live.calls, out, err)
			}
		})
	}
}

func TestStructuredGenerationDoesNotCacheFailuresOrCancellation(t *testing.T) {
	for _, failure := range []error{errors.New("provider unavailable"), &FinishReasonError{Reason: finishMaxTokens, Text: `{"score":`}} {
		store := &memoryCacheStore{values: map[string]string{}}
		live := &structuredCacheClient{err: failure}
		client := NewCachedClient(live, "m", store)
		for range 2 {
			var out boundedScore
			if err := client.GenerateStructured(generationContext("assembly"), "p", "s", MustSchemaOf[boundedScore](), &out); !errors.Is(err, failure) {
				t.Fatalf("generation failure changed: %v", err)
			}
		}
		if live.calls != 2 || len(store.values) != 0 {
			t.Fatalf("failure cached: calls=%d entries=%d", live.calls, len(store.values))
		}
	}
	store := &memoryCacheStore{values: map[string]string{}}
	live := &structuredCacheClient{response: `{"score":4}`}
	client := NewCachedClient(live, "m", store)
	var out boundedScore
	ctx, cancel := context.WithCancel(generationContext("assembly"))
	if err := client.GenerateStructured(ctx, "p", "s", MustSchemaOf[boundedScore](), &out); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := client.GenerateStructured(ctx, "p", "s", MustSchemaOf[boundedScore](), &out); !errors.Is(err, context.Canceled) || live.calls != 1 {
		t.Fatalf("cancellation lost to cached answer: calls=%d err=%v", live.calls, err)
	}
}
