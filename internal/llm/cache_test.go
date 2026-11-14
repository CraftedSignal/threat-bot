package llm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type cacheTestClient struct {
	response string
	err      error
	calls    int
}

func (c *cacheTestClient) Generate(context.Context, string, string) (string, error) {
	return c.response, c.err
}

func (c *cacheTestClient) GenerateJSON(_ context.Context, _, _ string, out any) error {
	c.calls++
	if c.err != nil {
		return c.err
	}
	return json.Unmarshal([]byte(c.response), out)
}

type memoryCacheStore struct {
	values map[string]string
	putErr error
}

func (s *memoryCacheStore) GetLLMCache(key string) (string, bool, error) {
	value, ok := s.values[key]
	return value, ok, nil
}

func (s *memoryCacheStore) PutLLMCache(key, response string) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.values[key] = response
	return nil
}

func TestCachedClientReusesSuccessfulStructuredResponse(t *testing.T) {
	inner := &cacheTestClient{response: `{"items":["one"]}`}
	store := &memoryCacheStore{values: make(map[string]string)}
	client := NewCachedClient(inner, "model-a", store)

	type result struct {
		Items []string `json:"items"`
	}
	var first result
	if err := client.GenerateJSON(context.Background(), "prompt", "system", &first); err != nil {
		t.Fatal(err)
	}
	first.Items[0] = "mutated"

	var second result
	if err := client.GenerateJSON(context.Background(), "prompt", "system", &second); err != nil {
		t.Fatal(err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d, want 1", inner.calls)
	}
	if got := second.Items[0]; got != "one" {
		t.Fatalf("cached result = %q, want fresh decoded value", got)
	}
}

func TestCachedClientDoesNotCacheFailedStructuredResponse(t *testing.T) {
	inner := &cacheTestClient{err: errors.New("invalid JSON")}
	store := &memoryCacheStore{values: make(map[string]string)}
	client := NewCachedClient(inner, "model-a", store)

	for range 2 {
		var out map[string]any
		if err := client.GenerateJSON(context.Background(), "prompt", "system", &out); err == nil {
			t.Fatal("expected structured generation error")
		}
	}
	if inner.calls != 2 {
		t.Fatalf("inner calls = %d, want 2", inner.calls)
	}
	if len(store.values) != 0 {
		t.Fatalf("failed response was cached: %#v", store.values)
	}
}

func TestCachedClientIgnoresCacheWriteFailure(t *testing.T) {
	inner := &cacheTestClient{response: `{"ok":true}`}
	store := &memoryCacheStore{values: make(map[string]string), putErr: errors.New("disk full")}
	client := NewCachedClient(inner, "model-a", store)

	var out map[string]any
	if err := client.GenerateJSON(context.Background(), "prompt", "system", &out); err != nil {
		t.Fatalf("cache write failure should fail open: %v", err)
	}
	if out["ok"] != true {
		t.Fatalf("unexpected output: %#v", out)
	}
}

func (c *cacheTestClient) GenerateStructured(context.Context, string, string, *Schema, any) error {
	c.calls++
	return c.err
}
