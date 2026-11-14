package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

type fakeHealthClient struct {
	err error
	ok  bool
}

func (c *fakeHealthClient) Generate(context.Context, string, string) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	if c.ok {
		return `{"ok":true}`, nil
	}
	return `{"ok":false}`, nil
}

func (c *fakeHealthClient) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	resp, err := c.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(resp), out)
}

func TestSmokeCheck(t *testing.T) {
	if err := SmokeCheck(context.Background(), &fakeHealthClient{ok: true}); err != nil {
		t.Fatalf("SmokeCheck returned error: %v", err)
	}
	if err := SmokeCheck(context.Background(), &fakeHealthClient{ok: false}); err == nil {
		t.Fatal("expected unexpected response error")
	}
}

func TestHealthMonitorTracksLatestStatus(t *testing.T) {
	monitor := NewHealthMonitor()
	client := &fakeHealthClient{ok: true}
	wrapped := monitor.Wrap("primary", "test-model", client)

	if status := monitor.Status(); status.OK {
		t.Fatal("unchecked model should be unhealthy")
	}

	if err := SmokeCheck(context.Background(), wrapped); err != nil {
		t.Fatal(err)
	}
	if status := monitor.Status(); !status.OK {
		t.Fatalf("model should be healthy after smoke check: %s", status.Message)
	}

	client.err = errors.New("provider down")
	if err := wrapped.GenerateJSON(context.Background(), "prompt", "system", &struct{}{}); err == nil {
		t.Fatal("expected provider error")
	}
	status := monitor.Status()
	if status.OK {
		t.Fatal("model should be unhealthy after latest call fails")
	}
	if len(status.Models) != 1 || status.Models[0].ConsecutiveErrors != 1 {
		t.Fatalf("unexpected model status: %+v", status.Models)
	}
}

func TestIsModelUnavailable(t *testing.T) {
	if !IsModelUnavailable(&HTTPError{StatusCode: 404, Body: "Publisher Model was not found"}) {
		t.Fatal("404 should be model unavailable")
	}
	if !IsModelUnavailable(&HTTPError{StatusCode: 410, Body: "model shut down"}) {
		t.Fatal("410 should be model unavailable")
	}
	if IsModelUnavailable(&HTTPError{StatusCode: 429, Body: "rate limit"}) {
		t.Fatal("429 should not be model unavailable")
	}
	if status, ok := HTTPStatus(&HTTPError{StatusCode: 500, Body: "boom"}); !ok || status != 500 {
		t.Fatalf("HTTPStatus = %d, %v; want 500, true", status, ok)
	}
}

func (c *fakeHealthClient) GenerateStructured(ctx context.Context, prompt, system string, _ *Schema, out any) error {
	return c.GenerateJSON(ctx, prompt, system, out)
}

func TestHealthIgnoresContentOutcomes(t *testing.T) {
	monitor := NewHealthMonitor()
	client := &fakeHealthClient{ok: true}
	wrapped := monitor.Wrap("primary", "test-model", client)
	if err := SmokeCheck(context.Background(), wrapped); err != nil {
		t.Fatal(err)
	}
	for _, content := range []error{
		&FinishReasonError{Reason: "MAX_TOKENS", Text: "{"},
		&FinishReasonError{Reason: "SAFETY"},
		&OutputError{Err: errors.New("bad"), Text: "x"},
		fmt.Errorf("wrapped: %w", &FinishReasonError{Reason: "MAX_TOKENS"}),
	} {
		client.err = content
		if err := wrapped.GenerateStructured(context.Background(), "p", "s", nil, &struct{}{}); err == nil {
			t.Fatal("expected the content error")
		}
		if status := monitor.Status(); !status.OK {
			t.Fatalf("%v marked the dependency unhealthy: %s", content, status.Message)
		}
	}
	client.err = &HTTPError{StatusCode: 503, Body: "unavailable"}
	if err := wrapped.GenerateStructured(context.Background(), "p", "s", nil, &struct{}{}); err == nil {
		t.Fatal("expected the transport error")
	}
	if status := monitor.Status(); status.OK {
		t.Fatal("a 5xx must mark the dependency unhealthy")
	}
}
