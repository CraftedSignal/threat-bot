package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVertexUsageAttributesProviderTokensWithoutPromptDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"candidates":[{"finishReason":"STOP","content":{"parts":[{"text":"{\"score\":4}"}]}}],"usageMetadata":{"promptTokenCount":101,"candidatesTokenCount":11,"thoughtsTokenCount":7,"cachedContentTokenCount":33,"totalTokenCount":119}}`)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	c := newVertexAIClientWithHTTP("p", "eu", "model-a", &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}}).WithLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	ctx := WithCallMetadata(context.Background(), CallMetadata{SourceID: "rss:item", Stage: "extract", AttemptID: "attempt-1"})
	var out boundedScore
	if err := c.GenerateJSON(ctx, "SECRET ARTICLE", "SECRET SYSTEM", &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"stage":"extract"`, `"source_id":"rss:item"`, `"input_tokens":101`, `"output_tokens":11`, `"thinking_tokens":7`, `"cached_tokens":33`, `"finish_reason":"STOP"`} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("missing %s in %s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Fatalf("prompt leaked: %s", logs.String())
	}
}

// Re-reading a recovered result is not a second billable generation event.
func TestRecoveredBatchUsageHasStableAccountingIdentity(t *testing.T) {
	api := &fakeBatchAPI{states: []string{jobSucceeded}}
	b, stop := newTestBatch(api, time.Millisecond, time.Second)
	defer stop()
	var logs bytes.Buffer
	b.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	store := &memoryJobs{jobs: map[string]string{}}
	b.WithJobStore(store)
	req := Request{Prompt: "batch secret", JSON: true, Metadata: CallMetadata{SourceID: "rss:batch", Stage: "quality"}}
	for range 2 {
		if _, err := b.run(context.Background(), []Request{req}); err != nil {
			t.Fatal(err)
		}
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e["msg"] == "llm usage" {
			id, _ := e["usage_event_id"].(string)
			if id == "" {
				t.Fatalf("missing dedup identity: %s", line)
			}
			ids = append(ids, id)
			if e["stage"] != "quality" || e["source_id"] != "rss:batch" {
				t.Fatalf("lost per-request attribution: %s", line)
			}
		}
	}
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("recovery counts as new spend: %v", ids)
	}
	if strings.Contains(logs.String(), "batch secret") {
		t.Fatal("batch prompt leaked")
	}
}

func TestVertexRetryTelemetryDoesNotExposeProviderErrorBody(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "SECRET PROVIDER BODY", 500)
			return
		}
		fmt.Fprint(w, `{"candidates":[{"content":{"parts":[{"text":"{\"score\":4}"}]}}]}`)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	c := newVertexAIClientWithHTTP("p", "eu", "model-a", &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}}).WithLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	var out boundedScore
	if err := c.GenerateJSON(WithCallMetadata(context.Background(), CallMetadata{Stage: "quality", SourceID: "rss:retry"}), "SECRET PROMPT", "", &out); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !strings.Contains(logs.String(), `"msg":"llm retry"`) || !strings.Contains(logs.String(), `"http_status":500`) {
		t.Fatalf("unobserved retry: calls=%d logs=%s", calls, logs.String())
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Fatal("retry log exposed response or source text")
	}
}

func TestUsageTelemetryRedactsUnknownFinishReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"candidates":[{"finishReason":"BENIGN_REASON_SENTINEL","content":{"parts":[{"text":"BENIGN_CONTENT_SENTINEL"}]}}]}`)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	client := newVertexAIClientWithHTTP("p", "eu", "model", &http.Client{Transport: &rewriteTransport{base: srv.Client().Transport, target: srv.URL}}).WithLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	var out boundedScore
	err := client.GenerateJSON(context.Background(), "BENIGN_PROMPT_SENTINEL", "", &out)
	if err == nil {
		t.Fatal("unknown finish reason should reject output")
	}
	if strings.Contains(logs.String(), "SENTINEL") || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatal("provider-controlled error content reached telemetry")
	}
	if !strings.Contains(logs.String(), `"error_kind":"finish_reason"`) {
		t.Fatal("redaction lost bounded error classification")
	}
}
