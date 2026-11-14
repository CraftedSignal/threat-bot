package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"time"
)

// CallMetadata attributes model work without retaining source text or prompts.
// Nonempty fields merge with existing metadata when a substage is entered.
type CallMetadata struct {
	SourceID  string
	Stage     string
	AttemptID string
}
type callMetadataKey struct{}

func WithCallMetadata(ctx context.Context, m CallMetadata) context.Context {
	old, _ := ctx.Value(callMetadataKey{}).(CallMetadata)
	if m.SourceID != "" {
		old.SourceID = m.SourceID
	}
	if m.Stage != "" {
		old.Stage = m.Stage
	}
	if m.AttemptID != "" {
		old.AttemptID = m.AttemptID
	}
	return context.WithValue(ctx, callMetadataKey{}, old)
}
func callMetadata(ctx context.Context) CallMetadata {
	m, _ := ctx.Value(callMetadataKey{}).(CallMetadata)
	return m
}
func logAttrs(ctx context.Context) []any {
	m := callMetadata(ctx)
	return []any{"source_id", m.SourceID, "stage", m.Stage, "attempt_id", m.AttemptID}
}
func loggerOrDefault(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}
func errorKind(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return "http"
	}
	var fe *FinishReasonError
	if errors.As(err, &fe) {
		return "finish_reason"
	}
	var oe *OutputError
	if errors.As(err, &oe) {
		return "decode"
	}
	return "request"
}

type tokenUsage struct {
	PromptTokenCount        int64 `json:"promptTokenCount"`
	CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
	ThoughtsTokenCount      int64 `json:"thoughtsTokenCount"`
	CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
	TotalTokenCount         int64 `json:"totalTokenCount"`
}

type batchJobTelemetryKey struct{}
type batchJobTelemetry struct {
	Name       string
	CreateTime time.Time
}

func logUsage(ctx context.Context, logger *slog.Logger, model, mode, key string, response vertexResponse, elapsed time.Duration, err error) {
	job, _ := ctx.Value(batchJobTelemetryKey{}).(batchJobTelemetry)
	identity := model + "\x00" + mode + "\x00" + key + "\x00" + job.Name + "\x00" + response.ResponseID
	if mode != "batch" && response.ResponseID == "" {
		identity += "\x00" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	digest := sha256.Sum256([]byte(identity))
	latencyKind := "online_request"
	if mode == "batch" {
		latencyKind = "unavailable"
		if !job.CreateTime.IsZero() {
			elapsed = time.Since(job.CreateTime)
			latencyKind = "batch_job_age"
		}
	}

	attrs := append(logAttrs(ctx), "model", model, "model_version", response.ModelVersion, "mode", mode, "usage_event_id", hex.EncodeToString(digest[:]), "provider_response_id", response.ResponseID, "batch_job", job.Name, "latency_kind", latencyKind, "request_key", key, "latency_ms", elapsed.Milliseconds(), "input_tokens", response.Usage.PromptTokenCount, "output_tokens", response.Usage.CandidatesTokenCount, "thinking_tokens", response.Usage.ThoughtsTokenCount, "cached_tokens", response.Usage.CachedContentTokenCount, "total_tokens", response.Usage.TotalTokenCount, "error_kind", errorKind(err), "usage_present", response.UsagePresent)
	var he *HTTPError
	if errors.As(err, &he) {
		attrs = append(attrs, "http_status", he.StatusCode)
	}
	finish := ""
	if len(response.Candidates) > 0 {
		finish = telemetryFinishReason(response.Candidates[0].FinishReason)
	}
	attrs = append(attrs, "finish_reason", finish)
	loggerOrDefault(logger).InfoContext(ctx, "llm usage", attrs...)
}

type retryTelemetryKey struct{}
type retryTelemetry struct {
	Logger            *slog.Logger
	Model, RequestKey string
}

func logRetry(ctx context.Context, attempt, status int, reason string) {
	event, ok := ctx.Value(retryTelemetryKey{}).(retryTelemetry)
	if !ok {
		return
	}
	attrs := append(logAttrs(ctx), "model", event.Model, "request_key", event.RequestKey, "attempt", attempt, "http_status", status, "reason", reason)
	loggerOrDefault(event.Logger).InfoContext(ctx, "llm retry", attrs...)
}

// Unknown provider diagnostics must not become arbitrary log content.
func telemetryFinishReason(reason string) string {
	switch reason {
	case "", "STOP", "MAX_TOKENS", "SAFETY", "RECITATION", "OTHER", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "MALFORMED_FUNCTION_CALL", "UNEXPECTED_TOOL_CALL", "FINISH_REASON_UNSPECIFIED":
		return reason
	default:
		return "unknown"
	}
}
