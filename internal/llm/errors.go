package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// HTTPError preserves the LLM provider status code so callers can distinguish
// permanent configuration failures from ordinary generation errors.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("LLM HTTP %d", e.StatusCode)
}

// HTTPStatus returns the provider HTTP status code from an LLM error.
func HTTPStatus(err error) (int, bool) {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode, true
	}
	return 0, false
}

// IsModelUnavailable identifies permanent model/configuration failures where a
// fallback model may keep the pipeline moving.
func IsModelUnavailable(err error) bool {
	status, ok := HTTPStatus(err)
	if !ok {
		return false
	}
	if status == 404 || status == 410 {
		return true
	}

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	body := strings.ToLower(httpErr.Body)
	return strings.Contains(body, "model") &&
		(strings.Contains(body, "not found") ||
			strings.Contains(body, "retired") ||
			strings.Contains(body, "shut down") ||
			strings.Contains(body, "shutdown"))
}

// FinishReasonError reports that the model stopped before it finished its
// answer: it hit the output token limit (MAX_TOKENS) or was stopped by a safety
// filter (SAFETY, PROHIBITED_CONTENT, ...). Text holds whatever was produced so
// callers can quarantine it. Callers classify it with errors.As; it is never
// worth retrying with the same request.
type FinishReasonError struct {
	Reason string
	Text   string
}

func (e *FinishReasonError) Error() string {
	return "LLM stopped before finishing its answer"
}

// Truncated reports whether the answer was cut off by the output token limit.
func (e *FinishReasonError) Truncated() bool { return e.Reason == finishMaxTokens }

// OutputError reports a complete answer that does not decode into the shape
// the request asked for. Err is the decoder's finding (for example a
// *json.SyntaxError or *json.UnmarshalTypeError) and Text the offending answer.
type OutputError struct {
	Err  error
	Text string
}

func (e *OutputError) Error() string {
	return "LLM answer does not match the requested schema"
}

func (e *OutputError) Unwrap() error { return e.Err }

// ErrorStatus is a bounded public classification. Provider bodies, model
// outputs and transport URLs must never cross readiness or log boundaries.
func ErrorStatus(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if code, ok := HTTPStatus(err); ok {
		switch {
		case code == 401 || code == 403:
			return "authentication_failed"
		case code == 404 || code == 410:
			return "model_unavailable"
		case code == 429:
			return "rate_limited"
		case code >= 500:
			return "provider_unavailable"
		}
	}
	return "request_failed"
}

// RequestError retains transport error identity for retry/cancellation logic
// while suppressing URLs, credentials and provider-controlled diagnostics.
type RequestError struct{ Err error }

func (e *RequestError) Error() string { return "LLM request: " + ErrorStatus(e.Err) }
func (e *RequestError) Unwrap() error { return e.Err }
