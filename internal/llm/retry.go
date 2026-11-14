package llm

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxRetryAttempts  = 5
	initialRetryDelay = time.Second
	maxRetryDelay     = 30 * time.Second
	maxRetryAfter     = time.Minute
)

// retryableStatusCodes are HTTP status codes that warrant a retry.
var retryableStatusCodes = map[int]bool{
	429: true, // Too Many Requests
	500: true, // Internal Server Error
	502: true, // Bad Gateway
	503: true, // Service Unavailable
	504: true, // Gateway Timeout
}

// retryDo executes an HTTP request with exponential backoff retries.
// It retries on retryable status codes and network errors, but not on
// client errors like 400 Bad Request.
func retryDo(client *http.Client, req *http.Request) (*http.Response, error) {
	var lastErr error
	retryAfter := ""
	for attempt := 0; attempt <= maxRetryAttempts; attempt++ {
		if attempt > 0 {
			delay := retryDelay(attempt-1, retryAfter, time.Now())
			retryAfter = ""
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}

			// Clone the request for retry (body must be re-readable).
			// The caller is responsible for providing a request with a
			// GetBody function (http.NewRequest does this automatically
			// for bytes.Reader bodies).
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("retry: resetting body: %w", err)
				}
				req.Body = body
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			// Network error — retry if we have attempts left.
			lastErr = &RequestError{Err: err}
			if attempt < maxRetryAttempts && isRetryableNetError(err) {
				logRetry(req.Context(), attempt+2, 0, "network")
				continue
			}
			return nil, lastErr
		}

		if retryableStatusCodes[resp.StatusCode] && attempt < maxRetryAttempts {
			logRetry(req.Context(), attempt+2, resp.StatusCode, "http")
			retryAfter = resp.Header.Get("Retry-After")
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("LLM HTTP %d (attempt %d/%d)", resp.StatusCode, attempt+1, maxRetryAttempts+1)
			continue
		}

		return resp, nil
	}

	return nil, lastErr
}

// retryDelay uses equal jitter to spread overloaded callers across an
// exponentially widening window. A valid Retry-After takes precedence.
func retryDelay(retry int, retryAfter string, now time.Time) time.Duration {
	if delay, ok := parseRetryAfter(retryAfter, now); ok {
		return min(delay, maxRetryAfter)
	}

	ceiling := initialRetryDelay
	for range retry {
		if ceiling >= maxRetryDelay/2 {
			ceiling = maxRetryDelay
			break
		}
		ceiling *= 2
	}
	floor := ceiling / 2
	return floor + time.Duration(rand.Int63n(int64(ceiling-floor)+1))
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0, false
		}
		if seconds > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	if retryAt, err := http.ParseTime(value); err == nil {
		return min(max(time.Duration(0), retryAt.Sub(now)), maxRetryAfter), true
	}
	return 0, false
}

// isRetryableNetError checks if a network error is transient and worth retrying.
func isRetryableNetError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Common transient network errors.
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "temporary failure")
}
