package publisher

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// doGitHubRead retries only transient failures of replayable metadata GETs.
// Successful response decoding stays with the caller: malformed or incomplete
// metadata must fail closed, never become an empty publication input.
func (p *Publisher) doGitHubRead(req *http.Request, errorBodyBytes int64) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("GitHub read retry requires GET")
	}
	ctx := req.Context()
	var lastErr error
	for attempt := 1; attempt <= putFileMaxAttempts; attempt++ {
		if err := p.awaitRateLimit(ctx); err != nil {
			return nil, err
		}
		next := req.Clone(ctx)
		p.setHeaders(next)
		resp, err := p.client.Do(next)
		wait := time.Duration(0)
		if err != nil {
			if resp != nil {
				_ = resp.Body.Close()
			}
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if !isRetryableGitHubError(err) && !retryableBlobError(err) {
				return nil, err
			}
		} else {
			p.recordRateLimit(resp)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return resp, nil
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyBytes))
			_ = resp.Body.Close()
			lastErr = &githubAPIError{status: resp.StatusCode, body: string(body)}
			if resp.StatusCode == http.StatusTooManyRequests {
				if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
					wait = time.Duration(min(seconds, 60)) * time.Second
				}
			}
		}
		if attempt < putFileMaxAttempts {
			if wait == 0 {
				wait = putFileRetryDelays[attempt-1]
			}
			p.logger.Info("retrying GitHub metadata read", "path", req.URL.Path, "attempt", attempt+1, "error", lastErr)
			if err := sleepWithContext(ctx, wait); err != nil {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("reading GitHub metadata after %d attempts: %w", putFileMaxAttempts, lastErr)
}
