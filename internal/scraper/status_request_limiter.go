package scraper

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StatusProviderOptions bounds exact-status resolution. Zero values use the
// provider's conservative defaults.
type StatusProviderOptions struct {
	DailyBudget     int
	RequestInterval time.Duration
	CacheEntries    int
}

type retryableStatusError struct {
	message    string
	retryAfter time.Duration
	cause      error
}

func (e *retryableStatusError) Error() string {
	if e.retryAfter > 0 {
		return fmt.Sprintf("%s (retry after %s)", e.message, e.retryAfter.Round(time.Second))
	}
	return e.message
}

func (e *retryableStatusError) Unwrap() error { return e.cause }

func IsRetryableStatusError(err error) bool {
	var target *retryableStatusError
	return errors.As(err, &target)
}

type statusRequestLimiter struct {
	sem chan struct{}

	mu           sync.Mutex
	dailyBudget  int
	interval     time.Duration
	day          string
	used         int
	next         time.Time
	blockedUntil time.Time
	failures     int
	circuitUntil time.Time
}

func newStatusRequestLimiter(dailyBudget int, interval time.Duration) *statusRequestLimiter {
	return &statusRequestLimiter{sem: make(chan struct{}, 1), dailyBudget: dailyBudget, interval: interval}
}

func (l *statusRequestLimiter) begin(ctx context.Context) (func(), error) {
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-l.sem }

	now := time.Now()
	l.mu.Lock()
	l.resetDay(now)
	if l.dailyBudget > 0 && l.used >= l.dailyBudget {
		retry := time.Until(now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour))
		l.mu.Unlock()
		release()
		return nil, &retryableStatusError{message: "status resolver daily budget exhausted", retryAfter: retry}
	}
	if l.blockedUntil.After(now) {
		retry := l.blockedUntil.Sub(now)
		l.mu.Unlock()
		release()
		return nil, &retryableStatusError{message: "status resolver is backing off", retryAfter: retry}
	}
	if l.circuitUntil.After(now) {
		retry := l.circuitUntil.Sub(now)
		l.mu.Unlock()
		release()
		return nil, &retryableStatusError{message: "status resolver circuit is open", retryAfter: retry}
	}
	wake := l.next
	l.mu.Unlock()

	if delay := time.Until(wake); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}

	now = time.Now()
	l.mu.Lock()
	l.resetDay(now)
	if l.dailyBudget > 0 && l.used >= l.dailyBudget {
		l.mu.Unlock()
		release()
		return nil, &retryableStatusError{message: "status resolver daily budget exhausted"}
	}
	l.used++
	l.next = now.Add(l.interval)
	l.mu.Unlock()
	return release, nil
}

func (l *statusRequestLimiter) resetDay(now time.Time) {
	day := now.UTC().Format("2006-01-02")
	if l.day != day {
		l.day = day
		l.used = 0
	}
}

func (l *statusRequestLimiter) success() {
	l.mu.Lock()
	l.failures = 0
	l.mu.Unlock()
}

func (l *statusRequestLimiter) failure(retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if retryAfter > 0 && now.Add(retryAfter).After(l.blockedUntil) {
		l.blockedUntil = now.Add(retryAfter)
	}
	l.failures++
	if l.failures >= 3 {
		l.circuitUntil = now.Add(15 * time.Minute)
		l.failures = 0
	}
}

func retryAfterDuration(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if seconds, err := strconv.Atoi(header); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(header); err == nil && when.After(now) {
		return when.Sub(now)
	}
	return 0
}

func retryableHTTPStatus(resp *http.Response, provider string) error {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
		return nil
	}
	retry := retryAfterDuration(resp.Header.Get("Retry-After"), time.Now())
	if retry <= 0 {
		retry = 5 * time.Minute
	}
	return &retryableStatusError{message: provider + " status " + resp.Status, retryAfter: retry}
}
