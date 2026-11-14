package scraper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func retryTestClient(delays []time.Duration, onRateLimit func(time.Time)) *http.Client {
	return &http.Client{Transport: &uaTransport{ua: "t", rt: http.DefaultTransport, delays: delays, onRateLimit: onRateLimit}}
}

func TestTransportRetriesBadGatewayUpToThreeAttempts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	resp, err := retryTestClient([]time.Duration{time.Millisecond, time.Millisecond}, nil).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 3 || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("hits = %d status = %d, want 3 attempts ending in 502", hits.Load(), resp.StatusCode)
	}
}

func TestTransportDoesNotRetryRateLimitAndReportsReset(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	var until time.Time
	resp, err := retryTestClient([]time.Duration{time.Millisecond, time.Millisecond}, func(u time.Time) { until = u }).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("hits = %d status = %d, want one 429 response", hits.Load(), resp.StatusCode)
	}
	if d := time.Until(until); d < 100*time.Second || d > 121*time.Second {
		t.Fatalf("reset in %s, want about 120s", d)
	}
}

func TestRateLimitResetHeaders(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{"retry-after seconds", http.Header{"Retry-After": {"30"}}, 30 * time.Second},
		{"retry-after date", http.Header{"Retry-After": {now.Add(45 * time.Second).Format(http.TimeFormat)}}, 45 * time.Second},
		{"reddit reset seconds", http.Header{"X-Ratelimit-Reset": {"87.5"}}, 87500 * time.Millisecond},
		{"larger wins", http.Header{"Retry-After": {"10"}, "X-Ratelimit-Reset": {"60"}}, 60 * time.Second},
		{"none uses default", http.Header{}, defaultRateLimitPause},
		{"capped", http.Header{"Retry-After": {"999999"}}, maxRateLimitPause},
	}
	for _, tt := range tests {
		if got := rateLimitReset(tt.header, now).Sub(now); got != tt.want {
			t.Errorf("%s: pause = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestJitterStaysWithinBounds(t *testing.T) {
	for i := 0; i < 200; i++ {
		if d := jitterDelay(40 * time.Second); d < 30*time.Second || d > 40*time.Second {
			t.Fatalf("jitter %s outside [30s, 40s]", d)
		}
	}
}

func TestRedditSkipsPollsUntilRateLimitReset(t *testing.T) {
	redditNextAllowed = time.Time{}
	defer func() { redditNextAllowed = time.Time{} }()
	origInterval := redditMinInterval
	redditMinInterval = time.Millisecond
	defer func() { redditMinInterval = origInterval }()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("x-ratelimit-reset", "300")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	s := newRedditScraper("reddit-test", "netsec")
	s.baseURL = srv.URL
	since := time.Now().Add(-time.Hour)

	if _, err := s.Poll(context.Background(), since); err == nil {
		t.Fatal("first poll should report the 429")
	}
	items, err := s.Poll(context.Background(), since)
	if !errors.Is(err, ErrPollSkipped) || items != nil {
		t.Fatalf("second poll = %v, %v; want ErrPollSkipped", items, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1: the skipped poll must not reach Reddit", hits.Load())
	}

	s.setBlockedUntil(time.Now().Add(-time.Second))
	if _, err := s.Poll(context.Background(), since); err == nil || hits.Load() != 2 {
		t.Fatalf("poll after reset: err=%v hits=%d, want a real request", err, hits.Load())
	}
}
