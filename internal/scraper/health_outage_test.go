package scraper

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func sourceHealthAfter(t *testing.T, interval time.Duration, failures ...error) (*Runner, SourceHealth) {
	t.Helper()
	r := NewRunner(nil, testLogger(), 0)
	r.RegisterWithInterval(staticScraper{name: "feed"}, interval)
	r.recordSuccess("feed", 1)
	for _, err := range failures {
		r.recordError("feed", err)
	}
	for _, h := range r.HealthSummary() {
		if h.Source == "feed" {
			return r, h
		}
	}
	t.Fatal("source health missing")
	return nil, SourceHealth{}
}

func upstream502() error {
	return statusErrorf(http.StatusBadGateway, "feed HTTP %d", http.StatusBadGateway)
}

// Retries during a short third-party outage are not a sustained outage. The
// same failures become unhealthy once the outage has lasted long enough to
// threaten coverage.
func TestUpstreamOutageBecomesUnhealthyOnlyWhenSustained(t *testing.T) {
	r, h := sourceHealthAfter(t, time.Hour, upstream502(), upstream502(), upstream502(), upstream502())
	if h.ConsecutiveErrors != 4 || !h.LastErrorExpectedUpstream {
		t.Fatalf("fixture health=%+v", h)
	}
	if !h.IsHealthy() {
		t.Fatal("four quick retries of an upstream 502 reported a sustained outage")
	}

	r.healthMu.Lock()
	stale := r.health["feed"]
	stale.outageStarted = time.Now().Add(-upstreamOutageTolerance(time.Hour) - time.Minute)
	r.health["feed"] = stale
	r.healthMu.Unlock()
	for _, h := range r.HealthSummary() {
		if h.IsHealthy() {
			t.Fatal("upstream outage past its tolerance stayed healthy")
		}
	}
}

func TestOwnFailuresStayUnhealthyAfterFourConsecutiveErrors(t *testing.T) {
	unexpected := errors.New("decoding response: unexpected field")
	if _, h := sourceHealthAfter(t, time.Hour, unexpected, unexpected, unexpected, unexpected); h.IsHealthy() {
		t.Fatal("repeated non-upstream failures must surface immediately")
	}
	// One non-transient failure in the streak means the outage may need action.
	if _, h := sourceHealthAfter(t, time.Hour, unexpected, upstream502(), upstream502(), upstream502()); h.IsHealthy() {
		t.Fatal("a streak containing a non-upstream failure used the upstream tolerance")
	}
	blocked := statusErrorf(http.StatusForbidden, "feed HTTP %d", http.StatusForbidden)
	if _, h := sourceHealthAfter(t, time.Hour, blocked, blocked, blocked, blocked); h.IsHealthy() {
		t.Fatal("a persistent block waited for the transient outage tolerance")
	}
}

func TestRecoveryResetsTheOutageClock(t *testing.T) {
	r, _ := sourceHealthAfter(t, time.Hour, upstream502(), upstream502(), upstream502(), upstream502())
	r.healthMu.Lock()
	stale := r.health["feed"]
	stale.outageStarted = time.Now().Add(-48 * time.Hour)
	r.health["feed"] = stale
	r.healthMu.Unlock()
	r.recordSuccess("feed", 0)
	for range 4 {
		r.recordError("feed", upstream502())
	}
	for _, h := range r.HealthSummary() {
		if !h.IsHealthy() {
			t.Fatal("a new short outage inherited the previous outage's start")
		}
	}
}

func TestUpstreamOutageToleranceScalesWithSlowSources(t *testing.T) {
	if got := upstreamOutageTolerance(time.Hour); got != 6*time.Hour {
		t.Fatalf("hourly tolerance=%s", got)
	}
	if got := upstreamOutageTolerance(12 * time.Hour); got != 36*time.Hour {
		t.Fatalf("twice-daily tolerance=%s", got)
	}
}
