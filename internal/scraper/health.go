package scraper

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// SourceHealth holds health metrics for a single scraper source.
type SourceHealth struct {
	Source                    string
	LastSuccess               time.Time
	LastError                 time.Time
	LastErrorMessage          string
	LastErrorClass            string
	LastErrorExpectedUpstream bool
	ConsecutiveErrors         int
	TotalItems                int
	SilentPolls               int // consecutive polls with 0 new items
	pollInterval              time.Duration
	lastErrorLog              time.Time
	lastErrorLogFingerprint   string
	// outageStarted is the first failure of the current error streak.
	outageStarted time.Time
	// streakNotTransient records a failure in the streak that is not a
	// transient upstream outage (a block, certificate or scraper failure).
	streakNotTransient bool
}

// upstreamOutageTolerance is how long transient upstream failures (5xx, 408,
// 429, timeouts, dropped connections) may last before the outage counts as
// sustained. Short third-party outages recover on their own; retries during
// them are not an operational fault. Slow sources get several polls' grace.
func upstreamOutageTolerance(pollInterval time.Duration) time.Duration {
	return max(6*time.Hour, 3*pollInterval)
}

// transientUpstreamFailure reports failures that a source normally recovers
// from without intervention. Blocks (403) and certificate failures persist
// until someone acts, so they keep the immediate consecutive-error rule.
func transientUpstreamFailure(err error) bool {
	if code, ok := upstreamStatus(err); ok {
		return code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || (code >= 500 && expectedUpstreamStatuses[code])
	}
	switch scraperErrorClass(err) {
	case "network_timeout", "network_eof":
		return true
	}
	return false
}

// IsHealthy returns true if the source has no concerning indicators.
// Sources producing zero new items are still considered healthy — some feeds
// (advisories, vendor bulletins) legitimately have long quiet stretches.
// Unhealthiness is driven by errors or a prolonged absence of any successful
// poll.
func (h SourceHealth) IsHealthy() bool {
	if h.ConsecutiveErrors > 3 {
		// A streak that includes any other failure may need action: surface it
		// immediately. A transient upstream outage must also last long enough.
		if h.streakNotTransient || h.outageStarted.IsZero() || time.Since(h.outageStarted) >= upstreamOutageTolerance(h.pollInterval) {
			return false
		}
	}
	if h.LastSuccess.IsZero() {
		return true
	}
	staleAfter := 24 * time.Hour
	if intervalWindow := 2 * h.pollInterval; intervalWindow > staleAfter {
		staleAfter = intervalWindow
	}
	return time.Since(h.LastSuccess) < staleAfter
}

// HealthSummary returns a snapshot of all source health metrics.
func (r *Runner) HealthSummary() []SourceHealth {
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()

	intervals := r.PollIntervals()
	result := make([]SourceHealth, 0, len(r.health))
	for _, h := range r.health {
		cp := h
		cp.pollInterval = intervals[h.Source]
		result = append(result, cp)
	}
	return result
}

// LogAnomalies emits a single WARN-level log line if the most recent
// poll cycle's health snapshot looks degraded. Call once per cycle
// after PollAll returns. Two heuristics:
//
//   - More than half the registered sources errored simultaneously
//     (LLM provider outage, GKE egress problem, scraper image bug).
//   - At least one source has been silent for more than its expected
//     window AND has not errored — pattern that hides parser drift
//     or upstream RSS reformat bugs that produce zero items without
//     an obvious failure. The window is twice the source's poll
//     interval, and at least 12h.
//
// Cheap to call (read-only on the health map). Idempotent — emits at
// most one warning per cycle even when multiple thresholds trip.
func (r *Runner) LogAnomalies(logger *slog.Logger) {
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()

	if len(r.health) == 0 {
		return
	}

	intervals := r.PollIntervals()
	errorCount := 0
	silent := []string{}
	for _, h := range r.health {
		if h.ConsecutiveErrors > 0 {
			errorCount++
		}
		window := max(12*time.Hour, 2*intervals[h.Source])
		if h.SilentPolls > 0 && !h.LastSuccess.IsZero() && time.Since(h.LastSuccess) > window && h.ConsecutiveErrors == 0 {
			silent = append(silent, h.Source)
		}
	}

	if errorCount*2 > len(r.health) {
		logger.Warn("scraper anomaly: more than half of sources are erroring",
			"erroring", errorCount, "total", len(r.health))
	}
	if len(silent) > 0 {
		logger.Warn("scraper anomaly: sources silent past expected cadence",
			"sources", silent)
	}
}

// recordSuccess updates health metrics after a successful poll.
func (r *Runner) recordSuccess(source string, newItems int) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()

	h := r.health[source]
	h.Source = source
	h.LastSuccess = time.Now()
	h.LastErrorExpectedUpstream = false
	h.LastErrorMessage = ""
	h.LastErrorClass = ""
	h.lastErrorLogFingerprint = ""
	h.ConsecutiveErrors = 0
	h.outageStarted = time.Time{}
	h.streakNotTransient = false
	h.TotalItems += newItems

	if newItems == 0 {
		h.SilentPolls++
	} else {
		h.SilentPolls = 0
	}

	r.health[source] = h
}

// Persistent failures retain their health state on every retry, but repeat
// diagnostics only every six hours. A changed failure or successful recovery
// starts a new diagnostic immediately.
const sourceErrorLogInterval = 6 * time.Hour

// recordError returns the updated health and whether a diagnostic is due.
func (r *Runner) recordError(source string, err error) (SourceHealth, bool) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()

	h := r.health[source]
	now := time.Now()
	errorClass := scraperErrorClass(err)
	message := boundedScraperError(err)
	fingerprint := errorClass
	if errorClass == "unexpected" && err != nil {
		// Distinct failures must not hide behind the same redacted display text.
		// Keep their identity internal; never retain credential-bearing raw URLs.
		fingerprint = fmt.Sprintf("%s:%x", errorClass, sha256.Sum256([]byte(err.Error())))
	}
	logFailure := h.ConsecutiveErrors == 0 || h.lastErrorLogFingerprint != fingerprint || now.Sub(h.lastErrorLog) >= sourceErrorLogInterval
	if logFailure {
		h.lastErrorLog = now
		h.lastErrorLogFingerprint = fingerprint
	}
	h.Source = source
	h.LastError = now
	h.LastErrorMessage = message
	h.LastErrorClass = errorClass
	h.LastErrorExpectedUpstream = isExpectedUpstreamScraperError(err)
	if h.ConsecutiveErrors == 0 {
		h.outageStarted = now
		h.streakNotTransient = false
	}
	h.streakNotTransient = h.streakNotTransient || !transientUpstreamFailure(err)
	h.ConsecutiveErrors++

	r.health[source] = h
	return h, logFailure
}
