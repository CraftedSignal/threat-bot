package pipeline

import (
	"fmt"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

const maxSourceRefreshRetryDelay = 12 * time.Hour

func (p *Pipeline) sourceRefreshRetryDelay(attempt int) time.Duration {
	delay := p.retryBackoff
	limit := max(delay, maxSourceRefreshRetryDelay)
	for n := 1; n < attempt && delay > 0 && delay < limit; n++ {
		if delay >= limit/2 {
			return limit
		}
		delay *= 2
	}
	return delay
}

// A source outage has its own deadline: it must not reset grounding budgets,
// delay a corrected feed revision, or re-fetch held merge evidence every poll.
func (state processingCandidate) sourceRefreshDeferred(inputKey string) bool {
	return time.Now().Before(state.RefreshRetries[inputKey])
}

func (p *Pipeline) deferSourceRefresh(cp storage.ProcessingCheckpoint, state processingCandidate, inputKey string, refreshErr error) error {
	now := time.Now()
	if state.RefreshRetries == nil {
		state.RefreshRetries = make(map[string]time.Time)
	}
	if state.RefreshRetryAttempts == nil {
		state.RefreshRetryAttempts = make(map[string]int)
	}
	// The intake queue can contain several revisions of the same source. Keep
	// each active deadline so alternating deliveries cannot defeat the delay.
	// Keep this revision's expired deadline and count until its next result so
	// repeated failures continue to back off instead of restarting at the base.
	for key, retryAt := range state.RefreshRetries {
		if key != inputKey && !now.Before(retryAt) {
			delete(state.RefreshRetries, key)
			delete(state.RefreshRetryAttempts, key)
		}
	}
	state.RefreshRetryAttempts[inputKey]++
	attempt := state.RefreshRetryAttempts[inputKey]
	delay := p.sourceRefreshRetryDelay(attempt)
	retryAt := now.Add(delay)
	state.RefreshRetries[inputKey] = retryAt
	if err := p.saveCandidate(cp.InputKey, state, cp.RetryAt); err != nil {
		return fmt.Errorf("saving source refresh retry: %w", err)
	}
	p.logger.Warn("source evidence refresh deferred",
		"source_id", state.Item.SourceID, "source", state.Item.Source,
		"error_class", "source_unavailable", "attempt", attempt,
		"retry_delay", delay, "retry_at", retryAt,
		"error", refreshErr)
	return nil
}
