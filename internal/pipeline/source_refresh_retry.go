package pipeline

import (
	"fmt"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

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
	// The intake queue can contain several revisions of the same source. Keep
	// each active deadline so alternating deliveries cannot defeat the delay.
	for key, retryAt := range state.RefreshRetries {
		if !now.Before(retryAt) {
			delete(state.RefreshRetries, key)
		}
	}
	retryAt := now.Add(p.retryBackoff)
	state.RefreshRetries[inputKey] = retryAt
	if err := p.saveCandidate(cp.InputKey, state, cp.RetryAt); err != nil {
		return fmt.Errorf("saving source refresh retry: %w", err)
	}
	p.logger.Warn("source evidence refresh deferred",
		"source_id", state.Item.SourceID, "source", state.Item.Source,
		"error_class", "source_unavailable", "retry_at", retryAt,
		"error", refreshErr)
	return nil
}
