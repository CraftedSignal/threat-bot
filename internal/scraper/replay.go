package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

// replayMaxAge bounds how long a queued item is re-emitted. An item that never
// reaches a terminal decision, such as one held back for a later grounding
// retry, stops being retried after this.
const replayMaxAge = 24 * time.Hour

// Replay re-emits source items queued by `threat-bot sources replay`, so the
// pipeline can process items that a since-fixed bug dropped. Each item keeps
// its original source and ID, and leaves the queue once it is seen again.
type Replay struct {
	db  *storage.DB
	now func() time.Time // time.Now when nil; tests inject a clock
}

func NewReplay(db *storage.DB) *Replay {
	return &Replay{db: db}
}

func (r *Replay) Name() string { return "replay" }

func (r *Replay) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	pending, err := r.db.PendingReplays(now().Add(-replayMaxAge))
	if err != nil {
		return nil, err
	}
	items := make([]RawItem, 0, len(pending))
	for _, itemJSON := range pending {
		var item RawItem
		if err := json.Unmarshal([]byte(itemJSON), &item); err != nil {
			return nil, fmt.Errorf("decoding replay item: %w", err)
		}
		items = append(items, item)
	}
	return items, nil
}
