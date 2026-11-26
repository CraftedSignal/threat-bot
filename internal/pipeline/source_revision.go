package pipeline

import (
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// A new revision of a source item that already backs a canonical brief has
// only two possible rebuild outcomes. sourceRevisionConflict holds any rebuilt
// narrative that differs from the canonical title, summary, content, actor or
// lists, which a regenerated brief practically always does; an exact match
// changes nothing. Paying for quality, extraction, assembly and grounding
// therefore never updated a brief: it only attached a rebuilt candidate to the
// editorial hold. Revisions that keep their indexed title and text complete
// without work; changed revisions are held with their evidence before any
// model call. Cross-source rebuilds of thin briefs are unaffected.
const sourceRevisionHoldReason = "source revision changes the evidence of a canonical brief; its narrative is never replaced automatically"

// sourceRevisionTarget returns the canonical brief that a new revision of an
// already-processed source item would rebuild.
func (p *Pipeline) sourceRevisionTarget(item scraper.RawItem) (storage.ContentIndexEntry, bool) {
	if item.Revision == "" {
		item.Revision = item.ContentRevision()
	}
	decision, entries, ok := p.dedup.sourceRevisionMatch(item)
	if !ok || decision != DedupMerge || len(entries) == 0 {
		return storage.ContentIndexEntry{}, false
	}
	return entries[0], true
}

// sourceRevisionUnchanged reports whether a revision keeps the title and text
// that its canonical brief last indexed from this source. NVD revises records
// for status, reference and analysis metadata alone. Indexed text includes
// fetched article bodies, so an enriched source never matches its bare feed
// entry and still takes the editorial hold path.
func (p *Pipeline) sourceRevisionUnchanged(item scraper.RawItem, target storage.ContentIndexEntry) bool {
	hash := NormalizeContentHash(item.Title, item.Content)
	entries, err := p.db.FindBySourceID(item.SourceID)
	if err != nil {
		return false
	}
	var latest *storage.ContentIndexEntry
	for i := range entries {
		entry := &entries[i]
		if entry.DraftID != target.DraftID || entry.Source != item.Source || entry.ContentHash == "" {
			continue
		}
		if latest == nil || entry.CreatedAt.After(latest.CreatedAt) || entry.CreatedAt.Equal(latest.CreatedAt) && entry.ID > latest.ID {
			latest = entry
		}
	}
	return latest != nil && latest.ContentHash == hash
}
