package pipeline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// A semantically incomplete draft needs a complete grounded narrative, rather
// than another union of identifiers. Changed evidence from its original source
// is never unioned either: routePreExtraction holds it for editorial review
// before any model work, because no rebuilt narrative may replace the canonical
// one automatically (see sourceRevisionHoldReason).
func (p *Pipeline) draftRebuildTarget(item scraper.RawItem, decision DedupDecision, entries []storage.ContentIndexEntry) string {
	if decision != DedupMerge && decision != DedupUpdate {
		return ""
	}
	for _, entry := range entries {
		if entry.DraftID == "" {
			continue
		}
		if p.dedup.isDraftThin(entry.DraftID) || p.isSourceRevisionTarget(item, entry.DraftID) {
			return entry.DraftID
		}
	}
	return ""
}

func (p *Pipeline) isSourceRevisionTarget(item scraper.RawItem, draftID string) bool {
	decision, entries, ok := p.dedup.sourceRevisionMatch(item)
	return ok && decision == DedupMerge && len(entries) > 0 && entries[0].DraftID == draftID
}

func (p *Pipeline) holdDraftRebuild(key string, state processingCandidate, candidate, reason string) error {
	state.BriefYAML, state.ReviewHold = candidate, true
	if err := p.saveCandidate(key, state, time.Time{}); err != nil {
		return err
	}
	reason = fmt.Sprintf("canonical draft %s requires editorial correction review: %s", state.RebuildDraftID, reason)
	if err := p.db.QuarantinePipelineItem(state.Item.SourceID, state.Item.Source, state.Item.Title, candidate, reason); err != nil {
		return err
	}
	p.logger.Warn("canonical rebuild held for editorial correction review", "draft_id", state.RebuildDraftID, "source_id", state.Item.SourceID, "reason", reason)
	return p.db.RecordProcessingEvent(state.Item.SourceID, key, state.AttemptID, "editorial", "held")
}

// finishDraftRebuild is reached only after the fresh candidate passed the full
// assembly, verification, grounding and final contract checks. It never creates
// a second draft, and the canonical identity is owned by the assembled merger.
func (p *Pipeline) finishDraftRebuild(ctx context.Context, key string, state processingCandidate, candidate string) error {
	draft, err := p.db.GetDraft(state.RebuildDraftID)
	if err != nil {
		return fmt.Errorf("rebuild canonical draft %s unavailable: %w", state.RebuildDraftID, err)
	}
	if draft == nil {
		return fmt.Errorf("rebuild canonical draft %s is missing", state.RebuildDraftID)
	}
	if draft.Status == storage.StatusRejected {
		return p.holdDraftRebuild(key, state, candidate, "canonical draft was rejected while the candidate was being grounded")
	}
	if err := p.validatePublication(candidate); err != nil {
		return p.holdDraftRebuild(key, state, candidate, err.Error())
	}
	var base, incoming map[string]any
	if err := yaml.Unmarshal([]byte(draft.BriefYAML), &base); err != nil {
		return err
	}
	if err := yaml.Unmarshal([]byte(candidate), &incoming); err != nil {
		return err
	}
	if p.isSourceRevisionTarget(state.Item, draft.ID) {
		if reason := sourceRevisionConflict(base, incoming); reason != "" {
			return p.holdDraftRebuild(key, state, candidate, reason)
		}
	}
	filtered, relevance, err := p.assessDraftMergeRelevance(ctx, base, state.Extraction, state.Item)
	if err != nil {
		return fmt.Errorf("rebuild relevance: %w", err)
	}
	if !relevance.Merge || !relevance.ReferenceRelevant {
		return p.holdDraftRebuild(key, state, candidate, "fresh source is not accepted as evidence for this canonical brief")
	}
	// The full narrative cannot be safely patched by silently dropping fields
	// the target-scope checker refused. Preserve both snapshots for review.
	if rebuildScopeChanged(state.Extraction, filtered) {
		return p.holdDraftRebuild(key, state, candidate, "fresh narrative includes extracted claims outside the accepted canonical scope")
	}
	if err := p.mergeAssembledBriefIntoDraftWithNarrative(draft.ID, candidate, state.Item, true); err != nil {
		// A final gate refusal happens before the canonical row changes.
		if strings.Contains(err.Error(), "requires editorial review") {
			return p.holdDraftRebuild(key, state, candidate, err.Error())
		}
		return err
	}
	p.indexContent(draft.ID, state.Item, state.PreCVEs, state.Extraction, candidate)
	p.decisions.record(outcomeMerged)
	return p.markSeen(state.Item)
}

func rebuildScopeChanged(before, after *ExtractionResult) bool {
	if before == nil || after == nil {
		return true
	}
	claims := func(e *ExtractionResult) any {
		return []any{e.CVEs, e.AffectedVendors, e.AffectedProducts, e.AffectedOS, e.IOCs}
	}
	a, _ := yaml.Marshal(claims(before))
	b, _ := yaml.Marshal(claims(after))
	return string(a) != string(b)
}

// A union cannot express retractions or replace previously accepted actions.
// Keep the old canonical snapshot and the fresh grounded candidate for an
// editor whenever a source revision needs that destructive interpretation.
func sourceRevisionConflict(base, incoming map[string]any) string {
	for _, key := range []string{"title", "summary", "content", "threat_actor"} {
		before := strings.TrimSpace(publicationString(base[key]))
		if before != "" && normalizeForQuote(before) != normalizeForQuote(publicationString(incoming[key])) {
			return "source correction replaces existing " + key
		}
	}
	for _, key := range []string{"cves", "affected_vendors", "affected_products", "affected_os", "iocs", "rules", "ttps", "action_plan"} {
		if base[key] == nil {
			continue
		}
		before, _ := yaml.Marshal(base[key])
		after, _ := yaml.Marshal(incoming[key])
		if string(before) != string(after) {
			return "source correction changes existing " + key + "; a union cannot safely apply removals or replacements"
		}
	}
	return ""
}
