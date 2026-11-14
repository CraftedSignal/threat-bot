package pipeline

import (
	"context"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// Bound both retained article text and model answers. Assembly and dedup still
// run sequentially; only the independent quality and extraction calls batch.
const prefetchChunkSize = llm.MaxBatchRequests

func (p *Pipeline) releasePrefetch() {
	quality, _ := p.quality.client.(llm.Prefetcher)
	extraction, _ := p.extractor.client.(llm.Prefetcher)
	if quality != nil {
		quality.Release()
	}
	if extraction != nil && extraction != quality {
		extraction.Release()
	}
}

// prefetchItems never marks an item seen or changes dedup state. processItem
// repeats those decisions after earlier items may have updated the database.
func (p *Pipeline) prefetchItems(ctx context.Context, items []scraper.RawItem) {
	quality, _ := p.quality.client.(llm.Prefetcher)
	extraction, _ := p.extractor.client.(llm.Prefetcher)
	if quality == nil && extraction == nil {
		return
	}
	var qualityRequests, extractionRequests []llm.Request
	var candidates []scraper.RawItem
	for i := range items {
		if ctx.Err() != nil {
			return
		}
		item := &items[i]
		seen, err := p.db.HasSeen(item.SourceID)
		if err != nil || seen {
			continue
		}
		for _, enrichmentErr := range p.enricher.Enrich(ctx, item) {
			p.logger.Warn("vendor advisory enrichment failed; continuing with available evidence", "source_id", item.SourceID, "source", item.Source, "error", enrichmentErr)
		}
		decision, _, _ := p.dedup.checkPreExtraction(*item, false)
		if decision == DedupNew && item.CorroborationOnly {
			continue
		}
		if decision == DedupSkip {
			continue
		}
		// Merging thin drafts does extraction without going through the quality gate.
		if decision == DedupMerge {
			if extraction != nil {
				extractionRequests = append(extractionRequests, extractionRequest(*item))
			}
			continue
		}
		if len(strings.TrimSpace(item.Content)) < 100 && item.SigmaRule == nil && !isExploitTracker(item.Source) {
			continue
		}
		if decision == DedupNew && (isLowValueItem(*item) != "" || isInformationalItem(*item) != "") {
			continue
		}
		candidates = append(candidates, *item)
		if quality != nil && !bypassQuality(*item) {
			qualityRequests = append(qualityRequests, qualityRequest(*item))
		}
	}
	if quality != nil && len(qualityRequests) > 0 {
		quality.Prefetch(ctx, qualityRequests)
	}
	if ctx.Err() != nil {
		return
	}
	if extraction == nil {
		return
	}
	for _, item := range candidates {
		if item.SigmaRule != nil {
			continue
		}
		raw, pass := 5.0, bypassQuality(item)
		if !pass {
			if quality == nil {
				continue
			}
			var score QualityScore
			if !quality.Cached(qualityRequest(item), &score) {
				continue
			}
			raw, pass, _ = p.quality.evaluateScore(score)
		}
		if pass && raw*(0.5+p.getSourceConfidence(item.Source)*0.5) >= p.quality.threshold {
			extractionRequests = append(extractionRequests, extractionRequest(item))
		}
	}
	if len(extractionRequests) > 0 {
		extraction.Prefetch(ctx, extractionRequests)
	}
}
