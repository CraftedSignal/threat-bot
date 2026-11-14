package pipeline

import (
	"context"
	"fmt"
	"regexp"
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
		item.Revision = item.ContentRevision()
		seen, err := p.db.HasSeenRevision(item.SourceID, item.Revision)
		if err != nil || seen {
			continue
		}
		checkpoint, err := p.db.GetProcessingCheckpoint(item.SourceID)
		if err != nil {
			p.logger.Warn("reading processing checkpoint before prefetch", "source_id", item.SourceID)
			continue
		}
		if checkpoint != nil {
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
				extractionRequests = append(extractionRequests, extractionBatchRequest(*item))
			}
			continue
		}
		if len(strings.TrimSpace(item.Content)) < 100 && item.SigmaRule == nil && !isExploitTracker(item.Source) {
			continue
		}
		if decision == DedupNew && (isLowValueItem(*item) != "" || isInformationalItem(*item) != "") {
			continue
		}
		if _, pass := meetsSourceSignalThreshold(*item, p.sourceSignalThresholds); !pass {
			continue
		}
		candidates = append(candidates, *item)
		if quality != nil && !bypassQuality(*item) {
			qualityRequests = append(qualityRequests, qualityBatchRequest(*item))
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
			if !quality.Cached(qualityBatchRequest(item), &score) {
				continue
			}
			raw, pass, _ = p.quality.evaluateScore(score)
		}
		if pass && raw*(0.5+p.getSourceConfidence(item.Source)*0.5) >= p.quality.threshold {
			extractionRequests = append(extractionRequests, extractionBatchRequest(item))
		}
	}
	if len(extractionRequests) > 0 {
		extraction.Prefetch(ctx, extractionRequests)
	}
}

var qualityCacheSchema = llm.MustSchemaOf[QualityScore]()
var extractionCacheSchema = llm.MustSchemaOf[ExtractionResult]()

func qualityBatchRequest(item scraper.RawItem) llm.Request {
	r := qualityRequest(item)
	r.Schema = qualityCacheSchema
	r.Metadata = llm.CallMetadata{SourceID: item.SourceID, Stage: "quality"}
	return r
}
func extractionBatchRequest(item scraper.RawItem) llm.Request {
	r := extractionRequest(item)
	r.Schema = extractionCacheSchema
	r.Metadata = llm.CallMetadata{SourceID: item.SourceID, Stage: "extraction"}
	return r
}

var extractedTechniqueID = regexp.MustCompile(`^T[0-9]{4}(?:\.[0-9]{3})?$`)

// ValidateLLMResponse rejects unusable typed artifacts before either online or
// batch cache persists them. Factual relevance still belongs to source grounding.
func (r *ExtractionResult) ValidateLLMResponse() error {
	if strings.TrimSpace(r.Summary) == "" && len(r.CVEs) == 0 && len(r.ChainedCVEs) == 0 && len(r.Techniques) == 0 && len(r.Tactics) == 0 && len(r.IOCs) == 0 && len(r.AffectedVendors) == 0 && len(r.AffectedProducts) == 0 && len(r.AffectedOS) == 0 && r.ClaimAssessment == nil && strings.TrimSpace(r.ThreatActor) == "" {
		return fmt.Errorf("empty extraction has no assessment")
	}
	for _, id := range r.CVEs {
		if cveRegex.FindString(id) != id {
			return fmt.Errorf("invalid extracted CVE identifier")
		}
	}
	for _, chain := range r.ChainedCVEs {
		for _, id := range chain {
			if cveRegex.FindString(id) != id {
				return fmt.Errorf("invalid extracted chained CVE identifier")
			}
		}
	}
	for _, id := range r.Techniques {
		if !extractedTechniqueID.MatchString(strings.ToUpper(id)) {
			return fmt.Errorf("invalid extracted technique identifier")
		}
	}
	for _, ioc := range r.IOCs {
		switch ioc.Type {
		case "ip", "domain", "url", "hash_sha256", "hash_md5", "email":
		default:
			return fmt.Errorf("invalid extracted indicator type")
		}
		if strings.TrimSpace(ioc.Value) == "" {
			return fmt.Errorf("empty extracted indicator")
		}
	}
	return nil
}
