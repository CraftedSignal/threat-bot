package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// Bound both retained article text and model answers. Assembly and dedup still
// run sequentially; only the independent quality and extraction calls batch.
const prefetchChunkSize = llm.MaxBatchRequests

type sourceRefreshMemoKey struct{}
type sourceRefreshResult struct {
	item, articleBase scraper.RawItem
	err               error
}

func (p *Pipeline) retainedBatchItems(items []scraper.RawItem) ([]scraper.RawItem, error) {
	var retained []scraper.RawItem
	for _, item := range items {
		ok, err := p.db.HasIngestionCandidate(item.SourceID, item.ContentRevision())
		if err != nil {
			return nil, err
		}
		if ok {
			retained = append(retained, item)
		}
	}
	return retained, nil
}

type sourceRefreshMemo map[string]sourceRefreshResult

func (p *Pipeline) hasPrefetcher() bool {
	_, quality := p.quality.client.(llm.Prefetcher)
	_, extraction := p.extractor.client.(llm.Prefetcher)
	return quality || extraction
}

// Reuse the existing intake queue, without changing any source watermark. Raw
// payloads survive provider waits, process restarts and disappearing feed items.
func (p *Pipeline) retainBatchItems(items []scraper.RawItem) error {
	var candidates []storage.IngestionCandidate
	for _, item := range items {
		item.Revision = item.ContentRevision()
		retained, err := p.db.HasIngestionCandidate(item.SourceID, item.Revision)
		if err != nil {
			return err
		}
		if retained {
			continue
		}
		payload, err := json.Marshal(item)
		if err != nil {
			return err
		}
		candidates = append(candidates, storage.IngestionCandidate{SourceID: item.SourceID, Source: item.Source, Revision: item.Revision, Payload: string(payload)})
	}
	if len(candidates) == 0 {
		return nil
	}
	return p.db.CommitIngestion("", time.Time{}, candidates)
}

// Readiness only reads source evidence, checkpoints and typed generation cache.
// A miss must never enter processItem: it could buy live inference, clear an
// attempt budget or mutate dedup state. Saved candidates still run grounding.
func (p *Pipeline) batchItemReady(ctx context.Context, item scraper.RawItem) (ready, terminal bool, extraction *ExtractionResult) {
	item.Revision = item.ContentRevision()
	if seen, err := p.db.HasSeenRevision(item.SourceID, item.Revision); err != nil || seen {
		return err == nil, true, nil
	}
	cp, err := p.db.GetProcessingCheckpoint(item.SourceID)
	if err != nil {
		return false, false, nil
	}
	if cp != nil {
		var state processingCandidate
		if yaml.Unmarshal([]byte(cp.Payload), &state) != nil || state.Item.SourceID != item.SourceID || state.PolicyKey != p.processingPolicyKey() {
			return false, false, nil
		}
		if state.MergeDraftID == "" && cp.InputKey == p.processingInputKey(item) && time.Now().Before(cp.RetryAt) {
			return true, true, state.Extraction
		}
		refreshed, err := p.refreshSourceEvidence(ctx, item)
		if err != nil || p.processingKey(refreshed) != state.EvidenceKey {
			return false, false, nil
		}
		if state.MergeDraftID != "" {
			key, err := p.mergeTargetKey(state.MergeDraftID)
			if err != nil || key != state.MergeTargetKey {
				return false, false, nil
			}
		}
		return true, false, state.Extraction
	}
	item, _ = p.refreshSourceEvidence(ctx, item)
	if ctx.Err() != nil {
		return false, false, nil
	}
	decision, _, _ := p.dedup.checkPreExtraction(item, false)
	if decision == DedupSkip || decision == DedupNew && item.CorroborationOnly {
		return true, true, nil
	}
	if decision != DedupMerge {
		if len(strings.TrimSpace(item.Content)) < 100 && item.SigmaRule == nil && !isExploitTracker(item.Source) {
			return true, true, nil
		}
		if decision == DedupNew && (isLowValueItem(item) != "" || isInformationalItem(item) != "") {
			return true, true, nil
		}
		if _, pass := meetsSourceSignalThreshold(item, p.sourceSignalThresholds); !pass {
			return true, true, nil
		}
		if !bypassQuality(item) {
			quality, ok := p.quality.client.(llm.Prefetcher)
			var score QualityScore
			if !ok || !quality.Cached(qualityBatchRequest(item), &score) {
				return false, false, nil
			}
			raw, pass, _ := p.quality.evaluateScore(score)
			if !pass || raw*(0.5+p.getSourceConfidence(item.Source)*0.5) < p.quality.threshold {
				return true, true, nil
			}
		}
		if item.SigmaRule != nil {
			return true, false, nil
		}
	}
	extractor, ok := p.extractor.client.(llm.Prefetcher)
	var result ExtractionResult
	if !ok || !extractor.Cached(extractionBatchRequest(item), &result) {
		return false, false, nil
	}
	return true, false, &result
}

// Preserve known source precedence. Unknown extraction can later reveal a
// relationship, exactly as with today's typed pending path; normal current
// dedup/merge runs again when that item is eventually consumed.
func batchIdentity(item scraper.RawItem, extraction *ExtractionResult) map[string]bool {
	keys := map[string]bool{"source:" + item.SourceID: true}
	if key := NormalizeTitleHash(item.Title); key != "" {
		keys["title:"+key] = true
	}
	if key := NormalizeContentHash(item.Title, item.Content); key != "" {
		keys["content:"+key] = true
	}
	for _, key := range sourceURLHashesForRawItem(item) {
		keys["url:"+key] = true
	}
	for _, cve := range subjectCVEs(item) {
		keys[cve] = true
	}
	if extraction != nil {
		for _, cve := range extraction.CVEs {
			keys[cve] = true
		}
		for _, chain := range extraction.ChainedCVEs {
			for _, cve := range chain {
				keys[cve] = true
			}
		}
		if key := ProductFingerprint(extraction.AffectedVendors, extraction.AffectedProducts); key != "" {
			keys["product:"+key] = true
		}
		if key := ClaimKey(extraction); key != "" {
			keys["claim:"+key] = true
		}
	}
	return keys
}

func (p *Pipeline) readyBatchItems(ctx context.Context, items []scraper.RawItem) (ready, waiting []scraper.RawItem) {
	blocked := map[string]bool{}
	for _, item := range items {
		if ctx.Err() != nil {
			return ready, waiting
		}
		item.Revision = item.ContentRevision()
		available, terminal, extraction := p.batchItemReady(ctx, item)
		if available && terminal {
			ready = append(ready, item)
			continue
		}
		// Include any known extraction even when quality is still pending.
		if extraction == nil {
			if client, ok := p.extractor.client.(llm.Prefetcher); ok {
				refreshed, _ := p.refreshSourceEvidence(ctx, item)
				var result ExtractionResult
				if client.Cached(extractionBatchRequest(refreshed), &result) {
					extraction = &result
				}
			}
		}
		refreshed, _ := p.refreshSourceEvidence(ctx, item)
		identity := batchIdentity(refreshed, extraction)
		if !terminal {
			for key := range identity {
				if blocked[key] {
					available = false
					break
				}
			}
		}
		if available {
			ready = append(ready, item)
			continue
		}
		waiting = append(waiting, item)
		for key := range identity {
			blocked[key] = true
		}
	}
	return ready, waiting
}

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

type prefetchCandidate struct {
	quality, extraction llm.Request
	bypass              bool
	confidenceFactor    float64
}

// The worker receives immutable requests and scalar eligibility snapshots,
// never RawItems, the source memo, or mutable pipeline/dedup state.
type batchPrefetchPlan struct {
	quality, extraction                 llm.Prefetcher
	gate                                QualityGate
	qualityRequests, extractionRequests []llm.Request
	candidates                          []prefetchCandidate
}

func (p *Pipeline) prefetchItems(ctx context.Context, items []scraper.RawItem) {
	p.planPrefetch(ctx, items).run(ctx)
}

// Planning never marks items seen or changes dedup state. It happens before
// parent processing starts; current dedup runs again at actual consumption.
func (p *Pipeline) planPrefetch(ctx context.Context, items []scraper.RawItem) batchPrefetchPlan {
	if _, ok := ctx.Value(sourceRefreshMemoKey{}).(sourceRefreshMemo); !ok {
		ctx = context.WithValue(ctx, sourceRefreshMemoKey{}, sourceRefreshMemo{})
	}
	quality, _ := p.quality.client.(llm.Prefetcher)
	extraction, _ := p.extractor.client.(llm.Prefetcher)
	plan := batchPrefetchPlan{quality: quality, extraction: extraction, gate: QualityGate{threshold: p.quality.threshold}}
	if quality == nil && extraction == nil {
		return plan
	}
	for i := range items {
		if ctx.Err() != nil {
			return plan
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
		refreshed, _ := p.refreshSourceEvidence(ctx, *item)
		if result, ok := ctx.Value(sourceRefreshMemoKey{}).(sourceRefreshMemo)[item.SourceID+"\x00"+item.ContentRevision()]; ok {
			// Waiting consumption reconstructs social context from the original
			// payload plus reusable article text, never an earlier social prefix.
			*item = result.articleBase
		}
		item = &refreshed
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
				plan.extractionRequests = append(plan.extractionRequests, extractionBatchRequest(*item))
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
		if item.SigmaRule == nil {
			plan.candidates = append(plan.candidates, prefetchCandidate{quality: qualityBatchRequest(*item), extraction: extractionBatchRequest(*item), bypass: bypassQuality(*item), confidenceFactor: 0.5 + p.getSourceConfidence(item.Source)*0.5})
		}
		if quality != nil && !bypassQuality(*item) {
			plan.qualityRequests = append(plan.qualityRequests, qualityBatchRequest(*item))
		}
	}
	return plan
}

func (plan batchPrefetchPlan) run(ctx context.Context) {
	if plan.quality != nil && len(plan.qualityRequests) > 0 {
		plan.quality.Prefetch(ctx, plan.qualityRequests)
	}
	if ctx.Err() != nil {
		return
	}
	if plan.extraction == nil {
		return
	}
	for _, candidate := range plan.candidates {
		raw, pass := 5.0, candidate.bypass
		if !pass {
			if plan.quality == nil {
				continue
			}
			var score QualityScore
			if !plan.quality.Cached(candidate.quality, &score) {
				continue
			}
			raw, pass, _ = plan.gate.evaluateScore(score)
		}
		if pass && raw*candidate.confidenceFactor >= plan.gate.threshold {
			plan.extractionRequests = append(plan.extractionRequests, candidate.extraction)
		}
	}
	if len(plan.extractionRequests) > 0 {
		plan.extraction.Prefetch(ctx, plan.extractionRequests)
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
