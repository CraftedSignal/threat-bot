package pipeline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// Increment when source interpretation, prompts or validation semantics change.
const processingPolicyVersion = "evidence-quality-2026-11-14-v1"

type processingCandidate struct {
	PolicyKey         string
	EvidenceKey       string
	AttemptID         string
	Item              scraper.RawItem
	Extraction        *ExtractionResult
	PreCVEs           []string
	Score, Confidence float64
	BriefYAML         string
	Issues            []string
	RebuildDraftID    string
	ReviewHold        bool
	MergeDraftID      string
	MergeTargetKey    string
	MergeAttempts     int
}

func configuredRetryBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return 15 * time.Minute
	}
	if d < 0 {
		return 0
	}
	return d
}
func (p *Pipeline) processingKey(item scraper.RawItem) string {
	schemas, _ := json.Marshal([]any{briefResponseSchema, revisedBriefSchema, detectionResponseSchema})
	prompts := qualitySystemPrompt + qualityPrompt + extractionSystemPrompt + extractionPrompt + briefSystemPrompt + briefPrompt + groundingSystem + groundingRepairSystemPrompt + mergeRelevanceSystemPrompt + mergeRelevancePrompt + roundupContentRelevanceSystemPrompt + roundupContentRelevancePrompt + mergeReviewPolicyVersion
	return fmt.Sprintf("%x", sha256.Sum256([]byte(string(schemas)+prompts+processingPolicyVersion+"\x00"+llm.CachePolicyVersion+"\x00"+p.processingPolicy+"\x00"+item.EvidenceRevision())))
}
func (p *Pipeline) processingPolicyKey() string { return p.processingKey(scraper.RawItem{}) }
func (p *Pipeline) processingInputKey(item scraper.RawItem) string {
	// Stable feed revision locates saved work before article enrichment.
	raw := scraper.RawItem{Revision: item.ContentRevision()}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(p.processingKey(raw)+raw.Revision)))
}

func (p *Pipeline) saveCandidate(key string, state processingCandidate, retry time.Time) error {
	// YAML retains trusted pipeline-only provenance that model-facing JSON hides.
	state.PolicyKey = p.processingPolicyKey()
	if state.EvidenceKey == "" {
		state.EvidenceKey = p.processingKey(state.Item)
	}
	b, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return p.db.PutProcessingCheckpoint(storage.ProcessingCheckpoint{SourceID: state.Item.SourceID, InputKey: key, Payload: string(b), RetryAt: retry})
}
func (p *Pipeline) markSeen(item scraper.RawItem) error {
	return p.db.MarkSeenRevision(item.SourceID, item.Source, item.Title, item.ContentRevision(), item.EvidenceRevision())
}
