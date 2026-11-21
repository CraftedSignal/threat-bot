package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// Increment when source interpretation, prompts or validation semantics change.
const processingPolicyVersion = "evidence-quality-2026-11-15-v5"

type processingCandidate struct {
	Stage             string
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
	GroundingFailure  *processingGroundingFailure
	ClaimAssessment   *processingClaimAssessment
	RefreshRetries    map[string]time.Time
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

// Repeated rejection or provider failure should not buy a repair/recheck on
// every poll. Keep the existing attempt budget, but give subsequent attempts
// increasing delays. An explicit longer base delay remains authoritative.
func (p *Pipeline) groundingRetryDelay(attempt int) time.Duration {
	delay := p.retryBackoff
	limit := max(delay, 2*time.Hour)
	for n := 1; n < attempt && delay > 0 && delay < limit; n++ {
		if delay >= limit/2 {
			return limit
		}
		delay *= 2
	}
	return delay
}

func (p *Pipeline) processingKey(item scraper.RawItem) string {
	schemas, _ := json.Marshal([]any{briefResponseSchema, revisedBriefSchema, detectionResponseSchema, groundingReportSchema, claimGroundingReportSchema, llm.MustSchemaOf[materialOmissionEvidenceReport]()})
	prompts := qualitySystemPrompt + qualityPrompt + extractionSystemPrompt + extractionPrompt + briefSystemPrompt + compactAdvisorySystemPrompt + briefPrompt + groundingSystem + groundingClaimsSystem + groundingRepairSystemPrompt + materialOmissionEvidenceSystem + mergeRelevanceSystemPrompt + mergeRelevancePrompt + roundupContentRelevanceSystemPrompt + roundupContentRelevancePrompt + mergeReviewPolicyVersion
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

// A held provider-output contract failure is not a negative factual verdict.
// The database already stores this typed record in its opaque checkpoint
// payload; no shared storage schema or factual-verdict cache is involved.
type processingGroundingFailure struct {
	Kind           string
	RequestDigest  string
	ContextDigest  string
	EvidenceDigest string
	Detail         string
}

// durableGroundingHoldError marks an item that was safely retained for
// editorial or evidence review. It remains an error for callers that inspect
// processItem directly, but the polling loop must not count it as an
// operational pipeline failure after the hold has been persisted.
type durableGroundingHoldError struct{ err error }

func (e durableGroundingHoldError) Error() string { return e.err.Error() }
func (e durableGroundingHoldError) Unwrap() error { return e.err }

func (p *Pipeline) groundingFailureContextDigest(state processingCandidate) string {
	data, _ := json.Marshal([]any{state.GroundingFailure.RequestDigest, p.processingPolicyKey(), state.EvidenceKey, state.BriefYAML, p.groundingFailureEvidenceDigest(state)})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func (p *Pipeline) groundingFailureEvidenceDigest(state processingCandidate) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(p.groundingEvidence(state.Item, state.BriefYAML))))
}
func (p *Pipeline) groundingFailureHeld(state processingCandidate) bool {
	return state.GroundingFailure != nil && state.GroundingFailure.ContextDigest == p.groundingFailureContextDigest(state)
}
func (p *Pipeline) holdGroundingContractFailure(key string, state *processingCandidate, err error) error {
	var failure *omissionEvidenceContractError
	if !errors.As(err, &failure) {
		return err
	}
	if state.EvidenceKey == "" {
		state.EvidenceKey = p.processingKey(state.Item)
	}
	state.GroundingFailure = &processingGroundingFailure{Kind: failure.FailureKind(), RequestDigest: failure.RequestDigest(), Detail: failure.Error()}
	state.GroundingFailure.EvidenceDigest = p.groundingFailureEvidenceDigest(*state)
	state.GroundingFailure.ContextDigest = p.groundingFailureContextDigest(*state)
	if saveErr := p.saveCandidate(key, *state, time.Time{}); saveErr != nil {
		return fmt.Errorf("saving grounding contract hold: %w", errors.Join(err, saveErr))
	}
	p.logger.Warn("holding candidate after grounding evidence contract failure", "source_id", state.Item.SourceID, "failure_kind", state.GroundingFailure.Kind, "request_digest", state.GroundingFailure.RequestDigest, "context_digest", state.GroundingFailure.ContextDigest)
	return durableGroundingHoldError{err: err}
}

// The verifier cache is process-local. Rehydrate it before deciding whether
// primary evidence changed; a cache miss or transport outage is not a new
// factual input and must not spend another full model check.
func (p *Pipeline) refreshHeldGroundingEvidence(ctx context.Context, state processingCandidate) error {
	if p.cveVerifier == nil {
		return nil
	}
	for id := range groundingTargetCVEs(parseBriefFrontmatter(state.BriefYAML)) {
		_, err := p.cveVerifier.checkCVE(ctx, id)
		if err != nil {
			return fmt.Errorf("primary evidence refresh unavailable; retaining grounding contract hold: %w", err)
		}
		meta := p.cveVerifier.GetMeta(id)
		if meta == nil || meta.CNAUnavailable || meta.Verification.Status == "unavailable" {
			return fmt.Errorf("primary evidence refresh unavailable for %s; retaining grounding contract hold", id)
		}
	}
	return ctx.Err()
}
