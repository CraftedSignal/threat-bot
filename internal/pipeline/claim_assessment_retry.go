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

const discoveryClaimStage = "discovery_claim_assessment_v1"

type processingClaimAssessment struct {
	RequestDigest string
	Outcome       string
	Attempts      int
}

// IsClaimAssessmentCheckpoint lets scheduling route pre-assembly checkpoints
// without paid prefetch. Unknown explicit stages and malformed saved work also
// stay on the normal, fail-closed processing path rather than buying new work.
func IsClaimAssessmentCheckpoint(payload string) bool {
	var state processingCandidate
	return yaml.Unmarshal([]byte(payload), &state) != nil || state.Stage != "" || state.ClaimAssessment != nil
}

func canonicalDiscoveryClaimExtraction(extraction *ExtractionResult) (*ExtractionResult, error) {
	// YAML checkpoints encode nil slices as empty lists. Use that durable
	// representation for the first request too, so a restart cannot change
	// null into [] and purchase the same semantic assessment a second time.
	raw, err := yaml.Marshal(extraction)
	if err != nil {
		return nil, err
	}
	var canonical ExtractionResult
	if err := yaml.Unmarshal(raw, &canonical); err != nil {
		return nil, err
	}
	return &canonical, nil
}

func (p *Pipeline) discoveryClaimRequestDigest(item scraper.RawItem, extraction *ExtractionResult) (string, error) {
	// Match CheckMergeDelta's model-facing serialization: trusted provenance
	// never enters JSON and cannot make a cached rejection appear changed.
	canonical, err := canonicalDiscoveryClaimExtraction(extraction)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	var delta map[string]any
	if err := json.Unmarshal(encoded, &delta); err != nil {
		return "", err
	}
	rendered, err := yaml.Marshal(delta)
	if err != nil {
		return "", err
	}
	content := groundingSource(item)
	source := item.Title + "\n\n" + content
	if len(source) > maxSourceLen {
		source = truncateUTF8(source, maxSourceLen)
	}
	prompt := fmt.Sprintf("## Original Source Material\n%s\n\n## Generated Brief (YAML)\n%s\n\nAssess the supplied YAML according to the system instructions, with verbatim quotes for factual blockers.", source, rendered)
	request := groundingRequestDigest(item.Title, content, string(rendered), prompt, groundingClaimsSystem, claimGroundingReportSchema)
	// Cover complete evidence beyond prompt truncation, extraction and all
	// configured provider/model/policy identities, without delivery clocks.
	data, err := json.Marshal([]any{discoveryClaimStage, p.processingPolicyKey(), item.EvidenceRevision(), request})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func (p *Pipeline) resumeDiscoveryClaim(ctx context.Context, key string, item scraper.RawItem, attemptID string, checkpoint storage.ProcessingCheckpoint, state processingCandidate) error {
	if state.Stage != discoveryClaimStage || state.ClaimAssessment == nil || state.Extraction == nil || state.Item.Discovery == nil {
		return fmt.Errorf("unrecognized or incomplete discovery claim checkpoint; retaining saved work")
	}
	switch state.ClaimAssessment.Outcome {
	case "pending", "unsupported", "transient":
	default:
		return fmt.Errorf("unrecognized discovery claim outcome; retaining saved work")
	}
	refreshed, err := p.refreshSourceEvidence(ctx, item)
	if err != nil {
		return fmt.Errorf("claim source refresh unavailable; retaining assessment: %w", err)
	}
	if state.PolicyKey != p.processingPolicyKey() || state.EvidenceKey != p.processingKey(refreshed) {
		if err := p.db.DeleteProcessingCheckpoint(item.SourceID); err != nil {
			return err
		}
		// Restart from the delivery, not the already-enriched copy: social
		// enrichment prepends fetched context and is not idempotent.
		return p.processItem(ctx, item)
	}
	state.Item, state.AttemptID = refreshed, attemptID
	digest, err := p.discoveryClaimRequestDigest(refreshed, state.Extraction)
	if err != nil {
		return err
	}
	if digest != state.ClaimAssessment.RequestDigest {
		state.ClaimAssessment = nil
		state.Issues = nil
	} else {
		if state.ClaimAssessment.Outcome == "unsupported" || time.Now().Before(checkpoint.RetryAt) {
			if err := p.saveCandidate(key, state, checkpoint.RetryAt); err != nil {
				return err
			}
			p.logger.Info("reusing held discovery claim assessment", "source_id", item.SourceID, "stage", discoveryClaimStage, "outcome", state.ClaimAssessment.Outcome)
			return nil
		}
		// After a failed burst, RetryAt schedules a recovery probe, not a
		// permanent factual hold. Start a new bounded burst only when due.
		if state.ClaimAssessment.Attempts >= p.maxGroundingAttempts {
			state.ClaimAssessment.Attempts = 0
		}
	}
	decision, _, entries := p.dedup.CheckPreExtraction(refreshed)
	return p.finishExtractedItem(ctx, key, state, decision, entries)
}

func (p *Pipeline) discoveryClaimRetryDelay(attempt int) time.Duration {
	const recoveryDelay = time.Hour
	if attempt >= p.maxGroundingAttempts {
		return recoveryDelay
	}
	delay := max(p.retryBackoff, time.Minute)
	for n := 1; n < attempt && delay < recoveryDelay; n++ {
		delay = min(delay, recoveryDelay/2) * 2
	}
	return min(delay, recoveryDelay)
}

func (p *Pipeline) assessDiscoveryClaim(ctx context.Context, key string, state *processingCandidate) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	canonical, err := canonicalDiscoveryClaimExtraction(state.Extraction)
	if err != nil {
		return false, err
	}
	// Preserve the extraction pointer used by the continuation, including
	// pipeline-only provenance freshly issued by the live claim checker.
	*state.Extraction = *canonical
	digest, err := p.discoveryClaimRequestDigest(state.Item, state.Extraction)
	if err != nil {
		return false, err
	}
	if state.ClaimAssessment == nil || state.ClaimAssessment.RequestDigest != digest {
		state.ClaimAssessment = &processingClaimAssessment{RequestDigest: digest}
	}
	state.Stage = discoveryClaimStage
	state.ClaimAssessment.Outcome = "pending"
	state.ClaimAssessment.Attempts++
	retryAt := time.Now().Add(p.discoveryClaimRetryDelay(state.ClaimAssessment.Attempts))
	// Reserve before the live checker: process death or persistence failure
	// cannot silently grant another immediate paid attempt on redelivery.
	if err := p.saveCandidate(key, *state, retryAt); err != nil {
		return false, fmt.Errorf("reserving discovery claim assessment: %w", err)
	}
	delta, callErr := p.grounding.CheckMergeDelta(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "claim_evidence_grounding"}), state.Item, state.Extraction)
	if callErr != nil {
		state.ClaimAssessment.Outcome = "transient"
		if saveErr := p.saveCandidate(key, *state, retryAt); saveErr != nil {
			return false, fmt.Errorf("saving discovery claim retry: %w", errors.Join(callErr, saveErr))
		}
		return false, fmt.Errorf("claim evidence grounding deferred: %w", callErr)
	}
	if !delta.Grounded {
		state.ClaimAssessment.Outcome = "unsupported"
		state.Issues = append([]string(nil), delta.Issues...)
		if err := p.saveCandidate(key, *state, time.Time{}); err != nil {
			return false, fmt.Errorf("saving unsupported discovery claim hold: %w", err)
		}
		p.logger.Warn("holding unsupported discovery claim", "source_id", state.Item.SourceID, "stage", discoveryClaimStage, "error_class", "discovery_claim_unsupported", "request_digest", digest)
		return false, nil
	}
	return true, nil
}
