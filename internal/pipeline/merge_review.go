package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// v2 grounds only the fields a merge writes (mergeAppliedDelta). Bumping it
// re-assesses merges held under v1 for findings on discarded fields.
const mergeReviewPolicyVersion = "merge-review-2026-11-19-v2"

var errMergeReviewRequired = errors.New("merge requires editorial review")
var errMergeTargetMissing = errors.New("merge target is missing")

// MergeClaimsRejectedError is a completed negative assessment. It is never an
// unavailable checker or evidence that the source is a separate story.
type MergeClaimsRejectedError struct {
	Issues     []string
	Extraction *ExtractionResult
}

func (e *MergeClaimsRejectedError) Error() string {
	return "incoming claims unsupported: " + strings.Join(e.Issues, "; ")
}
func (*MergeClaimsRejectedError) Unwrap() error { return errMergeReviewRequired }

// mergeTargetKey covers the facts and evidence used to interpret a merge.
// Publication bookkeeping and YAML formatting cannot restart paid assessments.
func (p *Pipeline) mergeTargetKey(draftID string) (string, error) {
	draft, err := p.db.GetDraft(draftID)
	if err != nil {
		return "", err
	}
	if draft == nil {
		return "", fmt.Errorf("%w: %s", errMergeTargetMissing, draftID)
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(draft.BriefYAML), &fm); err != nil {
		return "", err
	}
	semantic := map[string]any{"status": draft.Status}
	for _, field := range []string{"id", "slug", "title", "summary", "content", "cves", "chained_cves", "affected_vendors", "affected_products", "affected_os", "iocs", "threat_actor", "tags", "severity", "severity_basis", "rules", "ttps", "action_plan", "references", "exploitation_status", "exploitation_evidence", "has_poc", "rumour"} {
		semantic[field] = fm[field]
	}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded)), nil
}

func (p *Pipeline) mergeCheckpointMatches(state processingCandidate, item scraper.RawItem, draftID, targetKey string) bool {
	return state.MergeDraftID == draftID && state.MergeTargetKey == targetKey && state.PolicyKey == p.processingPolicyKey() && state.EvidenceKey == p.processingKey(item)
}

func (p *Pipeline) holdMergeCandidate(key string, state processingCandidate, reason string) error {
	state.ReviewHold = true
	if err := p.saveCandidate(key, state, time.Time{}); err != nil {
		return err
	}
	return p.ensureMergeReviewVisible(key, state, reason)
}

func (p *Pipeline) ensureMergeReviewVisible(key string, state processingCandidate, reason string) error {
	// Preserve the source, selected extraction and target identity together. The
	// source remains unseen so changed evidence can be reconsidered normally.
	raw, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	reason = fmt.Sprintf("merge into canonical draft %s held for editorial review: %s", state.MergeDraftID, reason)
	attemptID := state.AttemptID
	if attemptID == "" {
		// Direct routing callers may lack process metadata. A target change is
		// still a distinct review even for the same source and input revision.
		identity := state.MergeDraftID + "\x00" + state.MergeTargetKey + "\x00" + p.processingKey(state.Item)
		attemptID = fmt.Sprintf("merge-review:%x", sha256.Sum256([]byte(identity)))
	}
	recorded, err := p.db.EnsureMergeReviewHold(storage.MergeReviewHold{
		SourceID: state.Item.SourceID, Source: state.Item.Source, Title: state.Item.Title,
		RawOutput: string(raw), Reason: reason, InputKey: key, AttemptID: attemptID,
	})
	if err != nil {
		return err
	}
	if recorded {
		p.logger.Warn("merge candidate held for editorial review", "source_id", state.Item.SourceID, "draft_id", state.MergeDraftID, "attempt", state.MergeAttempts, "reason", reason)
	}
	return nil
}

func (p *Pipeline) mergeIntoDraft(ctx context.Context, draftID string, extraction *ExtractionResult, item scraper.RawItem) (resultErr error) {
	// Every operational failure must defer at all callers, including boolean
	// routing helpers. Otherwise a failed checkpoint write could fall through
	// into standalone assembly or mark this source seen.
	defer func() {
		if resultErr == nil || errors.Is(resultErr, errMergeReviewRequired) || errors.Is(resultErr, errMergeNotRelevant) || errors.Is(resultErr, errNonAuthoritativeRoundupSource) || errors.Is(resultErr, errMergeRelevanceUnavailable) {
			return
		}
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(resultErr, ctxErr) {
			return
		}
		resultErr = fmt.Errorf("%w: %w", errMergeRelevanceUnavailable, resultErr)
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	targetKey, err := p.mergeTargetKey(draftID)
	if err != nil {
		return fmt.Errorf("%w: %w", errMergeRelevanceUnavailable, err)
	}
	key := p.processingInputKey(item)
	state := processingCandidate{Item: item, Extraction: cloneExtraction(extraction), MergeDraftID: draftID, MergeTargetKey: targetKey, PinnedInput: p.pinnedInputFor(ctx, item)}
	state.AttemptID = llm.CallMetadataFromContext(ctx).AttemptID
	cp, err := p.db.GetProcessingCheckpoint(item.SourceID)
	if err != nil {
		return err
	}
	if cp != nil {
		var saved processingCandidate
		if err := yaml.Unmarshal([]byte(cp.Payload), &saved); err != nil {
			return fmt.Errorf("decoding merge checkpoint: %w", err)
		}
		if p.mergeCheckpointMatches(saved, item, draftID, targetKey) {
			state.MergeAttempts = saved.MergeAttempts
			if saved.ReviewHold {
				if err := p.ensureMergeReviewVisible(key, saved, strings.Join(saved.Issues, "; ")); err != nil {
					return err
				}
				return fmt.Errorf("%w: %s", errMergeReviewRequired, strings.Join(saved.Issues, "; "))
			}
			if time.Now().Before(cp.RetryAt) {
				return fmt.Errorf("%w: assessment retry deferred", errMergeRelevanceUnavailable)
			}
		}
	}
	if state.MergeAttempts >= p.maxGroundingAttempts {
		state.Issues = []string{fmt.Sprintf("merge assessment retry budget exhausted after %d attempts", state.MergeAttempts)}
		if err := p.holdMergeCandidate(key, state, state.Issues[0]); err != nil {
			return err
		}
		return fmt.Errorf("%w: %s", errMergeReviewRequired, state.Issues[0])
	}
	state.MergeAttempts++
	if err := p.saveCandidate(key, state, time.Now().Add(p.retryBackoff)); err != nil {
		return err
	}
	err = p.unionIntoDraft(ctx, draftID, extraction, item)
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return ctxErr
	}
	if err != nil {
		var rejected *MergeClaimsRejectedError
		if errors.As(err, &rejected) {
			state.Issues = append([]string(nil), rejected.Issues...)
			state.Extraction = cloneExtraction(rejected.Extraction)
			if holdErr := p.holdMergeCandidate(key, state, err.Error()); holdErr != nil {
				return holdErr
			}
			return err
		}
		if errors.Is(err, errMergeNotRelevant) || errors.Is(err, errNonAuthoritativeRoundupSource) {
			if clearErr := p.db.DeleteProcessingCheckpoint(item.SourceID); clearErr != nil {
				return clearErr
			}
			return err
		}
		if !errors.Is(err, errMergeRelevanceUnavailable) {
			err = fmt.Errorf("%w: %w", errMergeRelevanceUnavailable, err)
		}
		if eventErr := p.db.RecordProcessingEvent(item.SourceID, key, state.AttemptID, "merge_assessment", "unavailable"); eventErr != nil {
			return errors.Join(err, eventErr)
		}
		if state.MergeAttempts >= p.maxGroundingAttempts {
			state.Issues = []string{fmt.Sprintf("merge assessment unavailable after %d attempts: %v", state.MergeAttempts, err)}
			if holdErr := p.holdMergeCandidate(key, state, state.Issues[0]); holdErr != nil {
				return errors.Join(err, holdErr)
			}
		}
		return err
	}
	if err := p.db.DeleteProcessingCheckpoint(item.SourceID); err != nil {
		return err
	}
	p.decisions.record(outcomeMerged)
	return nil
}
