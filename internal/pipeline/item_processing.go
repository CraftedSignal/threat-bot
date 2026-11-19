package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/sigma"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

func (p *Pipeline) processItem(ctx context.Context, item scraper.RawItem) (resultErr error) {
	item.Revision = item.ContentRevision()
	attemptID := uuid.NewString()
	ctx = llm.WithCallMetadata(ctx, llm.CallMetadata{SourceID: item.SourceID, AttemptID: attemptID})
	key := p.processingInputKey(item)
	seen, err := p.db.HasSeenRevision(item.SourceID, item.Revision)
	if err != nil {
		return fmt.Errorf("checking seen state: %w", err)
	}
	if seen {
		return nil
	}

	workStarted := false
	var mergeExtraction *ExtractionResult
	defer func() {
		if !workStarted {
			return
		}
		outcome := "retained"
		if resultErr != nil {
			outcome = "error"
		} else if seen, _ := p.db.HasSeenRevision(item.SourceID, item.Revision); seen {
			outcome = "completed"
		}
		if err := p.db.RecordProcessingEvent(item.SourceID, key, attemptID, "process", outcome); err != nil {
			p.logger.Error("recording processing history", "source_id", item.SourceID, "error", err)
		}
	}()
	cp, err := p.db.GetProcessingCheckpoint(item.SourceID)
	if err != nil {
		return fmt.Errorf("reading processing checkpoint: %w", err)
	}
	if cp != nil {
		var state processingCandidate
		if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
			return fmt.Errorf("decoding processing checkpoint: %w", err)
		}
		if state.Item.SourceID != item.SourceID {
			return fmt.Errorf("checkpoint source identity mismatch")
		}
		if state.Stage != "" || state.ClaimAssessment != nil {
			return p.resumeDiscoveryClaim(ctx, key, item, attemptID, *cp, state)
		}
		if state.PolicyKey == p.processingPolicyKey() {
			if state.sourceRefreshDeferred(key) {
				return nil
			}
			if state.MergeDraftID == "" && cp.InputKey == key && time.Now().Before(cp.RetryAt) {
				return nil
			}
			refreshed, refreshErr := p.refreshSourceEvidence(ctx, item)
			if refreshErr != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				return p.deferSourceRefresh(*cp, state, key, refreshErr)
			}
			delete(state.RefreshRetries, key)
			item = refreshed
			targetMatches := true
			if state.MergeDraftID != "" {
				targetKey, targetErr := p.mergeTargetKey(state.MergeDraftID)
				if targetErr != nil && !errors.Is(targetErr, errMergeTargetMissing) {
					return fmt.Errorf("reading merge target; retaining candidate and budget: %w", targetErr)
				}
				targetMatches = targetErr == nil && targetKey == state.MergeTargetKey
			}
			if p.processingKey(item) == state.EvidenceKey && targetMatches {
				if state.GroundingFailure != nil {
					if err := p.refreshHeldGroundingEvidence(ctx, state); err != nil {
						if ctxErr := ctx.Err(); ctxErr != nil {
							return ctxErr
						}
						// The primary record is unavailable, not changed: keep
						// the hold and retry after the source outage delay.
						return p.deferSourceRefresh(*cp, state, key, err)
					}
					if !p.groundingFailureHeld(state) {
						if err := p.db.ClearGroundingAttempts(item.SourceID); err != nil {
							return err
						}
						state.GroundingFailure = nil
					}
				}
				state.Item.Revision = item.Revision
				state.Item.UpdatedAt = item.UpdatedAt
				if err := p.saveCandidate(key, state, cp.RetryAt); err != nil {
					return err
				}
				if state.ReviewHold {
					if state.MergeDraftID != "" {
						return p.ensureMergeReviewVisible(key, state, strings.Join(state.Issues, "; "))
					}
					return nil
				}
				if p.groundingFailureHeld(state) || time.Now().Before(cp.RetryAt) {
					return nil
				}
				workStarted = true
				state.AttemptID = attemptID
				if state.MergeDraftID == "" {
					p.logger.Info("resuming validated candidate", "source_id", item.SourceID, "stage", "grounding")
					return p.processCandidate(ctx, key, state)
				}
				if state.Extraction == nil {
					return fmt.Errorf("merge checkpoint has no extraction")
				}
				mergeExtraction = cloneExtraction(state.Extraction)
				p.logger.Info("resuming merge candidate", "source_id", item.SourceID, "draft_id", state.MergeDraftID, "stage", "merge_assessment")
			} else {
				p.logger.Info("source evidence or merge target changed; rebuilding candidate", "source_id", item.SourceID)
			}
		}
		if mergeExtraction == nil {
			if err := p.db.DeleteProcessingCheckpoint(item.SourceID); err != nil {
				return err
			}
		}
	}

	workStarted = true
	// A new policy or evidence revision starts a new bounded repair budget.
	if err := p.db.ClearGroundingAttempts(item.SourceID); err != nil {
		return err
	}
	p.decisions.record(outcomeProcessed)
	p.logger.Info("processing item", "source_id", item.SourceID, "source", item.Source, "title", item.Title)
	var sourceRefreshErr error
	item, sourceRefreshErr = p.refreshSourceEvidence(ctx, item)
	if sourceRefreshErr == nil {
		unchanged, err := p.db.SeenEvidenceMatches(item.SourceID, item.EvidenceRevision())
		if err != nil {
			return err
		}
		if unchanged {
			p.logger.Info("source update has unchanged evidence", "source_id", item.SourceID)
			return p.markSeen(item)
		}
	}

	routing, done, err := p.routePreExtraction(ctx, key, processingCandidate{AttemptID: attemptID, Item: item, Extraction: mergeExtraction})
	if done || err != nil {
		return err
	}
	dedupDecision, preCVEs := routing.Decision, routing.PreCVEs
	dedupEntries, rebuildDraftID := routing.Entries, routing.RebuildDraftID

	// Pre-filter: skip items with very short content even after enrichment.
	// Exploit trackers (exploit-db, sploitus) build their own structured content
	// and are exempt — their custom scrapers guarantee adequate content length.
	if len(strings.TrimSpace(item.Content)) < 100 && item.SigmaRule == nil && !isExploitTracker(item.Source) {
		if rebuildDraftID != "" {
			return p.holdDraftRebuild(key, processingCandidate{AttemptID: attemptID, Item: item, RebuildDraftID: rebuildDraftID}, item.Content, "source correction has insufficient evidence for an automatic rebuild")
		}
		p.logger.Info("skipping thin content", "source_id", item.SourceID, "len", len(item.Content))
		if err := p.markSeen(item); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}

	// Pre-filter: skip low-value vulnerability classes (e.g. ReDoS) that
	// rarely produce actionable detection intelligence. Only filter new items —
	// if the dedup system flagged this as an update (severity upgrade, exploit
	// disclosure, etc.), let it through.
	if dedupDecision == DedupNew {
		if label := isLowValueItem(item); label != "" {
			p.logger.Info("skipping low-value item", "source_id", item.SourceID, "label", label, "title", item.Title)
			// Still index CVEs so that future updates (e.g. severity upgrade,
			// exploit disclosure) can be detected by the dedup system.
			p.indexLowValueCVEs(item, preCVEs)
			if err := p.markSeen(item); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
		if label := isInformationalItem(item); label != "" {
			p.logger.Info("skipping informational item", "source_id", item.SourceID, "label", label, "title", item.Title)
			if err := p.markSeen(item); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
	}

	// Explicitly configured noisy sources must show deterministic evidence
	// before spending a quality-gate LLM call. Unconfigured sources are
	// unchanged, and rejected items are terminally marked seen.
	if signalScore, pass := meetsSourceSignalThreshold(item, p.sourceSignalThresholds); !pass {
		p.logger.Info("skipping low-signal item", "source_id", item.SourceID, "source", item.Source, "signal_score", signalScore, "threshold", p.sourceSignalThresholds[item.Source])
		if err := p.markSeen(item); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}

	// Quality gate with source confidence weighting.
	confidence := p.getSourceConfidence(item.Source)
	rawScore, pass, err := p.quality.Evaluate(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "quality"}), item)
	if err != nil {
		return fmt.Errorf("quality gate: %w", err)
	}
	// Apply confidence multiplier: adjustedScore = rawScore * (0.5 + confidence * 0.5)
	// confidence=1.0 → full score, 0.5 → 75%, 0.0 → 50%
	score := rawScore * (0.5 + confidence*0.5)
	pass = pass && score >= p.quality.threshold
	p.logger.Info("quality score", "source_id", item.SourceID, "raw_score", rawScore, "adjusted_score", score, "confidence", confidence, "pass", pass)

	if !pass {
		if rebuildDraftID != "" {
			return p.holdDraftRebuild(key, processingCandidate{AttemptID: attemptID, Item: item, RebuildDraftID: rebuildDraftID}, item.Content, "source correction did not meet the quality threshold")
		}
		if retryCriticalQualityRejection(item, time.Now()) {
			p.logger.Warn("retaining critical disclosure after low quality score", "source_id", item.SourceID, "score", score)
			return nil
		}
		if err := p.markSeen(item); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	p.decisions.record(outcomePassedQuality)

	// Extract IOCs, TTPs, and other threat data from narrative sources.
	var extraction *ExtractionResult
	if mergeExtraction != nil {
		extraction = cloneExtraction(mergeExtraction)
	} else if item.SigmaRule == nil {
		var extractErr error
		extraction, extractErr = p.extractor.Extract(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "extraction"}), item)
		if extractErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(extractErr, ctxErr) {
				return ctxErr
			}
			var pending *llm.PendingBatchError
			if errors.As(extractErr, &pending) {
				return fmt.Errorf("extraction deferred: %w", extractErr)
			}
			p.logger.Warn("extraction failed, continuing without", "source_id", item.SourceID, "error", extractErr)
		}
	}
	state := processingCandidate{AttemptID: attemptID, Item: item, Extraction: extraction, PreCVEs: preCVEs, Score: score, Confidence: confidence, RebuildDraftID: rebuildDraftID}
	return p.finishExtractedItem(ctx, key, state, dedupDecision, dedupEntries)
}

type preExtractionRouting struct {
	Decision       DedupDecision
	PreCVEs        []string
	Entries        []storage.ContentIndexEntry
	RebuildDraftID string
}

// Fresh work and pre-assembly resumes must use the same current routing. A
// newly covered source can finish without another checker; a new merge still
// passes the ordinary relevance, delta-grounding and target/review gates.
func (p *Pipeline) routePreExtraction(ctx context.Context, key string, state processingCandidate) (preExtractionRouting, bool, error) {
	item := state.Item
	decision, cves, entries := p.dedup.CheckPreExtraction(item)
	routing := preExtractionRouting{Decision: decision, PreCVEs: cves, Entries: entries}
	routing.RebuildDraftID = p.draftRebuildTarget(item, decision, entries)
	if routing.RebuildDraftID != "" && item.Source == "nvd" && item.CorroborationOnly {
		state.RebuildDraftID = routing.RebuildDraftID
		// This is an editorial correction hold, not a claim retry stage.
		state.Stage, state.ClaimAssessment = "", nil
		return routing, true, p.holdDraftRebuild(key, state, item.Content, "NVD source correction downgrades or retracts the record; canonical claims require review")
	}
	if decision == DedupNew && item.CorroborationOnly {
		p.logger.Info("skipping unmatched corroboration-only item", "source_id", item.SourceID, "source", item.Source)
		if err := p.markSeen(item); err != nil {
			return routing, true, fmt.Errorf("recording seen item: %w", err)
		}
		return routing, true, nil
	}
	if decision == DedupSkip {
		p.logger.Info("skipping cross-source duplicate", "source_id", item.SourceID, "matched_draft", entries[0].DraftID)
		if err := p.markSeen(item); err != nil {
			return routing, true, fmt.Errorf("recording seen item: %w", err)
		}
		return routing, true, nil
	}
	if decision == DedupMerge && routing.RebuildDraftID == "" {
		targetID := entries[0].DraftID
		extraction := cloneExtraction(state.Extraction)
		var extractErr error
		if state.Extraction == nil {
			extraction, extractErr = p.extractor.Extract(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "extraction"}), item)
		}
		if extractErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(extractErr, ctxErr) {
				return routing, true, ctxErr
			}
			return routing, true, fmt.Errorf("merge extraction unavailable; retaining source for retry: %w", extractErr)
		}
		err := p.mergeIntoDraft(ctx, targetID, extraction, item)
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return routing, true, ctxErr
		}
		switch {
		case err == nil:
			p.logger.Info("merged into thin draft", "source_id", item.SourceID, "draft_id", targetID)
		case errors.Is(err, errMergeReviewRequired):
			return routing, true, nil
		case errors.Is(err, errMergeRelevanceUnavailable):
			return routing, true, fmt.Errorf("merge assessment unavailable; retaining source for retry: %w", err)
		case errors.Is(err, errMergeNotRelevant) && !item.CorroborationOnly:
			p.logger.Info("merge into thin draft refused; processing as new item", "source_id", item.SourceID, "draft_id", targetID, "error", err)
			routing.Decision = DedupNew
		default:
			p.logMergeFailure("merge into thin draft failed", err, "source_id", item.SourceID, "draft_id", targetID)
		}
		if routing.Decision != DedupNew {
			if err := p.markSeen(item); err != nil {
				return routing, true, fmt.Errorf("recording seen item: %w", err)
			}
			return routing, true, nil
		}
	}
	if routing.Decision == DedupUpdate {
		p.logger.Info("processing CVE update", "source_id", item.SourceID, "cves", cves)
	}
	return routing, false, nil
}

// Continue only after quality and extraction have succeeded. Claim checkpoints
// resume here; their empty BriefYAML must never enter processCandidate.
func (p *Pipeline) finishExtractedItem(ctx context.Context, key string, state processingCandidate, dedupDecision DedupDecision, dedupEntries []storage.ContentIndexEntry) error {
	item, extraction := state.Item, state.Extraction
	preCVEs, rebuildDraftID := state.PreCVEs, state.RebuildDraftID
	// Look up related sigma rules for context.
	var sigmaRules []sigma.Rule
	if item.SigmaRule != nil {
		sigmaRules = append(sigmaRules, sigma.Rule{
			ID:        item.SigmaRule.ID,
			Title:     item.SigmaRule.Title,
			Tags:      item.SigmaRule.Tags,
			Level:     item.SigmaRule.Level,
			LogSource: sigma.LogSource(item.SigmaRule.LogSource),
			Detection: item.SigmaRule.Detection,
			RawYAML:   item.Content,
		})
	}

	if item.Discovery != nil && extraction != nil {
		proceed, err := p.assessDiscoveryClaim(ctx, key, &state)
		if err != nil || !proceed {
			return err
		}
	}
	if item.Discovery != nil {
		var assessment *ClaimAssessment
		if extraction != nil {
			assessment = extraction.ClaimAssessment
		}
		claimKey := ClaimKey(extraction)
		if claimKey != "" {
			assessmentJSON, _ := json.Marshal(assessment)
			candidateStatus := "below_gate"
			if !item.Discovery.ContextComplete {
				candidateStatus = "resolve_pending"
			}
			if err := p.db.UpsertRumourCandidate(&storage.RumourCandidate{ClaimKey: claimKey, SourceIDs: []string{item.SourceID}, SourceURLs: []string{item.URL}, AssessmentJSON: string(assessmentJSON), Status: candidateStatus, LastSeen: time.Now().UTC()}); err != nil {
				return fmt.Errorf("persisting rumour candidate: %w", err)
			}
		} else {
			return fmt.Errorf("social discovery extraction produced no stable claim key")
		}
		if ok, reason := PublishableRumour(item, assessment); !ok {
			p.logger.Info("holding social rumour below likely gate", "source_id", item.SourceID, "reason", reason)
			if item.Discovery.ContextComplete {
				if err := p.markSeen(item); err != nil {
					return fmt.Errorf("recording seen item: %w", err)
				}
			}
			return nil
		}
	}

	// Recover CVE briefs whose source never named an affected vendor/product
	// (they would otherwise be dropped by isGenericCVEBrief). Infer the fields
	// from the item before the brief is assembled so the value flows into the
	// draft, the dedup/routing fingerprints, and every emitted feed.
	if extraction != nil {
		applyVendorProductFallback(ctx, p.llmClient, p.logger, item, extraction)
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	// Post-extraction dedup: confirm subject CVEs and use the
	// vendor+product+class fingerprint fallback. On a skip, append the
	// new source URL to the original draft's notes so the canonical
	// brief still records that this source corroborated it.
	if extraction != nil && dedupDecision == DedupNew {
		postDecision, postEntries := p.dedup.CheckPostExtraction(item, extraction)
		rebuildDraftID = p.draftRebuildTarget(item, postDecision, postEntries)
	}
	if extraction != nil && dedupDecision == DedupNew && rebuildDraftID == "" {
		handled := p.handlePostExtractionDedup(ctx, item, extraction, preCVEs)
		if err := ctx.Err(); err != nil {
			return err
		}
		if handled {
			return nil
		}
		// Roundup consolidation (gated, off by default): fold a patch-cycle
		// vendor's monthly CVEs into one brief instead of one brief per CVE.
		handled = p.routeToRoundup(ctx, item, extraction)
		if err := ctx.Err(); err != nil {
			return err
		}
		if handled {
			return nil
		}
		// Campaign consolidation (gated, off by default): fold sightings of a
		// known campaign family (ClickFix, Shai-Hulud) into one umbrella brief.
		handled = p.routeToCampaign(ctx, item, extraction)
		if err := ctx.Err(); err != nil {
			return err
		}
		if handled {
			return nil
		}
	}

	// DedupUpdate path: pre-extraction flagged this item as carrying new
	// exploitation, patch, or severity signal for an already-indexed CVE.
	// Merge into the existing draft instead of assembling a parallel brief
	// that would fragment coverage of the same CVE. Falls through to new
	// draft creation only if every merge attempt fails (e.g. draft deleted).
	if extraction != nil && dedupDecision == DedupUpdate && len(dedupEntries) > 0 && rebuildDraftID == "" {
		for _, e := range dedupEntries {
			if e.DraftID == "" {
				continue
			}
			if err := p.mergeIntoDraft(ctx, e.DraftID, extraction, item); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
					return ctxErr
				}
				if errors.Is(err, errMergeReviewRequired) {
					return nil
				}
				if errors.Is(err, errMergeRelevanceUnavailable) {
					return fmt.Errorf("update merge assessment unavailable; retaining source for retry: %w", err)
				}
				p.logMergeFailure("DedupUpdate merge failed, will create new draft", err,
					"source_id", item.SourceID, "draft_id", e.DraftID)
				break
			}
			p.logger.Info("DedupUpdate: merged exploit/patch signal into existing draft",
				"source_id", item.SourceID, "draft_id", e.DraftID)
			p.indexContent(e.DraftID, item, preCVEs, extraction)
			if err := p.markSeen(item); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
	}

	briefYAML, err := p.assembleWithVerifiedEvidence(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "assembly"}), item, extraction, sigmaRules)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return ctxErr
		}
		var invalid *InvalidBriefYAMLError
		if errors.As(err, &invalid) {
			return p.quarantineInvalidBrief(item, invalid)
		}
		return fmt.Errorf("brief assembly: %w", err)
	}
	state.Item, state.Extraction = item, extraction
	state.BriefYAML, state.RebuildDraftID = briefYAML, rebuildDraftID
	state.Stage, state.ClaimAssessment = "", nil
	return p.processCandidate(ctx, key, state)
}
