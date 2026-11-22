package pipeline

import (
	"context"
	"errors"
	"fmt"
	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"strings"
	"time"
)

func (p *Pipeline) processCandidate(ctx context.Context, key string, state processingCandidate) (resultErr error) {
	if p.groundingFailureHeld(state) {
		return nil
	}
	if state.GroundingFailure != nil {
		if err := p.db.ClearGroundingAttempts(state.Item.SourceID); err != nil {
			return err
		}
	}
	state.GroundingFailure = nil
	item, extraction, preCVEs := state.Item, state.Extraction, state.PreCVEs
	score, confidence, briefYAML := state.Score, state.Confidence, state.BriefYAML
	var err error
	if err := p.saveCandidate(key, state, time.Time{}); err != nil {
		return err
	}
	// The assembler can drop an affected vendor/product that the extraction,
	// the NVD CPEs or the CNA still name; restore it so the generic-CVE
	// rejection below only fires when every source is empty.
	if backfilled, stages := backfillAffectedFromSources(item, extraction, briefYAML); len(stages) > 0 {
		briefYAML = backfilled
		p.logger.Info("backfilled affected vendor/product into assembled brief", "source_id", item.SourceID, "stages", stages)
	}
	// Feed the Sigma parser's errors back to the LLM for rules it got wrong;
	// validation rejects any rule that is still invalid.
	briefYAML, repairNotes, repairErr := p.assembler.RepairRules(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "rule_repair"}), briefYAML)
	if repairErr != nil {
		return repairErr
	}

	// Inject the originating scraper name so the publisher's classifier
	// can distinguish rule-feed sources (Sigma HQ / Splunk ESCU /
	// Elastic) from vulnerability writeups that the assembler attached
	// a synthesized Sigma rule to. Without this, every brief would
	// look the same to classifyType.
	briefYAML = injectSourceField(briefYAML, item.Source)
	// The source item is the provenance for this brief. The assembler can
	// return an empty references list even when the item has a public URL;
	// that would make the public site reject the entire deployment batch.
	briefYAML, err = ensureInitialSourceReference(briefYAML, item.URL)
	if err != nil {
		return p.quarantineInvalidBrief(item, &InvalidBriefYAMLError{Err: err, Raw: briefYAML})
	}
	briefYAML = normalizeDetectionSeverity(briefYAML, item)

	// Briefs sourced directly from exploit trackers are, by definition,
	// about a public exploit or PoC — set has_poc and record the source URL.
	if isExploitTracker(item.Source) {
		briefYAML = injectBoolField(briefYAML, "has_poc", true)
		if item.URL != "" {
			briefYAML = injectStringListField(briefYAML, "poc_references", item.URL)
		}
	}

	// Also set has_poc when the source says an exploit or PoC is public
	// ("The exploit has been released to the public and may be used"). The
	// source decides, not the model's content: has_poc is pipeline-owned and
	// hidden from grounding, so a PoC claim the model invented must not set it.
	if sourceReportsPublicExploit(item) {
		briefYAML = injectBoolField(briefYAML, "has_poc", true)
	}

	// Validate and clean the brief.
	cleanedYAML, validationNotes, valErr := p.validator.Validate(briefYAML)
	if valErr != nil {
		return p.quarantineInvalidBrief(item, &InvalidBriefYAMLError{Err: valErr, Raw: briefYAML})
	}
	validationNotes = append(repairNotes, validationNotes...)
	if len(validationNotes) > 0 {
		p.logger.Info("brief validation notes", "source_id", item.SourceID, "notes", validationNotes)
	}

	// Fact-checking verification: IOC format, CVE existence, grounding.
	iocYAML, iocNotes := p.iocVerifier.Verify(cleanedYAML)
	if len(iocNotes) > 0 {
		cleanedYAML = iocYAML
		validationNotes = append(validationNotes, iocNotes...)
		p.logger.Info("IOC format verification notes", "source_id", item.SourceID, "notes", iocNotes)
	}

	cveYAML, cveNotes := p.cveVerifier.Verify(ctx, cleanedYAML)
	cleanedYAML = cveYAML
	if len(cveNotes) > 0 {
		validationNotes = append(validationNotes, cveNotes...)
		p.logger.Info("CVE verification notes", "source_id", item.SourceID, "notes", cveNotes)
	}

	// Reject CVE briefs the LLM couldn't pin to a vendor or product.
	// They render as "Unauthenticated remote access via unsecured
	// configuration interface (CVE-…)" — accurate but useless because
	// nobody knows what to patch or scope detections to.
	if rejectGenericCVEBrief(item, cleanedYAML) {
		p.logger.Warn("rejecting generic CVE brief — no affected vendor/product extracted",
			"source_id", item.SourceID, "title", item.Title)
		if err := p.markSeen(item); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}

	// Facts the source states are rendered by code, never left to the LLM:
	// affected version ranges and the advisory severity. This runs before the
	// first grounding check so the checker sees the final values.
	cleanedYAML = p.injectSourceRanges(cleanedYAML, item)
	cleanedYAML = normalizeDetectionSeverity(cleanedYAML, item)

	state.BriefYAML = cleanedYAML
	if err := p.saveCandidate(key, state, time.Now().Add(p.retryBackoff)); err != nil {
		return err
	}
	attempts, err := p.db.RecordGroundingAttempt(item.SourceID)
	if err != nil {
		return fmt.Errorf("reserving grounding attempt: %w", err)
	}
	if attempts > p.maxGroundingAttempts {
		return p.quarantineUngrounded(item, cleanedYAML, &UngroundedBriefError{Attempts: p.maxGroundingAttempts, Issues: []string{"grounding retry budget exhausted"}})
	}
	retryDelay := p.groundingRetryDelay(attempts)
	if attempts > 1 {
		// Persist the longer delay before making a provider call so an outage
		// or process restart cannot fall back to the first-attempt schedule.
		if err := p.saveCandidate(key, state, time.Now().Add(retryDelay)); err != nil {
			return err
		}
	}
	// Only failed model calls count as unavailable grounding. Storage or
	// publication errors must preserve the candidate for retry.
	groundingUnavailable := false
	defer func() {
		if !groundingUnavailable || resultErr == nil || ctx.Err() != nil || state.GroundingFailure != nil {
			return
		}
		_ = p.db.RecordProcessingEvent(item.SourceID, key, state.AttemptID, "grounding", "unavailable")
		if attempts >= p.maxGroundingAttempts {
			resultErr = p.quarantineUngrounded(item, cleanedYAML, &UngroundedBriefError{Attempts: attempts, Issues: []string{"grounding unavailable within retry budget: " + resultErr.Error()}})
		}
	}()

	var groundingResult *GroundingResult
	var groundingErr error
	hadPriorIssues := len(state.Issues) > 0
	if hadPriorIssues {
		groundingResult = &GroundingResult{Issues: state.Issues}
	} else {
		groundingResult, groundingErr = p.grounding.Check(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "grounding"}), item.Title, p.groundingEvidence(item, cleanedYAML), groundingView(cleanedYAML, item.URL))
	}
	if groundingErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(groundingErr, ctxErr) {
			return ctxErr
		}
		groundingUnavailable = true
		return p.holdGroundingContractFailure(key, &state, fmt.Errorf("grounding check: %w", groundingErr))
	}
	if !groundingResult.Grounded {
		for _, issue := range groundingResult.Issues {
			validationNotes = append(validationNotes, fmt.Sprintf("grounding: %s", issue))
		}
		state.Issues = groundingResult.Issues
		if err := p.saveCandidate(key, state, time.Now().Add(retryDelay)); err != nil {
			return err
		}
		repaired, err := p.grounding.Repair(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "grounding_repair"}), item.Title, p.groundingEvidence(item, cleanedYAML), cleanedYAML, groundingResult.Issues)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return ctxErr
			}
			var invalid *InvalidBriefYAMLError
			if errors.As(err, &invalid) {
				return p.quarantineInvalidBrief(item, invalid)
			}
			groundingUnavailable = true
			return fmt.Errorf("grounding repair: %w", err)
		}
		repaired = injectSourceField(repaired, item.Source)
		repaired, err = ensureInitialSourceReference(repaired, item.URL)
		if err != nil {
			return fmt.Errorf("grounding repair source reference: %w", err)
		}
		cleanedYAML, _, err = p.validator.Validate(repaired)
		if err != nil {
			return p.quarantineInvalidBrief(item, &InvalidBriefYAMLError{Err: fmt.Errorf("grounding repair validation: %w", err), Raw: repaired})
		}
		cleanedYAML, _ = p.iocVerifier.Verify(cleanedYAML)
		cleanedYAML, _ = p.cveVerifier.Verify(ctx, cleanedYAML)
		cleanedYAML = p.injectSourceRanges(cleanedYAML, item)
		cleanedYAML = normalizeDetectionSeverity(cleanedYAML, item)
		state.BriefYAML, state.Issues = cleanedYAML, nil
		if err := p.saveCandidate(key, state, time.Now().Add(retryDelay)); err != nil {
			return err
		}
		groundingResult, err = p.grounding.Check(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "grounding_recheck"}), item.Title, p.groundingEvidence(item, cleanedYAML), groundingView(cleanedYAML, item.URL))
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return ctxErr
			}
			groundingUnavailable = true
			return p.holdGroundingContractFailure(key, &state, fmt.Errorf("grounding recheck: %w", err))
		}
		if !groundingResult.Grounded {
			p.decisions.record(outcomeRejectedUngrounded)
			history, repeated := trackGroundingIssueCycle(state.GroundingIssueHistory, groundingResult.Issues)
			if repeated {
				p.logger.Warn("quarantining repeated grounding finding", "source_id", item.SourceID, "attempt", attempts, "issues", groundingResult.Issues)
				return p.quarantineUngrounded(item, cleanedYAML, &UngroundedBriefError{Attempts: attempts, Issues: groundingResult.Issues})
			}
			state.GroundingIssueHistory = history
			state.Issues = groundingResult.Issues
			if err := p.saveCandidate(key, state, time.Now().Add(retryDelay)); err != nil {
				return err
			}
			if err := p.db.RecordProcessingEvent(item.SourceID, key, state.AttemptID, "grounding", "rejected"); err != nil {
				return err
			}
			if attempts >= p.maxGroundingAttempts {
				return p.quarantineUngrounded(item, cleanedYAML, &UngroundedBriefError{Attempts: attempts, Issues: groundingResult.Issues})
			}
			p.logger.Warn("retaining ungrounded item for retry", "source_id", item.SourceID, "attempt", attempts, "max_attempts", p.maxGroundingAttempts, "issues", groundingResult.Issues)
			return nil
		}
		p.logger.Info("repaired ungrounded brief", "source_id", item.SourceID)
	}
	if err := p.db.ClearGroundingAttempts(item.SourceID); err != nil {
		return fmt.Errorf("clearing grounding attempts: %w", err)
	}

	state.Issues = nil
	state.BriefYAML = cleanedYAML
	if err := p.saveCandidate(key, state, time.Time{}); err != nil {
		return err
	}
	if err := p.db.RecordProcessingEvent(item.SourceID, key, state.AttemptID, "grounding", "accepted"); err != nil {
		return err
	}

	// CVE enrichment: add EPSS, CVSS, KEV data per CVE.
	cleanedYAML, cves := p.cveEnricher.Enrich(cleanedYAML, nil)

	// Watchlist matching.
	watchlistMatch := false
	wl := p.getWatchlist()
	if wl != nil {
		var parsed map[string]interface{}
		_ = yaml.Unmarshal([]byte(cleanedYAML), &parsed)
		wb := WatchlistBrief{
			Title:       fmt.Sprintf("%v", parsed["title"]),
			Summary:     fmt.Sprintf("%v", parsed["summary"]),
			ThreatActor: fmt.Sprintf("%v", parsed["threat_actor"]),
		}
		if content, ok := parsed["content"].(string); ok {
			wb.Content = content
		}
		if tags, ok := parsed["tags"].([]interface{}); ok {
			for _, t := range tags {
				wb.Tags = append(wb.Tags, fmt.Sprintf("%v", t))
			}
		}
		watchlistMatch = wl.Matches(wb)
	}

	// Priority classification.
	corroborated := false
	extractedCVEIDs := cveRe.FindAllString(cleanedYAML, -1)
	seenCVEs := make(map[string]bool)
	for _, cveID := range extractedCVEIDs {
		if seenCVEs[cveID] {
			continue
		}
		seenCVEs[cveID] = true
		count, _ := p.db.CountDistinctSourcesForCVE(cveID)
		if count >= 2 {
			corroborated = true
			break
		}
	}

	// Active exploitation is a structured, attributed evidence state. The CVE
	// enricher creates that state for KEV records; prose and bare booleans do
	// not independently establish exploitation.
	activeExploitation := confirmedExploitationEvidence(cleanedYAML)

	if normalizedYAML, severityNotes := NormalizeOperationalSeverity(cleanedYAML, SeverityContext{
		CVEs:               cves,
		ActiveExploitation: activeExploitation,
		WatchlistMatch:     watchlistMatch,
	}); len(severityNotes) > 0 {
		cleanedYAML = normalizedYAML
		validationNotes = append(validationNotes, severityNotes...)
		p.logger.Info("severity normalization notes", "source_id", item.SourceID, "notes", severityNotes)
	}

	hasRules := strings.Contains(cleanedYAML, "rules:")
	hasIOCs := strings.Contains(cleanedYAML, "iocs:")

	priorityResult := ComputePriority(PriorityInput{
		CVEs:               cves,
		ActiveExploitation: activeExploitation,
		SourceConfidence:   confidence,
		Corroborated:       corroborated,
		WatchlistMatch:     watchlistMatch,
		HasRules:           hasRules,
		HasIOCs:            hasIOCs,
	})

	cleanedYAML = EnrichBriefWithPriority(cleanedYAML, priorityResult)
	cleanedYAML = EnrichBriefWithSourceAssessment(cleanedYAML, SourceAssessmentInput{
		Source:             item.Source,
		SourceConfidence:   confidence,
		Corroborated:       corroborated,
		ActiveExploitation: activeExploitation,
	})
	p.logger.Info("priority classified", "source_id", item.SourceID, "tier", priorityResult.Tier, "score", priorityResult.Score, "signals", priorityResult.Signals)

	// Rumour classification: low-confidence forum/social source with no CVE
	// reference, no corroboration, and no exploitation evidence is unconfirmed
	// chatter. Override severity → "rumour" so consumers can dismiss it cheaply.
	if item.Discovery != nil && extraction != nil {
		cleanedYAML = EnrichBriefWithRumourAssessment(cleanedYAML, extraction.ClaimAssessment)
		p.logger.Info("classified as evidence-backed likely rumour", "source_id", item.SourceID)
	} else if IsRumour(RumourInput{
		SourceConfidence:   confidence,
		CVEs:               cves,
		Corroborated:       corroborated,
		ActiveExploitation: activeExploitation,
		WatchlistMatch:     watchlistMatch,
		HasSigmaRule:       item.SigmaRule != nil,
	}) {
		// A plain rumour (low-confidence source, no CVE, no corroboration)
		// carries no claim assessment, so it can never satisfy the
		// likely-rumour contract. Hold it like a social rumour below the
		// likely gate instead of building a brief that is always quarantined.
		p.logger.Info("holding rumour: low-confidence source with no CVE, corroboration or claim assessment cannot meet the likely-rumour contract; no brief created",
			"source_id", item.SourceID, "confidence", confidence)
		if err := p.markSeen(item); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}

	// Enrichment changes severity, priority, evidence, and assessment fields.
	// Re-run the semantic release gate over the exact document that can be
	// saved or auto-published.
	finalYAML, finalNotes, finalErr := p.validator.Validate(cleanedYAML)
	if finalErr != nil {
		return p.quarantineInvalidBrief(item, &InvalidBriefYAMLError{Err: finalErr, Raw: cleanedYAML})
	}
	cleanedYAML = finalYAML
	validationNotes = append(validationNotes, finalNotes...)
	if err := ValidateBriefContract(cleanedYAML); err != nil {
		return p.quarantineInvalidBrief(item, &InvalidBriefYAMLError{Err: err, Raw: cleanedYAML})
	}

	// Reject briefs without detection evidence or a supported operational action.
	if !isActionableBrief(cleanedYAML) {
		if state.RebuildDraftID != "" {
			return p.holdDraftRebuild(key, state, cleanedYAML, "rebuilt candidate has no supported operational action")
		}
		p.logger.Info("skipping non-actionable brief", "source_id", item.SourceID, "title", item.Title)
		if err := p.markSeen(item); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	if state.RebuildDraftID != "" {
		if repairedYAML, ok := p.repairMissingHuntLeadGrounded(ctx, item, cleanedYAML); ok {
			cleanedYAML = repairedYAML
		}
		return p.finishDraftRebuild(ctx, key, state, cleanedYAML)
	}
	if handled, err := p.mergeSameWeekAssembledProductBrief(cleanedYAML, item, preCVEs, extraction); err != nil {
		p.logger.Warn("same-week product merge failed; deferring item to prevent a duplicate", "source_id", item.SourceID, "error", err)
		return nil
	} else if handled {
		p.decisions.record(outcomeMerged)
		p.logger.Info("merged assembled same-week product brief", "source_id", item.SourceID, "title", item.Title)
		if err := p.markSeen(item); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	if handled, err := p.mergeSameIncidentAssembledProductBrief(ctx, cleanedYAML, item, preCVEs, extraction); err != nil {
		p.logger.Warn("same-incident product merge unavailable; deferring item to prevent a duplicate", "source_id", item.SourceID, "error", err)
		return nil
	} else if handled {
		p.decisions.record(outcomeMerged)
		if err := p.markSeen(item); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	cleanedYAML, err = p.ensureUniqueDraftIdentity(cleanedYAML, item)
	if err != nil {
		return fmt.Errorf("reserving public brief identity: %w", err)
	}
	if repairedYAML, ok := p.repairMissingHuntLeadGrounded(ctx, item, cleanedYAML); ok {
		cleanedYAML = repairedYAML
		validationNotes = append(validationNotes, "hunt lead generated to cover source-supported TTPs")
	}
	reviewIssues := ValidatePublicationConsistency(cleanedYAML)
	if len(reviewIssues) == 0 && p.autoPublish && p.publisher != nil {
		if validator, ok := p.publisher.(interface{ ValidatePublication(string) error }); ok {
			if err := validator.ValidatePublication(cleanedYAML); err != nil {
				reviewIssues = append(reviewIssues, err.Error())
			}
		}
	}
	for _, issue := range reviewIssues {
		validationNotes = append(validationNotes, "editorial review: "+issue)
	}

	var notesJSON string
	if len(validationNotes) > 0 {
		quoted := make([]string, len(validationNotes))
		for i, n := range validationNotes {
			quoted[i] = fmt.Sprintf("%q", n)
		}
		notesJSON = "[" + strings.Join(quoted, ",") + "]"
	}

	draft := &storage.Draft{
		ID:              uuid.NewString(),
		Status:          storage.StatusPending,
		Score:           score,
		Source:          item.Source,
		SourceIDs:       fmt.Sprintf("[%q]", item.SourceID),
		BriefYAML:       cleanedYAML,
		ValidationNotes: notesJSON,
		CreatedAt:       time.Now(),
	}

	publish := p.autoPublish && p.publisher != nil && len(reviewIssues) == 0
	claimKey := ""
	if item.Discovery != nil {
		claimKey = ClaimKey(extraction)
	}
	if err := p.db.CompleteDraftProcessing(storage.DraftProcessingResult{
		Draft: draft, SourceID: item.SourceID, SourceTitle: item.Title,
		ExpectedInputKey: key,
		Revision:         item.ContentRevision(), EvidenceKey: item.EvidenceRevision(),
		ContentIndex: contentIndexEntries(draft.ID, item, preCVEs, extraction, cleanedYAML),
		Publish:      publish, ClaimKey: claimKey,
	}); err != nil {
		return fmt.Errorf("saving draft and completing processing: %w", err)
	}
	p.decisions.record(outcomeDraft)

	p.logger.Info("draft created", "draft_id", draft.ID, "source", item.Source, "title", item.Title)

	// The result and recovery intent are durable before external enqueueing.
	if p.autoPublish && p.publisher != nil {
		if len(reviewIssues) > 0 {
			p.logger.Warn("brief held for editorial review", "draft_id", draft.ID, "issues", reviewIssues)
			return nil
		}
		if err := p.enqueuePublicationIntent(storage.PublicationIntent{DraftID: draft.ID, BriefYAML: cleanedYAML, ClaimKey: claimKey, CompleteDraft: true}); err != nil {
			p.logger.Error("auto-publish failed", "draft_id", draft.ID, "error", err)
			// Recovery replays the committed intent without rebuilding a draft.
			return nil
		}
		p.logger.Info("queued for publication", "draft_id", draft.ID)
	}

	return nil
}
