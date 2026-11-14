package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/sigma"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

func (p *Pipeline) processItem(ctx context.Context, item scraper.RawItem) error {
	seen, err := p.db.HasSeen(item.SourceID)
	if err != nil {
		return fmt.Errorf("checking seen state: %w", err)
	}
	if seen {
		return nil
	}

	p.decisions.record(outcomeProcessed)
	p.logger.Info("processing item", "source", item.Source, "title", item.Title)
	if p.socialProvider != nil && (item.Discovery != nil || containsXStatusReference(item.URL+" "+item.Content)) {
		item = scraper.EnrichSocialContext(ctx, p.socialProvider, item, p.socialThreadDepth)
		if item.Discovery != nil && !item.Discovery.ContextComplete {
			p.logger.Warn("social context provider failed or returned incomplete thread", "source_id", item.SourceID, "url", item.URL)
		}
		if item.Discovery != nil {
			if item.Metadata == nil {
				item.Metadata = map[string]string{}
			}
			provenance := []string{item.Discovery.OriginalURL, item.Discovery.DiscoveryURL}
			provenance = append(provenance, item.Discovery.ParentURLs...)
			provenance = append(provenance, item.Discovery.QuoteURLs...)
			for i, raw := range provenance {
				if strings.TrimSpace(raw) == "" {
					continue
				}
				item.Metadata[fmt.Sprintf("reference_url_social_%03d", i)] = raw
			}
		}
	}

	// Enrich thin content before quality gate so scoring sees full article.
	origLen := len(item.Content)
	for _, enrichmentErr := range p.enricher.Enrich(ctx, &item) {
		p.logger.Warn("vendor advisory enrichment failed; continuing with available evidence", "source_id", item.SourceID, "source", item.Source, "error", enrichmentErr)
	}
	if len(item.Content) > origLen {
		p.logger.Debug("content enriched", "source_id", item.SourceID, "before", origLen, "after", len(item.Content))
	}

	// Cross-source dedup (pre-extraction, cheap regex).
	dedupDecision, preCVEs, dedupEntries := p.dedup.CheckPreExtraction(item)
	if dedupDecision == DedupNew && item.CorroborationOnly {
		p.logger.Info("skipping unmatched corroboration-only item", "source_id", item.SourceID, "source", item.Source)
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	if dedupDecision == DedupSkip {
		p.logger.Info("skipping cross-source duplicate", "source_id", item.SourceID, "matched_draft", dedupEntries[0].DraftID)
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	if dedupDecision == DedupMerge {
		// The matched draft is thin (no CVEs / no IOCs / no
		// product-with-version). Run extraction on the new item and
		// union its structured fields into the existing draft so the
		// next render benefits from the richer source.
		targetID := dedupEntries[0].DraftID
		extraction, extractErr := p.extractor.Extract(ctx, item)
		if extractErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(extractErr, ctxErr) {
				return ctxErr
			}
			p.logger.Warn("merge extraction failed, falling back to reference-only", "source_id", item.SourceID, "draft_id", targetID, "error", extractErr)
			note := fmt.Sprintf("[corroborated] %s %s", item.Source, item.URL)
			_ = p.db.AppendDraftReference(targetID, note)
			if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
		err := p.mergeIntoDraft(ctx, targetID, extraction, item)
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return ctxErr
		}
		switch {
		case err == nil:
			p.logger.Info("merged into thin draft", "source_id", item.SourceID, "draft_id", targetID)
		case errors.Is(err, errMergeNotRelevant) && !item.CorroborationOnly:
			// The relevance check found a separate story that merely matched
			// this draft: process it as a new item instead of dropping it.
			p.logger.Info("merge into thin draft refused; processing as new item", "source_id", item.SourceID, "draft_id", targetID, "error", err)
			dedupDecision = DedupNew
		default:
			p.logMergeFailure("merge into thin draft failed", err, "source_id", item.SourceID, "draft_id", targetID)
		}
		if dedupDecision != DedupNew {
			if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
	}
	if dedupDecision == DedupUpdate {
		p.logger.Info("processing CVE update", "source_id", item.SourceID, "cves", preCVEs)
	}

	// Pre-filter: skip items with very short content even after enrichment.
	// Exploit trackers (exploit-db, sploitus) build their own structured content
	// and are exempt — their custom scrapers guarantee adequate content length.
	if len(strings.TrimSpace(item.Content)) < 100 && item.SigmaRule == nil && !isExploitTracker(item.Source) {
		p.logger.Info("skipping thin content", "source_id", item.SourceID, "len", len(item.Content))
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
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
			if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
		if label := isInformationalItem(item); label != "" {
			p.logger.Info("skipping informational item", "source_id", item.SourceID, "label", label, "title", item.Title)
			if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
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
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}

	// Quality gate with source confidence weighting.
	confidence := p.getSourceConfidence(item.Source)
	rawScore, pass, err := p.quality.Evaluate(ctx, item)
	if err != nil {
		return fmt.Errorf("quality gate: %w", err)
	}
	// Apply confidence multiplier: adjustedScore = rawScore * (0.5 + confidence * 0.5)
	// confidence=1.0 → full score, 0.5 → 75%, 0.0 → 50%
	score := rawScore * (0.5 + confidence*0.5)
	pass = pass && score >= p.quality.threshold
	p.logger.Info("quality score", "source_id", item.SourceID, "raw_score", rawScore, "adjusted_score", score, "confidence", confidence, "pass", pass)

	if !pass {
		if retryCriticalQualityRejection(item, time.Now()) {
			p.logger.Warn("retaining critical disclosure after low quality score", "source_id", item.SourceID, "score", score)
			return nil
		}
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	p.decisions.record(outcomePassedQuality)

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

	// Extract IOCs, TTPs, and other threat data from narrative sources.
	var extraction *ExtractionResult
	if item.SigmaRule == nil {
		var extractErr error
		extraction, extractErr = p.extractor.Extract(ctx, item)
		if extractErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(extractErr, ctxErr) {
				return ctxErr
			}
			p.logger.Warn("extraction failed, continuing without", "source_id", item.SourceID, "error", extractErr)
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
				if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
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
	if extraction != nil && dedupDecision == DedupUpdate && len(dedupEntries) > 0 {
		for _, e := range dedupEntries {
			if e.DraftID == "" {
				continue
			}
			if err := p.mergeIntoDraft(ctx, e.DraftID, extraction, item); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
					return ctxErr
				}
				p.logMergeFailure("DedupUpdate merge failed, will create new draft", err,
					"source_id", item.SourceID, "draft_id", e.DraftID)
				break
			}
			p.logger.Info("DedupUpdate: merged exploit/patch signal into existing draft",
				"source_id", item.SourceID, "draft_id", e.DraftID)
			p.indexContent(e.DraftID, item, preCVEs, extraction)
			if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
	}

	briefYAML, err := p.assembler.Assemble(ctx, item, extraction, sigmaRules)
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
	// The assembler can drop an affected vendor/product that the extraction,
	// the NVD CPEs or the CNA still name; restore it so the generic-CVE
	// rejection below only fires when every source is empty.
	if backfilled, stages := backfillAffectedFromSources(item, extraction, briefYAML); len(stages) > 0 {
		briefYAML = backfilled
		p.logger.Info("backfilled affected vendor/product into assembled brief", "source_id", item.SourceID, "stages", stages)
	}
	// Feed the Sigma parser's errors back to the LLM for rules it got wrong;
	// validation rejects any rule that is still invalid.
	briefYAML, repairNotes, repairErr := p.assembler.RepairRules(ctx, briefYAML)
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
	if len(cveNotes) > 0 {
		cleanedYAML = cveYAML
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
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}

	// Facts the source states are rendered by code, never left to the LLM:
	// affected version ranges and the advisory severity. This runs before the
	// first grounding check so the checker sees the final values.
	cleanedYAML = injectAffectedRanges(cleanedYAML, item)
	cleanedYAML = normalizeDetectionSeverity(cleanedYAML, item)

	groundingResult, groundingErr := p.grounding.Check(ctx, item.Title, groundingSource(item), groundingView(cleanedYAML, item.URL))
	if groundingErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(groundingErr, ctxErr) {
			return ctxErr
		}
		return fmt.Errorf("grounding check: %w", groundingErr)
	}
	if !groundingResult.Grounded {
		for _, issue := range groundingResult.Issues {
			validationNotes = append(validationNotes, fmt.Sprintf("grounding: %s", issue))
		}
		repaired, err := p.grounding.Repair(ctx, item.Title, groundingSource(item), cleanedYAML, groundingResult.Issues)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return ctxErr
			}
			var invalid *InvalidBriefYAMLError
			if errors.As(err, &invalid) {
				return p.quarantineInvalidBrief(item, invalid)
			}
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
		cleanedYAML = injectAffectedRanges(cleanedYAML, item)
		cleanedYAML = normalizeDetectionSeverity(cleanedYAML, item)
		groundingResult, err = p.grounding.Check(ctx, item.Title, groundingSource(item), groundingView(cleanedYAML, item.URL))
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return ctxErr
			}
			return fmt.Errorf("grounding recheck: %w", err)
		}
		if !groundingResult.Grounded {
			p.decisions.record(outcomeRejectedUngrounded)
			attempts, err := p.db.RecordGroundingAttempt(item.SourceID)
			if err != nil {
				return fmt.Errorf("recording grounding attempt: %w", err)
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
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
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
		p.logger.Info("skipping non-actionable brief", "source_id", item.SourceID, "title", item.Title)
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	if handled, err := p.mergeSameWeekAssembledProductBrief(cleanedYAML, item, preCVEs, extraction); err != nil {
		p.logger.Warn("same-week product merge failed; deferring item to prevent a duplicate", "source_id", item.SourceID, "error", err)
		return nil
	} else if handled {
		p.decisions.record(outcomeMerged)
		p.logger.Info("merged assembled same-week product brief", "source_id", item.SourceID, "title", item.Title)
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
			return fmt.Errorf("recording seen item: %w", err)
		}
		return nil
	}
	if handled, err := p.mergeSameIncidentAssembledProductBrief(ctx, cleanedYAML, item, preCVEs, extraction); err != nil {
		p.logger.Warn("same-incident product merge unavailable; deferring item to prevent a duplicate", "source_id", item.SourceID, "error", err)
		return nil
	} else if handled {
		p.decisions.record(outcomeMerged)
		if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
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

	if err := p.createDraft(draft); err != nil {
		return fmt.Errorf("saving draft: %w", err)
	}

	p.logger.Info("draft created", "draft_id", draft.ID, "source", item.Source, "title", item.Title)

	// Index for future cross-source dedup.
	p.indexContent(draft.ID, item, preCVEs, extraction, cleanedYAML)

	// Auto-publish if configured.
	if p.autoPublish && p.publisher != nil {
		if len(reviewIssues) > 0 {
			p.logger.Warn("brief held for editorial review", "draft_id", draft.ID, "issues", reviewIssues)
			if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
		claimKey := ""
		if item.Discovery != nil {
			claimKey = ClaimKey(extraction)
		}
		if err := p.queueDraftPublication(cleanedYAML, draft.ID, claimKey); err != nil {
			p.logger.Error("auto-publish failed", "draft_id", draft.ID, "error", err)
			// Mark as seen anyway — the draft is saved in SQLite and can be
			// retried via the drafts CLI. Without this, the item would be
			// reprocessed in an infinite loop on every poll.
			if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
				return fmt.Errorf("recording seen item: %w", err)
			}
			return nil
		}
		p.logger.Info("queued for publication", "draft_id", draft.ID)
	}

	// Mark as seen only after successful processing (and publish if enabled).
	if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
		return fmt.Errorf("recording seen item: %w", err)
	}

	return nil
}
