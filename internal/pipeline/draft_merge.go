package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"gopkg.in/yaml.v3"
)

func (p *Pipeline) mergeSameWeekAssembledProductBrief(briefYAML string, item scraper.RawItem, regexCVEs []string, extraction *ExtractionResult) (bool, error) {
	productFP := briefProductFingerprint(briefYAML)
	if productFP == "" {
		return false, nil
	}
	if briefType(briefYAML) != "product" {
		return false, nil
	}
	incoming := parseBriefFrontmatter(briefYAML)
	var chains [][]string
	if extraction != nil {
		chains = extraction.ChainedCVEs
	}
	entries, err := p.db.FindByProduct(productFP, productMergeWindow)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.DraftID == "" || e.SourceID == item.SourceID {
			continue
		}
		draft, err := p.db.GetDraft(e.DraftID)
		if err != nil || draft == nil {
			continue
		}
		if draft.Status == storage.StatusRejected {
			continue
		}
		if briefType(draft.BriefYAML) != "product" {
			continue
		}
		if !briefAcceptsBrief(parseBriefFrontmatter(draft.BriefYAML), incoming, chains) {
			continue
		}
		if err := p.mergeAssembledBriefIntoDraft(e.DraftID, briefYAML, item); err != nil {
			return false, err
		}
		p.indexContent(e.DraftID, item, regexCVEs, extraction, briefYAML)
		return true, nil
	}

	// Older rule-only drafts may not have product fingerprints in content_index.
	// Fall back to recent approved drafts so the first deployment can still
	// converge same-week rule bursts into their canonical draft. Drafts are
	// scanned one at a time and the merge runs after the scan stops.
	var match string
	for d, err := range p.db.ApprovedDraftsSince(time.Now().AddDate(0, 0, -2)) {
		if err != nil {
			return false, err
		}
		if strings.Contains(d.SourceIDs, fmt.Sprintf("%q", item.SourceID)) {
			continue
		}
		if time.Since(d.CreatedAt) > productMergeWindow {
			continue
		}
		if briefProductFingerprint(d.BriefYAML) != productFP {
			continue
		}
		if briefType(d.BriefYAML) != "product" {
			continue
		}
		if !briefAcceptsBrief(parseBriefFrontmatter(d.BriefYAML), incoming, chains) {
			continue
		}
		match = d.ID
		break
	}
	if match == "" {
		return false, nil
	}
	if err := p.mergeAssembledBriefIntoDraft(match, briefYAML, item); err != nil {
		return false, err
	}
	p.indexContent(match, item, regexCVEs, extraction, briefYAML)
	return true, nil
}

func (p *Pipeline) mergeAssembledBriefIntoDraft(draftID, incomingYAML string, item scraper.RawItem) error {
	return p.mergeAssembledBriefIntoDraftWithNarrative(draftID, incomingYAML, item, false)
}

func (p *Pipeline) mergeAssembledBriefIntoDraftWithNarrative(draftID, incomingYAML string, item scraper.RawItem, preferIncomingNarrative bool) error {
	draft, err := p.db.GetDraft(draftID)
	if err != nil {
		return fmt.Errorf("assembled merge: load draft: %w", err)
	}
	if draft == nil {
		return fmt.Errorf("assembled merge: draft %s not found", draftID)
	}
	if draft.Status == storage.StatusRejected {
		return fmt.Errorf("assembled merge: draft %s was rejected", draftID)
	}
	var base map[string]any
	if err := yaml.Unmarshal([]byte(draft.BriefYAML), &base); err != nil {
		return fmt.Errorf("assembled merge: parse base: %w", err)
	}
	var incoming map[string]any
	if err := yaml.Unmarshal([]byte(incomingYAML), &incoming); err != nil {
		return fmt.Errorf("assembled merge: parse incoming: %w", err)
	}
	if preferIncomingNarrative && (briefType(draft.BriefYAML) != "product" || briefType(incomingYAML) != "product") {
		return fmt.Errorf("rebuilt narrative requires editorial review: narrative replacement is limited to product briefs (target=%s, incoming=%s)", briefType(draft.BriefYAML), briefType(incomingYAML))
	}
	pre := snapshotBriefSignals(base)
	narrativeChanged := false
	if preferIncomingNarrative {
		for _, key := range []string{"title", "summary", "content"} {
			value := strings.TrimSpace(fmt.Sprint(incoming[key]))
			if value == "" || value == "<nil>" || value == strings.TrimSpace(fmt.Sprint(base[key])) {
				continue
			}
			base[key] = incoming[key]
			narrativeChanged = true
		}
	}

	addedVendors := mergeStringList(base, "affected_vendors", yamlStringList(incoming["affected_vendors"]))
	addedProducts := mergeStringList(base, "affected_products", yamlStringList(incoming["affected_products"]))
	addedOS := mergeStringList(base, "affected_os", yamlStringList(incoming["affected_os"]))
	addedRefs := mergeStringList(base, "references", yamlStringList(incoming["references"]))
	addedTags := mergeStringList(base, "tags", yamlStringList(incoming["tags"]))
	addedCPEs := mergeStringList(base, "cpes", yamlStringList(incoming["cpes"]))
	addedPOCRefs := mergeStringList(base, "poc_references", yamlStringList(incoming["poc_references"]))
	addedPrioritySignals := mergeStringList(base, "priority_signals", yamlStringList(incoming["priority_signals"]))
	addedRules := mergeMapListByIdentityComplete(base, "rules", incoming["rules"], []string{"id", "title"})
	addedTTPs := mergeMapListByIdentityComplete(base, "ttps", incoming["ttps"], []string{"technique_id", "subtechnique_id", "tactic_id", "technique_name"})
	cleanCVEs, cleanedCVEs := dedupeExistingCVEEntries(base["cves"])
	if cleanedCVEs {
		base["cves"] = cleanCVEs
	}
	addedCVEs := mergeMapListByIdentityComplete(base, "cves", incoming["cves"], []string{"id"})
	addedIOCs := mergeMapListByIdentityComplete(base, "iocs", incoming["iocs"], []string{"type", "value"})
	severityChanged := mergeHigherSeverity(base, incoming)
	actorChanged := mergeScalarIfMissing(base, incoming, "threat_actor")
	pocChanged := mergeMonotonicBool(base, incoming, "has_poc")
	exploitationChanged := mergeExploitationState(base, incoming)
	priorityChanged := mergeHigherPriority(base, incoming)
	actionPlanChanged := mergeActionPlan(base, incoming)
	assessmentChanged := mergeMapIfMissing(base, incoming, "source_assessment")
	qaChanged := mergeMapIfMissing(base, incoming, "qa_status")

	otherChanged := narrativeChanged || addedVendors || addedProducts || addedOS || addedRefs || addedTags ||
		addedCPEs || addedPOCRefs || addedPrioritySignals || addedRules || addedTTPs || addedIOCs ||
		severityChanged || actorChanged || pocChanged || exploitationChanged || priorityChanged || actionPlanChanged ||
		assessmentChanged || qaChanged
	changed := otherChanged || addedCVEs || cleanedCVEs
	if !changed {
		note := fmt.Sprintf("[corroborated] %s %s", item.Source, item.URL)
		return p.db.AppendDraftReferenceWithSource(draftID, note, item.SourceID)
	}
	post := snapshotBriefSignals(base)

	out, err := yaml.Marshal(base)
	if err != nil {
		return fmt.Errorf("assembled merge: encode: %w", err)
	}
	merged := string(out)
	sourceURLs := []string(nil)
	if strings.TrimSpace(item.URL) != "" {
		sourceURLs = []string{item.URL}
	}
	level, summary := classifyUpdate(pre, post, addedVendors, addedProducts, addedOS, addedCVEs, addedIOCs, addedRefs)
	if level == "L0" {
		level = "L1"
	}
	if duplicateCVEOnlyCleanup(cleanedCVEs, addedCVEs, otherChanged) {
		summary = "corrected duplicate CVE entries"
	}
	if level != "L3" && (addedRules || actionPlanChanged) {
		summary = assembledUpdateSummary(incoming)
	}
	if strings.TrimSpace(summary) == "" {
		summary = assembledUpdateSummary(incoming)
	}
	event := storage.UpdateEvent{
		At:         time.Now().UTC(),
		Level:      level,
		Summary:    summary,
		Sources:    []string{item.Source},
		SourceURLs: sourceURLs,
	}
	if err := injectUpdateMetadata(&merged, draft, event); err != nil {
		p.logger.Warn("inject assembled update metadata failed", "draft_id", draftID, "error", err)
	}
	if preferIncomingNarrative {
		if err := p.validatePublication(merged); err != nil {
			return fmt.Errorf("rebuilt canonical brief requires editorial review: %w", err)
		}
	}
	if p.autoPublish && p.publisher != nil {
		held, err := p.holdMergedBriefForReview(draftID, item, merged)
		if err != nil || held {
			return err
		}
	}
	if err := p.db.RecordDraftUpdateWithPublication(draftID, merged, event, item.SourceID, p.autoPublish && p.publisher != nil); err != nil {
		return err
	}
	if p.autoPublish && p.publisher != nil {
		if err := p.enqueuePublicationIntent(storage.PublicationIntent{DraftID: draftID, BriefYAML: merged}); err != nil {
			return err
		}
	}
	return nil
}

func duplicateCVEOnlyCleanup(cleanedCVEs, addedCVEs, otherChanged bool) bool {
	return cleanedCVEs && !addedCVEs && !otherChanged
}

// logMergeFailure logs a failed merge. A merge the relevance check refused is
// a correct decision that the item is a separate story, not a failure, so it
// is logged at INFO; anything else is a real failure and stays at WARN.
func (p *Pipeline) logMergeFailure(msg string, err error, args ...any) {
	args = append(args, "error", err)
	if errors.Is(err, errMergeNotRelevant) {
		p.logger.Info("merge refused: source is a separate story", append(args, "context", msg)...)
		return
	}
	if errors.Is(err, errNonAuthoritativeRoundupSource) {
		p.logger.Info("merge refused by policy: non-authoritative source cannot update a vendor roundup; the item gets its own draft", append(args, "context", msg)...)
		return
	}
	p.logger.Warn(msg, args...)
}

// unionIntoDraft unions structured fields from a new extraction into
// an existing thin draft. Body content is intentionally untouched —
// only field-level signals (CVEs, products, vendors, OS, IOCs,
// references) are merged.
//
// On a successful merge that produced new structured signal, the draft
// is stamped with a lastmod, an update_count bump, and an entry in
// update_log. The tier (L1 / L2 / L3) is computed from what changed:
//   - L1 vendor / OS / tag / IOC added — visual pill only
//   - L2 new CVE id, new product version qualifier, new severity bump
//   - L3 KEV flipped on, exploited:true gained, severity → critical
//
// L3 events from a high-confidence source qualify the draft for an
// "update" notifier dispatch (gated by a per-draft cooldown handled
// outside this function).
//
// After the merge the draft re-runs through the CVE / IOC verifiers so
// new CVE entries pick up CVSS/EPSS/KEV enrichment and IOC context
// normalization. If verifiers add KEV after the field-level merge,
// the tier is recomputed once more.
func (p *Pipeline) unionIntoDraft(ctx context.Context, draftID string, extraction *ExtractionResult, item scraper.RawItem) error {
	if draftID == "" {
		return fmt.Errorf("merge: empty draft id")
	}
	if extraction == nil {
		extraction = &ExtractionResult{}
	}
	draft, err := p.db.GetDraft(draftID)
	if err != nil {
		return fmt.Errorf("merge: load draft: %w", err)
	}
	if draft == nil {
		return fmt.Errorf("merge: draft %s not found", draftID)
	}
	if draft.Status == storage.StatusRejected {
		return fmt.Errorf("merge: draft %s was rejected", draftID)
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(draft.BriefYAML), &fm); err != nil {
		return fmt.Errorf("merge: parse draft yaml: %w", err)
	}
	// CVEs the draft listed before this update; the enrichment below must not
	// drop them (the update's own CVEs are unioned into fm afterwards).
	preFoldCVEs := briefCVEIDs(fm)

	roundupVendor := roundupVendorFromFrontmatter(fm)
	campaignFamily := campaignFamilyFromFrontmatter(fm)
	// Roundups and campaign umbrellas collect many CVEs by design; any other
	// brief covers one vulnerability or one chain (cve_identity.go).
	cveScoped := roundupVendor == "" && campaignFamily == ""
	sourceReferenceRelevant := true
	pocSignalRelevant := true
	if cveScoped {
		listed := briefCVEIDs(fm)
		chains := cveChains(extraction.ChainedCVEs)
		if !cvesOverlap(listed, reportCVEs(item, extraction), chains) {
			return fmt.Errorf("merge: source %q is %w to draft %s: it covers none of the CVEs the brief lists", item.Source, errMergeNotRelevant, draftID)
		}
		// A source that also covers other CVEs contributes only the brief's.
		extraction = cloneExtraction(extraction)
		var accepted []string
		for _, cve := range extraction.CVEs {
			if cvesAccepted(listed, []string{cve}, chains) {
				accepted = append(accepted, cve)
			}
		}
		extraction.CVEs = accepted
	}
	if roundupVendor != "" {
		sanitizeRoundupFrontmatter(fm, roundupVendor)
		if !isVendorAuthoritativeSource(item.Source, item.URL, roundupVendor) {
			if out, err := yaml.Marshal(fm); err == nil {
				_ = p.db.UpdateDraftYAML(draftID, string(out))
			}
			return fmt.Errorf("merge: %w %q cannot update %s roundup", errNonAuthoritativeRoundupSource, item.Source, roundupVendor)
		}
		extraction = sanitizeRoundupExtraction(roundupVendor, extraction)
	} else {
		relevanceExtraction, relevance, err := p.assessDraftMergeRelevance(ctx, fm, extraction, item)
		if err != nil {
			return err
		}
		if !relevance.Merge {
			return fmt.Errorf("merge: source %q is %w to draft %s: %s", item.Source, errMergeNotRelevant, draftID, relevance.Reason)
		}
		extraction = relevanceExtraction
		sourceReferenceRelevant = relevance.ReferenceRelevant
		pocSignalRelevant = relevance.POCRelevant
	}
	// Enforced here rather than in routeToCampaign: CVE and content dedup
	// also merge into umbrellas.
	if campaignFamily != "" {
		extraction = sanitizeCampaignExtraction(extraction)
	}

	// Ground exactly what this merge changes, nothing it discards.
	var probeExploitation map[string]any
	if mergeAppliesExploitation(item, extraction) {
		probeExploitation = p.incomingExploitation(item)
	}
	delta, err := p.grounding.CheckMergeDelta(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "merge_delta_grounding"}), item,
		mergeAppliedDelta(item, extraction, fm, probeExploitation), yamlStringList(fm["affected_vendors"])...)
	if err != nil {
		return fmt.Errorf("%w: incoming claims could not be verified: %w", errMergeRelevanceUnavailable, err)
	}
	if !delta.Grounded {
		return &MergeClaimsRejectedError{Issues: append([]string(nil), delta.Issues...), Extraction: cloneExtraction(extraction)}
	}
	pre := snapshotBriefSignals(fm)
	lifecycleChanged := mergeRumourLifecycle(fm, extraction)

	// Set has_poc if the incoming source is an exploit tracker or the content
	// mentions a public exploit/PoC. Only ever flips true → stays true once set.
	if pocSet, _ := fm["has_poc"].(bool); roundupVendor == "" && pocSignalRelevant && !pocSet && sourceReportsPublicExploit(item) {
		fm["has_poc"] = true
	}

	// Track exploit-tracker URLs so the brief page can link directly to PoC sources.
	if roundupVendor == "" && pocSignalRelevant && isExploitTracker(item.Source) && item.URL != "" {
		mergeStringList(fm, "poc_references", []string{item.URL})
	}

	addedVendors := mergeStringList(fm, "affected_vendors", extraction.AffectedVendors)
	addedProducts := mergeStringList(fm, "affected_products", extraction.AffectedProducts)
	addedOS := mergeStringList(fm, "affected_os", extraction.AffectedOS)
	addedCVEs := mergeStringList(fm, "cves", extraction.CVEs)
	addedIOCs := mergeIOCList(fm, extraction.IOCs)
	actorChanged := false
	actor := strings.TrimSpace(extraction.ThreatActor)
	if mergeAppliesActor(item, extraction) {
		actorChanged = mergeScalarIfMissing(fm, map[string]any{"threat_actor": actor}, "threat_actor")
	}
	exploitationChanged := false
	if mergeAppliesExploitation(item, extraction) {
		exploitationChanged = mergeExploitationState(fm, p.incomingExploitation(item))
	}
	addedRef := false
	if sourceReferenceRelevant {
		references := referenceURLsForRawItem(item)
		if roundupVendor != "" {
			allowed := references[:0]
			for _, reference := range references {
				if roundupReferenceAllowed(roundupVendor, reference) {
					allowed = append(allowed, reference)
				}
			}
			references = allowed
		}
		addedRef = mergeStringList(fm, "references", references)
	}
	if roundupVendor != "" {
		sanitizeRoundupFrontmatter(fm, roundupVendor)
		addedVendors = false
		addedProducts = false
		addedOS = false
		addedIOCs = false
	}
	if !addedVendors && !addedProducts && !addedOS && !addedCVEs && !addedIOCs && !addedRef && !actorChanged && !exploitationChanged && !lifecycleChanged {
		// Nothing structural to add — at least record the corroboration.
		note := fmt.Sprintf("[corroborated] %s %s", item.Source, item.URL)
		return p.db.AppendDraftReferenceWithSource(draftID, note, item.SourceID)
	}

	out, err := yaml.Marshal(fm)
	if err != nil {
		return fmt.Errorf("merge: encode yaml: %w", err)
	}
	merged := string(out)
	merged, _ = p.cveVerifier.Verify(ctx, merged)
	if cveScoped {
		merged, _ = p.cveEnricher.EnrichListedCVEs(merged, preFoldCVEs)
	} else {
		merged, _ = p.cveEnricher.EnrichRoundup(merged, preFoldCVEs)
	}
	merged, _ = p.iocVerifier.Verify(merged)
	if roundupVendor != "" {
		var cleanFM map[string]any
		if err := yaml.Unmarshal([]byte(merged), &cleanFM); err == nil {
			sanitizeRoundupFrontmatter(cleanFM, roundupVendor)
			if out, err := yaml.Marshal(cleanFM); err == nil {
				merged = string(out)
			}
		}
	}

	// Re-parse to capture KEV / cvss / severity changes the verifiers
	// may have applied so the tier reflects the final signal set.
	post := pre
	var postFM map[string]any
	if err := yaml.Unmarshal([]byte(merged), &postFM); err == nil {
		post = snapshotBriefSignals(postFM)
	}

	level, summary := classifyUpdate(pre, post, addedVendors, addedProducts, addedOS, addedCVEs, addedIOCs, addedRef)
	if level == "L0" && actorChanged {
		level = "L1"
		summary = "added threat actor: " + actor
	}
	if level == "L0" {
		// All adds turned out to be reference-only or otherwise non-signal.
		if p.autoPublish && p.publisher != nil {
			held, err := p.holdMergedBriefForReview(draftID, item, merged)
			if err != nil || held {
				return err
			}
		}
		return p.db.UpdateDraftYAML(draftID, merged)
	}

	now := time.Now().UTC()
	var sourceURLs []string
	if strings.TrimSpace(item.URL) != "" {
		sourceURLs = []string{item.URL}
	}
	event := storage.UpdateEvent{
		At:         now,
		Level:      level,
		Summary:    summary,
		Sources:    []string{item.Source},
		SourceURLs: sourceURLs,
	}

	// Write lastmod + updates back into the brief YAML so the publisher
	// (which reads brief_yaml directly) sees the merged state. The
	// updates list is read from the draft row's prior log so the
	// snapshot in YAML matches what RecordDraftUpdate is about to commit.
	if err := injectUpdateMetadata(&merged, draft, event); err != nil {
		p.logger.Warn("inject update metadata failed", "draft_id", draftID, "error", err)
	}
	if p.autoPublish && p.publisher != nil {
		held, err := p.holdMergedBriefForReview(draftID, item, merged)
		if err != nil || held {
			return err
		}
	}
	if err := p.db.RecordDraftUpdateWithPublication(draftID, merged, event, item.SourceID, p.autoPublish && p.publisher != nil); err != nil {
		return err
	}
	if p.autoPublish && p.publisher != nil {
		if err := p.enqueuePublicationIntent(storage.PublicationIntent{DraftID: draftID, BriefYAML: merged}); err != nil {
			return err
		}
	}
	// L3 events earn an "update" dispatch to opted-in subscribers,
	// gated by source quality + per-brief cooldown. Best-effort: any
	// failure logs and falls through, the brief still got updated.
	if level == "L3" && !p.onlyStaleKEVNews(pre, post) {
		p.maybeDispatchL3Update(ctx, draftID, summary, item.Source, p.siteURL)
	}
	return nil
}

// onlyStaleKEVNews reports whether the only L3 news in a merge is KEV flags
// for listings older than the notification window: catching an old listing
// up (the reconciliation backlog) is not news. Exploitation or critical
// severity reached by other means still notifies.
func (p *Pipeline) onlyStaleKEVNews(pre, post briefSignals) bool {
	if p.cveVerifier == nil {
		return false
	}
	if post.exploited && !pre.exploited && len(post.kevSet) == 0 {
		return false
	}
	if post.severity == "critical" && pre.severity != "critical" {
		return false
	}
	catalog := p.cveVerifier.kev.Entries()
	var added []string
	for cve := range post.kevSet {
		if !pre.kevSet[cve] {
			added = append(added, cve)
		}
	}
	return len(added) > 0 && !kevListedWithin(added, catalog, time.Now().UTC(), KEVNotifyWithin)
}

// incomingExploitation is the attributed exploitation state a merge of item
// records. It is built fresh per call because merging may store it.
func (p *Pipeline) incomingExploitation(item scraper.RawItem) map[string]any {
	observedAt := ""
	if !item.PublishedAt.IsZero() {
		observedAt = item.PublishedAt.UTC().Format(time.RFC3339)
	}
	confidence := "medium"
	if sourceConfidence := p.getSourceConfidence(item.Source); sourceConfidence >= 0.85 {
		confidence = "high"
	} else if sourceConfidence < 0.5 {
		confidence = "low"
	}
	return map[string]any{
		"exploited": true,
		"exploitation_evidence": map[string]any{
			"status": "confirmed_active", "source_url": item.URL,
			"observed_at": observedAt, "confidence": confidence,
		},
	}
}

// referenceURLsForRawItem returns the item's canonical URL plus explicitly
// labelled public references. source_url_ metadata is intentionally excluded:
// it broadens dedup matching without flooding briefs with every aggregator link.
func referenceURLsForRawItem(item scraper.RawItem) []string {
	references := []string{item.URL}
	keys := make([]string, 0, len(item.Metadata))
	for key := range item.Metadata {
		if strings.HasPrefix(key, "reference_url_") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if reference := strings.TrimSpace(item.Metadata[key]); validSourceURL(reference) {
			references = append(references, reference)
		}
	}
	return dedupStrings(references)
}

// validatePublication checks a candidate before a draft changes or buffers.
func (p *Pipeline) validatePublication(brief string) error {
	if validator, ok := p.publisher.(interface{ ValidatePublication(string) error }); ok {
		return validator.ValidatePublication(brief)
	}
	if err := ValidateBriefContract(brief); err != nil {
		return err
	}
	issues := ValidatePublicationConsistency(brief)
	if len(issues) > 0 {
		return fmt.Errorf("brief requires editorial review: %s", strings.Join(issues, "; "))
	}
	return nil
}

// holdMergedBriefForReview keeps an approved draft intact when a source merge
// would produce data the publisher cannot accept. The candidate is stored for
// editorial inspection instead of repeatedly failing publication.
func (p *Pipeline) holdMergedBriefForReview(draftID string, item scraper.RawItem, merged string) (bool, error) {
	var issues []string
	if err := p.validatePublication(merged); err != nil {
		issues = append(issues, err.Error())
	}
	if len(issues) == 0 {
		return false, nil
	}
	reason := "merged brief requires editorial review: " + strings.Join(issues, "; ")
	if err := p.db.QuarantinePipelineItem(item.SourceID, item.Source, item.Title, merged, reason); err != nil {
		return false, err
	}
	if err := p.markSeen(item); err != nil {
		return false, err
	}
	p.logger.Warn("merged brief held for editorial review", "draft_id", draftID, "source_id", item.SourceID, "issues", issues)
	return true, nil
}
