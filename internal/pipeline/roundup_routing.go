package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// handlePostExtractionDedup runs the post-extraction dedup check and folds the
// new source into an existing draft when it matches — corroborate-and-skip, or
// merge in place — instead of assembling a parallel brief. Returns true when the
// item was consumed and the caller should stop processing it.
func (p *Pipeline) handlePostExtractionDedup(ctx context.Context, item scraper.RawItem, extraction *ExtractionResult, preCVEs []string) bool {
	decision, entries := p.dedup.CheckPostExtraction(item, extraction)
	switch decision {
	case DedupSkip:
		p.logger.Info("skipping cross-source duplicate (post-extraction)",
			"source_id", item.SourceID, "matched_via", "fingerprint-or-cve")
		p.decisions.record(outcomeMerged)
		for _, e := range entries {
			if e.DraftID == "" {
				continue
			}
			note := fmt.Sprintf("[corroborated] %s %s", item.Source, item.URL)
			if err := p.db.AppendDraftReference(e.DraftID, note); err != nil {
				p.logger.Warn("failed to append corroborating reference", "draft_id", e.DraftID, "err", err)
			}
		}
		if err := p.markSeen(item); err != nil {
			// The durable result remains retryable until the source write succeeds.
			p.decisions.record(outcomeFailed)
			p.logger.Error("failed to record seen item; source remains retryable", "source_id", item.SourceID, "error", err)
		}
		return true
	case DedupMerge:
		if len(entries) > 0 && entries[0].DraftID != "" {
			targetID := entries[0].DraftID
			if err := p.mergeIntoDraft(ctx, targetID, extraction, item); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
					return false
				}
				if errors.Is(err, errMergeReviewRequired) {
					return true
				}
				if errors.Is(err, errMergeRelevanceUnavailable) {
					p.logger.Warn("merge assessment unavailable; retaining source for retry", "source_id", item.SourceID, "error", err)
					return true
				}
				if errors.Is(err, errMergeNotRelevant) && !item.CorroborationOnly {
					// A separate story: let the caller process it as a new item.
					p.logger.Info("merge into thin draft refused (post-extraction); processing as new item", "source_id", item.SourceID, "draft_id", targetID, "error", err)
					return false
				}
				p.logMergeFailure("merge into thin draft failed (post-extraction)", err, "source_id", item.SourceID, "draft_id", targetID)
			} else {
				p.logger.Info("merged into thin draft (post-extraction)", "source_id", item.SourceID, "draft_id", targetID)
			}
			if err := p.markSeen(item); err != nil {
				// The durable result remains retryable until the source write succeeds.
				p.decisions.record(outcomeFailed)
				p.logger.Error("failed to record seen item; source remains retryable", "source_id", item.SourceID, "error", err)
			}
			return true
		}
	case DedupUpdate:
		// Same CVE surfaced by extraction with meaningful new info. Previously this
		// fell through and assembled a parallel brief; instead merge it into the
		// matched draft in place (mirrors the pre-extraction update path at the
		// DedupUpdate branch below), then index the new source under that draft.
		if len(entries) > 0 && entries[0].DraftID != "" {
			targetID := entries[0].DraftID
			if err := p.mergeIntoDraft(ctx, targetID, extraction, item); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
					return false
				}
				if errors.Is(err, errMergeReviewRequired) {
					return true
				}
				if errors.Is(err, errMergeRelevanceUnavailable) {
					p.logger.Warn("update merge assessment unavailable; retaining source for retry", "source_id", item.SourceID, "draft_id", targetID, "error", err)
					return true
				}
				p.logMergeFailure("post-extraction update merge failed", err, "source_id", item.SourceID, "draft_id", targetID)
				return false
			}
			p.logger.Info("post-extraction DedupUpdate: merged into existing draft", "source_id", item.SourceID, "draft_id", targetID)
			p.indexContent(targetID, item, preCVEs, extraction)
			if err := p.markSeen(item); err != nil {
				// The durable result remains retryable until the source write succeeds.
				p.decisions.record(outcomeFailed)
				p.logger.Error("failed to record seen item; source remains retryable", "source_id", item.SourceID, "error", err)
			}
			return true
		}
	}
	return false
}

// buildRoundupBriefYAML returns a template brief aggregating a vendor's
// scheduled advisories for a month. It is assembled without the LLM; individual
// CVEs are folded in via mergeIntoDraft as they arrive, and their details are
// written into the content body by enrichRoundupContent.
func buildRoundupBriefYAML(vendor string, now time.Time, firstCVE string) string {
	vslug := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(vendor), " ", "-"))
	cves := ""
	if firstCVE != "" {
		cves = "\ncves:\n  - " + strings.ToUpper(firstCVE)
	}
	return fmt.Sprintf(`id: "brief-%[1]s-%[2]s-security-updates"
slug: "%[1]s-%[2]s-security-updates"
title: "%[3]s Security Updates - %[4]s"
summary: "Roundup of %[3]s security advisories published in %[4]s."
severity: "high"
published_at: "%[5]s"
content: |
  ## Overview

  Aggregated %[3]s security advisories for %[4]s. CVEs from this cycle are folded
  into the list below as they are published.

  ## Recommendation

  Review affected products and apply %[3]s's %[4]s security updates.
tags:
  - roundup
affected_vendors:
  - "%[3]s"%[6]s
`, now.Format("2006-01"), vslug, vendor, now.Format("January 2006"), now.UTC().Format(time.RFC3339), cves)
}

// isCarvedOutFromRoundup returns true for CVEs that should get their own brief
// even for a patch-cycle vendor: KEV-listed or described as actively exploited.
func (p *Pipeline) isCarvedOutFromRoundup(item scraper.RawItem, extraction *ExtractionResult) bool {
	for _, cve := range extraction.CVEs {
		if listed, _ := p.kev.Lookup(cve); listed {
			return true
		}
	}
	return containsAny(strings.ToLower(item.Title+" "+item.Content), activeExploitTerms)
}

// indexRoundupItem records the folded item's CVEs under the roundup draft with
// the vendor-cycle key so future items in the cycle find and extend it.
func (p *Pipeline) indexRoundupItem(draftID, cycleKey string, item scraper.RawItem, extraction *ExtractionResult) {
	cves := map[string]bool{}
	for _, c := range ExtractCVEsFromText(item.Title, item.Content) {
		cves[c] = true
	}
	if extraction != nil {
		for _, c := range extraction.CVEs {
			cves[strings.ToUpper(c)] = true
		}
	}
	base := storage.ContentIndexEntry{
		VendorCycleKey:     cycleKey,
		TitleHash:          NormalizeTitleHash(item.Title),
		ContentHash:        NormalizeContentHash(item.Title, item.Content),
		SourceURLHash:      SourceURLHash(item.URL),
		SourcePublishedDay: SourcePublishedDay(item.PublishedAt),
		DraftID:            draftID,
		SourceID:           item.SourceID,
		Source:             item.Source,
		CreatedAt:          time.Now(),
	}
	if len(cves) == 0 {
		_ = p.db.IndexContent(&base)
		return
	}
	for c := range cves {
		e := base
		e.CVEID = c
		_ = p.db.IndexContent(&e)
	}
}

// singlePatchCycleVendor returns the vendor only when the extraction lists
// exactly one affected vendor and that vendor is a patch-cycle vendor. This
// prevents a multi-vendor advisory (e.g. Google + GitHub) from being routed
// into the first vendor's roundup and dragging in unrelated products.
func singlePatchCycleVendor(vendors []string) string {
	v := firstNonPlaceholder(vendors)
	if v == "" {
		return ""
	}
	for _, raw := range vendors {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" || s == strings.ToLower(v) {
			continue
		}
		return ""
	}
	if vendorCycleKey(v, time.Now().UTC()) == "" {
		return ""
	}
	return v
}

// isVendorAuthoritativeSource reports whether a source is authoritative enough
// to contribute to a patch-cycle vendor roundup. Vendor roundups are meant to
// aggregate the vendor's own scheduled advisories; news articles, detection
// rules, threat-research blogs, exploit trackers, and CERTs reporting on
// third-party incidents may mention the vendor but must not pollute the
// roundup with unrelated products, IOCs, or references.
//
// Authoritative sources are: the vendor's own PSIRT/MSRC feed, the canonical
// CVE registry (NVD), CISA KEV, and URLs hosted on the vendor's domain.
func isVendorAuthoritativeSource(source, rawURL, vendor string) bool {
	s := strings.ToLower(strings.TrimSpace(source))
	v := strings.ToLower(strings.TrimSpace(vendor))
	if v == "" {
		return false
	}

	// Vendor's own channels.
	if sourceMatchesVendor(s, v) {
		return true
	}

	// NVD is the canonical CVE registry; each entry is tied to a specific
	// vendor/product, so a single-vendor extraction from NVD is safe.
	if s == "nvd" {
		return true
	}

	// CISA KEV flags exploited CVEs regardless of who reported them.
	if s == "cisa-kev" {
		return true
	}

	// URL hosted on the vendor's domain covers generic scrapers that pull a
	// vendor advisory page.
	if rawURL != "" && hostnameMatchesVendor(rawURL, v) {
		return true
	}

	return false
}

// sourceMatchesVendor returns true when the named source is the vendor's own
// advisory or research channel.
func sourceMatchesVendor(source, vendor string) bool {
	s := strings.ToLower(strings.TrimSpace(source))
	v := strings.ToLower(strings.TrimSpace(vendor))
	switch v {
	case "microsoft":
		return s == "msrc" || s == "microsoft-threat-intel"
	case "adobe":
		return s == "adobe" || s == "adobe-psirt"
	case "apple":
		return s == "apple" || s == "apple-security"
	case "cisco":
		return s == "cisco-psirt" || s == "cisco"
	case "google":
		return s == "google" || s == "android" || s == "google-project-zero"
	case "mozilla":
		return s == "mozilla"
	case "oracle":
		return s == "oracle"
	case "sap":
		return s == "sap"
	case "qualcomm":
		return s == "qualcomm"
	case "siemens":
		return s == "siemens" || s == "siemens-productcert"
	case "atlassian":
		return s == "atlassian"
	}
	return false
}

// hostnameMatchesVendor returns true when the URL is hosted on a domain owned
// by the vendor.
func hostnameMatchesVendor(rawURL, vendor string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	v := strings.ToLower(strings.TrimSpace(vendor))
	switch v {
	case "microsoft":
		return hasDomainSuffix(host, "microsoft.com") ||
			hasDomainSuffix(host, "azure.com") ||
			hasDomainSuffix(host, "office.com")
	case "adobe":
		return hasDomainSuffix(host, "adobe.com")
	case "apple":
		return hasDomainSuffix(host, "apple.com")
	case "cisco":
		return hasDomainSuffix(host, "cisco.com")
	case "google":
		return hasDomainSuffix(host, "google.com") ||
			hasDomainSuffix(host, "android.com")
	case "mozilla":
		return hasDomainSuffix(host, "mozilla.org") ||
			hasDomainSuffix(host, "mozilla.com")
	case "oracle":
		return hasDomainSuffix(host, "oracle.com")
	case "sap":
		return hasDomainSuffix(host, "sap.com")
	case "qualcomm":
		return hasDomainSuffix(host, "qualcomm.com")
	case "siemens":
		return hasDomainSuffix(host, "siemens.com")
	case "atlassian":
		return hasDomainSuffix(host, "atlassian.com")
	}
	return false
}

func hasDomainSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func canonicalPatchCycleVendor(vendor string) string {
	key := strings.ToLower(strings.TrimSpace(vendor))
	if display, ok := patchCycleVendorDisplay[key]; ok {
		return display
	}
	return strings.TrimSpace(vendor)
}

func roundupVendorFromFrontmatter(fm map[string]any) string {
	if !stringListContainsFold(yamlStringList(fm["tags"]), "roundup") {
		return ""
	}
	title := strings.ToLower(strings.TrimSpace(fmt.Sprint(fm["title"])))
	slug := strings.ToLower(strings.TrimSpace(fmt.Sprint(fm["slug"])))

	vendors := make([]string, 0, len(patchCycleVendorDisplay))
	for v := range patchCycleVendorDisplay {
		vendors = append(vendors, v)
	}
	sort.Strings(vendors)
	for _, v := range vendors {
		display := strings.ToLower(patchCycleVendorDisplay[v])
		if strings.HasPrefix(title, display+" security updates") ||
			strings.Contains(slug, v+"-security-updates") {
			return patchCycleVendorDisplay[v]
		}
	}

	for _, raw := range yamlStringList(fm["affected_vendors"]) {
		if isPatchCycleVendor(raw) {
			return canonicalPatchCycleVendor(raw)
		}
	}
	return ""
}

func stringListContainsFold(values []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, v := range values {
		if strings.ToLower(strings.TrimSpace(v)) == want {
			return true
		}
	}
	return false
}

func sanitizeRoundupExtraction(vendor string, extraction *ExtractionResult) *ExtractionResult {
	if extraction == nil {
		return nil
	}
	clean := *extraction
	clean.AffectedVendors = []string{vendor}
	clean.AffectedProducts = nil
	clean.AffectedOS = nil
	clean.IOCs = nil
	return &clean
}

func sanitizeRoundupContentExtraction(vendor string, extraction *ExtractionResult) *ExtractionResult {
	if extraction == nil {
		return nil
	}
	clean := *extraction
	clean.AffectedVendors = []string{vendor}
	clean.IOCs = nil
	return &clean
}

func sanitizeRoundupFrontmatter(fm map[string]any, vendor string) {
	fm["affected_vendors"] = []string{vendor}
	setStringListOrDelete(fm, "references", filterRoundupReferences(vendor, yamlStringList(fm["references"])))
	setStringListOrDelete(fm, "cpes", filterRoundupCPEs(vendor, yamlStringList(fm["cpes"])))
	delete(fm, "affected_products")
	delete(fm, "affected_os")
	delete(fm, "iocs")
	delete(fm, "ioc_counts")
	delete(fm, "has_poc")
	delete(fm, "poc_references")
}

func setStringListOrDelete(fm map[string]any, key string, values []string) {
	if len(values) == 0 {
		delete(fm, key)
		return
	}
	fm[key] = values
}

func filterRoundupReferences(vendor string, refs []string) []string {
	return filterUniqueStrings(refs, func(ref string) bool {
		return roundupReferenceAllowed(vendor, ref)
	})
}

func filterRoundupCPEs(vendor string, cpes []string) []string {
	v := normalizeVendorName(vendor)
	return filterUniqueStrings(cpes, func(cpe string) bool {
		c := strings.ToLower(strings.TrimSpace(cpe))
		return v != "" && (strings.Contains(c, ":a:"+v+":") ||
			strings.Contains(c, ":o:"+v+":") ||
			strings.Contains(c, ":h:"+v+":"))
	})
}

func filterUniqueStrings(values []string, keep func(string) bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !keep(value) {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func roundupReferenceAllowed(vendor, rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	return hostnameMatchesVendor(rawURL, vendor) ||
		hasDomainSuffix(host, "nvd.nist.gov") ||
		hasDomainSuffix(host, "cisa.gov")
}

// routeToRoundup folds a patch-cycle vendor's CVE into a single monthly roundup
// brief instead of a standalone one. Returns true when the item was consumed.
// Gated by cfg.RoundupConsolidation; KEV / actively-exploited CVEs are carved
// out so hot 0-days still get their own brief.
//
// Only advisory-shaped items are folded: the item must carry at least one CVE
// and the affected vendor set must be a single patch-cycle vendor. News,
// detection rules, risk writeups, and multi-vendor advisories are left as
// standalone briefs. Campaign-style consolidation is handled separately by
// routeToCampaign.
func (p *Pipeline) routeToRoundup(ctx context.Context, item scraper.RawItem, extraction *ExtractionResult) bool {
	if !p.roundupConsolidation || extraction == nil {
		return false
	}
	// Roundups are for patch-cycle vendor advisories: require at least one CVE
	// and a single patch-cycle vendor. This keeps detection rules, news articles,
	// risk writeups, and cross-vendor advisories out of vendor monthly roundups.
	if len(extraction.CVEs) == 0 {
		return false
	}
	vendor := singlePatchCycleVendor(extraction.AffectedVendors)
	if vendor == "" {
		return false
	}
	if !isVendorAuthoritativeSource(item.Source, item.URL, vendor) {
		p.logger.Info("skipping vendor roundup for non-authoritative source",
			"source", item.Source, "vendor", vendor, "source_id", item.SourceID)
		return false
	}
	if p.nvdContradictsVendor(item, extraction, vendor) {
		p.logger.Info("skipping vendor roundup: NVD vendor data contradicts extraction",
			"source", item.Source, "vendor", vendor, "source_id", item.SourceID)
		return false
	}
	key := vendorCycleKey(vendor, time.Now().UTC())
	if key == "" || p.isCarvedOutFromRoundup(item, extraction) {
		return false
	}
	roundupExtraction := sanitizeRoundupExtraction(vendor, extraction)
	roundupContentExtraction, err := p.filterRoundupContentExtraction(ctx, vendor, extraction, item)
	if err != nil {
		if errors.Is(err, errMergeRelevanceUnavailable) {
			p.logger.Warn("roundup assessment unavailable; retaining source for retry", "source_id", item.SourceID, "error", err)
			return true
		}
		return false
	}
	// Fold into an existing roundup for this cycle if one exists.
	if entries, err := p.db.FindByVendorCycle(key); err == nil {
		for _, e := range entries {
			if e.DraftID == "" {
				continue
			}
			if err := p.mergeIntoDraft(ctx, e.DraftID, roundupExtraction, item); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
					return false
				}
				if errors.Is(err, errMergeReviewRequired) {
					return true
				}
				if errors.Is(err, errMergeRelevanceUnavailable) {
					p.logger.Warn("roundup merge assessment unavailable; retaining source for retry", "source_id", item.SourceID, "draft_id", e.DraftID, "error", err)
					return true
				}
				p.logMergeFailure("roundup merge failed", err, "cycle", key, "draft_id", e.DraftID)
				return false
			}
			if err := p.enrichRoundupContent(e.DraftID, roundupContentExtraction, item); err != nil {
				p.logger.Warn("roundup content enrichment failed", "cycle", key, "draft_id", e.DraftID, "error", err)
			}
			if err := p.annotateRoundupDraftCVEProducts(e.DraftID, roundupContentExtraction); err != nil {
				p.logger.Warn("roundup CVE product annotation failed", "cycle", key, "draft_id", e.DraftID, "error", err)
			}
			p.indexRoundupItem(e.DraftID, key, item, roundupExtraction)
			if err := p.markSeen(item); err != nil {
				// The durable result remains retryable until the source write succeeds.
				p.decisions.record(outcomeFailed)
				p.logger.Error("failed to record seen item; source remains retryable", "source_id", item.SourceID, "error", err)
			}
			p.logger.Info("folded CVE into vendor roundup", "cycle", key, "draft_id", e.DraftID)
			return true
		}
	}
	// Otherwise create the roundup (template — no LLM assembly).
	now := time.Now().UTC()
	yaml := buildRoundupBriefYAML(vendor, now, firstNonPlaceholder(extraction.CVEs))
	// The item that opens the roundup is its first source; without a reference
	// the brief has no attribution and is held at publication.
	if seeded, err := ensureInitialSourceReference(yaml, item.URL); err != nil {
		p.logger.Warn("roundup source reference not seeded", "cycle", key, "source_id", item.SourceID, "error", err)
	} else {
		yaml = seeded
	}
	// Build and gate the complete initial snapshot before any publication
	// intent exists; a crash cannot recover an unenriched placeholder.
	if enriched, err := enrichRoundupYAML(yaml, roundupContentExtraction, item); err != nil {
		p.logger.Warn("initial roundup content enrichment failed", "cycle", key, "error", err)
		return false
	} else {
		yaml = enriched
	}
	if annotated, err := annotateRoundupYAML(yaml, roundupContentExtraction); err != nil {
		return false
	} else {
		yaml = annotated
	}
	draft := &storage.Draft{
		ID:        uuid.NewString(),
		Status:    storage.StatusPending,
		Source:    item.Source,
		SourceIDs: fmt.Sprintf("[%q]", item.SourceID),
		BriefYAML: yaml,
		CreatedAt: now,
	}
	queueInitial, err := p.createTemplateDraft(draft)
	if err != nil {
		p.logger.Warn("roundup draft create failed", "cycle", key, "error", err)
		return false
	}
	// Record the initial "posted" event so the "What's new" timeline shows
	// when the roundup was created, not only subsequent CVE additions.
	if err := p.recordRoundupPosted(draft.ID, item); err != nil {
		p.logger.Warn("roundup posted event failed", "cycle", key, "draft_id", draft.ID, "error", err)
	}
	p.indexRoundupItem(draft.ID, key, item, roundupExtraction)
	if queueInitial {
		updated, _ := p.db.GetDraft(draft.ID)
		yamlToPublish := yaml
		if updated != nil {
			yamlToPublish = updated.BriefYAML
		}
		if err := p.validatePublication(yamlToPublish); err != nil {
			p.logger.Warn("roundup held for editorial review", "draft_id", draft.ID, "error", err)
		} else if err := p.enqueuePublicationIntent(storage.PublicationIntent{DraftID: draft.ID, BriefYAML: yamlToPublish, CompleteDraft: true}); err != nil {
			p.logger.Error("roundup auto-publish failed", "draft_id", draft.ID, "error", err)
		}
	}
	if err := p.markSeen(item); err != nil {
		// The durable result remains retryable until the source write succeeds.
		p.decisions.record(outcomeFailed)
		p.logger.Error("failed to record seen item; source remains retryable", "source_id", item.SourceID, "error", err)
	}
	p.logger.Info("created vendor roundup brief", "cycle", key, "draft_id", draft.ID)
	return true
}

// enrichRoundupContent appends a per-CVE section to a roundup brief's content
// for each CVE in extraction whose section is not already present. This turns
// the generic CVE list into a readable advisory index with summaries and
// affected-product/version references.
func (p *Pipeline) enrichRoundupContent(draftID string, extraction *ExtractionResult, item scraper.RawItem) error {
	draft, err := p.db.GetDraft(draftID)
	if err != nil {
		return fmt.Errorf("load draft: %w", err)
	}
	if draft == nil {
		return fmt.Errorf("draft %s not found", draftID)
	}
	updated, err := enrichRoundupYAML(draft.BriefYAML, extraction, item)
	if err != nil {
		return err
	}
	if updated == draft.BriefYAML {
		return nil
	}
	publish := p.autoPublish && p.publisher != nil && p.validatePublication(updated) == nil
	return p.db.UpdateDraftYAMLWithPublication(draftID, updated, publish, false)
}

func (p *Pipeline) annotateRoundupDraftCVEProducts(draftID string, extraction *ExtractionResult) error {
	if extraction == nil || len(extraction.CVEs) == 0 {
		return nil
	}
	product := firstNonPlaceholder(extraction.AffectedProducts)
	if product == "" {
		return nil
	}
	draft, err := p.db.GetDraft(draftID)
	if err != nil {
		return fmt.Errorf("load draft: %w", err)
	}
	if draft == nil {
		return fmt.Errorf("draft %s not found", draftID)
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(draft.BriefYAML), &fm); err != nil {
		return fmt.Errorf("parse draft yaml: %w", err)
	}
	if !annotateCVEProducts(fm, extraction.CVEs, product) {
		return nil
	}
	out, err := yaml.Marshal(fm)
	if err != nil {
		return fmt.Errorf("marshal draft yaml: %w", err)
	}
	publish := p.autoPublish && p.publisher != nil && p.validatePublication(string(out)) == nil
	return p.db.UpdateDraftYAMLWithPublication(draftID, string(out), publish, false)
}

func annotateCVEProducts(fm map[string]any, cves []string, product string) bool {
	product = strings.TrimSpace(product)
	if product == "" || isPlaceholder(product) {
		return false
	}
	want := map[string]bool{}
	for _, cve := range cves {
		id := strings.ToUpper(strings.TrimSpace(cve))
		if id != "" {
			want[id] = true
		}
	}
	if len(want) == 0 {
		return false
	}

	existing := yamlAnyList(fm["cves"])
	if len(existing) == 0 {
		return false
	}
	changed := false
	for i, item := range existing {
		if s, ok := item.(string); ok {
			id := strings.ToUpper(strings.TrimSpace(s))
			if want[id] {
				existing[i] = map[string]any{"id": id, "product": product}
				changed = true
			}
			continue
		}
		m, ok := asStringMap(item)
		if !ok {
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(fmt.Sprint(m["id"])))
		if !want[id] {
			continue
		}
		current := strings.TrimSpace(fmt.Sprint(m["product"]))
		if current == "" || current == "<nil>" || isPlaceholder(current) {
			m["product"] = product
			existing[i] = m
			changed = true
		}
	}
	if changed {
		fm["cves"] = existing
	}
	return changed
}

// rebuildRoundupContent regenerates the Overview and Summary sections of a
// vendor roundup from the current CVE list and the per-CVE detail sections,
// leaving the CVE detail sections intact. This keeps the roundup body useful
// as more CVEs are folded in, instead of leaving a one-sentence overview.
func rebuildRoundupContent(fm map[string]any, content string) string {
	vendor := firstNonPlaceholder(yamlStringList(fm["affected_vendors"]))
	cves := yamlCVEEntries(fm["cves"])
	sections := extractRoundupCVESections(content)
	if len(sections) == 0 {
		return content
	}

	cveByID := make(map[string]roundupCVEEntry, len(cves))
	for _, c := range cves {
		cveByID[c.id] = c
	}
	for i := range sections {
		if cve, ok := cveByID[sections[i].id]; ok {
			if len(sections[i].products) == 0 && cve.product != "" {
				sections[i].products = []string{cve.product}
			}
			sections[i].cvss = cve.cvss
			sections[i].cvssVector = cve.cvssVector
			sections[i].epss = cve.epss
			sections[i].epssPercentile = cve.epssPercentile
			sections[i].kev = cve.kev
		}
	}

	var b strings.Builder
	b.WriteString("## Overview\n\n")
	b.WriteString(buildRoundupOverview(vendor, sections))
	b.WriteString("\n\n## Summary\n\n")
	b.WriteString(buildRoundupSummaryTable(sections))
	b.WriteString("\n\n")
	if index := buildRoundupProductIndex(sections); index != "" {
		b.WriteString("## By product\n\n")
		b.WriteString(index)
		b.WriteString("\n\n")
	}
	// Keep the template's response guidance when replacing the overview and
	// summary. Dropping it leaves an accurate CVE index without remediation.
	firstCVE := strings.Index(content, "## CVE-")
	if start := strings.Index(content, "## Recommendation\n"); start >= 0 && (firstCVE < 0 || start < firstCVE) {
		recommendation := content[start:]
		if end := strings.Index(recommendation[len("## Recommendation\n"):], "\n## "); end >= 0 {
			recommendation = recommendation[:len("## Recommendation\n")+end]
		}
		b.WriteString(strings.TrimSpace(recommendation))
		b.WriteString("\n\n")
	}

	// Drop the legacy per-section "Related in this roundup:" lines that
	// earlier revisions injected; the By product index replaces them.
	content = stripRoundupRelatedLines(content)
	idx := strings.Index(content, "## CVE-")
	if idx >= 0 {
		b.WriteString(strings.TrimSpace(content[idx:]))
	} else {
		b.WriteString(content)
	}
	return b.String()
}

func enrichRoundupYAML(briefYAML string, extraction *ExtractionResult, item scraper.RawItem) (string, error) {
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &fm); err != nil {
		return "", fmt.Errorf("parse draft yaml: %w", err)
	}

	content, _ := fm["content"].(string)
	content = strings.TrimSpace(content)

	var b strings.Builder
	b.WriteString(content)
	if !strings.HasSuffix(content, "\n") {
		b.WriteString("\n")
	}

	added := false
	for _, raw := range extraction.CVEs {
		cve := strings.ToUpper(strings.TrimSpace(raw))
		if cve == "" {
			continue
		}
		// Skip if a section for this CVE already exists in the content.
		if strings.Contains(content, "\n## "+cve) || strings.HasPrefix(content, "## "+cve) {
			continue
		}
		b.WriteString("\n## ")
		b.WriteString(cve)
		b.WriteString("\n\n")
		if extraction.Summary != "" {
			b.WriteString(extraction.Summary)
			b.WriteString("\n\n")
		}
		if len(extraction.AffectedProducts) > 0 {
			b.WriteString("Affected products:\n")
			for _, prod := range extraction.AffectedProducts {
				prod = strings.TrimSpace(prod)
				if prod != "" {
					b.WriteString("- ")
					b.WriteString(prod)
					b.WriteString("\n")
				}
			}
			b.WriteString("\n")
		}
		if item.URL != "" {
			b.WriteString("Source: ")
			b.WriteString(item.URL)
			b.WriteString("\n")
		}
		added = true
	}

	if !added {
		return briefYAML, nil
	}

	content = b.String()
	content = rebuildRoundupContent(fm, content)
	fm["content"] = content
	out, err := yaml.Marshal(fm)
	if err != nil {
		return "", fmt.Errorf("marshal updated draft: %w", err)
	}
	return string(out), nil
}
