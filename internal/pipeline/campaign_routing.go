package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"github.com/google/uuid"
)

// buildCampaignBriefYAML returns a template umbrella brief for a campaign /
// technique family (e.g. ClickFix). Individual sightings are folded in via
// mergeIntoDraft as they arrive.
func buildCampaignBriefYAML(family string, now time.Time) string {
	name := displayCampaignFamily(family)
	return fmt.Sprintf(`id: "brief-%[1]s-%[2]s-campaign"
slug: "%[1]s-%[2]s-campaign"
title: "%[3]s Campaign Activity"
summary: "Tracking brief for the %[3]s campaign; individual sightings are folded in as reported."
severity: "high"
published_at: "%[4]s"
content: |
  ## Overview

  This brief tracks activity attributed to the %[3]s campaign. Sightings and
  indicators from separate reports are folded in as they are published, rather
  than creating a separate brief per report.

  ## Recommendation

  Review the collected indicators and references and hunt for %[3]s delivery
  patterns across endpoint and network telemetry.
tags:
  - campaign
  - %[2]s
`, now.Format("2006-01"), family, name, now.UTC().Format(time.RFC3339))
}

// campaignFamilyFromFrontmatter returns the family of an umbrella brief built
// by buildCampaignBriefYAML, else "".
func campaignFamilyFromFrontmatter(fm map[string]any) string {
	tags := yamlStringList(fm["tags"])
	if !stringListContainsFold(tags, "campaign") {
		return ""
	}
	slug := strings.ToLower(strings.TrimSpace(fmt.Sprint(fm["slug"])))
	for family := range campaignDisplay {
		if stringListContainsFold(tags, family) && strings.HasSuffix(slug, "-"+family+"-campaign") {
			return family
		}
	}
	return ""
}

// sanitizeCampaignExtraction keeps a merged item from widening an umbrella's
// vendor/product scope. The umbrella tracks a technique or malware family; the
// brands a sighting names (lures, impersonated apps, stealer targets, abused
// hosting, payload tooling) are not what the family affects.
func sanitizeCampaignExtraction(extraction *ExtractionResult) *ExtractionResult {
	if extraction == nil {
		return nil
	}
	clean := *extraction
	clean.AffectedVendors = nil
	clean.AffectedProducts = nil
	return &clean
}

// routeToCampaign folds a sighting of a known campaign/technique family into a
// single umbrella brief instead of a standalone brief per report. Returns true
// when the item was consumed. Gated by cfg.CampaignConsolidation.
func (p *Pipeline) routeToCampaign(ctx context.Context, item scraper.RawItem, extraction *ExtractionResult) bool {
	if !p.campaignConsolidation {
		return false
	}
	family := matchCampaignFamily(item.Title)
	if family == "" {
		return false
	}
	if extraction == nil {
		extraction = &ExtractionResult{}
	}
	key := "campaign|" + family
	// Fold into the existing umbrella for this family if one exists.
	if entries, err := p.db.FindByVendorCycle(key); err == nil {
		for _, e := range entries {
			if e.DraftID == "" {
				continue
			}
			if err := p.mergeIntoDraft(ctx, e.DraftID, extraction, item); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
					return false
				}
				if errors.Is(err, errMergeRelevanceUnavailable) {
					p.logger.Warn("campaign merge assessment unavailable; retaining source for retry", "source_id", item.SourceID, "draft_id", e.DraftID, "error", err)
					return true
				}
				p.logMergeFailure("campaign merge failed", err, "family", family, "draft_id", e.DraftID)
				return false
			}
			p.indexRoundupItem(e.DraftID, key, item, extraction)
			if err := p.markSeen(item); err != nil {
				// The durable result remains retryable until the source write succeeds.
				p.decisions.record(outcomeFailed)
				p.logger.Error("failed to record seen item; source remains retryable", "source_id", item.SourceID, "error", err)
			}
			p.logger.Info("folded sighting into campaign brief", "family", family, "draft_id", e.DraftID)
			return true
		}
	}
	// Otherwise create the umbrella (template — no LLM assembly).
	yaml := buildCampaignBriefYAML(family, time.Now().UTC())
	if seeded, err := ensureInitialSourceReference(yaml, item.URL); err != nil {
		p.logger.Warn("campaign source reference not seeded", "family", family, "error", err)
		return false
	} else {
		yaml = seeded
	}
	draft := &storage.Draft{
		ID:        uuid.NewString(),
		Status:    storage.StatusPending,
		Source:    item.Source,
		SourceIDs: fmt.Sprintf("[%q]", item.SourceID),
		BriefYAML: yaml,
		CreatedAt: time.Now(),
	}
	queueInitial, err := p.createTemplateDraft(draft)
	if err != nil {
		p.logger.Warn("campaign draft create failed", "family", family, "error", err)
		return false
	}
	p.indexRoundupItem(draft.ID, key, item, extraction)
	if queueInitial {
		if err := p.validatePublication(yaml); err != nil {
			p.logger.Warn("campaign held for editorial review", "draft_id", draft.ID, "error", err)
		} else if err := p.enqueuePublicationIntent(storage.PublicationIntent{DraftID: draft.ID, BriefYAML: yaml, CompleteDraft: true}); err != nil {
			p.logger.Error("campaign auto-publish failed", "draft_id", draft.ID, "error", err)
		}
	}
	if err := p.markSeen(item); err != nil {
		// The durable result remains retryable until the source write succeeds.
		p.decisions.record(outcomeFailed)
		p.logger.Error("failed to record seen item; source remains retryable", "source_id", item.SourceID, "error", err)
	}
	p.logger.Info("created campaign umbrella brief", "family", family, "draft_id", draft.ID)
	return true
}
