package publisher

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
)

// enrichBriefsInSegment infers affected vendor/product for briefs that lack
// both fields, restricted to slugs in want (empty want = all). Returns the
// briefs that were changed (nil if none), each carrying its enriched
// AffectedVendors/AffectedProducts, so callers can re-emit exactly those.
// Pure over the slice; callers persist the result.
func enrichBriefsInSegment(ctx context.Context, client llm.Client, briefs []BundleBrief, want map[string]bool, logger *slog.Logger) []BundleBrief {
	var changed []BundleBrief
	for i := range briefs {
		b := &briefs[i]
		if len(want) > 0 && !want[b.Slug] {
			continue
		}
		if hasMeaningfulString(b.AffectedVendors) || hasMeaningfulString(b.AffectedProducts) {
			continue
		}
		vendors, products, err := pipeline.InferVendorProduct(ctx, client, b.Title, b.Content, b.References)
		if err != nil {
			logger.Warn("vendor/product inference failed", "slug", b.Slug, "error", err)
			continue
		}
		if len(vendors) == 0 && len(products) == 0 {
			continue
		}
		b.AffectedVendors = vendors
		b.AffectedProducts = products
		changed = append(changed, *b)
		logger.Info("enriched brief vendor/product", "slug", b.Slug, "vendors", vendors, "products", products)
	}
	return changed
}

// EnrichVendorProduct infers affected vendor/product for briefs (restricted to
// slugs, empty = all) that lack both fields, writes the result back into the
// encrypted bundle, and re-emits the affected Markdown. Segment, manifest,
// Markdown, and STIX changes are staged and exposed through one branch update,
// so a mid-run failure cannot strand a segment behind a stale checksum. The
// per-brief Markdown re-emit loop is paced with backfillSleep between calls
// to stay under GitHub's secondary rate limit across a 1000+ brief run.
// With dryRun, it reports what it would change without writing anything (no
// putFile, putJSONFile, publishBriefMarkdown, or PublishSTIXBundle call is
// reachable).
func (p *Publisher) EnrichVendorProduct(ctx context.Context, slugs []string, dryRun bool) error {
	if dryRun {
		return p.enrichVendorProductRelease(ctx, slugs, true)
	}
	return p.withAtomicPublication("chore: publish vendor/product enrichment", func() error {
		return p.enrichVendorProductRelease(ctx, slugs, false)
	})
}

func (p *Publisher) enrichVendorProductRelease(ctx context.Context, slugs []string, dryRun bool) error {
	want := make(map[string]bool, len(slugs))
	for _, s := range slugs {
		want[s] = true
	}

	manifest, _, err := p.fetchManifest()
	if err != nil {
		return fmt.Errorf("fetching manifest: %w", err)
	}

	now := bundleTimestamp()
	total := 0
	for _, seg := range manifest.Segments {
		segPath := "output/" + seg.Path
		content, sha, fetchErr := p.fetchSegment(segPath)
		if fetchErr != nil {
			p.logger.Warn("enrich: skipping unreadable segment", "path", segPath, "err", fetchErr)
			continue
		}
		changed := enrichBriefsInSegment(ctx, p.llmClient, content.Briefs, want, p.logger)
		if len(changed) == 0 {
			continue
		}
		if dryRun {
			p.logger.Info("enrich (dry-run): would update segment", "path", segPath, "changed", len(changed))
			total += len(changed)
			continue
		}
		encrypted, encErr := EncryptSegment(content, bundleVersion(), now, p.publicKey)
		if encErr != nil {
			return fmt.Errorf("encrypting segment %s: %w", segPath, encErr)
		}
		checksum, err := p.putFile(segPath, encrypted, sha, fmt.Sprintf("chore: enrich vendor/product (%d briefs)", len(changed)))
		if err != nil {
			return fmt.Errorf("pushing segment %s: %w", segPath, err)
		}

		// Keep the manifest's per-segment checksum/count/timestamp in sync
		// with the segment blob we just rewrote.
		for i := range manifest.Segments {
			if manifest.Segments[i].Path == seg.Path {
				manifest.Segments[i].Checksum = checksum
				manifest.Segments[i].BriefCount = len(content.Briefs)
				manifest.Segments[i].LastModified = now
				break
			}
		}

		// Refresh the staged manifest after each segment so subsequent reads in
		// this release observe its latest checksum/count.
		msha, shaErr := p.getFileSHA(manifestPath)
		if shaErr != nil {
			return fmt.Errorf("checking existing manifest: %w", shaErr)
		}
		if err := p.putJSONFile(manifestPath, manifest, msha, "chore: update manifest (vendor/product enrichment)"); err != nil {
			return fmt.Errorf("pushing manifest after segment %s: %w", segPath, err)
		}

		p.logger.Info("enrich: segment updated", "path", segPath, "changed", len(changed))
		for _, b := range changed {
			if err := p.publishBriefMarkdown(b); err != nil {
				p.logger.Warn("enrich: markdown re-emit failed", "slug", b.Slug, "err", err)
			}
			// Pace re-emits so a 1000+ brief backfill doesn't trip GitHub's
			// secondary rate limit.
			time.Sleep(backfillSleep)
		}
		total += len(changed)
	}

	if dryRun {
		p.logger.Info("enrich (dry-run) complete", "would_enrich_reemit", total)
		return nil
	}

	if total > 0 {
		if err := p.PublishSTIXBundle(); err != nil {
			p.logger.Warn("enrich: STIX republish failed", "err", err)
		}
	}
	p.logger.Info("enrich complete", "reemitted", total)
	return nil
}
