package publisher

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// FlushSegmented publishes all encrypted segments, indexes, public Markdown,
// and STIX artifacts through one branch ref update. Pending state is retained
// unless that ref update succeeds.
func (p *Publisher) FlushSegmented() error {
	p.rejectedIDs = nil
	if err := p.retryDraftCompletions(); err != nil {
		return err
	}
	if err := p.checkDraftPublications(); err != nil {
		return err
	}
	if len(p.pending) == 0 && len(p.pendingDigests) == 0 && len(p.pendingRetirements) == 0 {
		return nil
	}
	count := len(p.pending)
	flushed := p.outboxSnapshot()
	message := fmt.Sprintf("chore: publish threat feed release (%d briefs)", count)
	for {
		err := p.withAtomicPublication(message, p.flushSegmentedRelease)
		if errors.Is(err, errRestartFlush) {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	completionErr := p.finishDraftPublications(flushed)
	p.pending = nil
	p.pendingDigests = nil
	p.pendingRetirements = nil
	p.retiredInFavourOf = nil
	restored := p.restoredRetirements
	p.restoredRetirements = nil
	if p.retirementApplied != nil {
		// Keep a restored retirement's row until its callback succeeds; the
		// callback is idempotent and reruns on the next start otherwise.
		for id := range restored {
			delete(flushed, retirementOutboxID(id))
		}
	}
	p.clearOutbox(flushed)
	p.finishRestoredRetirements(restored)
	return completionErr
}

// finishRestoredRetirements runs the retirement-applied callback for every
// restored retirement the flush just published (those a rejected canonical
// brief dropped were removed earlier) and forgets them.
func (p *Publisher) finishRestoredRetirements(restored map[string]Retirement) {
	if p.retirementApplied == nil {
		return
	}
	for _, r := range restored {
		if err := p.retirementApplied(r); err != nil {
			p.logger.Error("finishing restored retirement failed; row kept for the next start", "brief_id", r.BriefID, "draft_id", r.DraftID, "error", err)
			continue
		}
		p.dropOutboxRow(retirementOutboxID(r.BriefID))
	}
}

// RejectedBriefIDs lists the brief IDs whose revision the most recent
// segmented flush rejected and dropped. A flush that returns nil may still have
// dropped a brief; callers that publish one specific brief must check this.
func (p *Publisher) RejectedBriefIDs() []string {
	return slices.Clone(p.rejectedIDs)
}

func (p *Publisher) flushSegmentedRelease() error {
	count := len(p.pending)
	p.logger.Info("flushing segmented", "new_briefs", count, "new_digests", len(p.pendingDigests))

	// digestsBySegment collects all digests (legacy + pending) keyed by year.
	// Declared early so the migration block can populate it too.
	digestsBySegment := make(map[string][]BundleDigest)

	// 1. Fetch the manifest. A read failure must stop publication: treating it
	// as an absent manifest can overwrite the index of existing segments.
	manifest, manifestSHA, err := p.fetchManifest()
	if err != nil {
		return fmt.Errorf("fetching manifest: %w", err)
	}
	modifiedSegments := make(map[string]bool)
	if manifestSHA == "" {
		// A genuine 404 may mean the feed still uses the legacy flat bundle.
		legacy, _, legacyErr := p.fetchBundle()
		if legacyErr != nil {
			return fmt.Errorf("fetching legacy bundle: %w", legacyErr)
		}
		if len(legacy.Briefs) > 0 || len(legacy.Digests) > 0 {
			p.logger.Info("migrating legacy bundle to segmented format", "briefs", len(legacy.Briefs), "digests", len(legacy.Digests))
			manifest = MigrateBundleToSegments(legacy)
			// Push every segment created from the legacy bundle.
			for _, seg := range manifest.Segments {
				key := strings.TrimPrefix(strings.TrimSuffix(seg.Path, ".json"), "briefs/")
				modifiedSegments[key] = true
			}
			// Carry legacy digests into digestsBySegment so they get embedded in year segments.
			for _, digest := range legacy.Digests {
				ts, parseErr := time.Parse(time.RFC3339, digest.PublishedAt)
				if parseErr != nil {
					ts = time.Now().UTC()
				}
				key := SegmentKey(ts)
				modifiedSegments[key] = true
				digestsBySegment[key] = append(digestsBySegment[key], digest)
				manifest.EnsureSegment(key)
			}
		}
	}
	listedAtFetch := make(map[string]bool, len(manifest.Segments))
	if manifestSHA != "" {
		for _, segment := range manifest.Segments {
			listedAtFetch[segment.Path] = true
		}
	}

	// 2. Fetch existing changelog (404 → new).
	changelog, changelogSHA, err := p.fetchChangelog()
	if err != nil {
		return fmt.Errorf("fetching changelog: %w", err)
	}

	deltaStart := len(changelog.currentEntry().Changes)

	// 3. Group pending digests by segment key so they get embedded alongside briefs.
	for _, digest := range p.pendingDigests {
		ts, parseErr := time.Parse(time.RFC3339, digest.PublishedAt)
		if parseErr != nil {
			ts = time.Now().UTC()
		}
		key := SegmentKey(ts)
		modifiedSegments[key] = true
		digestsBySegment[key] = append(digestsBySegment[key], digest)
		manifest.EnsureSegment(key)
	}

	// Complete the yearly→monthly migration before rewriting segments:
	// pre-migration manifests still list yearly segments, and thousands of
	// briefs live only there. Move those into their monthly segments, then
	// drop the yearly entries so consumers stop ingesting duplicates.
	if err := p.redistributeLegacySegments(manifest, modifiedSegments, digestsBySegment); err != nil {
		return fmt.Errorf("redistributing legacy segments: %w", err)
	}

	// Monthly segment files can exist without a manifest listing (briefs
	// published while the manifest churned); consumers only sync listed
	// segments, so those briefs are invisible until reconciled.
	if err := p.listUnlistedMonthlySegments(manifest); err != nil {
		return fmt.Errorf("reconciling unlisted segments: %w", err)
	}

	// Backfill and retain the location index, then resolve every incoming
	// identity against the whole canonical feed. Identity and first publication
	// are feed-wide and immutable, so an update is always routed to its stored
	// month and MergeBriefs rejects a changed publication timestamp.
	if len(p.pending) > 0 || len(p.pendingRetirements) > 0 {
		if err := p.ensureBriefLocations(manifest, listedAtFetch, modifiedSegments); err != nil {
			return fmt.Errorf("indexing existing briefs: %w", err)
		}
		// The in-memory map may contain briefs redistributed from legacy yearly
		// segments in this run; those do not yet exist in monthly files.
		for key, briefs := range manifest.briefsBySegment {
			for _, brief := range briefs {
				addBriefLocation(manifest.BriefLocations, brief.ID, key)
			}
		}

		identity, err := p.loadCanonicalIdentity(manifest, modifiedSegments)
		if err != nil {
			return fmt.Errorf("loading canonical brief identity: %w", err)
		}
		// A retirement in favour of a canonical that is neither published nor
		// pending would delete public content with nothing replacing it.
		pendingIDs := make(map[string]bool, len(p.pending))
		for _, raw := range p.pending {
			pendingIDs[raw.ID] = true
		}
		for id := range p.pendingRetirements {
			canonical := p.retiredInFavourOf[id]
			if canonical == "" || pendingIDs[canonical] {
				continue
			}
			if _, published := identity.byID[canonical]; !published {
				p.rejectRetirement(&RetirementRejectedError{BriefID: id, Slug: p.pendingRetirements[id], CanonicalID: canonical,
					Err: fmt.Errorf("canonical brief %q is neither published nor pending", canonical)})
			}
		}
		alreadyAbsentRetirements := make(map[string]bool)
		for id := range p.pendingRetirements {
			location, exists := identity.byID[id]
			if !exists {
				alreadyAbsentRetirements[id] = true
				p.logger.Info("published brief already absent; retirement is idempotent", "brief", id)
				continue
			}
			p.pendingRetirements[id] = location.slug
			modifiedSegments[location.key] = true
			delete(manifest.BriefLocations, id)
			changelog.RecordRemove(id)
		}
		for _, raw := range p.pending {
			brief := NormalizePublicationMetadata(raw)
			location, isUpdate := identity.byID[brief.ID]
			key := location.key
			if !isUpdate {
				published, parseErr := time.Parse(time.RFC3339Nano, brief.PublishedAt)
				if parseErr != nil {
					return fmt.Errorf("brief %q has invalid published_at: %w", brief.ID, parseErr)
				}
				key = SegmentKey(published)
				if owner, exists := identity.byEvent[brief.EventID]; exists && owner != brief.ID {
					// A candidate's own identity clash must not block the flush
					// (or every later one, once restored from the outbox).
					rejected := &RevisionRejectedError{BriefID: brief.ID, Err: fmt.Errorf("event_id %q already belongs to brief %q", brief.EventID, owner)}
					p.logger.Error("brief revision rejected", "brief_id", brief.ID, "error", rejected.Error())
					p.dropRejected(brief.ID)
					if p.dropRetirementsFavouring(brief.ID) {
						return errRestartFlush
					}
					continue
				}
				if slug := strings.ToLower(strings.TrimSpace(brief.Slug)); slug != "" {
					if owner, exists := identity.bySlug[slug]; exists && owner != brief.ID {
						used := make(map[string]struct{}, len(identity.bySlug))
						for existing := range identity.bySlug {
							used[existing] = struct{}{}
						}
						original := brief.Slug
						brief.Slug = uniqueRepairedSlug(brief, used)
						slug = normalizedSlug(brief.Slug)
						p.logger.Warn("disambiguated colliding slug before first publication",
							"brief", brief.ID, "requested_slug", original, "canonical_slug", brief.Slug, "existing_owner", owner)
					}
					identity.bySlug[slug] = brief.ID
				}
				identity.byID[brief.ID] = canonicalBriefLocation{key: key, slug: brief.Slug}
				identity.byEvent[brief.EventID] = brief.ID
			} else if requested := normalizedSlug(brief.Slug); requested != "" && requested != normalizedSlug(location.slug) {
				// A first publication may have repaired a generated slug because
				// another brief already owned it. Future source updates can generate
				// that same colliding slug again; keep the stored canonical slug in
				// that specific case while leaving unrelated identity mutations for
				// MergeBriefs to reject.
				if owner, collides := identity.bySlug[requested]; collides && owner != brief.ID {
					p.logger.Warn("preserved repaired canonical slug on update",
						"brief", brief.ID, "requested_slug", brief.Slug, "canonical_slug", location.slug, "existing_owner", owner)
					brief.Slug = location.slug
				}
			}
			modifiedSegments[key] = true
			manifest.AddBriefToSegment(key, brief)
			manifest.BriefLocations[brief.ID] = []string{key}
			if isUpdate {
				changelog.RecordUpdate(brief.ID, []string{"content"})
			} else {
				changelog.RecordAdd(brief.ID)
			}
		}
		for id := range alreadyAbsentRetirements {
			requestedSlug := normalizedSlug(p.pendingRetirements[id])
			if owner, inUse := identity.bySlug[requestedSlug]; requestedSlug != "" && inUse {
				p.rejectRetirement(&RetirementRejectedError{BriefID: id, Slug: p.pendingRetirements[id], CanonicalID: p.retiredInFavourOf[id],
					Err: fmt.Errorf("cannot retire already-absent brief %q: slug %q belongs to published brief %q", id, p.pendingRetirements[id], owner)})
			}
		}
	}

	// 4. For each modified segment, fetch existing, merge, encrypt, upload.
	runTime := time.Now().UTC()
	now := runTime.Format(time.RFC3339)
	mergedByID := make(map[string]BundleBrief, len(p.pending))
	type mergedSegment struct {
		existing SegmentContent
		sha      string
		briefs   []BundleBrief
	}
	mergedSegments := make(map[string]mergedSegment, len(modifiedSegments))
	for key := range modifiedSegments {
		segPath := "output/briefs/" + key + ".json"

		// Fetch existing segment if any.
		existingSeg, segSHA, fetchErr := p.fetchSegment(segPath)
		if fetchErr != nil {
			return fmt.Errorf("fetching segment %s: %w", key, fetchErr)
		}

		// Get all briefs for this segment from the manifest.
		existingSeg.Briefs = excludeRetiredBriefs(existingSeg.Briefs, p.pendingRetirements)
		segBriefs := excludeRetiredBriefs(manifest.GetSegmentBriefs(key), p.pendingRetirements)

		// Merge with existing briefs from the segment file.
		// A candidate that violates the append-only revision rules is excluded
		// from this release without blocking the others. Only typed candidate
		// rejections are isolated; errors about published data still abort.
		var merged []BundleBrief
		for {
			var mergeErr error
			merged, mergeErr = MergeBriefs(existingSeg.Briefs, segBriefs, runTime)
			var rejected *RevisionRejectedError
			if !errors.As(mergeErr, &rejected) {
				if mergeErr != nil {
					return fmt.Errorf("merging segment %s: %w", key, mergeErr)
				}
				break
			}
			p.rejectRevision(rejected, existingSeg.Briefs, segBriefs, changelog, deltaStart)
			if p.dropRetirementsFavouring(rejected.BriefID) {
				// Retirements were already applied to this attempt's state;
				// rerun without them and without the rejected brief.
				return errRestartFlush
			}
			segBriefs = excludeBriefID(segBriefs, rejected.BriefID)
		}
		for _, brief := range merged {
			mergedByID[brief.ID] = brief
		}
		mergedSegments[key] = mergedSegment{existing: *existingSeg, sha: segSHA, briefs: merged}
	}

	// Every rejection is known now. With nothing left to publish, skip the
	// release entirely instead of rewriting segments, changelog, manifest, STIX.
	if len(p.rejectedIDs) > 0 && len(p.pending) == 0 && len(p.pendingDigests) == 0 && len(p.pendingRetirements) == 0 {
		p.logger.Warn("every pending brief was rejected; skipping release", "rejected", len(p.rejectedIDs))
		return nil
	}
	if p.publication != nil {
		p.publication.message = fmt.Sprintf("chore: publish threat feed release (%d briefs)", len(p.pending))
	}
	for key := range modifiedSegments {
		segPath := "output/briefs/" + key + ".json"
		existingSeg, segSHA, merged := mergedSegments[key].existing, mergedSegments[key].sha, mergedSegments[key].briefs

		segContent := &SegmentContent{
			Briefs:  merged,
			Digests: mergeDigests(existingSeg.Digests, digestsBySegment[key]),
		}

		encrypted, encErr := EncryptSegment(segContent, bundleVersion(), now, p.publicKey)
		if encErr != nil {
			return fmt.Errorf("encrypting segment %s: %w", key, encErr)
		}

		commitMsg := fmt.Sprintf("chore: update segment %s (%d briefs)", key, len(merged))
		checksum, err := p.putFile(segPath, encrypted, segSHA, commitMsg)
		if err != nil {
			return fmt.Errorf("pushing segment %s: %w", key, err)
		}

		// Update manifest segment entry with checksum and modification time.
		for i := range manifest.Segments {
			if manifest.Segments[i].Path == segmentPath(key) {
				manifest.Segments[i].Checksum = checksum
				manifest.Segments[i].BriefCount = len(merged)
				manifest.Segments[i].LastModified = now
				break
			}
		}

		p.logger.Info("segment staged", "key", key, "briefs", len(merged))
	}

	// 5. Prune and upload changelog (plain JSON, not encrypted).
	changelog.Prune(7*24*time.Hour, 50)
	if err := p.putJSONFile(changelogPath, changelog, changelogSHA, "chore: update changelog"); err != nil {
		return fmt.Errorf("pushing changelog: %w", err)
	}
	if len(changelog.Entries) > 0 {
		manifest.ChangelogRef = &ChangelogEntry{
			Path:  changelogPath,
			Since: changelog.Entries[0].Timestamp,
		}
	}

	// 6. Upload manifest (plain JSON, not encrypted).
	if err := p.putJSONFile(manifestPath, manifest, manifestSHA, "chore: update segment manifest"); err != nil {
		return fmt.Errorf("pushing manifest: %w", err)
	}

	// 7. Emit public Markdown for the Hugo site. Run after the encrypted
	//    bundle is consistent so a partial Markdown failure can't leave
	//    plaintext for a brief whose encrypted segment didn't land.
	//    Per-brief errors are logged but don't fail the flush — segment
	//    success is more important than Markdown completeness.
	mdSuccess, mdFail := 0, 0
	for _, pending := range p.pending {
		brief := pending
		if merged, ok := mergedByID[pending.ID]; ok {
			brief = merged
		}
		if err := p.publishBriefMarkdown(brief); err != nil {
			p.logger.Error("public markdown emission failed", "brief", brief.ID, "err", err)
			mdFail++
			continue
		}
		mdSuccess++
	}
	for id, slug := range p.pendingRetirements {
		path := publicMarkdownPath(BundleBrief{ID: id, Slug: slug})
		if err := p.stageGitDelete(path); err != nil {
			return fmt.Errorf("removing duplicate public Markdown %s: %w", path, err)
		}
	}
	if mdSuccess > 0 || mdFail > 0 {
		p.logger.Info("public markdown staged", "success", mdSuccess, "failed", mdFail)
	}

	// Publish STIX after the encrypted segments are consistent. The caller must
	// see a source/parity failure so a partial public contract cannot masquerade
	// as a successful feed release.
	if err := p.PublishSTIXBundle(); err != nil {
		return fmt.Errorf("publishing STIX bundles: %w", err)
	}
	p.afterPublicationCommit(func() {
		p.logger.Info("segmented flush complete", "new_briefs", count, "segments_modified", len(modifiedSegments))
	})
	return nil
}

// rejectRevision logs a rejected candidate, drops it from the pending buffer
// (the same snapshot can never succeed; the draft's next update re-buffers a
// fresh one) and removes its changelog entry recorded earlier in this run.
func (p *Publisher) rejectRevision(rejected *RevisionRejectedError, published, candidates []BundleBrief, changelog *Changelog, deltaStart int) {
	id := rejected.BriefID
	cveIDs := func(briefs []BundleBrief) []string {
		var ids []string
		for _, b := range briefs {
			if b.ID == id {
				for _, cve := range b.CVEs {
					ids = append(ids, cve.ID)
				}
			}
		}
		return ids
	}
	p.logger.Error("brief revision rejected",
		"brief_id", id, "error", rejected.Error(),
		"published_cves", cveIDs(published), "candidate_cves", cveIDs(candidates))
	p.dropRejected(id)
	// Only deltas appended by this run (index >= deltaStart) are removed;
	// earlier history of the brief in the accumulating entry stays.
	if n := len(changelog.Entries); n > 0 {
		changes := changelog.Entries[n-1].Changes
		kept := changes[:min(deltaStart, len(changes))]
		for i := deltaStart; i < len(changes); i++ {
			if changes[i].BriefID != id || changes[i].Type == "removed" {
				kept = append(kept, changes[i])
			}
		}
		changelog.Entries[n-1].Changes = kept
	}
}

// dropRejected removes a rejected brief from the pending buffer and the outbox
// and records it as rejected. The snapshot is dropped on purpose; restoring it
// would only be rejected again.
func (p *Publisher) dropRejected(id string) {
	p.pending = excludeBriefID(p.pending, id)
	delete(p.pendingDrafts, id)
	if seq, ok := p.outboxSeq[id]; ok {
		p.clearOutbox(map[string]int64{id: seq})
	}
	if !slices.Contains(p.rejectedIDs, id) {
		p.rejectedIDs = append(p.rejectedIDs, id)
	}
}

func excludeBriefID(briefs []BundleBrief, id string) []BundleBrief {
	kept := make([]BundleBrief, 0, len(briefs))
	for _, brief := range briefs {
		if brief.ID != id {
			kept = append(kept, brief)
		}
	}
	return kept
}

func excludeRetiredBriefs(briefs []BundleBrief, retired map[string]string) []BundleBrief {
	if len(retired) == 0 {
		return briefs
	}
	kept := make([]BundleBrief, 0, len(briefs))
	for _, brief := range briefs {
		if _, remove := retired[brief.ID]; !remove {
			kept = append(kept, brief)
		}
	}
	return kept
}

type canonicalBriefLocation struct {
	key  string
	slug string
}

type canonicalBriefIdentity struct {
	byID    map[string]canonicalBriefLocation
	byEvent map[string]string
	bySlug  map[string]string
}

func (p *Publisher) loadCanonicalIdentity(manifest *SegmentManifest, modified map[string]bool) (*canonicalBriefIdentity, error) {
	identity := &canonicalBriefIdentity{
		byID: make(map[string]canonicalBriefLocation), byEvent: make(map[string]string), bySlug: make(map[string]string),
	}
	register := func(raw BundleBrief, key string) error {
		brief := NormalizePublicationMetadata(raw)
		published, err := time.Parse(time.RFC3339Nano, brief.PublishedAt)
		if err != nil {
			return fmt.Errorf("brief %q in segment %s has invalid published_at: %w", brief.ID, key, err)
		}
		if SegmentKey(published) != key {
			return fmt.Errorf("brief %q published in %s is stored in segment %s", brief.ID, SegmentKey(published), key)
		}
		if previous, exists := identity.byID[brief.ID]; exists {
			return fmt.Errorf("duplicate canonical brief id %q in segments %s and %s", brief.ID, previous.key, key)
		}
		if owner, exists := identity.byEvent[brief.EventID]; exists && owner != brief.ID {
			return fmt.Errorf("event_id %q belongs to both %q and %q", brief.EventID, owner, brief.ID)
		}
		slug := strings.ToLower(strings.TrimSpace(brief.Slug))
		if owner, exists := identity.bySlug[slug]; slug != "" && exists && owner != brief.ID {
			return fmt.Errorf("slug %q belongs to both %q and %q", brief.Slug, owner, brief.ID)
		}
		identity.byID[brief.ID] = canonicalBriefLocation{key: key, slug: brief.Slug}
		identity.byEvent[brief.EventID] = brief.ID
		if slug != "" {
			identity.bySlug[slug] = brief.ID
		}
		return nil
	}
	for _, entry := range manifest.Segments {
		if !monthlySegmentPath.MatchString(entry.Path) {
			continue
		}
		key := strings.TrimSuffix(strings.TrimPrefix(entry.Path, "briefs/"), ".json")
		var content *SegmentContent
		var err error
		if modified[key] {
			// Migration or a digest can create a new monthly manifest entry
			// before its file exists. ensureBriefLocations already rejected a
			// missing entry that existed at fetch time; here an absent file is a
			// valid empty starting point for a segment this run will write.
			content, _, err = p.fetchSegment("output/" + entry.Path)
		} else {
			content, _, err = p.fetchManifestSegment(entry)
		}
		if err != nil {
			return nil, err
		}
		for _, brief := range content.Briefs {
			if err := register(brief, key); err != nil {
				return nil, err
			}
		}
		for _, brief := range manifest.GetSegmentBriefs(key) {
			if err := register(brief, key); err != nil {
				return nil, err
			}
		}
	}
	return identity, nil
}
