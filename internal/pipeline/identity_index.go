package pipeline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"gopkg.in/yaml.v3"
)

func containsXStatusReference(text string) bool {
	for _, word := range strings.Fields(text) {
		if _, _, ok := scraper.ParseXStatusURL(strings.Trim(word, "()[]{}<>,.;\"'")); ok {
			return true
		}
	}
	return false
}

// ensureUniqueDraftIdentity prevents two active SQLite drafts from claiming
// the same public ID or URL. Generated IDs are human-readable rather than
// globally unique, so independent same-day sources can legitimately collide.
// Deduplication and same-incident merging get first refusal; candidates that
// remain distinct receive a deterministic source-derived suffix before they
// can reach the publisher.
func (p *Pipeline) ensureUniqueDraftIdentity(briefYAML string, item scraper.RawItem) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return "", fmt.Errorf("parsing generated identity: %w", err)
	}
	id := publicationString(doc["id"])
	slug := strings.ToLower(publicationString(doc["slug"]))
	publishedAt, err := time.Parse(time.RFC3339, publicationString(doc["published_at"]))
	if err != nil {
		return "", fmt.Errorf("parsing published_at: %w", err)
	}
	if id == "" || slug == "" {
		return briefYAML, nil
	}

	monthStart := time.Date(publishedAt.Year(), publishedAt.Month(), 1, 0, 0, 0, 0, time.UTC)
	usedIDs := make(map[string]struct{})
	usedSlugs := make(map[string]struct{})
	for draft, rowErr := range p.db.ActiveDraftsSince(monthStart) {
		if rowErr != nil {
			return "", rowErr
		}
		var identity struct {
			ID   string `yaml:"id"`
			Slug string `yaml:"slug"`
		}
		if yaml.Unmarshal([]byte(draft.BriefYAML), &identity) != nil {
			continue
		}
		if existingID := strings.TrimSpace(identity.ID); existingID != "" {
			usedIDs[existingID] = struct{}{}
		}
		if existingSlug := strings.ToLower(strings.TrimSpace(identity.Slug)); existingSlug != "" {
			usedSlugs[existingSlug] = struct{}{}
		}
	}
	_, idCollision := usedIDs[id]
	_, slugCollision := usedSlugs[slug]
	if !idCollision && !slugCollision {
		return briefYAML, nil
	}

	sum := sha256.Sum256([]byte(item.SourceID + "\x00" + id + "\x00" + slug))
	hexSum := fmt.Sprintf("%x", sum)
	for length := 8; length <= len(hexSum); length += 4 {
		suffix := hexSum[:length]
		candidateID := id + "-" + suffix
		candidateSlug := slug + "-" + suffix
		if _, exists := usedIDs[candidateID]; exists {
			continue
		}
		if _, exists := usedSlugs[candidateSlug]; exists {
			continue
		}
		doc["id"] = candidateID
		doc["slug"] = candidateSlug
		encoded, err := yaml.Marshal(doc)
		if err != nil {
			return "", fmt.Errorf("encoding disambiguated identity: %w", err)
		}
		p.logger.Warn("disambiguated generated public identity",
			"source_id", item.SourceID, "requested_id", id, "canonical_id", candidateID,
			"requested_slug", slug, "canonical_slug", candidateSlug)
		return string(encoded), nil
	}
	return "", fmt.Errorf("could not disambiguate public identity %q", id)
}

func confirmedExploitationEvidence(rawYAML string) bool {
	var doc struct {
		Evidence *ExploitationEvidence `yaml:"exploitation_evidence"`
	}
	if yaml.Unmarshal([]byte(rawYAML), &doc) != nil || doc.Evidence == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(doc.Evidence.Status), "confirmed_active") &&
		validSourceURL(doc.Evidence.SourceURL)
}

func (p *Pipeline) quarantineInvalidBrief(item scraper.RawItem, invalid *InvalidBriefYAMLError) error {
	if err := p.db.QuarantinePipelineItem(item.SourceID, item.Source, item.Title, invalid.Raw, invalid.Error()); err != nil {
		return fmt.Errorf("persisting malformed brief quarantine: %w", err)
	}
	if err := p.markSeen(item); err != nil {
		return fmt.Errorf("marking quarantined brief seen: %w", err)
	}
	p.logger.Warn("quarantined malformed brief after bounded repair", "source_id", item.SourceID, "source", item.Source, "error", invalid.Err)
	return nil
}

// indexContent stores CVE and title-hash entries in the content_index for
// future cross-source dedup. It indexes CVEs asserted by the item subject
// and populates the vendor+product+class fingerprint plus the normalized
// title (for token-Jaccard sim against future entries).
func (p *Pipeline) indexContent(draftID string, item scraper.RawItem, regexCVEs []string, extraction *ExtractionResult, briefYAML ...string) {
	for _, entry := range contentIndexEntries(draftID, item, regexCVEs, extraction, briefYAML...) {
		if err := p.db.IndexContent(&entry); err != nil {
			p.logger.Warn("failed to index content", "cve", entry.CVEID, "error", err)
		}
	}
}

func sourceURLHashesForIndexedBrief(item scraper.RawItem, briefYAML ...string) []string {
	values := []string{item.URL}
	for _, raw := range briefYAML {
		var fm map[string]any
		if err := yaml.Unmarshal([]byte(raw), &fm); err != nil {
			continue
		}
		values = append(values, yamlStringList(fm["references"])...)
	}
	return SourceURLHashes(values...)
}

func briefProductFingerprint(briefYAML string) string {
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &fm); err != nil {
		return ""
	}
	return ProductFingerprint(yamlStringList(fm["affected_vendors"]), yamlStringList(fm["affected_products"]))
}

// indexLowValueCVEs indexes CVEs from a skipped low-value item so that
// future updates (severity upgrade, exploit disclosure, active exploitation)
// can trigger the dedup update path instead of being silently dropped.
func (p *Pipeline) indexLowValueCVEs(item scraper.RawItem, regexCVEs []string) {
	if len(regexCVEs) == 0 {
		return
	}
	cveCtx := BuildCVEContext(item, nil)
	ctxJSON, _ := json.Marshal(cveCtx)
	titleHash := NormalizeTitleHash(item.Title)
	now := time.Now()

	for _, cve := range regexCVEs {
		if err := p.db.IndexContent(&storage.ContentIndexEntry{
			CVEID:      strings.ToUpper(cve),
			TitleHash:  titleHash,
			DraftID:    "", // no draft was created
			SourceID:   item.SourceID,
			Source:     item.Source,
			CVEContext: string(ctxJSON),
			CreatedAt:  now,
		}); err != nil {
			p.logger.Warn("failed to index low-value CVE", "cve", cve, "error", err)
		}
	}
}

func contentIndexEntries(draftID string, item scraper.RawItem, regexCVEs []string, extraction *ExtractionResult, briefYAML ...string) []storage.ContentIndexEntry {
	cveCtx := BuildCVEContext(item, extraction)
	ctxJSON, _ := json.Marshal(cveCtx)
	titleHash := NormalizeTitleHash(item.Title)
	titleNorm := normalizeTitleTokens(item.Title)
	var fp, productFP string
	if extraction != nil {
		fp = Fingerprint(extraction.AffectedVendors, extraction.AffectedProducts, effectiveVulnClass(item.Title, extraction))
		productFP = ProductFingerprint(extraction.AffectedVendors, extraction.AffectedProducts)
	}
	if productFP == "" && len(briefYAML) > 0 {
		productFP = briefProductFingerprint(briefYAML[0])
	}
	now := time.Now()

	// Only asserted subject CVEs become index keys. Extraction can include a
	// historical CVE mentioned for comparison; indexing it would poison later
	// dedup decisions even if this item was processed correctly.
	allCVEs := make(map[string]bool)
	for _, c := range regexCVEs {
		allCVEs[c] = true
	}
	for _, c := range subjectCVEs(item) {
		allCVEs[c] = true
	}
	for _, c := range confirmedExtractionCVEs(item, extraction) {
		allCVEs[c] = true
	}

	urlHashes := sourceURLHashesForIndexedBrief(item, briefYAML...)
	sourceURLHash := ""
	if len(urlHashes) > 0 {
		sourceURLHash = urlHashes[0]
	}

	base := storage.ContentIndexEntry{
		TitleHash:              titleHash,
		FingerprintHash:        fp,
		ProductFingerprintHash: productFP,
		TitleNorm:              titleNorm,
		DraftID:                draftID,
		SourceID:               item.SourceID,
		Source:                 item.Source,
		CVEContext:             string(ctxJSON),
		ContentHash:            NormalizeContentHash(item.Title, item.Content),
		SourceURLHash:          sourceURLHash,
		SourcePublishedDay:     SourcePublishedDay(item.PublishedAt),
		ClaimKey:               ClaimKey(extraction),
		CreatedAt:              now,
	}

	var entries []storage.ContentIndexEntry
	if len(allCVEs) == 0 {
		entries = append(entries, base)
	} else {
		for cve := range allCVEs {
			entry := base
			entry.CVEID = cve
			entries = append(entries, entry)
		}
	}
	return append(entries, sourceURLAliasEntries(base, urlHashes)...)
}

func sourceURLAliasEntries(base storage.ContentIndexEntry, hashes []string) []storage.ContentIndexEntry {
	if len(hashes) < 2 {
		return nil
	}
	var entries []storage.ContentIndexEntry
	seen := map[string]bool{base.SourceURLHash: true}
	for _, hash := range hashes {
		if hash == "" || seen[hash] {
			continue
		}
		seen[hash] = true
		entry := storage.ContentIndexEntry{
			SourceURLHash:      hash,
			SourcePublishedDay: base.SourcePublishedDay,
			DraftID:            base.DraftID,
			SourceID:           base.SourceID,
			Source:             base.Source,
			CreatedAt:          base.CreatedAt,
		}
		entries = append(entries, entry)
	}
	return entries
}
