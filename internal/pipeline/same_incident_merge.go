package pipeline

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

const sameIncidentCandidateLimit = 5

var errSameIncidentDecisionUnavailable = errors.New("same-incident decision unavailable")

const sameIncidentSystemPrompt = `You are a threat intelligence editor deciding whether two product briefs describe the same underlying real-world incident or disclosure.

Return JSON only.

Set merge=true only when the briefs cover the same concrete incident, compromise, vulnerability disclosure, or certificate/key event. An upstream incident and a downstream package, trust-store, browser, or vendor remediation advisory count as the same incident when the remediation is directly caused by that incident.

Set merge=false when the briefs merely share a vendor, product family, weakness class, technology, or general topic. When evidence is incomplete or ambiguous, set merge=false.

Set prefer_incoming_narrative=true only when the incoming brief gives the more complete and accurate account of the shared incident. This replaces only the existing title, summary, and content; stable identity and publication fields remain unchanged.

Respond with this exact schema:
{"merge":true,"prefer_incoming_narrative":false,"reason":""}`

const sameIncidentPrompt = `Existing brief:
%s

Incoming brief:
%s

Incoming source: %s
Incoming URL: %s`

type sameIncidentLLMResponse struct {
	Merge                   *bool  `json:"merge"`
	PreferIncomingNarrative *bool  `json:"prefer_incoming_narrative"`
	Reason                  string `json:"reason"`
}

type sameIncidentMatch struct {
	draft          *storage.Draft
	preferIncoming bool
	reason         string
}

type sameIncidentCandidate struct {
	draft    *storage.Draft
	existing map[string]any
	score    int
}

// mergeSameIncidentAssembledProductBrief is the conservative fallback after
// exact product-key merging misses. It considers only recent approved product
// briefs with an overlapping vendor, and requires an explicit LLM decision.
func (p *Pipeline) mergeSameIncidentAssembledProductBrief(ctx context.Context, briefYAML string, item scraper.RawItem, regexCVEs []string, extraction *ExtractionResult) (bool, error) {
	if briefType(briefYAML) != "product" {
		return false, nil
	}

	var incoming map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &incoming); err != nil {
		return false, nil
	}
	incomingVendorNames := yamlStringList(incoming["affected_vendors"])
	incomingVendors := normalizedVendorSet(incomingVendorNames)
	if len(incomingVendors) == 0 {
		return false, nil
	}
	var chains [][]string
	if extraction != nil {
		chains = extraction.ChainedCVEs
	}
	var candidates []sameIncidentCandidate
	var matches []sameIncidentMatch
	decisionUnavailable := false

	for draft, err := range p.db.ApprovedDraftsSince(time.Now().Add(-productMergeWindow)) {
		if err != nil {
			return false, err
		}
		if draft.ID == "" {
			continue
		}
		if briefType(draft.BriefYAML) != "product" {
			continue
		}
		var existing map[string]any
		if err := yaml.Unmarshal([]byte(draft.BriefYAML), &existing); err != nil {
			continue
		}
		if !briefAcceptsBrief(existing, incoming, chains) {
			continue
		}
		existingVendorNames := yamlStringList(existing["affected_vendors"])
		if !vendorSetsOverlap(incomingVendors, normalizedVendorSet(existingVendorNames)) {
			continue
		}
		vendorNames := append(append([]string(nil), incomingVendorNames...), existingVendorNames...)
		score := sharedIncidentTokenCount(
			briefIncidentTokens(existing, vendorNames),
			briefIncidentTokens(incoming, vendorNames),
		)
		if score < 2 {
			continue
		}
		candidates = append(candidates, sameIncidentCandidate{draft: draft, existing: existing, score: score})
	}

	if len(candidates) == 0 {
		return false, nil
	}
	if p.llmClient == nil {
		return false, errSameIncidentDecisionUnavailable
	}
	// Spend the bounded LLM budget on the most textually similar incidents,
	// not merely the newest rows returned by storage. A busy vendor such as
	// Microsoft can have many recent product briefs; lower-ranked candidates
	// should not make a distinct high-ranked incident permanently retry.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].draft.CreatedAt.After(candidates[j].draft.CreatedAt)
	})
	if len(candidates) > sameIncidentCandidateLimit {
		candidates = candidates[:sameIncidentCandidateLimit]
	}

	for _, candidate := range candidates {

		prompt := fmt.Sprintf(
			sameIncidentPrompt,
			mergeTargetContext(candidate.existing),
			mergeTargetContext(incoming),
			item.Source,
			item.URL,
		)
		var decision sameIncidentLLMResponse
		if err := p.llmClient.GenerateJSON(ctx, prompt, sameIncidentSystemPrompt, &decision); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return false, ctxErr
			}
			if p.logger != nil {
				p.logger.Warn("same-incident LLM check failed; deferring item", "source_id", item.SourceID, "candidate_draft", candidate.draft.ID, "error", err)
			}
			decisionUnavailable = true
			continue
		}
		if decision.Merge == nil {
			decisionUnavailable = true
			continue
		}
		if !*decision.Merge {
			continue
		}

		matches = append(matches, sameIncidentMatch{
			draft:          candidate.draft,
			preferIncoming: decision.PreferIncomingNarrative != nil && *decision.PreferIncomingNarrative,
			reason:         strings.TrimSpace(decision.Reason),
		})
	}

	if len(matches) == 0 {
		if decisionUnavailable {
			return false, errSameIncidentDecisionUnavailable
		}
		return false, nil
	}
	if decisionUnavailable {
		return false, errSameIncidentDecisionUnavailable
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].draft.CreatedAt.Before(matches[j].draft.CreatedAt)
	})
	canonical := matches[0]
	// The incoming brief can match several approved briefs, and two of them
	// can cover different CVEs of the incident. Only briefs the canonical one
	// accepts converge into it; the rest keep their own CVE.
	canonicalFM := parseBriefFrontmatter(canonical.draft.BriefYAML)
	converging := []sameIncidentMatch{canonical}
	for _, match := range matches[1:] {
		if briefAcceptsBrief(canonicalFM, parseBriefFrontmatter(match.draft.BriefYAML), nil) {
			converging = append(converging, match)
		}
	}
	matches = converging
	// Merge only after the streaming draft query has closed. SQLite test and
	// production configurations may otherwise need a second connection while
	// the first still owns the iterator.
	if len(matches) > 1 {
		if err := p.convergeSameIncidentDrafts(matches, briefYAML, item); err != nil {
			return false, err
		}
	} else if err := p.mergeAssembledBriefIntoDraftWithNarrative(canonical.draft.ID, briefYAML, item, canonical.preferIncoming); err != nil {
		return false, err
	}
	p.indexContent(canonical.draft.ID, item, regexCVEs, extraction, briefYAML)
	if p.logger != nil {
		p.logger.Info("merged assembled same-incident product brief", "source_id", item.SourceID, "draft_id", canonical.draft.ID, "converged_duplicates", len(matches)-1, "reason", canonical.reason)
	}
	return true, nil
}

func (p *Pipeline) convergeSameIncidentDrafts(matches []sameIncidentMatch, incomingYAML string, item scraper.RawItem) error {
	retirer, ok := p.publisher.(BriefRetirementPublisher)
	if !p.autoPublish || !ok {
		return fmt.Errorf("%w: multiple approved incident briefs require a retirement-capable publisher", errSameIncidentDecisionUnavailable)
	}
	canonical := matches[0]
	type retirement struct {
		draftID string
		briefID string
		slug    string
	}
	retirements := make([]retirement, 0, len(matches)-1)
	for _, match := range matches[1:] {
		var identity struct {
			ID   string `yaml:"id"`
			Slug string `yaml:"slug"`
		}
		if err := yaml.Unmarshal([]byte(match.draft.BriefYAML), &identity); err != nil {
			return fmt.Errorf("parsing duplicate identity %s: %w", match.draft.ID, err)
		}
		identity.ID = strings.TrimSpace(identity.ID)
		identity.Slug = strings.TrimSpace(identity.Slug)
		if identity.ID == "" || identity.Slug == "" {
			return fmt.Errorf("duplicate draft %s has no public ID or slug", match.draft.ID)
		}
		retirements = append(retirements, retirement{draftID: match.draft.ID, briefID: identity.ID, slug: identity.Slug})
	}

	// Fold every already-approved snapshot into the oldest stable identity
	// before applying the newest source. Publisher buffering keeps only the
	// final canonical snapshot.
	for _, match := range matches[1:] {
		duplicateItem := scraper.RawItem{Source: match.draft.Source, Title: "same-incident duplicate convergence"}
		if err := p.mergeAssembledBriefIntoDraftWithNarrative(canonical.draft.ID, match.draft.BriefYAML, duplicateItem, false); err != nil {
			return fmt.Errorf("merging duplicate draft %s: %w", match.draft.ID, err)
		}
	}
	if err := p.mergeAssembledBriefIntoDraftWithNarrative(canonical.draft.ID, incomingYAML, item, canonical.preferIncoming); err != nil {
		return err
	}
	canonicalBriefID := ""
	if id, ok := parseBriefFrontmatter(canonical.draft.BriefYAML)["id"].(string); ok {
		canonicalBriefID = strings.TrimSpace(id)
	}
	for _, retirement := range retirements {
		var err error
		if durable, ok := retirer.(interface {
			RetireBriefForDrafts(id, slug, canonicalID, draftID, canonicalDraftID string) error
		}); ok {
			err = durable.RetireBriefForDrafts(retirement.briefID, retirement.slug, canonicalBriefID, retirement.draftID, canonical.draft.ID)
		} else if favour, ok := retirer.(interface {
			RetireBriefInFavourOf(id, slug, canonicalID string) error
		}); ok {
			err = favour.RetireBriefInFavourOf(retirement.briefID, retirement.slug, canonicalBriefID)
		} else {
			err = retirer.RetireBrief(retirement.briefID, retirement.slug)
		}
		if err != nil {
			return fmt.Errorf("queuing duplicate retirement %s: %w", retirement.draftID, err)
		}
	}
	if err := retirer.Flush(); err != nil {
		return fmt.Errorf("publishing converged incident: %w", err)
	}
	// Flush drops a rejected revision and still returns nil; retiring the
	// duplicates then would lose the incident from the feed.
	if r, ok := retirer.(interface{ RejectedBriefIDs() []string }); ok {
		if slices.Contains(r.RejectedBriefIDs(), canonicalBriefID) {
			return fmt.Errorf("converged incident not published, duplicates kept: publisher rejected revision of %s", canonicalBriefID)
		}
	}
	duplicateIDs := make([]string, 0, len(retirements))
	for _, retirement := range retirements {
		duplicateIDs = append(duplicateIDs, retirement.draftID)
	}
	if err := p.db.ConsolidateApprovedDrafts(canonical.draft.ID, duplicateIDs, "automatically consolidated as the same incident"); err != nil {
		return fmt.Errorf("recording converged incident: %w", err)
	}
	return nil
}

func normalizedVendorSet(vendors []string) map[string]struct{} {
	out := make(map[string]struct{}, len(vendors))
	for _, vendor := range vendors {
		if normalized := normalizeVendorName(vendor); normalized != "" {
			out[normalized] = struct{}{}
		}
	}
	return out
}

func vendorSetsOverlap(a, b map[string]struct{}) bool {
	for vendor := range a {
		if _, ok := b[vendor]; ok {
			return true
		}
	}
	return false
}

var genericIncidentTokens = map[string]bool{
	"advisory": true, "attack": true, "critical": true, "disclosure": true,
	"high": true, "incident": true, "issue": true, "product": true,
	"security": true, "threat": true, "update": true, "vulnerability": true,
}

func briefIncidentTokens(brief map[string]any, vendors []string) map[string]struct{} {
	text := fmt.Sprint(brief["title"]) + " " + fmt.Sprint(brief["summary"])
	tokens := parseTokens(normalizeTitleTokens(text))
	for _, vendor := range vendors {
		for token := range parseTokens(normalizeTitleTokens(vendor)) {
			delete(tokens, token)
		}
	}
	for token := range tokens {
		if genericIncidentTokens[token] {
			delete(tokens, token)
			continue
		}
		// A tiny plural normalization keeps "key"/"keys" and
		// "certificate"/"certificates" comparable without broad stemming.
		if len(token) > 3 && strings.HasSuffix(token, "s") && !strings.HasSuffix(token, "ss") {
			delete(tokens, token)
			tokens[strings.TrimSuffix(token, "s")] = struct{}{}
		}
	}
	return tokens
}

func sharedIncidentTokenCount(a, b map[string]struct{}) int {
	count := 0
	for token := range a {
		if _, ok := b[token]; ok {
			count++
		}
	}
	return count
}
