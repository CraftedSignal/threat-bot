package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

const mergeRelevanceSystemPrompt = `You are a threat intelligence editor deciding whether fields extracted from a new source belong in an existing threat brief.

Return JSON only. Choose only from the candidate values provided in the prompt. Do not invent, rename, broaden, or normalize values.

Rules:
- Set merge=false when the new source is a separate story that merely mentions the same CVE, vendor, product, or platform.
- Keep CVEs, affected vendors, affected products, affected OS, and IOCs only when they are directly about the same vulnerability, campaign, intrusion set, or detection topic as the target brief.
- Drop brands that are impersonated or used as lures, hosting/distribution platforms, package registries, repositories, runtimes, security tools that are bypassed, and products mentioned only as social or environmental context.
- Drop IOCs for a different malware/campaign, benign infrastructure, article/advisory URLs, repository/API endpoints, package mirrors, and cloud storage/CDN hosts unless the source explicitly identifies the exact value as malicious infrastructure for the same target brief.
- Set reference_relevant=true only when the source itself is useful corroboration for the target brief.
- Set poc_relevant=true only when the source documents a public exploit or proof-of-concept for the same target vulnerability.

Respond with this exact schema:
{"merge":true,"reference_relevant":true,"poc_relevant":false,"cves":[],"affected_vendors":[],"affected_products":[],"affected_os":[],"iocs":[{"type":"","value":"","context":""}],"reason":""}`

const mergeRelevancePrompt = `Target brief:
%s

New source:
Title: %s
Source: %s
URL: %s
Content:
%s

Candidate extracted fields:
%s`

const roundupContentRelevanceSystemPrompt = `You are a threat intelligence analyst cleaning one CVE item before it is inserted into a vendor patch-cycle roundup.

Return JSON only. Choose only from the candidate affected_products and affected_os values provided in the prompt. Do not invent, rename, broaden, or normalize values.

Keep a product or OS only when the source says it is directly affected by the CVE(s) in this item and belongs in this vendor's security update roundup. Drop unrelated brands, games, chat apps, developer platforms, package mirrors, repositories, runtimes, hosting platforms, security tools, and merely incidental operating systems.

Respond with this exact schema:
{"relevant":true,"affected_products":[],"affected_os":[],"reason":""}`

const roundupContentRelevancePrompt = `Vendor roundup: %s

Source:
Title: %s
Source: %s
URL: %s
Content:
%s

Candidate CVEs: %s
Candidate affected products: %s
Candidate affected OS: %s`

type mergeRelevanceLLMResponse struct {
	Merge             *bool          `json:"merge"`
	ReferenceRelevant *bool          `json:"reference_relevant"`
	POCRelevant       *bool          `json:"poc_relevant"`
	CVEs              []string       `json:"cves"`
	AffectedVendors   []string       `json:"affected_vendors"`
	AffectedProducts  []string       `json:"affected_products"`
	AffectedOS        []string       `json:"affected_os"`
	IOCs              []ExtractedIOC `json:"iocs"`
	Reason            string         `json:"reason"`
}

type mergeRelevanceDecision struct {
	Merge             bool
	ReferenceRelevant bool
	POCRelevant       bool
	Reason            string
}

// errMergeNotRelevant marks a merge the relevance check refused because the
// new source is a separate story. Callers process such an item as new
// instead of dropping it.
var errMergeNotRelevant = errors.New("not relevant")

// errMergeRelevanceUnavailable means the checker could not make a complete
// decision. Callers must defer the source instead of merging or rejecting it.
var errMergeRelevanceUnavailable = errors.New("merge relevance unavailable")

// errNonAuthoritativeRoundupSource marks a merge refused by policy: only
// authoritative sources may update a vendor roundup. It is a deterministic
// decision, not a failure; the item gets its own draft.
var errNonAuthoritativeRoundupSource = errors.New("non-authoritative source")

type roundupContentRelevanceResponse struct {
	Relevant         *bool    `json:"relevant"`
	AffectedProducts []string `json:"affected_products"`
	AffectedOS       []string `json:"affected_os"`
	Reason           string   `json:"reason"`
}

func (p *Pipeline) assessDraftMergeRelevance(ctx context.Context, fm map[string]any, extraction *ExtractionResult, item scraper.RawItem) (*ExtractionResult, mergeRelevanceDecision, error) {
	if err := ctx.Err(); err != nil {
		return nil, mergeRelevanceDecision{}, err
	}
	if p.llmClient == nil {
		return nil, mergeRelevanceDecision{}, fmt.Errorf("%w for source %q: no LLM client", errMergeRelevanceUnavailable, item.SourceID)
	}
	if extraction == nil {
		return nil, mergeRelevanceDecision{}, fmt.Errorf("%w for source %q: no extraction", errMergeRelevanceUnavailable, item.SourceID)
	}

	candidateJSON, err := json.Marshal(extraction)
	if err != nil {
		return nil, mergeRelevanceDecision{}, fmt.Errorf("%w for source %q: encode candidates: %w", errMergeRelevanceUnavailable, item.SourceID, err)
	}
	prompt := fmt.Sprintf(
		mergeRelevancePrompt,
		mergeTargetContext(fm),
		item.Title,
		item.Source,
		item.URL,
		smartTruncate(item.Content, 4000),
		string(candidateJSON),
	)

	var resp mergeRelevanceLLMResponse
	err = p.llmClient.GenerateJSON(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "merge_relevance"}), prompt, mergeRelevanceSystemPrompt, &resp)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, mergeRelevanceDecision{}, ctxErr
	}
	if err != nil {
		return nil, mergeRelevanceDecision{}, fmt.Errorf("%w for source %q: LLM call: %w", errMergeRelevanceUnavailable, item.SourceID, err)
	}
	if resp.Merge == nil {
		return nil, mergeRelevanceDecision{}, fmt.Errorf("%w for source %q: missing merge decision", errMergeRelevanceUnavailable, item.SourceID)
	}

	decision := mergeRelevanceDecision{
		Merge:  *resp.Merge,
		Reason: strings.TrimSpace(resp.Reason),
	}
	if !decision.Merge {
		return &ExtractionResult{}, decision, nil
	}
	var missing []string
	if resp.ReferenceRelevant == nil {
		missing = append(missing, "reference_relevant")
	}
	if resp.POCRelevant == nil {
		missing = append(missing, "poc_relevant")
	}
	if len(missing) > 0 {
		return nil, mergeRelevanceDecision{}, fmt.Errorf("%w for source %q: missing %s decision", errMergeRelevanceUnavailable, item.SourceID, strings.Join(missing, ", "))
	}
	decision.ReferenceRelevant = *resp.ReferenceRelevant
	decision.POCRelevant = *resp.POCRelevant

	filtered := &ExtractionResult{
		Tactics:              extraction.Tactics,
		Techniques:           extraction.Techniques,
		CVEs:                 filterSelectedStrings(extraction.CVEs, resp.CVEs, strings.ToUpper),
		ChainedCVEs:          extraction.ChainedCVEs,
		Platforms:            extraction.Platforms,
		AffectedVendors:      filterSelectedStrings(extraction.AffectedVendors, resp.AffectedVendors, strings.ToLower),
		AffectedProducts:     filterSelectedStrings(extraction.AffectedProducts, resp.AffectedProducts, strings.ToLower),
		AffectedOS:           filterSelectedStrings(extraction.AffectedOS, resp.AffectedOS, strings.ToLower),
		IOCs:                 filterSelectedIOCs(extraction.IOCs, resp.IOCs),
		ThreatActor:          extraction.ThreatActor,
		ActiveExploitation:   extraction.ActiveExploitation,
		ExploitationEvidence: extraction.ExploitationEvidence,
		Summary:              extraction.Summary,
		VulnClass:            extraction.VulnClass,
		ClaimAssessment:      extraction.ClaimAssessment,
	}
	return constrainMergeToTargetScope(fm, filtered), decision, nil
}

func (p *Pipeline) filterRoundupContentExtraction(ctx context.Context, vendor string, extraction *ExtractionResult, item scraper.RawItem) (*ExtractionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base := sanitizeRoundupContentExtraction(vendor, extraction, item)
	if base == nil || (len(base.AffectedProducts) == 0 && len(base.AffectedOS) == 0) {
		return base, nil
	}
	if p.llmClient == nil {
		return nil, fmt.Errorf("%w for roundup source %q: no LLM client", errMergeRelevanceUnavailable, item.SourceID)
	}

	prompt := fmt.Sprintf(
		roundupContentRelevancePrompt,
		vendor,
		item.Title,
		item.Source,
		item.URL,
		smartTruncate(item.Content, 4000),
		strings.Join(base.CVEs, ", "),
		strings.Join(base.AffectedProducts, ", "),
		strings.Join(base.AffectedOS, ", "),
	)

	var resp roundupContentRelevanceResponse
	err := p.llmClient.GenerateJSON(llm.WithCallMetadata(ctx, llm.CallMetadata{Stage: "roundup_relevance"}), prompt, roundupContentRelevanceSystemPrompt, &resp)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, fmt.Errorf("%w for roundup source %q: LLM call: %w", errMergeRelevanceUnavailable, item.SourceID, err)
	}
	if resp.Relevant == nil {
		return nil, fmt.Errorf("%w for roundup source %q: missing relevant decision", errMergeRelevanceUnavailable, item.SourceID)
	}
	if !*resp.Relevant {
		base.AffectedProducts = nil
		base.AffectedOS = nil
		return base, nil
	}

	base.AffectedProducts = filterSelectedStrings(base.AffectedProducts, resp.AffectedProducts, strings.ToLower)
	base.AffectedOS = filterSelectedStrings(base.AffectedOS, resp.AffectedOS, strings.ToLower)
	return base, nil
}

func mergeTargetContext(fm map[string]any) string {
	context := map[string]any{
		"title":             strings.TrimSpace(fmt.Sprint(fm["title"])),
		"summary":           strings.TrimSpace(fmt.Sprint(fm["summary"])),
		"tags":              yamlStringList(fm["tags"]),
		"cves":              yamlStringList(fm["cves"]),
		"affected_vendors":  yamlStringList(fm["affected_vendors"]),
		"affected_products": yamlStringList(fm["affected_products"]),
		"affected_os":       yamlStringList(fm["affected_os"]),
		"references":        yamlStringList(fm["references"]),
		"content":           smartTruncate(strings.TrimSpace(fmt.Sprint(fm["content"])), 2000),
	}
	out, err := json.Marshal(context)
	if err != nil {
		return "{}"
	}
	return string(out)
}

func cloneExtraction(extraction *ExtractionResult) *ExtractionResult {
	if extraction == nil {
		return &ExtractionResult{}
	}
	clone := *extraction
	clone.Tactics = append([]string(nil), extraction.Tactics...)
	clone.Techniques = append([]string(nil), extraction.Techniques...)
	clone.CVEs = append([]string(nil), extraction.CVEs...)
	clone.ChainedCVEs = append([][]string(nil), extraction.ChainedCVEs...)
	clone.Platforms = append([]string(nil), extraction.Platforms...)
	clone.AffectedVendors = append([]string(nil), extraction.AffectedVendors...)
	clone.AffectedProducts = append([]string(nil), extraction.AffectedProducts...)
	clone.AffectedOS = append([]string(nil), extraction.AffectedOS...)
	clone.IOCs = append([]ExtractedIOC(nil), extraction.IOCs...)
	return &clone
}

func filterSelectedStrings(candidates, selected []string, norm func(string) string) []string {
	if len(candidates) == 0 || len(selected) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(selected))
	for _, value := range selected {
		key := norm(strings.TrimSpace(value))
		if key != "" {
			wanted[key] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, value := range candidates {
		value = strings.TrimSpace(value)
		key := norm(value)
		if value == "" || key == "" || !wanted[key] || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

// constrainMergeToTargetScope is a deterministic backstop behind the LLM
// relevance filter. Broad survey articles often mention the target product
// alongside adjacent products; those sources are useful references, but their
// unrelated vendors/products/CVEs must not be merged into a narrow brief.
func constrainMergeToTargetScope(fm map[string]any, extraction *ExtractionResult) *ExtractionResult {
	scoped := cloneExtraction(extraction)
	if scoped == nil {
		return &ExtractionResult{}
	}

	targetVendors := yamlStringList(fm["affected_vendors"])
	targetProducts := yamlStringList(fm["affected_products"])
	targetText := strings.Join([]string{
		strings.TrimSpace(fmt.Sprint(fm["title"])),
		strings.TrimSpace(fmt.Sprint(fm["summary"])),
		strings.TrimSpace(fmt.Sprint(fm["content"])),
	}, " ")
	targetCVEs := targetCVESet(fm, targetText)
	// A brief explicitly named for one CVE remains scoped to that CVE even
	// when a later bulletin mentions it alongside unrelated vulnerabilities.
	// This is common with multi-product KEV and patch-cycle announcements.
	if titleCVEs := cveRe.FindAllString(fmt.Sprint(fm["title"]), -1); len(titleCVEs) == 1 {
		if existingCVEs := cveRe.FindAllString(fmt.Sprint(fm["cves"]), -1); len(existingCVEs) == 1 && strings.EqualFold(titleCVEs[0], existingCVEs[0]) {
			var kept []string
			chains := cveChains(scoped.ChainedCVEs)
			for _, cve := range scoped.CVEs {
				if chains.linked(cve, titleCVEs[0]) {
					kept = appendUniqueString(kept, strings.ToUpper(strings.TrimSpace(cve)))
				}
			}
			scoped.CVEs = kept
		}
	}

	contaminatedScope := false
	if len(targetVendors) > 0 && len(scoped.AffectedVendors) > 0 {
		var kept []string
		for _, vendor := range scoped.AffectedVendors {
			if vendorMatchesTarget(vendor, targetVendors) {
				kept = appendUniqueString(kept, strings.TrimSpace(vendor))
			} else {
				contaminatedScope = true
			}
		}
		scoped.AffectedVendors = kept
	}
	if len(targetProducts) > 0 && len(scoped.AffectedProducts) > 0 {
		var kept []string
		for _, product := range scoped.AffectedProducts {
			if productMatchesTarget(product, targetProducts) {
				kept = appendUniqueString(kept, strings.TrimSpace(product))
			} else {
				contaminatedScope = true
			}
		}
		scoped.AffectedProducts = kept
	}
	if contaminatedScope && len(targetCVEs) > 0 && len(scoped.CVEs) > 0 {
		var kept []string
		for _, cve := range scoped.CVEs {
			key := strings.ToUpper(strings.TrimSpace(cve))
			if targetCVEs[key] {
				kept = appendUniqueString(kept, key)
			}
		}
		scoped.CVEs = kept
	}
	return scoped
}

func targetCVESet(fm map[string]any, targetText string) map[string]bool {
	out := map[string]bool{}
	for _, cve := range cveRe.FindAllString(strings.Join([]string{targetText, fmt.Sprint(fm["cves"])}, " "), -1) {
		out[strings.ToUpper(cve)] = true
	}
	return out
}

func vendorMatchesTarget(candidate string, targets []string) bool {
	candidateKey := vendorMergeKey(candidate)
	if candidateKey == "" {
		return false
	}
	for _, target := range targets {
		targetKey := vendorMergeKey(target)
		if targetKey != "" && candidateKey == targetKey {
			return true
		}
	}
	return false
}

func vendorMergeKey(v string) string {
	key := strings.ToLower(strings.TrimSpace(v))
	key = strings.NewReplacer(".", " ", ",", " ", "-", " ", "_", " ").Replace(key)
	key = strings.Join(strings.Fields(key), " ")
	switch key {
	case "amazon web services", "aws":
		return "aws"
	case "google llc":
		return "google"
	}
	return key
}

func productMatchesTarget(candidate string, targets []string) bool {
	candidateTokens := productMergeTokens(candidate)
	if len(candidateTokens) == 0 {
		return false
	}
	for _, target := range targets {
		targetTokens := productMergeTokens(target)
		if len(targetTokens) == 0 {
			continue
		}
		if productTokenOverlap(candidateTokens, targetTokens) >= productOverlapThreshold(candidateTokens, targetTokens) {
			return true
		}
	}
	return false
}

func productOverlapThreshold(a, b map[string]bool) int {
	if len(a) == 1 || len(b) == 1 {
		return 1
	}
	return 2
}

func productTokenOverlap(a, b map[string]bool) int {
	n := 0
	for token := range a {
		if b[token] {
			n++
		}
	}
	return n
}

var productMergeStopwords = map[string]bool{
	"": true, "a": true, "an": true, "and": true, "the": true, "for": true, "of": true,
	"to": true, "in": true, "on": true, "with": true, "by": true, "from": true,
	"version": true, "versions": true, "prior": true, "before": true, "below": true,
	"through": true, "including": true, "earlier": true, "later": true, "less": true,
	"than": true, "or": true, "v": true, "plugin": true, "plugins": true, "extension": true,
	"extensions": true, "toolkit": true, "toolkits": true,
}

func productMergeTokens(product string) map[string]bool {
	s := strings.ToLower(product)
	if idx := strings.Index(s, "("); idx >= 0 {
		s = s[:idx]
	}
	s = strings.NewReplacer(".", " ", ",", " ", "-", " ", "_", " ", "/", " ").Replace(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	out := map[string]bool{}
	for _, token := range fields {
		token = strings.TrimSpace(token)
		if len(token) > 3 && strings.HasSuffix(token, "s") {
			token = strings.TrimSuffix(token, "s")
		}
		if len(token) < 2 || productMergeStopwords[token] {
			continue
		}
		out[token] = true
	}
	return out
}

func appendUniqueString(list []string, value string) []string {
	if value == "" {
		return list
	}
	key := strings.ToLower(value)
	for _, existing := range list {
		if strings.ToLower(existing) == key {
			return list
		}
	}
	return append(list, value)
}

func filterSelectedIOCs(candidates, selected []ExtractedIOC) []ExtractedIOC {
	if len(candidates) == 0 || len(selected) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(selected))
	for _, ioc := range selected {
		key := iocSelectionKey(ioc.Type, ioc.Value)
		if key != "" {
			wanted[key] = true
		}
	}
	var out []ExtractedIOC
	seen := map[string]bool{}
	for _, ioc := range candidates {
		key := iocSelectionKey(ioc.Type, ioc.Value)
		if key == "" || !wanted[key] || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ioc)
	}
	return out
}

func iocSelectionKey(iocType, value string) string {
	iocType = strings.ToLower(strings.TrimSpace(iocType))
	value = strings.ToLower(strings.TrimSpace(value))
	if iocType == "" || value == "" {
		return ""
	}
	return iocType + "|" + value
}
