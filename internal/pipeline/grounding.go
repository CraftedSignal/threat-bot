package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// GroundingChecker uses an LLM to verify that a generated brief is grounded
// in the original source material — i.e., it doesn't contain hallucinated
// claims, IOCs, CVEs, or technical details.
type GroundingChecker struct {
	llm       llm.Client
	repairLLM llm.Client
	logger    *slog.Logger
}

// WithRepairClient selects an optional repair-only client. Fact checks keep
// using the primary client and the repair still requires a subsequent check.
func (g *GroundingChecker) WithRepairClient(client llm.Client) *GroundingChecker {
	g.repairLLM = client
	return g
}

// NewGroundingChecker creates a new GroundingChecker.
func NewGroundingChecker(client llm.Client) *GroundingChecker {
	return &GroundingChecker{llm: client, logger: slog.Default()}
}

// WithLogger sets the logger the checker audits dropped issues on.
func (g *GroundingChecker) WithLogger(logger *slog.Logger) *GroundingChecker {
	if logger != nil {
		g.logger = logger
	}
	return g
}

// GroundingResult holds factual blockers: unsupported claims or material,
// source-quoted omissions from a complete brief.
type GroundingResult struct {
	Grounded bool     `json:"grounded"`
	Issues   []string `json:"issues"`
}

// Issue kinds the checker can report.
const (
	groundingKindUnsupported      = "unsupported_claim"
	groundingKindOmission         = "omission"
	groundingKindMaterialOmission = "material_omission"
)

// groundingIssue is one finding of the structured grounding check.
type groundingIssue struct {
	Kind             string `json:"kind" enum:"unsupported_claim,omission,material_omission"`
	Field            string `json:"field"`
	BriefQuote       string `json:"brief_quote"`
	Reason           string `json:"reason"`
	Subject          string `json:"subject" desc:"For material_omission, copy one eligible completeness subject exactly. Empty for other kinds."`
	SourceEvidenceID string `json:"source_evidence_id" desc:"For material_omission select a scoped source evidence ID whose subjects include the exact selected subject; its quote is resolved locally. Empty for other kinds."`
	SourceQuote      string `json:"source_quote" desc:"For material_omission, a verbatim source passage including its subject and missing fact, or the complete text of a CVE/product-scoped primary evidence field. Empty for other kinds."`
}

// groundingReport is the structured answer of the grounding check.
type groundingReport struct {
	Issues []groundingIssue `json:"issues"`
}

var groundingReportSchema = llm.MustSchemaOf[groundingReport]()

type claimGroundingIssue struct {
	Kind       string `json:"kind" enum:"unsupported_claim"`
	Field      string `json:"field"`
	BriefQuote string `json:"brief_quote"`
	Reason     string `json:"reason"`
}

var claimGroundingReportSchema = llm.MustSchemaOf[struct {
	Issues []claimGroundingIssue `json:"issues"`
}]()

const maxSourceLen = 24000

// Routing ratings are generated decisions, not factual quotations. Only
// absence-of-rating findings are ignored; impact and exploitation disputes
// remain blocking even when the field named by the checker is severity.
func nonFactualRatingIssue(issue groundingIssue, brief string) bool {
	field := strings.ToLower(strings.TrimSpace(issue.Field))
	rating := field == "severity" || field == "severity_basis" || (strings.HasPrefix(field, "rules") && strings.HasSuffix(field, "level"))
	if !rating {
		return false
	}
	reason := strings.ToLower(issue.Reason)
	for _, factual := range []string{"overstat", "impact", "exploit", "execution", "compromise", "privilege", "destruct"} {
		if strings.Contains(reason, factual) {
			return false
		}
	}
	for _, absent := range []string{"not stated", "not explicitly", "does not specify", "does not state", "doesn't specify", "not present", "absent", "no severity", "no rating", "not provided", "does not provide"} {
		if strings.Contains(reason, absent) {
			return true
		}
	}
	return false
}

const groundingFactSystem = `You are a fact-checking assistant for threat intelligence briefs. Compare the supplied claims with the source for factual accuracy.

Report only statements that are present in the brief and that the source does not support or clearly derive. For each, set kind to "unsupported_claim", name the brief field, quote the statement VERBATIM from the brief in brief_quote, and explain in reason why the source does not support it.

Check substantive claims in title, summary, content, CVEs, IOCs, affected assets, techniques, and action evidence.

The severity field is an operational urgency label, not a quoted claim: do not flag it for being absent from the source, but do flag it when it clearly overstates the impact the source describes. Publication IDs, slugs, timestamps, source URLs, QA status, and source/priority assessments are generated metadata, not claims from the article. A recommendation can be a clear operational response to a sourced fact even when the source does not use the same imperative wording. Do not excuse invented attack paths, affected versions, fixed versions, exploitation, or observed impact.

` + exploitationStatesDefinition + ` Flag confirmed_active only when the source does not report attacks actually exploiting the vulnerability or attempts to exploit it. Flag not_observed only when the source reports attacks actually exploiting the vulnerability or attempts to exploit it. A vendor saying it is not aware of malicious exploitation supports not_observed within that vendor's stated scope; it does not assert that exploitation is impossible or that global monitoring found none. Do not flag a source-supported exploitation status merely because the source uses different wording.`

const groundingSystem = groundingFactSystem + `

Also check material completeness of this entire brief. If an explicit source fact is missing and changes applicability or the defender response, report kind "material_omission". This includes affected products/version ranges, fixed releases or remediation, authentication/privilege requirements, required dependencies or user interaction, and concrete impact limits. Set subject to the target product name or CVE, source_quote to a VERBATIM source passage containing that subject and the missing fact, and field to the field needing repair. Include identifying context, not a bare version or prerequisite detached from its product. Do not borrow a neighboring product's version, role, fix or CVE. Do not report a fact already covered in another brief field as omitted. Brief_quote may be empty for omissions.

Use an exact subject from the eligible completeness subjects supplied with the brief. Prefer source_evidence_id from the scoped source evidence catalogue, selecting only a reference whose subjects include that subject; leave source_quote empty when selecting an ID because the server resolves its text locally. Never invent IDs or use an unrelated target reference. For structured primary CVE evidence, source_quote may instead be the complete decoded text field of one fact whose CVE and product match the brief; its explicit record scope supplies the identity. Do not splice fields or quote a detached version fragment. A record-wide fact without a product must name the brief's product in its text.

Missing minor background, credits, or incidental details can be kind "omission" and are advisory. Unspecified source facts are gaps, not facts to invent: do not demand a fixed release, role, impact, exploit chain, detector or IOC that the supplied source does not establish. Use empty subject/source_quote for unsupported claims and minor omissions.

Return an empty issues array only when statements are supported and no material source fact is omitted.`

const groundingClaimsSystem = groundingFactSystem + `

This is a partial incoming claim set or an added hunt lead, not an entire brief. Check only statements present. Do not demand omitted applicability, remediation or other full-brief fields. Report only unsupported_claim findings. Return an empty issues array when every supplied claim is supported.`

// normalizeForQuote collapses whitespace and lowercases s so a model quote can
// be compared against the brief regardless of YAML line wrapping.
func normalizeForQuote(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// A material omission may request adding a claim. Unlike an unsupported-claim
// report, it therefore needs verifiable source text and an existing target.
// Malformed or cross-target findings defer through the normal bounded retry
// path rather than being trusted as repair instructions or silently accepted.
func validateMaterialOmission(issue groundingIssue, source, brief string) error {
	source = materialOmissionSource(source)
	quote, subject := normalizeForQuote(issue.SourceQuote), normalizeForQuote(issue.Subject)
	if quote == "" || subject == "" || len(issue.SourceQuote) > 4000 {
		return fmt.Errorf("material omission requires a verbatim source quote with its target subject")
	}
	doc := parseBriefFrontmatter(brief)
	ids := groundingTargetCVEs(doc)
	matched := false
	if id := normalizeCVEID(issue.Subject); id != "" {
		matched = ids[id]
	} else {
		for _, product := range yamlStringList(doc["affected_products"]) {
			if scopeProductKey(product) == scopeProductKey(issue.Subject) {
				matched = true
				break
			}
		}
	}
	if !matched {
		return fmt.Errorf("material omission subject does not match the brief target")
	}
	// Structured primary evidence carries identity/product outside its text
	// value. Bind a complete verbatim field to that explicit scope rather than
	// requiring the CVE identifier to be repeated inside an ordinary sentence.
	scoped := materialQuoteInScopedFact(issue, source, doc)
	var quotedFact cnaSourceFact
	structuredQuote := json.Unmarshal([]byte(issue.SourceQuote), &quotedFact) == nil && quotedFact.CVEID != ""
	mentionsSubject := strings.Contains(quote, subject) || productNameLocation(issue.SourceQuote, issue.Subject) != nil
	// A complete structured record carries a CVE even when its product is a
	// neighbor. Its metadata must not bypass the explicit product binding.
	if !scoped && (structuredQuote || !materialQuoteInProse(issue.SourceQuote, source) || !mentionsSubject) {
		return fmt.Errorf("material omission requires a verbatim source quote with its target subject")
	}
	for _, id := range sourceCVEPattern.FindAllString(issue.SourceQuote, -1) {
		if !ids[strings.ToUpper(id)] {
			return fmt.Errorf("material omission quote belongs to another CVE")
		}
	}
	return nil
}

// The generated primary supplement mixes retained CNA facts with provenance
// and coverage bookkeeping. Only its structured facts can establish a material
// source omission; a registry URL or an unknown-coverage notice cannot supply a
// missing fixed release. Keep the original article intact, including genuine
// vendor statements about unknown or unavailable remediation.
func materialOmissionSource(source string) string {
	if !strings.Contains(source, "Verified primary CVE evidence.") {
		return source
	}
	var lines []string
	primary := false
	for _, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(line, "Verified primary CVE evidence.") {
			primary = true
			continue
		}
		if primary && line == "Original source:" {
			primary = false
		}
		if primary {
			var fact cnaSourceFact
			if json.Unmarshal([]byte(line), &fact) != nil || fact.CVEID == "" {
				continue
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// Structured record bodies cannot serve as ordinary prose: that would bypass
// their CVE/product binding or accept a partial decoded field. Keep records as
// attribution boundaries so excluding them cannot splice disconnected prose.
func materialQuoteInProse(quote, source string) bool {
	quote = normalizeForQuote(quote)
	var prose strings.Builder
	for _, line := range strings.Split(source, "\n") {
		var fact cnaSourceFact
		if json.Unmarshal([]byte(line), &fact) == nil && fact.CVEID != "" {
			if strings.Contains(normalizeForQuote(prose.String()), quote) {
				return true
			}
			prose.Reset()
			continue
		}
		prose.WriteString(line)
		prose.WriteByte('\n')
	}
	return strings.Contains(normalizeForQuote(prose.String()), quote)
}

func materialQuoteInScopedFact(issue groundingIssue, source string, doc map[string]any) bool {
	ids := groundingTargetCVEs(doc)
	subjectID := normalizeCVEID(issue.Subject)
	products := yamlStringList(doc["affected_products"])
	for _, line := range strings.Split(source, "\n") {
		var fact cnaSourceFact
		if json.Unmarshal([]byte(line), &fact) != nil || !ids[fact.CVEID] {
			continue
		}
		quote := normalizeForQuote(issue.SourceQuote)
		if normalizeForQuote(fact.Text) != quote && normalizeForQuote(line) != quote {
			continue
		}
		switch fact.Kind {
		case "affected", "solution", "workaround", "metric", "description":
		default:
			continue
		}
		if subjectID != "" {
			if fact.CVEID != subjectID {
				continue
			}
		} else if scopeProductKey(fact.Product) != scopeProductKey(issue.Subject) {
			continue
		}
		if len(products) > 0 {
			productMatch := false
			for _, product := range products {
				if fact.Product != "" && scopeProductKey(fact.Product) == scopeProductKey(product) || fact.Product == "" && productNameLocation(fact.Text, product) != nil {
					productMatch = true
				}
			}
			if !productMatch {
				continue
			}
		}
		return true
	}
	return false
}

// Check compares the brief YAML against the original source content and
// returns a GroundingResult indicating whether the brief is grounded. Every
// unsupported claim and validated material omission counts.
func (g *GroundingChecker) Check(ctx context.Context, sourceTitle, sourceContent, briefYAML string) (*GroundingResult, error) {
	return g.check(ctx, sourceTitle, sourceContent, briefYAML, true)
}

func (g *GroundingChecker) checkClaims(ctx context.Context, sourceTitle, sourceContent, briefYAML string) (*GroundingResult, error) {
	return g.check(ctx, sourceTitle, sourceContent, briefYAML, false)
}

func (g *GroundingChecker) check(ctx context.Context, sourceTitle, sourceContent, briefYAML string, completeness bool) (*GroundingResult, error) {
	source := sourceTitle + "\n\n" + sourceContent
	if len(source) > maxSourceLen {
		source = truncateUTF8(source, maxSourceLen)
	}

	prompt := fmt.Sprintf(`## Original Source Material
%s

## Generated Brief (YAML)
%s

Assess the supplied YAML according to the system instructions, with verbatim quotes for factual blockers.`, source, briefYAML)
	system := groundingClaimsSystem
	schema := claimGroundingReportSchema
	var refs []scopedGroundingEvidence
	if completeness {
		system = groundingSystem
		schema = llm.MustSchemaOf[groundingReport]()
		refs = scopedOmissionEvidence(source, briefYAML)
		// Mixed-kind findings need honest empty subjects and reference IDs.
		// Validate material targets and references locally, without empty enums.
		subjects, _ := json.Marshal(materialOmissionSubjects(briefYAML))
		prompt += "\n\nEligible completeness subjects (copy exactly for material_omission):\n" + string(subjects)
		prompt += omissionEvidencePrompt(refs)
	}

	var report groundingReport
	if err := g.llm.GenerateStructured(ctx, prompt, system, schema, &report); err != nil {
		return nil, fmt.Errorf("grounding check LLM call: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if completeness {
		if err := g.repairMaterialOmissionEvidence(ctx, source, briefYAML, &report, refs); err != nil {
			var contract *omissionEvidenceContractError
			if errors.As(err, &contract) {
				contract.Digest = groundingRequestDigest(sourceTitle, sourceContent, briefYAML, prompt, system, schema)
			}
			return nil, fmt.Errorf("grounding completeness evidence: %w", err)
		}
	}

	normalizedBrief := normalizeForQuote(briefYAML)
	result := &GroundingResult{Issues: identityGroundingIssues(sourceTitle+"\n"+sourceContent, briefYAML)}
	for _, issue := range report.Issues {
		if !completeness && issue.Kind != groundingKindUnsupported {
			return nil, fmt.Errorf("partial grounding returned an invalid issue kind %q", issue.Kind)
		}
		if issue.Kind == groundingKindMaterialOmission {
			if err := validateMaterialOmission(issue, source, briefYAML); err != nil {
				return nil, fmt.Errorf("grounding completeness evidence: %w", err)
			}
			result.Issues = append(result.Issues, fmt.Sprintf("%s: missing source-supported fact for %s: %s (source: %s)", issue.Field, issue.Subject, issue.Reason, issue.SourceQuote))
			continue
		}
		if nonFactualRatingIssue(issue, briefYAML) {
			g.logger.Info("grounding rating issue dropped", "field", issue.Field, "reason", issue.Reason)
			continue
		}
		if issue.Kind == groundingKindOmission {
			// Minor omissions do not change applicability or defender response.
			g.logger.Info("grounding issue dropped", "kind", issue.Kind, "field", issue.Field, "reason", issue.Reason)
			continue
		}
		// Anything else is a claim the source does not support. Keep it even
		// when the quote does not match the brief: the model sometimes quotes
		// the source instead, and dropping those would publish the claim.
		quote := normalizeForQuote(issue.BriefQuote)
		if quote != "" && strings.Contains(normalizedBrief, quote) {
			result.Issues = append(result.Issues, fmt.Sprintf("%s: %s (%s)", issue.Field, issue.Reason, issue.BriefQuote))
		} else {
			result.Issues = append(result.Issues, fmt.Sprintf("%s: %s", issue.Field, issue.Reason))
		}
	}
	result.Grounded = len(result.Issues) == 0
	return result, nil
}

// groundingRepairSystemPrompt is the repair call's system prompt. Rules in the
// revised brief use the same structured Sigma form as the original answer.
const groundingRepairSystemPrompt = "Revise the threat brief to contain only claims supported by the supplied source and restore missing source-supported facts that change applicability or remediation. Do not invent unspecified versions, roles, dependencies, impact, exploitation or detectors; preserve canonical identity and explicit uncertainty.\n\n" + sigmaStructureGuidance

// Repair asks the model to remove unsupported claims once, using the same
// source material the checker saw. The caller must validate and re-check the
// result before it can be saved or published.
func (g *GroundingChecker) Repair(ctx context.Context, sourceTitle, sourceContent, briefYAML string, issues []string) (string, error) {
	source := sourceTitle + "\n\n" + sourceContent
	if len(source) > maxSourceLen {
		source = truncateUTF8(source, maxSourceLen)
	}
	prompt := fmt.Sprintf(`Original source:
%s

Rejected YAML:
%s

Factual blockers (unsupported claims and missing source-supported facts):
%s

Return the complete revised brief. Restore material facts from their quoted source
passages, with the correct product/CVE scope, even when the revision removes other
claims. Include supported affected ranges, fixed releases/remediation, privileges,
dependencies, interaction and impact limits; explicitly retain unknowns when the
source does not specify them. Remove unsupported claims, invented attack stages,
affected versions, fixed versions, CVEs, IOCs, and mitigations. Preserve the
identity fields and source reference. A short verified notice is better than a
detailed speculative brief. If exploitation_evidence is present, its status
must be exactly confirmed_active, not_observed, or unknown. Use confirmed_active
only when the source shows exploitation or exploitation attempts in the wild.

%s`, source, briefYAML, strings.Join(issues, "\n"), exploitationStatesDefinition)
	var revised revisedBrief
	client := g.repairLLM
	if client == nil {
		client = g.llm
	}
	if err := generateStructured(ctx, client, prompt, groundingRepairSystemPrompt, revisedBriefSchema, &revised, "grounding repair LLM call"); err != nil {
		return "", err
	}
	var original map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &original); err != nil {
		return "", fmt.Errorf("grounding repair original YAML: %w", err)
	}
	merged, err := mergeGroundingRepair(original, revised)
	if err != nil {
		return "", err
	}
	encoded, err := yaml.Marshal(merged)
	if err != nil {
		return "", fmt.Errorf("grounding repair re-encoding YAML: %w", err)
	}
	return string(encoded), nil
}

// repairOwnedKeys are the top-level fields the repair step rewrites: everything
// the response schema carries, plus the structured CVE list and the exploited
// flag, which follow from the rewritten text and the exploitation status.
var repairOwnedKeys = func() map[string]bool {
	keys := map[string]bool{"cves": true, "exploited": true}
	for name := range revisedBriefSchema.Properties {
		keys[name] = true
	}
	return keys
}()

// mergeGroundingRepair applies the model's revision to the already-validated
// original. The model owns every field of the schema (references included), so
// a field it left out is a claim it deleted and is dropped. Fields the
// pipeline wrote (source, revision history, has_poc, ...) are carried over
// from the original untouched, as are the identity fields: losing published_at
// or the id can poison the publisher's entire pending batch at Flush. Two
// pipeline-owned claims follow the revision instead of surviving it unchanged:
// a CVE entry is kept, with its enrichment, only while its exact ID is still
// mentioned in the revised brief's text, and exploitation evidence is
// restored from the original or, when the model supplies confirmed_active
// with a valid source URL, accepted; any other confirmed claim is downgraded
// to unknown.
func mergeGroundingRepair(original map[string]any, revised revisedBrief) (map[string]any, error) {
	doc, err := revised.document()
	if err != nil {
		return nil, err
	}
	merged := make(map[string]any, len(original))
	for key, value := range original {
		if !repairOwnedKeys[key] {
			merged[key] = value
		}
	}
	for key, value := range doc {
		merged[key] = value
	}
	// A checker-rejected scope is not eligible for automatic re-injection
	// after repair. The revised product can still carry a corrected scope.
	blocked := yamlStringList(original["grounding_rejected_scope"])
	for _, before := range yamlStringList(original["affected_products"]) {
		preserved := false
		for _, after := range yamlStringList(doc["affected_products"]) {
			if before == after {
				preserved = true
			}
		}
		if !preserved {
			blocked = appendUniqueString(blocked, scopeProductKey(before))
		}
	}
	if len(blocked) > 0 {
		merged["grounding_rejected_scope"] = blocked
	}
	// "rumour" is assigned by the pipeline, not offered by the schema's severity
	// enum, so a rumour must not lose it to the label the model had to pick.
	if severity, _ := original["severity"].(string); strings.EqualFold(severity, "rumour") {
		merged["severity"] = original["severity"]
	}
	for _, key := range []string{"id", "slug"} {
		if value, ok := original[key]; ok {
			merged[key] = value
		} else {
			delete(merged, key)
		}
	}

	// Only the brief's text counts: id and slug are echoed from the original
	// and would keep a CVE alive that the revision removed.
	text := maps.Clone(doc)
	delete(text, "id")
	delete(text, "slug")
	rendered, err := yaml.Marshal(text)
	if err != nil {
		return nil, fmt.Errorf("grounding repair re-encoding YAML: %w", err)
	}
	mentioned := make(map[string]bool)
	for _, id := range mentionedCVERe.FindAllString(string(rendered), -1) {
		mentioned[strings.ToUpper(id)] = true
	}
	var cves []any
	if list, ok := original["cves"].([]any); ok {
		for _, entry := range list {
			if id := cveEntryID(entry); id != "" && mentioned[strings.ToUpper(id)] {
				cves = append(cves, entry)
			}
		}
	}
	if len(cves) > 0 {
		merged["cves"] = cves
	} else {
		delete(merged, "cves")
	}

	delete(merged, "exploitation_evidence")
	if revised.ExploitationEvidence != nil {
		if evidence, ok := repairedExploitationEvidence(original, *revised.ExploitationEvidence); ok {
			merged["exploitation_evidence"] = evidence
		}
	}
	return merged, nil
}

// cveEntryID returns the ID of a structured CVE entry, which is either a map
// or, for briefs written before the structured form, a bare ID string.
func cveEntryID(entry any) string {
	switch e := entry.(type) {
	case string:
		return strings.TrimSpace(e)
	case map[string]any:
		id, _ := e["id"].(string)
		return strings.TrimSpace(id)
	}
	return ""
}

// repairedExploitationEvidence returns the exploitation evidence a revised
// brief carries. confirmed_active survives only when it is attributed: when the
// validated original carried the same attested state that state is restored
// as it was, and otherwise the revision must bring its own valid source_url.
// A confirmed claim without either is downgraded to unknown so validation can
// continue without asserting exploitation. observed_at is normalised by
// parseObservedAt; one that cannot be read is dropped, and validation then
// falls back to the brief's published_at, as it does for a missing one.
func repairedExploitationEvidence(original map[string]any, revised generatedExploitation) (map[string]any, bool) {
	status := strings.ToLower(strings.TrimSpace(revised.Status))
	if status == "" {
		return nil, false
	}
	evidence := map[string]any{"status": status}
	if confidence := strings.ToLower(strings.TrimSpace(revised.Confidence)); confidence != "" {
		evidence["confidence"] = confidence
	}
	if observed, err := parseObservedAt(revised.ObservedAt); err == nil {
		evidence["observed_at"] = observed
	}
	if sourceURL := strings.TrimSpace(revised.SourceURL); sourceURL != "" {
		evidence["source_url"] = sourceURL
	}
	if status == "confirmed_active" {
		if previous, ok := asStringMap(original["exploitation_evidence"]); ok &&
			strings.EqualFold(strings.TrimSpace(fmt.Sprint(previous["status"])), status) &&
			validSourceURL(fmt.Sprint(previous["source_url"])) {
			return maps.Clone(previous), true
		}
		if !validSourceURL(revised.SourceURL) {
			return map[string]any{"status": "unknown"}, true
		}
		return evidence, true
	}
	if status != "not_observed" {
		status = "unknown"
	}
	return map[string]any{"status": status}, true
}

// defaultMaxGroundingAttempts bounds how often an item whose brief keeps
// failing the grounding check is retried before it is quarantined.
const defaultMaxGroundingAttempts = 5

func groundingAttemptLimit(configured int) int {
	if configured > 0 {
		return configured
	}
	return defaultMaxGroundingAttempts
}

// UngroundedBriefError reports an item whose brief still failed grounding
// after the configured number of attempts.
type UngroundedBriefError struct {
	Attempts int
	Issues   []string
}

func (e *UngroundedBriefError) Error() string {
	return fmt.Sprintf("ungrounded after %d attempts: %s", e.Attempts, strings.Join(e.Issues, "; "))
}

// quarantineUngrounded records the terminal failure through the same durable
// quarantine as malformed briefs and marks the item seen so it stops retrying.
func (p *Pipeline) quarantineUngrounded(item scraper.RawItem, briefYAML string, cause *UngroundedBriefError) error {
	if err := p.db.QuarantinePipelineItem(item.SourceID, item.Source, item.Title, briefYAML, cause.Error()); err != nil {
		return fmt.Errorf("persisting ungrounded brief quarantine: %w", err)
	}
	if err := p.markSeen(item); err != nil {
		return fmt.Errorf("marking quarantined brief seen: %w", err)
	}
	p.logger.Warn("quarantined ungrounded brief", "source_id", item.SourceID, "source", item.Source, "attempts", cause.Attempts, "issues", cause.Issues)
	return nil
}

// pipelineOwnedTopLevelFields are brief fields the pipeline derives itself:
// has_poc and poc_references from the source and exploit trackers, exploited
// from the exploitation evidence (which stays visible when it asserts a state).
var pipelineOwnedTopLevelFields = []string{"has_poc", "poc_references", "exploited"}

// groundingView returns the brief as the grounding checker should judge it:
// without the fields the pipeline writes itself. Those are the item's own URL
// in references, every CVE enrichment field (CVSS, EPSS, KEV: the validator's
// placeholders before enrichment, authoritative values after it), the
// pipeline-derived has_poc, poc_references and exploited, and an exploitation
// state of unknown, which asserts nothing. Enrichment is a source of claims,
// not something to ground against the article. The severity label stays
// visible: the pipeline only ever lowers it, so an LLM label can be published.
// Every LLM-authored claim is left untouched. If the YAML cannot be parsed the
// brief is returned unchanged.
func groundingView(briefYAML, itemURL string) string {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil || doc == nil {
		return briefYAML
	}

	if refs, ok := doc["references"].([]any); ok {
		own := strings.TrimSpace(itemURL)
		kept := make([]any, 0, len(refs))
		for _, ref := range refs {
			if s, isStr := ref.(string); isStr && own != "" && strings.TrimSpace(s) == own {
				continue
			}
			kept = append(kept, ref)
		}
		if len(kept) == 0 {
			delete(doc, "references")
		} else {
			doc["references"] = kept
		}
	}

	if cves, ok := doc["cves"].([]any); ok {
		for _, entry := range cves {
			cve, isMap := entry.(map[string]any)
			if !isMap {
				continue
			}
			for key := range cve {
				if key != "id" && cveEnrichmentOwnedFields[key] {
					delete(cve, key)
				}
			}
		}
	}

	for _, key := range pipelineOwnedTopLevelFields {
		delete(doc, key)
	}
	if basis, ok := asStringMap(doc["severity_basis"]); ok {
		switch fmt.Sprint(basis["kind"]) {
		case "operational_policy", "source_cvss", "source_severity":
			delete(doc, "severity")
		}
		delete(doc, "severity_basis")
	}
	delete(doc, "cve_verification")
	delete(doc, "grounding_rejected_scope")
	if rules, ok := doc["rules"].([]any); ok {
		for _, raw := range rules {
			if rule, ok := asStringMap(raw); ok {
				delete(rule, "level")
			}
		}
	}
	if evidence, ok := doc["exploitation_evidence"].(map[string]any); ok &&
		strings.EqualFold(strings.TrimSpace(fmt.Sprint(evidence["status"])), "unknown") {
		delete(doc, "exploitation_evidence")
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

// groundingSource is the material the checker and repair step treat as the
// source: the item text plus the structured advisory facts the generation
// prompt told the model to copy, so those facts can never be flagged.
func groundingSource(item scraper.RawItem) string {
	source := item.URL + "\n" + item.Content + structuredAdvisoryData(item)
	// These values are supplied by dedicated advisory scrapers, not the
	// extraction model. Generic webpage metadata is not trusted authority.
	if item.Source == "nvd" || item.Source == "ghsa" || item.Source == "cisa-kev" {
		keys := []string{"cve_id", "cve", "cves"}
		// NVD/GHSA ranges already appear in the shared advisory data above.
		if item.Source == "cisa-kev" {
			keys = append(keys, "affected_ranges")
		}
		for _, key := range keys {
			if value := item.Metadata[key]; value != "" {
				source += "\n" + key + ": " + value
			}
		}
	}
	return source
}
