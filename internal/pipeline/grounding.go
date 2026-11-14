package pipeline

import (
	"context"
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
	llm    llm.Client
	logger *slog.Logger
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

// GroundingResult holds the result of a grounding check. Issues holds only
// the kept issues (unsupported claims quoted verbatim from the brief), each
// formatted as "field: reason (quote)".
type GroundingResult struct {
	Grounded bool     `json:"grounded"`
	Issues   []string `json:"issues"`
}

// Issue kinds the checker can report.
const (
	groundingKindUnsupported = "unsupported_claim"
	groundingKindOmission    = "omission"
)

// groundingIssue is one finding of the structured grounding check.
type groundingIssue struct {
	Kind       string `json:"kind" enum:"unsupported_claim,omission"`
	Field      string `json:"field"`
	BriefQuote string `json:"brief_quote"`
	Reason     string `json:"reason"`
}

// groundingReport is the structured answer of the grounding check.
type groundingReport struct {
	Issues []groundingIssue `json:"issues"`
}

var groundingReportSchema = llm.MustSchemaOf[groundingReport]()

const maxSourceLen = 24000

const groundingSystem = `You are a fact-checking assistant for threat intelligence briefs. Your job is to compare a generated brief against the original source material and report statements in the brief that the source does NOT support.

Report only statements that are present in the brief and that the source does not support or clearly derive. For each, set kind to "unsupported_claim", name the brief field, quote the statement VERBATIM from the brief in brief_quote, and explain in reason why the source does not support it.

Information that the source contains but the brief leaves out is not an unsupported claim: report it with kind "omission" (brief_quote may then be empty). Omissions are advisory only.

If every statement in the brief is supported, return an empty issues array.

Check substantive claims in title, summary, content, CVEs, IOCs, affected assets, techniques, and action evidence.

The severity field is an operational urgency label, not a quoted claim: do not flag it for being absent from the source, but do flag it when it clearly overstates the impact the source describes. Publication IDs, slugs, timestamps, source URLs, QA status, and source/priority assessments are generated metadata, not claims from the article. A recommendation can be a clear operational response to a sourced fact even when the source does not use the same imperative wording. Do not excuse invented attack paths, affected versions, fixed versions, exploitation, or observed impact.

` + exploitationStatesDefinition + ` Flag confirmed_active only when the source does not report exploitation, and not_observed only when the source reports it.`

// normalizeForQuote collapses whitespace and lowercases s so a model quote can
// be compared against the brief regardless of YAML line wrapping.
func normalizeForQuote(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// Check compares the brief YAML against the original source content and
// returns a GroundingResult indicating whether the brief is grounded. Every
// unsupported claim counts; omissions are logged at Info and dropped.
func (g *GroundingChecker) Check(ctx context.Context, sourceTitle, sourceContent, briefYAML string) (*GroundingResult, error) {
	source := sourceTitle + "\n\n" + sourceContent
	if len(source) > maxSourceLen {
		source = truncateUTF8(source, maxSourceLen)
	}

	prompt := fmt.Sprintf(`## Original Source Material
%s

## Generated Brief (YAML)
%s

Report only statements present in the brief that the source does not support, quoting each verbatim in brief_quote. Missing information is kind "omission".`, source, briefYAML)

	var report groundingReport
	if err := g.llm.GenerateStructured(ctx, prompt, groundingSystem, groundingReportSchema, &report); err != nil {
		return nil, fmt.Errorf("grounding check LLM call: %w", err)
	}

	normalizedBrief := normalizeForQuote(briefYAML)
	result := &GroundingResult{Issues: []string{}}
	for _, issue := range report.Issues {
		if issue.Kind == groundingKindOmission {
			// Completeness is not grounding: leaving out a source fact makes no
			// false claim, and Repair (which only removes claims) could never
			// converge on it.
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
const groundingRepairSystemPrompt = "Revise the threat brief to contain only claims supported by the supplied source.\n\n" + sigmaStructureGuidance

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

Unsupported claims:
%s

Return the complete revised brief. Remove unsupported claims, invented attack stages,
affected versions, fixed versions, CVEs, IOCs, and mitigations. Preserve the
identity fields and source reference. A short verified notice is better than a
detailed speculative brief. If exploitation_evidence is present, its status
must be exactly confirmed_active, not_observed, or unknown. Use confirmed_active
only when the source shows observed exploitation.

%s`, source, briefYAML, strings.Join(issues, "\n"), exploitationStatesDefinition)
	var revised revisedBrief
	if err := generateStructured(ctx, g.llm, prompt, groundingRepairSystemPrompt, revisedBriefSchema, &revised, "grounding repair LLM call"); err != nil {
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
	merged := make(map[string]any, len(original)+len(doc))
	for key, value := range original {
		if !repairOwnedKeys[key] {
			merged[key] = value
		}
	}
	for key, value := range doc {
		merged[key] = value
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
	if err := p.db.MarkSeen(item.SourceID, item.Source, item.Title); err != nil {
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
	return item.Content + structuredAdvisoryData(item)
}
