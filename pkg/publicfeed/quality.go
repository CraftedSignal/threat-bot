package publicfeed

import (
	"html"
	"regexp"
	"strings"
	"unicode"
)

// ContentQualityInput is shared by internal publication and public Markdown
// validation. These checks assess readiness; source grounding checks accuracy.
type ContentQualityInput struct {
	Summary, Content string
	HasCVE           bool
	ActionPlan       map[string]any
}

// ContentQualityIssues rejects empty or operationally incomplete text without
// imposing a length target or demanding details absent from the source.
func ContentQualityIssues(input ContentQualityInput) []string {
	var issues []string
	content := input.Content
	if !substantiveMarkdown(content) {
		issues = append(issues, "content must contain substantive brief text")
	} else if normalizeText(plainText(prose(content))) == normalizeText(plainText(input.Summary)) {
		issues = append(issues, "content repeats the summary without additional analysis or guidance")
	}
	if input.HasCVE {
		if !hasResponse(content, input.ActionPlan) {
			issues = append(issues, "CVE brief requires a substantive recommendation or evidence-backed action plan beyond inventory or verifying usage; include remediation or a concrete step to confirm it")
		}
		if impact := markdownSection(content, map[string]bool{"impact": true, "impact & exploitation status": true}); scoreOnlyImpact(impact) {
			issues = append(issues, "impact section only reports a score or severity; explain source-supported consequences or state that impact details are unavailable")
		}
	}
	return issues
}

var headingPattern = regexp.MustCompile(`^(#{1,6})\s+(.+?)\s*#*\s*$`)
var commentPattern = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)`)
var linkDefinitionPattern = regexp.MustCompile(`^\s*\[[^\]]+\]:\s*\S+`)
var inlineLinkPattern = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
var htmlTagPattern = regexp.MustCompile(`</?[A-Za-z][^>\n]*>`)
var listMarkerPattern = regexp.MustCompile(`(?m)^\s*(?:[-*+]|\d+[.)])\s+(?:\[[ xX]\]\s+)?`)

func normalizeText(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func prose(text string) string {
	var lines []string
	fence := ""
	for _, line := range strings.Split(commentPattern.ReplaceAllString(text, ""), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			marker := line[:3]
			switch fence {
			case "":
				fence = marker
			case marker:
				fence = ""
			}
			continue
		}
		if fence != "" || strings.Trim(line, "#*_~-+> \t") == "" || headingPattern.MatchString(line) || linkDefinitionPattern.MatchString(line) {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func substantiveMarkdown(text string) bool {
	for _, line := range strings.Split(prose(text), "\n") {
		if MeaningfulText(line) {
			return true
		}
	}
	return false
}

// MeaningfulText and HasTelemetry keep detection coverage checks consistent
// with the same placeholder/formatting rules used by the publication contract.
func MeaningfulText(value any) bool {
	text, _ := value.(string)
	text = plainText(text)
	switch strings.ToLower(text) {
	case "", "n/a", "na", "none", "null", "unknown", "unspecified", "tbd", "todo", "not applicable":
		return false
	}
	return strings.IndexFunc(text, unicode.IsLetter) >= 0
}

func HasTelemetry(value any) bool {
	switch names := value.(type) {
	case []any:
		for _, name := range names {
			if MeaningfulText(name) {
				return true
			}
		}
	case []string:
		for _, name := range names {
			if MeaningfulText(name) {
				return true
			}
		}
	}
	return false
}

func plainText(text string) string {
	text = html.UnescapeString(htmlTagPattern.ReplaceAllString(text, ""))
	text = inlineLinkPattern.ReplaceAllString(text, "$1")
	text = listMarkerPattern.ReplaceAllString(text, "")
	return strings.Trim(text, "*_`~->+.,;:!? \t\n")
}

func markdownSection(content string, names map[string]bool) string {
	var lines []string
	fence, depth := "", 0
	for _, line := range strings.Split(commentPattern.ReplaceAllString(content, ""), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			marker := trimmed[:3]
			switch fence {
			case "":
				fence = marker
			case marker:
				fence = ""
			}
			continue
		}
		if fence != "" {
			continue
		}
		if heading := headingPattern.FindStringSubmatch(trimmed); heading != nil {
			if names[strings.ToLower(strings.TrimSpace(heading[2]))] {
				depth = len(heading[1])
			} else if depth > 0 && len(heading[1]) <= depth {
				depth = 0
			}
			continue
		}
		if depth > 0 && !linkDefinitionPattern.MatchString(trimmed) {
			lines = append(lines, trimmed)
		}
	}
	return prose(strings.Join(lines, "\n"))
}

var responseHeadings = map[string]bool{"recommendation": true, "recommendations": true, "recommended actions": true, "remediation": true, "mitigation": true, "mitigations": true, "response": true, "next steps": true}

// Actions begin a clause or follow an explicit instruction. Matching a verb
// anywhere would also count nouns in "no patch is available" as instructions.
const instructionStart = `(?:^|[.!?;,\n]\s*|\b(?:and|then|should|must)\s+)`

var mitigationAction = regexp.MustCompile(`(?im)` + instructionStart + `(?:apply|install|deploy|upgrade|update|patch|disable|deactivate|remove|restrict|block|isolate|revoke|rotate|avoid|restore|roll back)\s+([^.!?;\n]+)`)
var patchedReleaseAction = regexp.MustCompile(`(?im)` + instructionStart + `use\s+(?:the\s+)?(?:patched|fixed|updated)\s+([^.!?;\n]+)`)
var nonActionTarget = regexp.MustCompile(`(?i)^(?:is|are|was|were|has|have|availability|information|details|status)\b`)
var advisoryAction = regexp.MustCompile(`(?i)\b(?:consult|check|review|monitor|confirm|contact|follow)\b[^\n.!?;]*\b(?:advisory|vendor|release notes|bulletin|guidance|cited source)\b`)
var remediationContext = regexp.MustCompile(`(?i)\b(?:remediation|fix|fixed|patch|mitigation|security update|guidance|affected versions|response)\b`)
var inventoryObject = regexp.MustCompile(`(?i)\b(?:inventory|inventories|asset list|installation list|software list|asset register|cmdb)\b`)

func actionableResponse(text string) bool {
	text = plainText(prose(text))
	text = strings.NewReplacer("*", "", "`", "").Replace(text)
	if !MeaningfulText(text) {
		return false
	}
	actions := mitigationAction.FindAllStringSubmatch(text, -1)
	actions = append(actions, patchedReleaseAction.FindAllStringSubmatch(text, -1)...)
	for _, action := range actions {
		target := strings.TrimSpace(action[1])
		for _, article := range []string{"the ", "a ", "an "} {
			target = strings.TrimPrefix(strings.ToLower(target), article)
		}
		if target == "the" || target == "a" || target == "an" || nonActionTarget.MatchString(target) {
			continue
		}
		// Updating an inventory changes our knowledge, not the affected
		// installation. A later, separately targeted mitigation can still count.
		object := strings.SplitN(strings.SplitN(target, " to ", 2)[0], " and ", 2)[0]
		if inventoryObject.MatchString(object) {
			continue
		}
		if MeaningfulText(target) {
			return true
		}
	}
	return advisoryAction.MatchString(text) && remediationContext.MatchString(text)
}

func hasResponse(content string, plan map[string]any) bool {
	if actionableResponse(markdownSection(content, responseHeadings)) {
		return true
	}
	for _, key := range []string{"immediate_actions", "mitigation_plan", "hunt_leads"} {
		items, _ := plan[key].([]any)
		for _, item := range items {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if key == "hunt_leads" {
				if MeaningfulText(entry["lead"]) && MeaningfulText(entry["evidence"]) && HasTelemetry(entry["data_needed"]) {
					return true
				}
			} else if action, ok := entry["action"].(string); ok && actionableResponse(action) && MeaningfulText(entry["evidence"]) {
				return true
			}
		}
	}
	return false
}

var wordPattern = regexp.MustCompile(`[a-z]+`)
var digitPattern = regexp.MustCompile(`[0-9]`)
var cvssVectorPattern = regexp.MustCompile(`(?i)\bCVSS:[234](?:\.[0-9]+)?(?:/[A-Z][A-Z0-9]*:[A-Z0-9.]+)+`)
var metricAttribution = regexp.MustCompile(`(?im)(?:^|\n)\s*(?:according to|per)\s+[^,\n]+,\s*`)
var metricWords = map[string]bool{"the": true, "this": true, "vulnerability": true, "vulnerabilities": true, "has": true, "have": true, "been": true, "is": true, "was": true, "are": true, "a": true, "an": true, "assigned": true, "rated": true, "rating": true, "with": true, "of": true, "and": true, "as": true, "its": true, "it": true, "cvss": true, "v": true, "version": true, "base": true, "score": true, "scores": true, "severity": true, "critical": true, "high": true, "medium": true, "low": true, "none": true, "impact": true}

func scoreOnlyImpact(text string) bool {
	plain := strings.ToLower(plainText(text))
	plain = metricAttribution.ReplaceAllString(plain, "")
	hasVector := cvssVectorPattern.MatchString(plain)
	plain = cvssVectorPattern.ReplaceAllString(plain, "")
	words := wordPattern.FindAllString(plain, -1)
	if len(words) == 0 {
		return hasVector || digitPattern.MatchString(plain)
	}
	for _, word := range words {
		if !metricWords[word] {
			return false
		}
	}
	return true
}
