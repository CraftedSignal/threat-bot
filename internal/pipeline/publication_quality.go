package pipeline

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode"
)

// publicationQualityIssues is deliberately independent of the model's self
// assessment and grounding. A factual registry paragraph can still omit the
// information a defender needs. Run this on the final publication snapshot.
func publicationQualityIssues(brief map[string]any) []string {
	var issues []string
	content := publicationString(brief["content"])
	summary := publicationString(brief["summary"])
	if content == "" || !substantiveMarkdown(content) {
		issues = append(issues, "content must contain substantive brief text")
	} else if normalizeForQuote(plainPublicationText(publicationProse(content))) == normalizeForQuote(plainPublicationText(summary)) {
		issues = append(issues, "content repeats the summary without additional analysis or guidance")
	}
	for _, product := range yamlStringList(brief["affected_products"]) {
		if strings.Contains(product, "|") {
			issues = append(issues, fmt.Sprintf("product label requires a canonical name without a marketplace feature list: %q", product))
		}
	}
	// Do not force detector-grade behavior or an invented attack chain out of
	// sparse CVE notices. A short, sourced response (including checking the
	// advisory when no fix is named) is sufficient.
	visible := strings.Join([]string{publicationString(brief["title"]), summary, content}, "\n")
	if len(publicationCVEs(brief["cves"], visible)) > 0 && !hasPublicationResponse(brief, content) {
		issues = append(issues, "CVE brief requires a substantive recommendation section or an evidence-backed action plan")
	}
	if qa, ok := asStringMap(brief["qa_status"]); ok {
		verdict := strings.ToLower(publicationString(qa["verdict"]))
		if verdict == "do_not_publish" || verdict == "fail" || len(yamlAnyList(qa["unsupported_claims"])) > 0 || len(yamlAnyList(qa["format_gaps"])) > 0 {
			issues = append(issues, "QA assessment has unresolved publication blockers")
		}
	}
	return issues
}

var publicationHeadingRe = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*\s*$`)
var publicationCommentRe = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)`)
var publicationLinkDefinitionRe = regexp.MustCompile(`^\s*\[[^\]]+\]:\s*\S+`)
var publicationInlineLinkRe = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
var publicationHTMLTagRe = regexp.MustCompile(`</?[A-Za-z][^>\n]*>`)
var publicationListMarkerRe = regexp.MustCompile(`(?m)^\s*(?:[-*+]|\d+[.)])\s+(?:\[[ xX]\]\s+)?`)

func substantiveMarkdown(text string) bool {
	for _, line := range strings.Split(publicationProse(text), "\n") {
		if meaningfulPublicationText(line) {
			return true
		}
	}
	return false
}

// Ignore formatting and examples when testing whether a human-readable body
// exists. This is a structural check; grounding still checks factual support.
func publicationProse(text string) string {
	var lines []string
	fence := ""
	for _, line := range strings.Split(publicationCommentRe.ReplaceAllString(text, ""), "\n") {
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
		if fence != "" || strings.Trim(line, "#*_~-+> \t") == "" || publicationHeadingRe.MatchString(line) || publicationLinkDefinitionRe.MatchString(line) {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func hasPublicationResponse(brief map[string]any, content string) bool {
	plan, _ := asStringMap(brief["action_plan"])
	for _, item := range yamlAnyList(plan["hunt_leads"]) {
		lead, ok := asStringMap(item)
		if ok && meaningfulPublicationText(lead["lead"]) && meaningfulPublicationText(lead["evidence"]) && hasPublicationTelemetry(lead["data_needed"]) {
			return true
		}
	}
	for _, key := range []string{"immediate_actions", "mitigation_plan"} {
		for _, item := range yamlAnyList(plan[key]) {
			action, ok := asStringMap(item)
			if ok && meaningfulPublicationText(action["action"]) && meaningfulPublicationText(action["evidence"]) {
				return true
			}
		}
	}
	// Fenced examples are not recommendations. Headings alone do not count.
	response, fence := false, ""
	for _, line := range strings.Split(publicationCommentRe.ReplaceAllString(content, ""), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			marker := trimmed[:3]
			if fence == "" {
				fence = marker
			} else if marker == fence {
				fence = ""
			}
			continue
		}
		if fence != "" {
			continue
		}
		if heading := publicationHeadingRe.FindStringSubmatch(trimmed); heading != nil {
			switch strings.ToLower(strings.TrimSpace(heading[1])) {
			case "recommendation", "recommendations", "recommended actions", "remediation", "mitigation", "mitigations", "response", "next steps":
				response = true
			default:
				response = false
			}
			continue
		}
		if response && substantiveMarkdown(trimmed) {
			return true
		}
	}
	return false
}

func meaningfulPublicationText(value any) bool {
	text := plainPublicationText(publicationString(value))
	return strings.IndexFunc(text, unicode.IsLetter) >= 0 && !isPlaceholder(text)
}

func plainPublicationText(value string) string {
	text := html.UnescapeString(publicationHTMLTagRe.ReplaceAllString(value, ""))
	text = publicationInlineLinkRe.ReplaceAllString(text, "$1")
	text = publicationListMarkerRe.ReplaceAllString(text, "")
	return strings.Trim(text, "*_`~->+.,;:!? \t\n")
}

func hasPublicationTelemetry(value any) bool {
	for _, name := range yamlStringList(value) {
		if meaningfulPublicationText(name) {
			return true
		}
	}
	return false
}
