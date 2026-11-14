package scraper

import (
	"regexp"
	"strings"
)

var (
	discoveryIdentifierRE = regexp.MustCompile(`(?i)\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z-]+|0-?day)\b`)
	discoveryURLOnlyRE    = regexp.MustCompile(`^https?://\S+$`)
	discoveryArtifactRE   = regexp.MustCompile(`(?i)https?://(?:github\.com|gitlab\.com|codeberg\.org|nvd\.nist\.gov|[^/]+/(?:advisory|security|commit|issues?)(?:/|\b))`)
)

var discoveryMechanismTerms = []string{
	"auth bypass", "authentication bypass", "buffer overflow", "command injection",
	"decompression", "deserialization", "heap leak", "memory corruption",
	"heap bytes", "memory disclosure", "out-of-bounds", "path traversal", "remote code execution",
	"sandbox escape", "sql injection", "ssrf", "use-after-free", "xss",
}

var discoveryEvidenceTerms = []string{
	"in our tests", "we tested", "we reproduced", "reproduced", "reproducer",
	"proof of concept", "poc", "crash trace", "stack trace", "patch commit",
}

var discoveryImpactTerms = []string{
	"arbitrary code", "code execution", "credential theft", "data exfiltration",
	"denial of service", "information disclosure", "memory leak", "remote code execution",
	"sandbox escape", "takeover",
}

var discoveryProductTerms = []string{
	"android", "apache", "chrome", "cisco", "firefox", "fortinet", "ios",
	"linux", "microsoft", "node.js", "nodejs", "openssl", "windows",
}

var discoveryMarketingTerms = []string{
	"register now", "webinar", "book a demo", "download our report", "sponsored",
}

// SecuritySignalClasses returns distinct, deterministic evidence classes in a
// stable order. These classes control cost and relevance, not truth.
func SecuritySignalClasses(item RawItem) []string {
	text := strings.ToLower(strings.TrimSpace(item.Title + "\n" + item.Content))
	if text == "" {
		return nil
	}

	var classes []string
	if discoveryIdentifierRE.MatchString(text) {
		classes = append(classes, "identifier")
	}
	if containsDiscoveryTerm(text, discoveryMechanismTerms) {
		classes = append(classes, "mechanism")
	}
	if containsDiscoveryTerm(text, discoveryEvidenceTerms) {
		classes = append(classes, "evidence")
	}
	if discoveryArtifactRE.MatchString(text) {
		classes = append(classes, "artifact")
	}
	if containsDiscoveryTerm(text, discoveryProductTerms) && containsDiscoveryTerm(text, discoveryImpactTerms) {
		classes = append(classes, "product_impact")
	}
	return classes
}

// IsRelevantDiscoveryCandidate applies the cheap pre-LLM social discovery gate.
func IsRelevantDiscoveryCandidate(item RawItem) bool {
	text := strings.TrimSpace(item.Title + " " + item.Content)
	lower := strings.ToLower(text)
	if text == "" || discoveryURLOnlyRE.MatchString(text) || strings.HasPrefix(lower, "rt @") || strings.HasPrefix(lower, "repost ") {
		return false
	}
	if containsDiscoveryTerm(lower, discoveryMarketingTerms) {
		return false
	}
	return len(SecuritySignalClasses(item)) >= 2
}

func containsDiscoveryTerm(text string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}
