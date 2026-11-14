package pipeline

import (
	"regexp"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// lowValuePatterns lists vulnerability classes that rarely produce actionable
// detection intelligence. Each entry has a human-readable label and a set of
// case-insensitive patterns matched against the item title and content.
var lowValuePatterns = []struct {
	Label    string
	Patterns []*regexp.Regexp
}{
	{
		Label: "ReDoS",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bRe[- ]?DoS\b`),
			regexp.MustCompile(`(?i)\bregular\s+expression\s+denial\s+of\s+service\b`),
			regexp.MustCompile(`(?i)\bregex\s+denial\s+of\s+service\b`),
		},
	},
}

// isLowValueItem returns a non-empty label if the item matches a known
// low-value vulnerability class that should be skipped.
func isLowValueItem(item scraper.RawItem) string {
	// Only check the first 2000 chars of content to keep this fast.
	content := item.Content
	if len(content) > 2000 {
		content = truncateUTF8(content, 2000)
	}
	text := item.Title + "\n" + content

	for _, lv := range lowValuePatterns {
		for _, p := range lv.Patterns {
			if p.MatchString(text) {
				// Guard: skip the filter if the item covers multiple CVEs
				// (likely a roundup where ReDoS is mentioned alongside
				// something more interesting).
				if countCVEs(text) > 1 {
					return ""
				}
				return lv.Label
			}
		}
	}
	return ""
}

var lowValueCVERe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
var informationalTIDRe = regexp.MustCompile(`\bT[0-9]{4}(?:\.[0-9]{3})?\b`)
var informationalHashRe = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b`)
var informationalIPRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var informationalShortThreatRe = regexp.MustCompile(`\b(?:apt|c2|ioc|rce)s?\b`)

var informationalAnnouncementTerms = []string{
	"announces",
	"announced",
	"announcement",
	"introduces",
	"introduced",
	"launches",
	"launched",
	"unveils",
	"released",
	"release",
	"now available",
	"generally available",
	"availability",
	"supports",
	"support for",
	"adds support",
	"integrates",
	"integration",
	"partner",
	"partnership",
	"capability",
	"capabilities",
	"feature",
	"features",
	"platform",
	"solution",
	"offering",
	"pricing",
	"services expansion",
}

var informationalProductTerms = []string{
	"next-gen siem",
	"siem",
	"edr",
	"xdr",
	"falcon",
	"cloud security",
	"identity protection",
	"exposure management",
	"security operations",
	"managed detection",
	"third-party",
	"federated search",
	"dashboard",
	"console",
	"module",
	"workflow",
	"connector",
	"data source",
}

var concreteThreatTerms = []string{
	"actively exploited",
	"active exploitation",
	"exploitation in the wild",
	"in-the-wild exploitation",
	"observed in attacks",
	"used in attacks",
	"zero-day",
	"0-day",
	"vulnerability",
	"remote code execution",
	"privilege escalation",
	"authentication bypass",
	"command injection",
	"sql injection",
	"path traversal",
	"malware",
	"ransomware",
	"infostealer",
	"backdoor",
	"trojan",
	"loader",
	"botnet",
	"phishing",
	"credential theft",
	"credential harvesting",
	"data exfiltration",
	"exfiltration",
	"lateral movement",
	"persistence",
	"command and control",
	"threat actor",
	"campaign",
	"indicator of compromise",
	"indicators of compromise",
}

func countCVEs(text string) int {
	seen := make(map[string]bool)
	for _, m := range lowValueCVERe.FindAllString(strings.ToUpper(text), -1) {
		seen[m] = true
	}
	return len(seen)
}

// isInformationalItem returns a label when an item is vendor/product news
// rather than threat intelligence. The classifier is intentionally
// conservative: announcement/product language must be present and concrete
// threat signals must be absent.
func isInformationalItem(item scraper.RawItem) string {
	content := item.Content
	if len(content) > 4000 {
		content = truncateUTF8(content, 4000)
	}
	text := strings.ToLower(item.Title + "\n" + content)

	if hasConcreteThreatSignal(text) {
		return ""
	}
	if !hasAnyTerm(text, informationalAnnouncementTerms) {
		return ""
	}
	if !hasAnyTerm(text, informationalProductTerms) {
		return ""
	}
	return "informational-product-announcement"
}

func hasConcreteThreatSignal(text string) bool {
	upper := strings.ToUpper(text)
	if lowValueCVERe.MatchString(upper) || informationalTIDRe.MatchString(upper) || informationalShortThreatRe.MatchString(text) || informationalHashRe.MatchString(text) || informationalIPRe.MatchString(text) {
		return true
	}
	return hasAnyTerm(text, concreteThreatTerms)
}

func hasAnyTerm(text string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

// isGenericCVEBrief returns true when a brief mentions a CVE but the
// LLM failed to extract any specific vendor or product. Without a
// vendor/product the brief is unactionable — there's nothing for a
// detection engineer to scope rules to and nothing for a defender to
// patch. These usually come from CERT advisories or NVD entries where
// the affected-product metadata wasn't fetched in time.
func isGenericCVEBrief(briefYAMLStr string) bool {
	var b struct {
		Title            string   `yaml:"title"`
		Summary          string   `yaml:"summary"`
		AffectedVendors  []string `yaml:"affected_vendors"`
		AffectedProducts []string `yaml:"affected_products"`
	}
	if err := yaml.Unmarshal([]byte(briefYAMLStr), &b); err != nil {
		return false
	}
	if !lowValueCVERe.MatchString(b.Title) && !lowValueCVERe.MatchString(b.Summary) {
		return false
	}
	if hasMeaningfulEntry(b.AffectedVendors) || hasMeaningfulEntry(b.AffectedProducts) {
		return false
	}
	return true
}

func hasMeaningfulEntry(items []string) bool {
	for _, raw := range items {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" || placeholders[s] {
			continue
		}
		return true
	}
	return false
}
