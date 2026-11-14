package pipeline

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// truncateUTF8 returns a prefix of s no longer than maxBytes, without
// splitting a UTF-8 encoded rune. The limit is in bytes to match prompt caps.
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

// iocSectionRe matches common IOC table/section headers in threat reports.
var iocSectionRe = regexp.MustCompile(`(?im)^#{0,4}\s*(?:indicators?\s*of\s*compromise|iocs?|appendix|hashes|domains|ip\s*addresses|c2\s*infrastructure|network\s*indicators)`)

// smartTruncate truncates content to maxLen while preserving IOC sections.
// If the content exceeds maxLen and contains an IOC section in the tail,
// it keeps the head and the IOC tail, truncating the middle narrative.
func smartTruncate(content string, maxLen int) string {
	if len(content) <= maxLen {
		return content
	}

	// Look for IOC section header in the latter half of the content.
	halfPoint := len(content) / 2
	tail := content[halfPoint:]
	loc := iocSectionRe.FindStringIndex(tail)

	if loc == nil {
		// No IOC section found — simple truncation at maxLen.
		return truncateUTF8(content, maxLen)
	}

	// Found an IOC section — keep head + IOC tail.
	iocStart := halfPoint + loc[0]
	iocTail := content[iocStart:]

	// Reserve space for the IOC tail (up to 3000 chars) and a separator.
	tailBudget := len(iocTail)
	if tailBudget > 3000 {
		tailBudget = 3000
	}

	headBudget := maxLen - tailBudget - 50 // 50 chars for separator
	if headBudget < 1000 {
		headBudget = 1000
	}

	var b strings.Builder
	b.WriteString(truncateUTF8(content, headBudget))
	b.WriteString("\n\n[... content truncated ...]\n\n")
	b.WriteString(truncateUTF8(iocTail, tailBudget))
	return b.String()
}
