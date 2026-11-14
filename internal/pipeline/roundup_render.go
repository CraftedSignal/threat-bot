package pipeline

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

type roundupCVEEntry struct {
	id             string
	product        string
	cvss           float64
	cvssVector     string
	epss           float64
	epssPercentile float64
	kev            bool
}

// yamlCVEEntries parses the frontmatter cves field into a slice of entries.
// It tolerates both plain CVE strings and maps with id/cvss/epss/kev keys.
func yamlCVEEntries(v any) []roundupCVEEntry {
	list := yamlAnyList(v)
	var out []roundupCVEEntry
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, roundupCVEEntry{id: strings.ToUpper(strings.TrimSpace(s))})
			continue
		}
		if m, ok := asStringMap(item); ok {
			id := strings.TrimSpace(fmt.Sprint(m["id"]))
			cvss := parseRoundupFloat(m["cvss"])
			epss := parseRoundupFloat(m["epss"])
			epssPercentile := parseRoundupFloat(m["epss_percentile"])
			product := strings.TrimSpace(fmt.Sprint(m["product"]))
			if product == "<nil>" {
				product = ""
			}
			cvssVector := strings.TrimSpace(fmt.Sprint(m["cvss_vector"]))
			if cvssVector == "<nil>" {
				cvssVector = ""
			}
			kev := parseRoundupBool(m["kev"])
			if id != "" && id != "<nil>" {
				out = append(out, roundupCVEEntry{
					id:             strings.ToUpper(id),
					product:        product,
					cvss:           cvss,
					cvssVector:     cvssVector,
					epss:           epss,
					epssPercentile: epssPercentile,
					kev:            kev,
				})
			}
		}
	}
	return out
}

type roundupCVESection struct {
	id             string
	cvss           float64
	cvssVector     string
	epss           float64
	epssPercentile float64
	kev            bool
	summary        string
	products       []string
	source         string
}

// extractRoundupCVESections parses the per-CVE detail sections from the
// roundup markdown content. It extracts the CVE id, the first paragraph as
// a summary, the "Affected products:" list, and the source URL.
func extractRoundupCVESections(content string) []roundupCVESection {
	var sections []roundupCVESection
	var current *roundupCVESection
	inAffectedProducts := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "## CVE-") {
			if current != nil {
				sections = append(sections, *current)
			}
			current = &roundupCVESection{id: strings.TrimSpace(strings.TrimPrefix(line, "## "))}
			inAffectedProducts = false
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "Affected products:") {
			inAffectedProducts = true
			continue
		}
		if inAffectedProducts {
			if strings.HasPrefix(line, "- ") {
				current.products = append(current.products, strings.TrimPrefix(line, "- "))
				continue
			}
			if line == "" {
				inAffectedProducts = false
				continue
			}
			inAffectedProducts = false
		}
		if strings.HasPrefix(line, "Source:") {
			current.source = strings.TrimSpace(strings.TrimPrefix(line, "Source:"))
			continue
		}
		if line != "" && !strings.HasPrefix(line, "Related in this roundup:") && current.summary == "" {
			current.summary = line
		}
	}
	if current != nil {
		sections = append(sections, *current)
	}
	return sections
}

func buildRoundupOverview(vendor string, sections []roundupCVESection) string {
	v := vendor
	if v == "" {
		v = "the vendor"
	}
	minCVSS, maxCVSS := roundupCVSSRange(sections)
	families := roundupProductFamilies(sections)

	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "This roundup covers %d %s security vulnerabilities. ", len(sections), v)
	if minCVSS > 0 && maxCVSS > 0 {
		if minCVSS == maxCVSS {
			_, _ = fmt.Fprintf(&b, "All have a CVSS base score of %.1f. ", maxCVSS)
		} else {
			_, _ = fmt.Fprintf(&b, "CVSS base scores range from %.1f to %.1f. ", minCVSS, maxCVSS)
		}
	}
	if kevCount := roundupKEVCount(sections); kevCount > 0 {
		if kevCount == 1 {
			b.WriteString("1 is listed in the CISA Known Exploited Vulnerabilities catalog.")
		} else {
			_, _ = fmt.Fprintf(&b, "%d are listed in the CISA Known Exploited Vulnerabilities catalog.", kevCount)
		}
	} else {
		b.WriteString("None are reported as actively exploited at the time of release.")
	}
	if len(families) > 0 {
		sort.Strings(families)
		_, _ = fmt.Fprintf(&b, " The issues affect %s.", strings.Join(families, ", "))
	}
	return b.String()
}

func roundupKEVCount(sections []roundupCVESection) int {
	count := 0
	for _, s := range sections {
		if s.kev {
			count++
		}
	}
	return count
}

func buildRoundupSummaryTable(sections []roundupCVESection) string {
	var b strings.Builder
	b.WriteString("| CVE | Product | Severity | CVSS | EPSS | KEV | Source |\n")
	b.WriteString("|-----|---------|----------|------|------|-----|--------|\n")
	for _, s := range sections {
		product := firstNonPlaceholder(s.products)
		if product == "" {
			product = "n/a"
		}
		_, _ = fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %s | %s | %s | %s |\n",
			markdownTableCell(s.id),
			roundupMarkdownAnchor(s.id),
			markdownTableCell(product),
			roundupSeverityLabel(s.cvss),
			roundupCVSSDisplay(s.cvss),
			roundupEPSSDisplay(s.epss),
			roundupKEVDisplay(s.kev),
			roundupSourceDisplay(s.source))
	}
	return b.String()
}

func parseRoundupFloat(v any) float64 {
	if v == nil {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(v)), 64)
	return f
}

func parseRoundupBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true") || strings.EqualFold(strings.TrimSpace(t), "yes")
	default:
		b, _ := strconv.ParseBool(strings.TrimSpace(fmt.Sprint(v)))
		return b
	}
}

func roundupSeverityLabel(cvss float64) string {
	switch {
	case cvss >= 9:
		return "Critical"
	case cvss >= 7:
		return "High"
	case cvss >= 4:
		return "Medium"
	case cvss > 0:
		return "Low"
	default:
		return ""
	}
}

func roundupCVSSDisplay(cvss float64) string {
	if cvss <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f", cvss)
}

func roundupEPSSDisplay(epss float64) string {
	if epss <= 0 {
		return ""
	}
	return fmt.Sprintf("%.2f%%", epss*100)
}

func roundupKEVDisplay(kev bool) string {
	if kev {
		return "yes"
	}
	return "no"
}

func roundupSourceDisplay(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "n/a"
	}
	label := roundupSourceLabel(source)
	if label == "" {
		label = "source"
	}
	return fmt.Sprintf("[%s](%s) (authoritative)", markdownTableCell(label), source)
}

func roundupSourceLabel(source string) string {
	lower := strings.ToLower(source)
	switch {
	case strings.Contains(lower, "msrc.microsoft.com"):
		return "MSRC"
	case strings.Contains(lower, "nvd.nist.gov"):
		return "NVD"
	case strings.Contains(lower, "cisa.gov"):
		return "CISA"
	default:
		return ""
	}
}

func roundupMarkdownAnchor(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

func markdownTableCell(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	if s == "" {
		return "n/a"
	}
	return s
}

// buildRoundupProductIndex renders one "By product" index: each product
// family with more than one CVE maps to its CVE IDs, and each CVE is listed
// at most once. Single-CVE families and CVEs without a product are omitted. This replaces per-section "Related in this roundup" lines,
// whose link count grew quadratically with the family size (k*(k-1)).
func buildRoundupProductIndex(sections []roundupCVESection) string {
	byFamily := make(map[string][]string)
	seen := make(map[string]struct{}, len(sections))
	for _, s := range sections {
		family := roundupProductFamily(s)
		if family == "" {
			continue
		}
		key := family + "\x00" + s.id
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		byFamily[family] = append(byFamily[family], s.id)
	}
	families := make([]string, 0, len(byFamily))
	for family, ids := range byFamily {
		if len(ids) > 1 {
			families = append(families, family)
		}
	}
	sort.Strings(families)
	lines := make([]string, 0, len(families))
	for _, family := range families {
		lines = append(lines, fmt.Sprintf("- **%s**: %s", markdownTableCell(family), roundupRelatedLinks(byFamily[family])))
	}
	return strings.Join(lines, "\n")
}

func roundupProductFamily(s roundupCVESection) string {
	p := firstNonPlaceholder(s.products)
	if p == "" {
		return ""
	}
	bare := strings.TrimSpace(strings.SplitN(p, "(", 2)[0])
	bare = strings.TrimSpace(strings.TrimSuffix(bare, "for Android"))
	bare = strings.TrimSpace(strings.TrimSuffix(bare, "(Chromium-based)"))
	return bare
}

func stripRoundupRelatedLines(content string) string {
	if !strings.Contains(content, "Related in this roundup:") {
		return content
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		if strings.HasPrefix(strings.TrimSpace(raw), "Related in this roundup:") {
			// Also drop the blank separator that preceded the line.
			if n := len(out); n > 0 && strings.TrimSpace(out[n-1]) == "" {
				out = out[:n-1]
			}
			continue
		}
		out = append(out, raw)
	}
	return strings.Join(out, "\n")
}

func roundupRelatedLinks(ids []string) string {
	var links []string
	for _, id := range ids {
		links = append(links, fmt.Sprintf("[%s](#%s)", id, roundupMarkdownAnchor(id)))
	}
	return strings.Join(links, ", ")
}

func roundupCVSSRange(sections []roundupCVESection) (min, max float64) {
	seen := false
	for _, s := range sections {
		if s.cvss <= 0 {
			continue
		}
		if !seen || s.cvss < min {
			min = s.cvss
		}
		if !seen || s.cvss > max {
			max = s.cvss
		}
		seen = true
	}
	return
}

func roundupProductFamilies(sections []roundupCVESection) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range sections {
		bare := roundupProductFamily(s)
		if bare == "" || seen[bare] {
			continue
		}
		seen[bare] = true
		out = append(out, bare)
	}
	return out
}

// recordRoundupPosted writes an L1 "posted roundup" update event so the public
// "What's new" timeline includes the original creation of the roundup, not only
// later CVE additions.
func (p *Pipeline) recordRoundupPosted(draftID string, item scraper.RawItem) error {
	draft, err := p.db.GetDraft(draftID)
	if err != nil {
		return err
	}
	event := storage.UpdateEvent{
		At:      time.Now().UTC(),
		Level:   "L1",
		Summary: "posted roundup",
		Sources: []string{item.Source},
	}
	if strings.TrimSpace(item.URL) != "" {
		event.SourceURLs = []string{item.URL}
	}
	merged := draft.BriefYAML
	if err := injectUpdateMetadata(&merged, draft, event); err != nil {
		return err
	}
	publish := p.autoPublish && p.publisher != nil && p.validatePublication(merged) == nil
	return p.db.RecordDraftUpdateWithPublication(draftID, merged, event, "", publish)
}
