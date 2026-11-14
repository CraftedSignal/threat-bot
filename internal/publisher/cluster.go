package publisher

import (
	"regexp"
	"sort"
	"strings"
)

// cvePattern matches CVE IDs, optionally wrapped in parentheses.
var cvePattern = regexp.MustCompile(`\(?\s*CVE-\d{4}-\d{4,}\s*\)?`)

// briefCluster groups one or more BundleBriefs that share a normalized product title.
type briefCluster struct {
	Key             string
	DisplayTitle    string
	BriefIDs        []string
	CVEs            []string
	HighestSeverity string
	Sources         []string
	TotalRules      int
	TotalIOCs       int
	TotalTTPs       int
	References      []string
	RepContent      string
	OriginalSummary string
	OriginalURL     string
}

// normalizeTitle strips CVE IDs, trailing punctuation, lowercases, and trims.
func normalizeTitle(title string) string {
	s := cvePattern.ReplaceAllString(title, "")
	s = strings.ToLower(s)
	s = strings.TrimRight(s, " .,;:!?-")
	s = strings.TrimSpace(s)
	return s
}

// displayTitle strips CVE IDs and trailing punctuation while preserving original case.
func displayTitle(title string) string {
	s := cvePattern.ReplaceAllString(title, "")
	s = strings.TrimRight(s, " .,;:!?-")
	s = strings.TrimSpace(s)
	return s
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default: // informational, unknown, empty
		return 0
	}
}

// clusterBriefs groups briefs by normalized title, preserving insertion order.
func clusterBriefs(briefs []*BundleBrief) []briefCluster {
	type entry struct {
		key    string
		briefs []*BundleBrief
	}

	seen := make(map[string]int) // key -> index in entries
	var entries []entry

	for _, b := range briefs {
		key := normalizeTitle(b.Title)
		if idx, ok := seen[key]; ok {
			entries[idx].briefs = append(entries[idx].briefs, b)
		} else {
			seen[key] = len(entries)
			entries = append(entries, entry{key: key, briefs: []*BundleBrief{b}})
		}
	}

	clusters := make([]briefCluster, 0, len(entries))
	for _, e := range entries {
		clusters = append(clusters, aggregateCluster(e.key, e.briefs))
	}
	return clusters
}

// aggregateCluster builds a briefCluster from a set of briefs sharing the same key.
func aggregateCluster(key string, briefs []*BundleBrief) briefCluster {
	if len(briefs) == 0 {
		return briefCluster{Key: key}
	}

	first := briefs[0]

	c := briefCluster{
		Key:          key,
		DisplayTitle: displayTitle(first.Title),
		RepContent:   first.Content,
	}

	// Collect BriefIDs
	c.BriefIDs = make([]string, 0, len(briefs))
	for _, b := range briefs {
		c.BriefIDs = append(c.BriefIDs, b.ID)
	}

	// Aggregate CVEs (deduped, sorted)
	cveSet := make(map[string]struct{})
	for _, b := range briefs {
		for _, cve := range b.CVEs {
			cveSet[cve.ID] = struct{}{}
		}
	}
	c.CVEs = make([]string, 0, len(cveSet))
	for id := range cveSet {
		c.CVEs = append(c.CVEs, id)
	}
	sort.Strings(c.CVEs)

	// Highest severity
	best := 0
	bestStr := briefs[0].Severity
	for _, b := range briefs {
		if r := severityRank(b.Severity); r > best {
			best = r
			bestStr = b.Severity
		}
	}
	c.HighestSeverity = bestStr

	// Totals
	for _, b := range briefs {
		c.TotalRules += len(b.Rules)
		c.TotalIOCs += len(b.IOCs)
		c.TotalTTPs += len(b.TTPs)
	}

	// Union of references (preserve order, dedupe)
	refSeen := make(map[string]struct{})
	for _, b := range briefs {
		for _, ref := range b.References {
			if _, ok := refSeen[ref]; !ok {
				refSeen[ref] = struct{}{}
				c.References = append(c.References, ref)
			}
		}
	}

	// Sources (brief IDs as source identifiers, same as BriefIDs here)
	c.Sources = c.BriefIDs

	// Single-brief cluster: set OriginalSummary and OriginalURL
	if len(briefs) == 1 {
		c.OriginalSummary = first.Summary
		// OriginalURL: use first reference if available
		if len(first.References) > 0 {
			c.OriginalURL = first.References[0]
		}
	}

	return c
}
