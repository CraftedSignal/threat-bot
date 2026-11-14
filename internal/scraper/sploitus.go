package scraper

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
)

// Sploitus aggregates exploits from Exploit-DB, Packet Storm, and GitHub PoC repos.
// The RSS feed carries no description field — just a title. This scraper:
//   - Filters out noise entries (bare GitHub repo names with no CVE or product context)
//   - Builds structured content from the title so items clear the pipeline pre-filter
type Sploitus struct {
	rss *RSS
}

func NewSploitus() *Sploitus {
	return &Sploitus{rss: NewRSS("sploitus", "https://sploitus.com/rss")}
}

func (s *Sploitus) Name() string { return "sploitus" }

// sploitusCVERe matches "Exploit for CVE-YYYY-NNNNN" titles.
var sploitusCVERe = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)

// sploitusProductRe matches "Exploit for <VulnClass> in <Software>" titles.
var sploitusProductRe = regexp.MustCompile(`(?i)^Exploit for (.+?) in (.+?)\s+exploit$`)

// sploitusVulnRe matches "Exploit for <Product> <Version> - <VulnClass>" (EDB-style mirror).
var sploitusVulnDashRe = regexp.MustCompile(`(?i)^Exploit for (.+?)\s+-\s+(.+?)\s+exploit$`)

func (s *Sploitus) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	fp := gofeed.NewParser()
	fp.Client = s.rss.parser.Client
	feed, err := fp.ParseURLWithContext(s.rss.url, ctx)
	if err != nil {
		return nil, fmt.Errorf("parsing sploitus feed: %w", err)
	}

	var items []RawItem
	for _, entry := range feed.Items {
		published := time.Now()
		if entry.PublishedParsed != nil {
			published = *entry.PublishedParsed
		}
		if published.After(time.Now()) {
			published = time.Now()
		}
		if published.Before(since) {
			continue
		}

		content := buildSploitusContent(entry.Title, entry.Link)
		if content == "" {
			// Title didn't match any known pattern — noise entry, skip.
			continue
		}

		guid := entry.GUID
		if guid == "" {
			guid = entry.Link
		}

		items = append(items, RawItem{
			SourceID:    fmt.Sprintf("sploitus:%s", guid),
			Source:      "sploitus",
			Title:       strings.TrimSuffix(strings.TrimSpace(entry.Title), " exploit"),
			URL:         entry.Link,
			Content:     content,
			PublishedAt: published,
		})
	}
	return items, nil
}

func buildSploitusContent(title, link string) string {
	// Normalise: Sploitus appends " exploit" to all titles.
	clean := strings.TrimSuffix(strings.TrimSpace(title), " exploit")

	cves := sploitusCVERe.FindAllString(clean, -1)

	// Pattern 1: "Exploit for <VulnClass> in <Software>"
	if m := sploitusProductRe.FindStringSubmatch(title); m != nil {
		vulnClass := strings.TrimSpace(m[1])
		software := strings.TrimSpace(m[2])
		var sb strings.Builder
		fmt.Fprintf(&sb, "A public exploit has been published on Sploitus demonstrating **%s** in **%s**.\n\n",
			vulnClass, software)
		fmt.Fprintf(&sb, "- Vulnerability class: %s\n", vulnClass)
		fmt.Fprintf(&sb, "- Affected software: %s\n", software)
		if len(cves) > 0 {
			fmt.Fprintf(&sb, "- CVE: %s\n", strings.Join(cves, ", "))
		}
		fmt.Fprintf(&sb, "- Source: %s\n", link)
		sb.WriteString("\nThe availability of a working exploit significantly elevates the risk for unpatched systems.")
		return sb.String()
	}

	// Pattern 2: "Exploit for <Product> - <VulnClass>" (EDB mirror style)
	if m := sploitusVulnDashRe.FindStringSubmatch(title); m != nil {
		product := strings.TrimSpace(m[1])
		vulnClass := strings.TrimSpace(m[2])
		var sb strings.Builder
		fmt.Fprintf(&sb, "A public exploit has been published on Sploitus for **%s**, demonstrating a **%s** vulnerability.\n\n",
			product, vulnClass)
		fmt.Fprintf(&sb, "- Affected software: %s\n", product)
		fmt.Fprintf(&sb, "- Vulnerability class: %s\n", vulnClass)
		if len(cves) > 0 {
			fmt.Fprintf(&sb, "- CVE: %s\n", strings.Join(cves, ", "))
		}
		fmt.Fprintf(&sb, "- Source: %s\n", link)
		sb.WriteString("\nThe availability of a working exploit significantly elevates the risk for unpatched systems.")
		return sb.String()
	}

	// Pattern 3: bare CVE reference with no other context
	if len(cves) > 0 {
		var sb strings.Builder
		fmt.Fprintf(&sb, "A public exploit or PoC has been published on Sploitus for **%s**.\n\n",
			strings.Join(cves, ", "))
		fmt.Fprintf(&sb, "- CVE: %s\n", strings.Join(cves, ", "))
		fmt.Fprintf(&sb, "- Source: %s\n", link)
		sb.WriteString("\nThe availability of a working exploit significantly elevates the risk for unpatched systems.")
		return sb.String()
	}

	// No recognisable structure — discard (GitHub repo noise etc.)
	return ""
}
