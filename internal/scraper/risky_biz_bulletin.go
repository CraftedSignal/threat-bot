package scraper

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"golang.org/x/net/html"
)

const riskyBizBulletinFeed = "https://news.risky.biz/rss/"

// skipSections lists h2 section names (lowercase) whose stories are not
// actionable threat intelligence.
var riskyBizSkipSections = map[string]bool{
	"risky business podcasts": true,
	"sponsor section":         true,
	"infosec industry":        true,
}

// RiskyBizBulletin fetches the Risky Biz newsletter RSS feed and emits one
// RawItem per individual story rather than one per full bulletin edition.
type RiskyBizBulletin struct {
	parser *gofeed.Parser
}

func NewRiskyBizBulletin() *RiskyBizBulletin {
	fp := gofeed.NewParser()
	fp.Client = &http.Client{
		Timeout:   180 * time.Second,
		Transport: &uaTransport{ua: userAgent, rt: http.DefaultTransport},
	}
	return &RiskyBizBulletin{parser: fp}
}

func (r *RiskyBizBulletin) Name() string { return "risky-biz-bulletin" }

func (r *RiskyBizBulletin) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	feed, err := r.parser.ParseURLWithContext(riskyBizBulletinFeed, ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching risky-biz-bulletin: %w", err)
	}
	var items []RawItem
	for _, fi := range feed.Items {
		if fi.PublishedParsed == nil || fi.PublishedParsed.Before(since) {
			continue
		}
		stories, err := parseRiskyBizStories(fi.Content, fi.Link, *fi.PublishedParsed)
		if err != nil {
			continue
		}
		items = append(items, stories...)
	}
	return items, nil
}

// parseRiskyBizStories parses the content:encoded HTML of a single bulletin
// and returns one RawItem per story paragraph (<p><strong>Title:</strong> …).
func parseRiskyBizStories(content, bulletinURL string, pubDate time.Time) ([]RawItem, error) {
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return nil, err
	}

	dateStr := pubDate.UTC().Format("20060102")
	var items []RawItem
	var currentSection string
	skipSection := true // skip content before the first known section

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "h2":
				text := strings.TrimSpace(extractHTMLText(n))
				if riskyBizSkipSections[strings.ToLower(text)] {
					skipSection = true
				} else {
					currentSection = text
					skipSection = false
				}
				return // don't recurse — h2 has no nested stories
			case "p":
				if skipSection {
					return
				}
				first := firstNonSpaceChild(n)
				if first == nil || first.Type != html.ElementNode || first.Data != "strong" {
					break // not a story paragraph
				}
				title := strings.TrimRight(strings.TrimSpace(extractHTMLText(first)), ":")
				if title == "" {
					break
				}
				fullText := strings.TrimSpace(extractHTMLText(n))
				body := strings.TrimSpace(strings.TrimPrefix(fullText, title+":"))

				links := extractHTMLLinks(n)

				var sb strings.Builder
				fmt.Fprintf(&sb, "[Section: %s]\n\n**%s:** %s", currentSection, title, body)
				if len(links) > 0 {
					fmt.Fprintf(&sb, "\n\nSources: %s", strings.Join(links, " "))
				}

				items = append(items, RawItem{
					SourceID:    fmt.Sprintf("risky-biz-bulletin:%s:%s", dateStr, slugifyRBB(title)),
					Source:      "risky-biz-bulletin",
					Title:       title,
					URL:         bulletinURL,
					Content:     sb.String(),
					PublishedAt: pubDate,
				})
				return // don't recurse into <p> children
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return items, nil
}

// firstNonSpaceChild returns the first child node of n that is not pure whitespace.
func firstNonSpaceChild(n *html.Node) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode && strings.TrimSpace(c.Data) == "" {
			continue
		}
		return c
	}
	return nil
}

// extractHTMLText returns the concatenated text content of a node tree.
func extractHTMLText(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}

// extractHTMLLinks returns all href values from <a> elements within n.
func extractHTMLLinks(n *html.Node) []string {
	var links []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "a" {
			for _, attr := range node.Attr {
				if attr.Key == "href" && strings.HasPrefix(attr.Val, "http") {
					links = append(links, attr.Val)
					break
				}
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return links
}

// slugifyRBB converts a story title to a URL-safe slug for use in SourceID.
func slugifyRBB(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	prevDash := true
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteRune('-')
			prevDash = true
		}
	}
	result := strings.TrimRight(b.String(), "-")
	if len(result) > 60 {
		result = result[:60]
	}
	return result
}
