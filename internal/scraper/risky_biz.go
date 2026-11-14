package scraper

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"golang.org/x/net/html"
)

const riskyBizPodcastFeed = "https://risky.biz/feeds/risky-business/"

// RiskyBiz fetches the main Risky Business podcast feed and emits one RawItem
// per show note link rather than one item per full episode. This prevents
// buried stories from being invisible to the quality gate and lets the
// content enricher fetch the original article for each link.
type RiskyBiz struct {
	parser  *gofeed.Parser
	feedURL string
}

func NewRiskyBiz() *RiskyBiz {
	fp := gofeed.NewParser()
	fp.Client = &http.Client{
		Timeout:   180 * time.Second,
		Transport: &uaTransport{ua: userAgent, rt: rssHTTPTransport()},
	}
	return &RiskyBiz{parser: fp, feedURL: riskyBizPodcastFeed}
}

func (r *RiskyBiz) Name() string { return "risky-biz" }

func (r *RiskyBiz) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	feed, err := r.parser.ParseURLWithContext(r.feedURL, ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching risky-biz podcast feed: %w", err)
	}

	var items []RawItem
	for _, fi := range feed.Items {
		if fi.PublishedParsed == nil || fi.PublishedParsed.Before(since) {
			continue
		}
		content := fi.Description
		if content == "" {
			content = fi.Content
		}
		stories, err := parseRiskyBizEpisode(content, fi.Link, *fi.PublishedParsed)
		if err != nil {
			continue
		}
		items = append(items, stories...)
	}
	return items, nil
}

// parseRiskyBizEpisode parses the description HTML of a single podcast episode
// and returns one RawItem per show note link found after the "Show notes" heading.
func parseRiskyBizEpisode(content, episodeURL string, pubDate time.Time) ([]RawItem, error) {
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return nil, err
	}

	dateStr := pubDate.UTC().Format("20060102")
	introText := extractRiskyBizIntro(doc)

	var items []RawItem
	var inShowNotes bool

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "h3":
				text := strings.TrimSpace(extractHTMLText(n))
				if strings.Contains(strings.ToLower(text), "show notes") {
					inShowNotes = true
				}
				return // don't recurse into h3
			case "ul", "ol":
				if !inShowNotes {
					break
				}
				// Collect direct li children that contain a link.
				for li := n.FirstChild; li != nil; li = li.NextSibling {
					if li.Type != html.ElementNode || li.Data != "li" {
						continue
					}
					link := findFirstLink(li)
					if link == nil {
						continue
					}
					url := link.n.Attr[link.hrefIdx].Val
					if !strings.HasPrefix(url, "http") {
						continue
					}
					title := strings.TrimSpace(extractHTMLText(link.n))
					if title == "" {
						continue
					}

					var sb strings.Builder
					if introText != "" {
						fmt.Fprintf(&sb, "Episode context:\n%s\n\n", introText)
					}
					fmt.Fprintf(&sb, "Show note: %s\n%s", title, url)

					items = append(items, RawItem{
						SourceID:    fmt.Sprintf("risky-biz:%s:%s", dateStr, slugifyRBP(title)),
						Source:      "risky-biz",
						Title:       title,
						URL:         url,
						Content:     sb.String(),
						PublishedAt: pubDate,
					})
				}
				return // don't recurse into the list after processing
			}
		}
		if !inShowNotes || n.Data != "ul" && n.Data != "ol" {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
	}
	walk(doc)
	return items, nil
}

// extractRiskyBizIntro returns the plain text of the episode description before
// the "Show notes" heading.
func extractRiskyBizIntro(doc *html.Node) string {
	var parts []string
	var skip bool

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "h3" {
			text := strings.TrimSpace(extractHTMLText(n))
			if strings.Contains(strings.ToLower(text), "show notes") {
				skip = true
			}
			return
		}
		if skip {
			return
		}
		if n.Type == html.TextNode {
			parts = append(parts, n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	text := strings.Join(parts, "")
	text = strings.ReplaceAll(text, "\n", " ")
	re := regexp.MustCompile(`\s{2,}`)
	text = re.ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

// linkResult holds an <a> node and the index of its href attribute.
type linkResult struct {
	n       *html.Node
	hrefIdx int
}

// findFirstLink returns the first <a> element inside n that has an http(s) href.
func findFirstLink(n *html.Node) *linkResult {
	var walk func(*html.Node) *linkResult
	walk = func(node *html.Node) *linkResult {
		if node.Type == html.ElementNode && node.Data == "a" {
			for i, attr := range node.Attr {
				if attr.Key == "href" && strings.HasPrefix(attr.Val, "http") {
					return &linkResult{n: node, hrefIdx: i}
				}
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			if r := walk(c); r != nil {
				return r
			}
		}
		return nil
	}
	return walk(n)
}

// slugifyRBP converts a show note title to a URL-safe slug for use in SourceID.
func slugifyRBP(s string) string {
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
