package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"golang.org/x/net/html"

	"github.com/craftedsignal/threat-bot/internal/urlsafe"
)

// BridgedSocial ingests a social account that publishes nothing but pointers:
// a sentence of commentary plus a link to someone else's report. Such accounts
// have no first-party feed (LinkedIn company pages are auth-walled and have no
// RSS), so the feed URL comes from a third-party bridge and is supplied by
// config rather than hardcoded.
//
// The one piece of real work is URL rewriting. Bridges set <link> to the social
// permalink, which is useless downstream: ContentEnricher would re-fetch the
// auth wall and the item would die at the thin-content gate. Promoting the
// outbound story link to RawItem.URL instead means enrichment pulls the real
// report, briefs cite it, and dedup collapses the item onto the publisher's own
// draft when threat-bot already has it.
type BridgedSocial struct {
	name     string
	feedURL  string
	postHost string // platform whose permalinks are not the story, e.g. "linkedin.com"
	parser   *gofeed.Parser
	client   *http.Client

	// shorteners lists hosts whose redirects are resolved at poll time.
	// allowURL guards each redirect hop. Both are fields so tests can point
	// them at a local server; production uses the defaults below.
	shorteners map[string]bool
	allowURL   func(string) bool
}

const (
	// Bridges respond fast — they serve a cached render, not a live scrape.
	bridgedFeedTimeout = 60 * time.Second
	shortlinkTimeout   = 10 * time.Second
	// Allows up to 3 redirects plus the request that confirms the final URL.
	maxShortlinkHops = 4
)

// defaultShorteners are link wrappers whose target must be resolved before the
// URL is stored. LinkedIn rewrites every outbound link to lnkd.in; enrichment
// would follow the redirect anyway, but dedup hashes RawItem.URL, so an
// unresolved shortlink never collapses against the same article arriving from
// its publisher's own feed.
var defaultShorteners = map[string]bool{
	"lnkd.in": true,
	"bit.ly":  true,
	"t.co":    true,
	"ow.ly":   true,
	"buff.ly": true,
}

// bridgeShimHosts are the bridges' own tracking and permalink hosts. They show
// up in post bodies and are never the story.
var bridgeShimHosts = []string{"rss.app", "fetchrss.com", "feedly.com"}

var bridgedURLRe = regexp.MustCompile(`https?://[^\s<>"')\]]+`)

func NewBridgedSocial(name, feedURL, postHost string) *BridgedSocial {
	fp := gofeed.NewParser()
	fp.Client = &http.Client{
		Timeout:   bridgedFeedTimeout,
		Transport: &uaTransport{ua: browserUserAgent, rt: rssHTTPTransport()},
	}
	return &BridgedSocial{
		name:     name,
		feedURL:  feedURL,
		postHost: strings.ToLower(postHost),
		parser:   fp,
		client: &http.Client{
			Timeout:   shortlinkTimeout,
			Transport: urlsafe.NewHTTPTransport(),
			// Inspect every hop instead of following blindly: each target has
			// to clear the SSRF guard before we request it.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		shorteners: defaultShorteners,
		allowURL:   urlsafe.IsPublicHTTPURL,
	}
}

func (b *BridgedSocial) Name() string { return b.name }

func (b *BridgedSocial) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	feed, err := b.parser.ParseURLWithContext(b.feedURL, ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", b.name, err)
	}

	var items []RawItem
	for _, entry := range feed.Items {
		published := time.Now()
		if entry.PublishedParsed != nil {
			published = *entry.PublishedParsed
		} else if entry.UpdatedParsed != nil {
			published = *entry.UpdatedParsed
		}
		// Clamp future dates to now (scheduled/pre-published posts).
		if published.After(time.Now()) {
			published = time.Now()
		}
		if published.Before(since) {
			continue
		}

		permalink := entry.Link
		body := entry.Description
		if entry.Content != "" {
			if body != "" {
				body += "\n\n"
			}
			body += entry.Content
		}

		// Fall back to the permalink when a post carries no outbound link.
		// Enrichment then no-ops and the thin-content gate drops it, which is
		// the right outcome for commentary-only posts.
		storyURL := permalink
		if out := firstOutboundLink(body, b.postHost); out != "" {
			storyURL = b.resolveShortlink(ctx, out)
		}

		guid := entry.GUID
		if guid == "" {
			guid = permalink
		}

		items = append(items, RawItem{
			SourceID:    fmt.Sprintf("%s:%s", b.name, guid),
			Source:      b.name,
			Title:       stripBridgeTitlePrefix(entry.Title, b.postHost),
			URL:         storyURL,
			Content:     body,
			PublishedAt: published,
			// The permalink is hashed by sourceURLHashesForRawItem alongside
			// URL, so it participates in dedup and keeps provenance.
			Metadata: map[string]string{
				"permalink": permalink,
				"curator":   b.name,
			},
		})
	}

	return items, nil
}

// firstOutboundLink returns the first link in body that points somewhere other
// than the social platform itself or the bridge. Empty when there is none.
func firstOutboundLink(body, postHost string) string {
	for _, candidate := range outboundCandidates(body) {
		u, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" || hostMatches(host, postHost) {
			continue
		}
		if isBridgeShimHost(host) {
			continue
		}
		return candidate
	}
	return ""
}

// outboundCandidates collects candidate links in document order: <a> hrefs and
// bare URLs sitting in text. Both shapes occur — bridges sometimes render the
// post as an anchor and sometimes leave the raw URL as text. Attributes other
// than href are ignored so tracking pixels and <img> sources never win.
func outboundCandidates(body string) []string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var candidates []string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.ElementNode:
			if n.Data == "a" {
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						if trimmed := trimBridgedURL(attr.Val); trimmed != "" {
							candidates = append(candidates, trimmed)
						}
						break
					}
				}
			}
		case html.TextNode:
			for _, match := range bridgedURLRe.FindAllString(n.Data, -1) {
				if trimmed := trimBridgedURL(match); trimmed != "" {
					candidates = append(candidates, trimmed)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	return candidates
}

// trimBridgedURL strips sentence punctuation that trails a bare URL in prose.
func trimBridgedURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), `.,;:!?'"()[]`)
}

// hostMatches reports whether host is postHost or a subdomain of it, so a post
// linking to another post on the same platform is not mistaken for a story.
func hostMatches(host, postHost string) bool {
	return host == postHost || strings.HasSuffix(host, "."+postHost)
}

func isBridgeShimHost(host string) bool {
	for _, shim := range bridgeShimHosts {
		if hostMatches(host, shim) {
			return true
		}
	}
	return false
}

// stripBridgeTitlePrefix removes the "<Company> on LinkedIn: " prefix bridges
// prepend to every item. Left in place it defeats the NormalizeTitleHash dedup
// fallback, because the publisher's own feed carries the bare headline.
func stripBridgeTitlePrefix(title, postHost string) string {
	label := postHost
	if i := strings.Index(label, "."); i > 0 {
		label = label[:i]
	}
	needle := " on " + label + ": "
	// Require a non-empty company name before the needle, so a headline that
	// merely happens to contain the phrase is left alone.
	if i := strings.Index(strings.ToLower(title), strings.ToLower(needle)); i > 0 {
		return strings.TrimSpace(title[i+len(needle):])
	}
	return strings.TrimSpace(title)
}

// resolveShortlink follows a link-wrapper redirect chain to the canonical URL.
// It returns rawURL unchanged for non-shortener hosts, on any error, when a hop
// fails the SSRF guard, or when the hop cap trips. No response body is ever
// read, so a hostile chain costs at worst a blind request to a public address.
func (b *BridgedSocial) resolveShortlink(ctx context.Context, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if !b.shorteners[strings.ToLower(u.Hostname())] {
		return rawURL
	}
	if !b.allowURL(rawURL) {
		return rawURL
	}

	current := rawURL
	for hop := 0; hop < maxShortlinkHops; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, current, nil)
		if err != nil {
			return rawURL
		}
		req.Header.Set("User-Agent", browserUserAgent)

		resp, err := b.client.Do(req)
		if err != nil {
			return rawURL
		}
		_ = resp.Body.Close()

		location := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || location == "" {
			return current
		}

		base, err := url.Parse(current)
		if err != nil {
			return rawURL
		}
		next, err := base.Parse(location)
		if err != nil {
			return rawURL
		}
		if !b.allowURL(next.String()) {
			return rawURL
		}
		current = next.String()
	}

	return rawURL
}
