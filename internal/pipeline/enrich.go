package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/urlsafe"
)

const (
	// Fetch full content when an RSS entry has less than this much text.
	minContentLength = 500
	// Excerpts often exceed the thin-content threshold while omitting the
	// finding itself. Keep full-article fetching bounded to short entries.
	maxExcerptLength = 3000
	// Max bytes to read from a page.
	maxFetchBytes = 512 * 1024
	// Request timeout for enrichment fetches.
	enrichTimeout            = 15 * time.Second
	enrichUserAgent          = "threat-bot/1.0"
	enrichBrowserUserAgent   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	maxVendorAdvisoryFetches = 2
)

var (
	reScript     = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyle      = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reTag        = regexp.MustCompile(`<[^>]+>`)
	reWhitespace = regexp.MustCompile(`\s{3,}`)
)

// ContentEnricher fetches full article text for thin items and RSS excerpts.
type ContentEnricher struct {
	client *http.Client
}

func NewContentEnricher() *ContentEnricher {
	return &ContentEnricher{
		client: &http.Client{
			Timeout:   enrichTimeout,
			Transport: urlsafe.NewHTTPTransport(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				if !urlsafe.IsPublicHTTPURL(req.URL.String()) {
					return fmt.Errorf("redirect target is not a safe public HTTP URL")
				}
				return nil
			},
		},
	}
}

// Enrich fetches the full page content for thin items or marked excerpts.
// It modifies items in place.
func (e *ContentEnricher) Enrich(ctx context.Context, item *scraper.RawItem) []error {
	advisoryURLs := nvdVendorAdvisoryURLs(*item)
	if !shouldEnrich(*item) && len(advisoryURLs) == 0 {
		return nil
	}
	item.Enriched = true
	required := item.NeedsFullArticle
	var appended []string
	var enrichmentErrors []error
	if len(advisoryURLs) > 0 {
		for _, advisoryURL := range advisoryURLs {
			text, err := e.fetchText(ctx, advisoryURL)
			if err == nil && strings.TrimSpace(text) != "" {
				appended = append(appended, "Vendor advisory ("+advisoryURL+"):\n"+text)
			} else if err != nil {
				enrichmentErrors = append(enrichmentErrors, fmt.Errorf("fetching vendor advisory %s: %w", advisoryURL, err))
			}
		}
		if len(appended) > 0 {
			item.Content += "\n\n---\n\n" + strings.Join(appended, "\n\n---\n\n")
			item.NeedsFullArticle = false
		}
		return enrichmentErrors
	}
	if item.URL == "" || !urlsafe.IsPublicHTTPURL(item.URL) {
		return nil
	}

	text, err := e.fetchText(ctx, item.URL)
	if err != nil || (!required && len(text) < len(item.Content)) {
		return nil
	}
	item.NeedsFullArticle = false

	// Prepend original content (RSS summary) then the full page text.
	if item.Content != "" {
		item.Content = item.Content + "\n\n---\n\n" + text
	} else {
		item.Content = text
	}
	return nil
}

func nvdVendorAdvisoryURLs(item scraper.RawItem) []string {
	if item.Enriched || !strings.EqualFold(strings.TrimSpace(item.Source), "nvd") || len(item.Content) >= minContentLength {
		return nil
	}
	var urls []string
	if err := json.Unmarshal([]byte(item.Metadata["vendor_advisory_urls"]), &urls); err != nil {
		return nil
	}
	seen := make(map[string]bool, len(urls))
	out := make([]string, 0, min(len(urls), maxVendorAdvisoryFetches))
	for _, raw := range urls {
		u := strings.TrimSpace(raw)
		if !urlsafe.IsPublicHTTPURL(u) || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
		if len(out) == maxVendorAdvisoryFetches {
			break
		}
	}
	return out
}

func shouldEnrich(item scraper.RawItem) bool {
	if item.Enriched {
		return false
	}
	if item.NeedsFullArticle {
		return true
	}
	if len(item.Content) < minContentLength {
		return true
	}
	return len(item.Content) < maxExcerptLength && strings.Contains(strings.ToLower(item.Content), "read full article")
}

func (e *ContentEnricher) fetchText(ctx context.Context, url string) (string, error) {
	text, status, err := e.fetchTextWithUA(ctx, url, enrichUserAgent)
	if err == nil {
		return text, nil
	}
	if status == http.StatusForbidden || status == http.StatusTooManyRequests {
		text, _, err = e.fetchTextWithUA(ctx, url, enrichBrowserUserAgent)
		return text, err
	}
	return "", err
}

func (e *ContentEnricher) fetchTextWithUA(ctx context.Context, url, userAgent string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html")

	resp, err := e.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	// Closing a response body only releases the connection after its result is handled.
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Only process HTML responses.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "text/xml") && ct != "" {
		return "", resp.StatusCode, fmt.Errorf("not HTML: %s", ct)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return "", resp.StatusCode, err
	}

	return htmlToText(string(body)), resp.StatusCode, nil
}

func htmlToText(html string) string {
	// Remove script and style blocks.
	text := reScript.ReplaceAllString(html, "")
	text = reStyle.ReplaceAllString(text, "")

	// Convert common block elements to newlines.
	for _, tag := range []string{"</p>", "</div>", "</li>", "<br>", "<br/>", "<br />"} {
		text = strings.ReplaceAll(text, tag, "\n")
	}

	// Strip remaining HTML tags.
	text = reTag.ReplaceAllString(text, "")

	// Decode common HTML entities.
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	text = strings.ReplaceAll(text, "&#39;", "'")
	text = strings.ReplaceAll(text, "&nbsp;", " ")

	// Collapse excessive whitespace.
	text = reWhitespace.ReplaceAllString(text, "\n\n")
	text = strings.TrimSpace(text)

	return text
}
