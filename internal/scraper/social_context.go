package scraper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type SocialStatus struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Author      string    `json:"author"`
	Text        string    `json:"text"`
	ParentID    string    `json:"parent_id"`
	QuoteID     string    `json:"quote_id"`
	PublishedAt time.Time `json:"published_at"`
	// Incomplete is true when the provider can resolve only this leaf and
	// cannot determine whether parents or quotes are missing.
	Incomplete bool `json:"incomplete"`
}
type StatusProvider interface {
	FetchStatus(context.Context, string) (SocialStatus, error)
}

var (
	xStatusRE   = regexp.MustCompile(`^/[^/]+/status/(\d+)(?:/.*)?$`)
	xStatusIDRE = regexp.MustCompile(`^\d+$`)
)

func ParseXStatusURL(raw string) (string, string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", false
	}
	host := strings.ToLower(u.Hostname())
	if host != "x.com" && host != "www.x.com" && host != "mobile.x.com" && host != "twitter.com" && host != "www.twitter.com" && host != "mobile.twitter.com" {
		return "", "", false
	}
	m := xStatusRE.FindStringSubmatch(u.Path)
	if len(m) != 2 {
		return "", "", false
	}
	return m[1], "https://x.com/i/status/" + m[1], true
}

type providerChain struct{ providers []StatusProvider }

func NewProviderChain(p []StatusProvider) StatusProvider { return &providerChain{providers: p} }
func (p *providerChain) FetchStatus(ctx context.Context, id string) (SocialStatus, error) {
	var errs []error
	for _, provider := range p.providers {
		s, err := provider.FetchStatus(ctx, id)
		if err == nil && s.ID == id {
			return s, nil
		}
		if err == nil {
			err = fmt.Errorf("resolver returned status %q for %q", s.ID, id)
		}
		errs = append(errs, err)
	}
	return SocialStatus{}, errors.Join(errs...)
}

type HTTPStatusProvider struct {
	BaseURL  string
	Client   *http.Client
	MaxBytes int64
}

type OEmbedStatusProvider struct {
	BaseURL  string
	Client   *http.Client
	MaxBytes int64
	limiter  *statusRequestLimiter
}

func NewOEmbedStatusProvider(baseURL string, maxBytes int64, configured ...StatusProviderOptions) StatusProvider {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://publish.x.com/oembed"
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}
	options := StatusProviderOptions{DailyBudget: 100, RequestInterval: 2 * time.Second}
	if len(configured) > 0 {
		if configured[0].DailyBudget > 0 {
			options.DailyBudget = configured[0].DailyBudget
		}
		if configured[0].RequestInterval > 0 {
			options.RequestInterval = configured[0].RequestInterval
		}
	}
	return &OEmbedStatusProvider{BaseURL: baseURL, MaxBytes: maxBytes, Client: &http.Client{Timeout: 5 * time.Second}, limiter: newStatusRequestLimiter(options.DailyBudget, options.RequestInterval)}
}

func (p *OEmbedStatusProvider) FetchStatus(ctx context.Context, id string) (SocialStatus, error) {
	if !xStatusIDRE.MatchString(id) {
		return SocialStatus{}, fmt.Errorf("invalid X status ID %q", id)
	}
	base, err := url.Parse(p.BaseURL)
	if err != nil {
		return SocialStatus{}, err
	}
	q := base.Query()
	q.Set("url", "https://x.com/i/status/"+id)
	q.Set("omit_script", "true")
	q.Set("dnt", "true")
	base.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	release, err := p.limiter.begin(ctx)
	if err != nil {
		return SocialStatus{}, err
	}
	defer release()
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		p.limiter.failure(0)
		return SocialStatus{}, err
	}
	defer discardClose(resp.Body)
	if retryable := retryableHTTPStatus(resp, "oEmbed resolver"); retryable != nil {
		var statusErr *retryableStatusError
		_ = errors.As(retryable, &statusErr)
		p.limiter.failure(statusErr.retryAfter)
		return SocialStatus{}, retryable
	}
	if resp.StatusCode/100 != 2 {
		p.limiter.success()
		return SocialStatus{}, fmt.Errorf("oEmbed resolver status %s", resp.Status)
	}
	p.limiter.success()
	limit := p.MaxBytes
	if limit <= 0 {
		limit = 256 << 10
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return SocialStatus{}, err
	}
	if int64(len(body)) > limit {
		return SocialStatus{}, fmt.Errorf("oEmbed response exceeds %d bytes", limit)
	}
	var payload struct {
		URL        string `json:"url"`
		AuthorURL  string `json:"author_url"`
		AuthorName string `json:"author_name"`
		HTML       string `json:"html"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return SocialStatus{}, fmt.Errorf("decoding oEmbed response: %w", err)
	}
	returnedID, canonical, ok := ParseXStatusURL(payload.URL)
	if !ok || returnedID != id {
		return SocialStatus{}, fmt.Errorf("oEmbed returned status %q for %q", returnedID, id)
	}
	text, err := oEmbedPostText(payload.HTML)
	if err != nil {
		return SocialStatus{}, err
	}
	author := strings.Trim(strings.TrimSpace(mustURLPath(payload.AuthorURL)), "/")
	if strings.Contains(author, "/") {
		author = strings.Split(author, "/")[0]
	}
	return SocialStatus{ID: id, URL: canonical, Author: author, Text: text, Incomplete: true}, nil
}

func mustURLPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

func oEmbedPostText(raw string) (string, error) {
	doc, err := html.Parse(strings.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("parsing oEmbed HTML: %w", err)
	}
	var paragraph *html.Node
	var find func(*html.Node)
	find = func(n *html.Node) {
		if paragraph != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "p" {
			paragraph = n
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			find(child)
		}
	}
	find(doc)
	if paragraph == nil {
		return "", fmt.Errorf("oEmbed response contained no post text")
	}
	var out strings.Builder
	var render func(*html.Node)
	render = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			out.WriteString(n.Data)
		case html.ElementNode:
			if n.Data == "br" {
				out.WriteByte('\n')
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			render(child)
		}
	}
	render(paragraph)
	text := strings.TrimSpace(out.String())
	if text == "" {
		return "", fmt.Errorf("oEmbed response contained empty post text")
	}
	return text, nil
}

func (p *HTTPStatusProvider) FetchStatus(ctx context.Context, id string) (SocialStatus, error) {
	base, err := url.Parse(p.BaseURL)
	if err != nil {
		return SocialStatus{}, err
	}
	q := base.Query()
	q.Set("id", id)
	base.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return SocialStatus{}, err
	}
	defer discardClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return SocialStatus{}, fmt.Errorf("resolver status %s", resp.Status)
	}
	limit := p.MaxBytes
	if limit <= 0 {
		limit = 256 << 10
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return SocialStatus{}, err
	}
	if int64(len(body)) > limit {
		return SocialStatus{}, fmt.Errorf("resolver response exceeds %d bytes", limit)
	}
	var s SocialStatus
	if err = json.Unmarshal(body, &s); err != nil {
		return SocialStatus{}, err
	}
	return s, nil
}

func EnrichSocialContext(ctx context.Context, p StatusProvider, item RawItem, maxDepth int) RawItem {
	if p == nil {
		return item
	}
	id, canonical, ok := ParseXStatusURL(item.URL)
	if !ok {
		for _, word := range strings.Fields(item.Content) {
			if parsed, can, yes := ParseXStatusURL(strings.Trim(word, "()[]{}<>,.;\"'")); yes {
				id, canonical, ok = parsed, can, true
				break
			}
		}
	}
	if !ok {
		return item
	}
	if maxDepth <= 0 {
		maxDepth = 6
	}
	if item.Discovery == nil {
		item.Discovery = &DiscoveryContext{Platform: "x", OriginalURL: canonical, DiscoveryURL: item.URL}
	}
	seen := map[string]bool{}
	var blocks, parentURLs, quoteURLs []string
	complete := true
	current := id
	for depth := 0; current != "" && depth < maxDepth; depth++ {
		if seen[current] {
			complete = false
			break
		}
		seen[current] = true
		s, err := p.FetchStatus(ctx, current)
		if err != nil {
			complete = false
			break
		}
		if s.URL == "" {
			s.URL = "https://x.com/i/status/" + s.ID
		}
		if s.Incomplete {
			complete = false
		}
		blocks = append(blocks, s.Text)
		if depth == 0 {
			item.Discovery.Author = s.Author
		} else {
			parentURLs = append(parentURLs, s.URL)
		}
		if s.QuoteID != "" && !seen[s.QuoteID] {
			q, err := p.FetchStatus(ctx, s.QuoteID)
			if err == nil {
				if q.URL == "" {
					q.URL = "https://x.com/i/status/" + q.ID
				}
				blocks = append(blocks, q.Text)
				quoteURLs = append(quoteURLs, q.URL)
				seen[s.QuoteID] = true
				if q.Incomplete || q.ParentID != "" || q.QuoteID != "" {
					complete = false
				}
			} else {
				complete = false
			}
		}
		current = s.ParentID
		if depth == maxDepth-1 && current != "" {
			complete = false
		}
	}
	if len(blocks) > 0 {
		for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
			blocks[i], blocks[j] = blocks[j], blocks[i]
		}
		item.Content = strings.Join(blocks, "\n\n") + "\n\n" + item.Content
	}
	item.Discovery.ParentURLs = parentURLs
	item.Discovery.QuoteURLs = quoteURLs
	item.Discovery.ContextComplete = complete
	return item
}
