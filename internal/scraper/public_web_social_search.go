package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
)

type SearchResult struct {
	URL          string
	Title        string
	Snippet      string
	PublishedAt  time.Time
	DiscoveryURL string
}

type SearchProvider interface {
	Search(context.Context, string, time.Time, int) ([]SearchResult, error)
}

type PublicWebSocialSearch struct {
	cfg      config.PublicWebSocialSearchConfig
	provider SearchProvider
	mu       sync.Mutex
	next     int
	polls    int
	hotNext  int
	hot      []hotSearchQuery
}

type hotSearchQuery struct {
	query     string
	expiresAt time.Time
	nextAt    time.Time
}

const (
	hotSearchQueryTTL   = 72 * time.Hour
	hotSearchRepeat     = 6 * time.Hour
	maxHotSearchQueries = 128
)

func NewPublicWebSocialSearch(cfg config.PublicWebSocialSearchConfig) *PublicWebSocialSearch {
	if cfg.Limit <= 0 {
		cfg.Limit = 25
	}
	if cfg.ResponseLimit <= 0 {
		cfg.ResponseLimit = 256 << 10
	}
	if len(cfg.QueryGroups) == 0 {
		cfg.QueryGroups = [][]string{{"CVE", "0day", "vulnerability"}, {"exploit", "proof of concept", "security advisory"}}
	}
	var provider SearchProvider
	if strings.EqualFold(cfg.Provider, "brave") {
		provider = NewBraveSearchProvider(cfg.Endpoint, cfg.APIKey, cfg.ResponseLimit)
	} else {
		provider = &legacyJSONSearchProvider{endpoint: cfg.Endpoint, maxBytes: cfg.ResponseLimit, client: &http.Client{Timeout: 20 * time.Second}}
	}
	return &PublicWebSocialSearch{cfg: cfg, provider: provider}
}

func (p *PublicWebSocialSearch) Name() string { return "public-web-social-search" }

func (p *PublicWebSocialSearch) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	if !p.cfg.Enabled || strings.TrimSpace(p.cfg.Endpoint) == "" {
		return nil, nil
	}
	p.mu.Lock()
	query := p.nextQueryLocked(time.Now())
	p.mu.Unlock()
	results, err := p.provider.Search(ctx, query, since, p.cfg.Limit)
	if err != nil {
		return nil, err
	}

	out := make([]RawItem, 0, len(results))
	for _, result := range results {
		id, canonical, ok := ParseXStatusURL(result.URL)
		if !ok {
			continue
		}
		item := RawItem{
			SourceID:    p.Name() + ":" + id,
			Source:      p.Name(),
			Title:       result.Title,
			URL:         canonical,
			Content:     result.Snippet,
			PublishedAt: result.PublishedAt,
			Discovery: &DiscoveryContext{
				Platform:        "x",
				OriginalURL:     canonical,
				DiscoveryURL:    result.DiscoveryURL,
				ContextComplete: false,
			},
		}
		if IsRelevantDiscoveryCandidate(item) {
			out = append(out, item)
		}
		if len(out) >= p.cfg.Limit {
			break
		}
	}
	return out, nil
}

func (p *PublicWebSocialSearch) nextQueryLocked(now time.Time) string {
	kept := p.hot[:0]
	for _, candidate := range p.hot {
		if candidate.expiresAt.After(now) {
			kept = append(kept, candidate)
		}
	}
	p.hot = kept
	p.polls++
	if len(p.hot) > 0 && p.polls%2 == 1 {
		for offset := 0; offset < len(p.hot); offset++ {
			index := (p.hotNext + offset) % len(p.hot)
			if p.hot[index].nextAt.After(now) {
				continue
			}
			p.hot[index].nextAt = now.Add(hotSearchRepeat)
			p.hotNext = (index + 1) % len(p.hot)
			return p.hot[index].query
		}
	}
	group := p.cfg.QueryGroups[p.next%len(p.cfg.QueryGroups)]
	p.next++
	quoted := make([]string, 0, len(group))
	for _, term := range group {
		if term = strings.TrimSpace(term); term != "" {
			quoted = append(quoted, strconv.Quote(term))
		}
	}
	return "site:x.com (" + strings.Join(quoted, " OR ") + ")"
}

// ObserveDiscoveryItems turns identifiers and technical context from other
// feeds into short-lived search queries. This gives broad polling a bounded,
// autonomous refinement lane without author or account allowlists.
func (p *PublicWebSocialSearch) ObserveDiscoveryItems(items []RawItem) {
	p.observeDiscoveryItemsAt(items, time.Now())
}

func (p *PublicWebSocialSearch) observeDiscoveryItemsAt(items []RawItem, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	existing := make(map[string]int, len(p.hot))
	for index, candidate := range p.hot {
		if candidate.expiresAt.After(now) {
			existing[candidate.query] = index
		}
	}
	for _, item := range items {
		if item.Discovery != nil || item.Source == p.Name() {
			continue
		}
		text := strings.TrimSpace(item.Title + "\n" + item.Content)
		lower := strings.ToLower(text)
		for _, identifier := range discoveryIdentifierRE.FindAllString(text, -1) {
			identifier = strings.ToUpper(identifier)
			if !strings.HasPrefix(identifier, "CVE-") && !strings.HasPrefix(identifier, "GHSA-") {
				continue
			}
			contextTerms := matchingAnchorTerms(lower, 3)
			query := "site:x.com " + strconv.Quote(identifier)
			if len(contextTerms) > 0 {
				quoted := make([]string, 0, len(contextTerms))
				for _, term := range contextTerms {
					quoted = append(quoted, strconv.Quote(term))
				}
				query += " (" + strings.Join(quoted, " OR ") + ")"
			}
			if index, ok := existing[query]; ok {
				p.hot[index].expiresAt = now.Add(hotSearchQueryTTL)
				continue
			}
			p.hot = append(p.hot, hotSearchQuery{query: query, expiresAt: now.Add(hotSearchQueryTTL), nextAt: now})
			existing[query] = len(p.hot) - 1
			if len(p.hot) > maxHotSearchQueries {
				delete(existing, p.hot[0].query)
				p.hot = p.hot[1:]
				for key, index := range existing {
					existing[key] = index - 1
				}
			}
		}
	}
}

func matchingAnchorTerms(lower string, limit int) []string {
	var out []string
	seen := map[string]bool{}
	for _, terms := range [][]string{discoveryProductTerms, discoveryMechanismTerms, discoveryImpactTerms} {
		for _, term := range terms {
			if seen[term] || !strings.Contains(lower, term) {
				continue
			}
			seen[term] = true
			out = append(out, term)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

type legacyJSONSearchProvider struct {
	endpoint string
	client   *http.Client
	maxBytes int64
}

func (p *legacyJSONSearchProvider) Search(ctx context.Context, query string, since time.Time, limit int) ([]SearchResult, error) {
	u, err := url.Parse(p.endpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("since", since.UTC().Format(time.RFC3339))
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, statusErrorf(resp.StatusCode, "public web search: %s", resp.Status)
	}
	body, err := readBoundedSearchBody(resp.Body, p.maxBytes)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Results []struct {
			URL, Title, Snippet string
			PublishedAt         time.Time `json:"published_at"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	out := make([]SearchResult, 0, len(payload.Results))
	for _, result := range payload.Results {
		out = append(out, SearchResult{URL: result.URL, Title: result.Title, Snippet: result.Snippet, PublishedAt: result.PublishedAt, DiscoveryURL: u.String()})
	}
	return out, nil
}

type BraveSearchProvider struct {
	endpoint string
	apiKey   string
	client   *http.Client
	maxBytes int64
}

func NewBraveSearchProvider(endpoint, apiKey string, maxBytes int64) SearchProvider {
	if endpoint == "" {
		endpoint = "https://api.search.brave.com/res/v1/web/search"
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && (!strings.EqualFold(req.URL.Scheme, via[0].URL.Scheme) || !strings.EqualFold(req.URL.Host, via[0].URL.Host)) {
				return fmt.Errorf("refusing cross-origin Brave Search redirect")
			}
			return nil
		},
	}
	return &BraveSearchProvider{endpoint: endpoint, apiKey: strings.TrimSpace(apiKey), maxBytes: maxBytes, client: client}
}

func (p *BraveSearchProvider) Search(ctx context.Context, query string, since time.Time, limit int) ([]SearchResult, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("public web search requires a Brave API key")
	}
	u, err := url.Parse(p.endpoint)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 20 {
		limit = 20
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("count", strconv.Itoa(limit))
	q.Set("safesearch", "off")
	if freshness := braveFreshness(since, time.Now()); freshness != "" {
		q.Set("freshness", freshness)
	}
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", p.apiKey)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, statusErrorf(resp.StatusCode, "Brave Search: %s", resp.Status)
	}
	body, err := readBoundedSearchBody(resp.Body, p.maxBytes)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Web struct {
			Results []struct {
				URL         string `json:"url"`
				Title       string `json:"title"`
				Description string `json:"description"`
				PageAge     string `json:"page_age"`
			} `json:"results"`
		} `json:"web"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decoding Brave Search response: %w", err)
	}
	out := make([]SearchResult, 0, len(payload.Web.Results))
	for _, result := range payload.Web.Results {
		published, _ := time.Parse(time.RFC3339, result.PageAge)
		out = append(out, SearchResult{URL: result.URL, Title: result.Title, Snippet: result.Description, PublishedAt: published, DiscoveryURL: u.String()})
	}
	return out, nil
}

func braveFreshness(since, now time.Time) string {
	if since.IsZero() {
		return ""
	}
	age := now.Sub(since)
	switch {
	case age <= 24*time.Hour:
		return "pd"
	case age <= 7*24*time.Hour:
		return "pw"
	case age <= 31*24*time.Hour:
		return "pm"
	case age <= 366*24*time.Hour:
		return "py"
	default:
		return ""
	}
}

func readBoundedSearchBody(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("search response exceeds %d bytes", maxBytes)
	}
	return body, nil
}
