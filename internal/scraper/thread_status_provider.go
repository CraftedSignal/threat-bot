package scraper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ThreadStatusProvider resolves an exact public X URL through an
// x-lookup-compatible endpoint. One response populates the whole ancestry
// cache so EnrichSocialContext does not make a request per parent.
type ThreadStatusProvider struct {
	BaseURL  string
	Client   *http.Client
	MaxBytes int64
	limiter  *statusRequestLimiter

	mu         sync.RWMutex
	cache      map[string]SocialStatus
	cacheOrder []string
	cacheLimit int
}

func NewThreadStatusProvider(baseURL string, maxBytes int64, configured ...StatusProviderOptions) *ThreadStatusProvider {
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}
	options := StatusProviderOptions{DailyBudget: 20, RequestInterval: 2 * time.Second, CacheEntries: 512}
	if len(configured) > 0 {
		if configured[0].DailyBudget > 0 {
			options.DailyBudget = configured[0].DailyBudget
		}
		if configured[0].RequestInterval > 0 {
			options.RequestInterval = configured[0].RequestInterval
		}
		if configured[0].CacheEntries > 0 {
			options.CacheEntries = configured[0].CacheEntries
		}
	}
	return &ThreadStatusProvider{
		BaseURL:    strings.TrimSpace(baseURL),
		Client:     &http.Client{Timeout: 10 * time.Second},
		MaxBytes:   maxBytes,
		limiter:    newStatusRequestLimiter(options.DailyBudget, options.RequestInterval),
		cache:      make(map[string]SocialStatus),
		cacheLimit: options.CacheEntries,
	}
}

func (p *ThreadStatusProvider) FetchStatus(ctx context.Context, id string) (SocialStatus, error) {
	if !xStatusIDRE.MatchString(id) {
		return SocialStatus{}, fmt.Errorf("invalid X status ID %q", id)
	}
	p.mu.RLock()
	status, ok := p.cache[id]
	p.mu.RUnlock()
	if ok {
		return status, nil
	}
	if p.BaseURL == "" {
		return SocialStatus{}, fmt.Errorf("thread resolver URL is required")
	}

	endpoint, err := url.Parse(p.BaseURL)
	if err != nil {
		return SocialStatus{}, err
	}
	q := endpoint.Query()
	q.Set("url", "https://x.com/i/status/"+id)
	q.Set("format", "json")
	q.Set("thread", "full")
	q.Set("context", "thread")
	q.Set("replies", "off")
	q.Set("userinfo", "off")
	endpoint.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	release, err := p.limiter.begin(ctx)
	if err != nil {
		return SocialStatus{}, err
	}
	defer release()
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		p.limiter.failure(0)
		return SocialStatus{}, err
	}
	defer discardClose(resp.Body)
	if retryable := retryableHTTPStatus(resp, "thread resolver"); retryable != nil {
		var statusErr *retryableStatusError
		if errors.As(retryable, &statusErr) {
			p.limiter.failure(statusErr.retryAfter)
		}
		return SocialStatus{}, retryable
	}
	if resp.StatusCode/100 != 2 {
		p.limiter.success()
		return SocialStatus{}, fmt.Errorf("thread resolver status %s", resp.Status)
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
		return SocialStatus{}, fmt.Errorf("thread response exceeds %d bytes", limit)
	}

	var payload struct {
		Warnings []json.RawMessage `json:"warnings"`
		Posts    []struct {
			ID               string          `json:"id"`
			URL              string          `json:"url"`
			Text             string          `json:"text"`
			Author           json.RawMessage `json:"author"`
			ParentID         string          `json:"parent_id"`
			QuoteID          string          `json:"quote_id"`
			PublishedAt      string          `json:"published_at"`
			CreatedAt        string          `json:"created_at"`
			CreatedTimestamp int64           `json:"created_timestamp"`
			ReplyingTo       *struct {
				Status string `json:"status"`
			} `json:"replying_to"`
		} `json:"posts"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return SocialStatus{}, fmt.Errorf("decoding thread response: %w", err)
	}
	if len(payload.Posts) == 0 {
		return SocialStatus{}, fmt.Errorf("thread response contained no posts")
	}
	if len(payload.Posts) > 8 {
		return SocialStatus{}, fmt.Errorf("thread response contained more than 8 posts")
	}
	sort.SliceStable(payload.Posts, func(i, j int) bool {
		iTime := parseThreadTimestamp(payload.Posts[i].PublishedAt, payload.Posts[i].CreatedAt, payload.Posts[i].CreatedTimestamp)
		jTime := parseThreadTimestamp(payload.Posts[j].PublishedAt, payload.Posts[j].CreatedAt, payload.Posts[j].CreatedTimestamp)
		if !iTime.IsZero() && !jTime.IsZero() && !iTime.Equal(jTime) {
			return iTime.Before(jTime)
		}
		return statusIDLess(payload.Posts[i].ID, payload.Posts[j].ID)
	})

	decoded := make(map[string]SocialStatus, len(payload.Posts))
	ordered := make([]SocialStatus, 0, len(payload.Posts))
	previousID := ""
	for _, post := range payload.Posts {
		if !xStatusIDRE.MatchString(post.ID) {
			return SocialStatus{}, fmt.Errorf("thread response contained invalid status ID %q", post.ID)
		}
		returnedID, canonical, validURL := ParseXStatusURL(post.URL)
		if !validURL || returnedID != post.ID {
			return SocialStatus{}, fmt.Errorf("thread response URL did not match status %q", post.ID)
		}
		parentID := post.ParentID
		if parentID == "" && post.ReplyingTo != nil {
			parentID = post.ReplyingTo.Status
		}
		if parentID != "" && !xStatusIDRE.MatchString(parentID) {
			return SocialStatus{}, fmt.Errorf("thread response contained invalid parent ID %q", parentID)
		}
		if post.QuoteID != "" && !xStatusIDRE.MatchString(post.QuoteID) {
			return SocialStatus{}, fmt.Errorf("thread response contained invalid quote ID %q", post.QuoteID)
		}
		if parentID == "" {
			parentID = previousID
		}
		published := parseThreadTimestamp(post.PublishedAt, post.CreatedAt, post.CreatedTimestamp)
		status := SocialStatus{
			ID: post.ID, URL: canonical, Author: threadAuthor(post.Author), Text: strings.TrimSpace(post.Text),
			ParentID: parentID, QuoteID: post.QuoteID, PublishedAt: published, Incomplete: len(payload.Warnings) > 0,
		}
		decoded[post.ID] = status
		ordered = append(ordered, status)
		previousID = post.ID
	}
	requested, found := decoded[id]
	if !found {
		return SocialStatus{}, fmt.Errorf("thread response did not contain requested status %q", id)
	}
	p.mu.Lock()
	for _, value := range ordered {
		p.putCacheLocked(value)
	}
	p.mu.Unlock()
	return requested, nil
}

func (p *ThreadStatusProvider) putCacheLocked(value SocialStatus) {
	if _, exists := p.cache[value.ID]; exists {
		p.cache[value.ID] = value
		return
	}
	for p.cacheLimit > 0 && len(p.cacheOrder) >= p.cacheLimit {
		delete(p.cache, p.cacheOrder[0])
		p.cacheOrder = p.cacheOrder[1:]
	}
	p.cache[value.ID] = value
	p.cacheOrder = append(p.cacheOrder, value.ID)
}

func statusIDLess(left, right string) bool {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if len(left) != len(right) {
		return len(left) < len(right)
	}
	return left < right
}

func parseThreadTimestamp(publishedAt, createdAt string, unixSeconds int64) time.Time {
	for _, candidate := range []string{publishedAt, createdAt} {
		for _, layout := range []string{time.RFC3339, "Mon Jan 02 15:04:05 -0700 2006"} {
			if parsed, err := time.Parse(layout, candidate); err == nil {
				return parsed
			}
		}
	}
	if unixSeconds > 0 {
		return time.Unix(unixSeconds, 0).UTC()
	}
	return time.Time{}
}

func threadAuthor(raw json.RawMessage) string {
	var handle string
	if err := json.Unmarshal(raw, &handle); err == nil {
		return strings.TrimPrefix(strings.TrimSpace(handle), "@")
	}
	var author struct {
		ScreenName string `json:"screen_name"`
		Handle     string `json:"handle"`
	}
	if err := json.Unmarshal(raw, &author); err != nil {
		return ""
	}
	if author.ScreenName != "" {
		return strings.TrimPrefix(author.ScreenName, "@")
	}
	return strings.TrimPrefix(author.Handle, "@")
}
