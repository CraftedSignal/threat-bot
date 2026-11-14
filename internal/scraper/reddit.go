package scraper

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/mmcdole/gofeed"
)

// RedditScraper fetches posts from a subreddit using Reddit's RSS feed.
type RedditScraper struct {
	name      string
	subreddit string
	baseURL   string
	parser    *gofeed.Parser

	mu           sync.Mutex
	blockedUntil time.Time // Reddit's 429 told us to stay away until then
}

func newRedditScraper(name, subreddit string) *RedditScraper {
	fp := gofeed.NewParser()
	fp.Client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: &uaTransport{ua: userAgent, rt: http.DefaultTransport},
	}
	r := &RedditScraper{
		name:      name,
		subreddit: subreddit,
		baseURL:   "https://www.reddit.com",
		parser:    fp,
	}
	fp.Client.Transport.(*uaTransport).onRateLimit = r.setBlockedUntil
	return r
}

func (r *RedditScraper) setBlockedUntil(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blockedUntil = t
}

// rateLimited reports whether a 429 still tells us to wait.
func (r *RedditScraper) rateLimited() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Now().Before(r.blockedUntil)
}

func (r *RedditScraper) Name() string { return r.name }

// redditMinInterval is Reddit's observed unauthenticated per-IP budget for
// the .rss endpoint: x-ratelimit-remaining drops to 0.0 after a single
// request and x-ratelimit-reset is ~10s (confirmed live 2026-08-13). A var,
// not a const, so tests can shrink it.
var redditMinInterval = 11 * time.Second

var (
	redditGateMu      sync.Mutex
	redditNextAllowed time.Time
)

// waitForRedditSlot serializes every reddit-* scraper onto one shared
// budget. All three (netsec, blueteamsec, cybersecurity) used to poll
// concurrently and independently hit the same per-IP limit, so at least two
// of three got HTTP 429 almost every cycle regardless of how conservatively
// any single scraper behaved.
func waitForRedditSlot(ctx context.Context) error {
	redditGateMu.Lock()
	now := time.Now()
	wait := redditNextAllowed.Sub(now)
	if wait < 0 {
		wait = 0
	}
	redditNextAllowed = now.Add(wait + redditMinInterval)
	redditGateMu.Unlock()

	if wait == 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *RedditScraper) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	// Reddit said when the limit resets; polling before then only extends the
	// block. Skipping is not a failure.
	if r.rateLimited() {
		return nil, ErrPollSkipped
	}
	if err := waitForRedditSlot(ctx); err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}

	feedURL := fmt.Sprintf("%s/r/%s/.rss", r.baseURL, r.subreddit)

	feed, err := r.parser.ParseURLWithContext(feedURL, ctx)
	if err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}

	var items []RawItem
	for _, entry := range feed.Items {
		published := time.Now()
		if entry.PublishedParsed != nil {
			published = *entry.PublishedParsed
		} else if entry.UpdatedParsed != nil {
			published = *entry.UpdatedParsed
		}
		if published.After(time.Now()) {
			published = time.Now()
		}
		if published.Before(since) {
			continue
		}

		guid := entry.GUID
		if guid == "" {
			guid = entry.Link
		}

		// For link posts, the entry link is the external URL.
		// Content is the RSS description (usually HTML with the post body).
		content := entry.Description
		if entry.Content != "" {
			content = entry.Content
		}

		items = append(items, RawItem{
			SourceID:    fmt.Sprintf("%s:%s", r.name, guid),
			Source:      r.name,
			Title:       entry.Title,
			URL:         entry.Link,
			Content:     content,
			PublishedAt: published,
		})
	}

	return items, nil
}

func NewRedditNetSec() *RedditScraper {
	return newRedditScraper("reddit-netsec", "netsec")
}

func NewRedditBlueTeamSec() *RedditScraper {
	return newRedditScraper("reddit-blueteamsec", "blueteamsec")
}

func NewRedditCybersecurity() *RedditScraper {
	return newRedditScraper("reddit-cybersecurity", "cybersecurity")
}
