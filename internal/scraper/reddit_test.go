package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"
)

func rssAtomFeed(entries []struct {
	id, title, link, content string
	published                time.Time
}) string {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>test</title>`
	for _, e := range entries {
		body += fmt.Sprintf(`
<entry>
  <id>%s</id>
  <title>%s</title>
  <link href="%s"/>
  <content type="html">%s</content>
  <updated>%s</updated>
</entry>`, e.id, e.title, e.link, e.content, e.published.Format(time.RFC3339))
	}
	body += "\n</feed>"
	return body
}

func TestRedditScraper(t *testing.T) {
	now := time.Now().UTC()

	entries := []struct {
		id, title, link, content string
		published                time.Time
	}{
		{
			id:        "t3_abc123",
			title:     "New RCE in popular library",
			link:      "https://example.com/vuln",
			content:   "Details about the vulnerability",
			published: now,
		},
		{
			id:        "t3_def456",
			title:     "Discussion about security tools",
			link:      "https://www.reddit.com/r/netsec/comments/def456/discussion/",
			content:   "What tools do you use for pen testing?",
			published: now,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Error("expected User-Agent header to be set")
		}
		w.Header().Set("Content-Type", "application/atom+xml")
		fmt.Fprint(w, rssAtomFeed(entries))
	}))
	defer srv.Close()

	s := newRedditScraper("reddit-netsec", "netsec")
	// Override the parser to use our test server.
	s.parser.Client = srv.Client()
	items, err := s.parser.ParseURLWithContext(srv.URL, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items.Items))
	}

	// Test via Poll with a real server that serves on the expected path.
	srvPoll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/atom+xml")
		fmt.Fprint(w, rssAtomFeed(entries))
	}))
	defer srvPoll.Close()

	// Patch the subreddit to route to test server — use the RSS struct directly.
	rss := NewRSS("reddit-netsec", srvPoll.URL)
	rssItems, err := rss.Poll(context.Background(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rssItems) != 2 {
		t.Fatalf("expected 2 items, got %d", len(rssItems))
	}
	if rssItems[0].Title != "New RCE in popular library" {
		t.Errorf("unexpected title: %s", rssItems[0].Title)
	}
}

func TestRedditScraperFiltersSince(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour).UTC()
	recent := time.Now().UTC()

	entries := []struct {
		id, title, link, content string
		published                time.Time
	}{
		{id: "t3_old", title: "Old post", link: "https://example.com/old", published: old},
		{id: "t3_new", title: "New post", link: "https://example.com/new", published: recent},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/atom+xml")
		fmt.Fprint(w, rssAtomFeed(entries))
	}))
	defer srv.Close()

	rss := NewRSS("reddit-netsec", srv.URL)
	items, err := rss.Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item (old filtered out), got %d", len(items))
	}
	if items[0].Title != "New post" {
		t.Errorf("expected recent post, got: %s", items[0].Title)
	}
}

// Reddit's unauthenticated .rss endpoint allows roughly one request per ~10s
// per source IP (x-ratelimit-remaining hits 0.0 after a single hit, reset
// ~10s later — confirmed live 2026-08-13). The three reddit-* scrapers used
// to fire concurrently every poll cycle with no coordination, so at least
// two of three got HTTP 429 on almost every cycle. They must share one gate.
func TestRedditScrapersShareRateGate(t *testing.T) {
	origInterval := redditMinInterval
	redditMinInterval = 80 * time.Millisecond
	redditNextAllowed = time.Time{}
	defer func() {
		redditMinInterval = origInterval
		redditNextAllowed = time.Time{}
	}()

	var mu sync.Mutex
	var hits []time.Time

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, time.Now())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/atom+xml")
		fmt.Fprint(w, rssAtomFeed(nil))
	}))
	defer srv.Close()

	scrapers := []*RedditScraper{
		newRedditScraper("reddit-netsec", "netsec"),
		newRedditScraper("reddit-blueteamsec", "blueteamsec"),
		newRedditScraper("reddit-cybersecurity", "cybersecurity"),
	}
	for _, s := range scrapers {
		s.baseURL = srv.URL
		s.parser.Client = srv.Client()
	}

	var wg sync.WaitGroup
	for _, s := range scrapers {
		wg.Add(1)
		go func(s *RedditScraper) {
			defer wg.Done()
			if _, err := s.Poll(context.Background(), time.Now().Add(-time.Hour)); err != nil {
				t.Errorf("Poll (%s): %v", s.Name(), err)
			}
		}(s)
	}
	wg.Wait()

	if len(hits) != 3 {
		t.Fatalf("expected 3 requests to reach the server, got %d", len(hits))
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Before(hits[j]) })
	for i := 1; i < len(hits); i++ {
		if gap := hits[i].Sub(hits[i-1]); gap < redditMinInterval-10*time.Millisecond {
			t.Errorf("requests %d and %d landed %v apart, want >= %v", i-1, i, gap, redditMinInterval)
		}
	}
}
