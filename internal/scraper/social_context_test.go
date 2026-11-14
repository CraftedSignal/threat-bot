package scraper

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeStatusProvider struct {
	statuses map[string]SocialStatus
	err      error
}

func (f fakeStatusProvider) FetchStatus(_ context.Context, id string) (SocialStatus, error) {
	if f.err != nil {
		return SocialStatus{}, f.err
	}
	s, ok := f.statuses[id]
	if !ok {
		return SocialStatus{}, errors.New("missing")
	}
	return s, nil
}

func TestSocialStatusURLParsing(t *testing.T) {
	for _, raw := range []string{"https://x.com/julianor/status/2114371617463611732?s=20", "https://twitter.com/julianor/status/2114371617463611732"} {
		id, canonical, ok := ParseXStatusURL(raw)
		if !ok || id != "2114371617463611732" || canonical != "https://x.com/i/status/2114371617463611732" {
			t.Fatalf("%q => %q %q %v", raw, id, canonical, ok)
		}
	}
	if _, _, ok := ParseXStatusURL("https://x.com/a/status/not-a-number"); ok {
		t.Fatal("accepted invalid id")
	}
}

func TestProviderChainFailsOverAndRejectsMismatchedID(t *testing.T) {
	chain := NewProviderChain([]StatusProvider{fakeStatusProvider{statuses: map[string]SocialStatus{"42": {ID: "41"}}}, fakeStatusProvider{statuses: map[string]SocialStatus{"42": {ID: "42", Text: "ok"}}}})
	s, err := chain.FetchStatus(context.Background(), "42")
	if err != nil || s.Text != "ok" {
		t.Fatalf("status=%+v err=%v", s, err)
	}
}

// Catches returning the embed chrome/author/date as evidence instead of only
// the public post text, and catches omission of X's privacy flags.
func TestOEmbedStatusProviderParsesLeafAndMarksItIncomplete(t *testing.T) {
	var gotURL, gotOmitScript, gotDNT string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.Query().Get("url")
		gotOmitScript = r.URL.Query().Get("omit_script")
		gotDNT = r.URL.Query().Get("dnt")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"url":         "https://x.com/julianor/status/2114371617463611732",
			"author_name": "Juliano Rizzo",
			"author_url":  "https://x.com/julianor",
			"html":        `<blockquote class="twitter-tweet"><p>A malicious server returns a partial OG image URL.<br><br>In our tests, the bot sent its own heap memory.</p>&mdash; Juliano Rizzo (@julianor) <a href="https://x.com/julianor/status/2114371617463611732">October 25, 2026</a></blockquote>`,
			"type":        "rich",
			"version":     "1.0",
		})
	}))
	defer s.Close()

	p := NewOEmbedStatusProvider(s.URL, 64<<10)
	got, err := p.FetchStatus(context.Background(), "2114371617463611732")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "2114371617463611732" || got.Author != "julianor" || !got.Incomplete {
		t.Fatalf("status=%+v", got)
	}
	wantText := "A malicious server returns a partial OG image URL.\n\nIn our tests, the bot sent its own heap memory."
	if got.Text != wantText {
		t.Fatalf("text=%q want=%q", got.Text, wantText)
	}
	if gotURL != "https://x.com/i/status/2114371617463611732" || gotOmitScript != "true" || gotDNT != "true" {
		t.Fatalf("query url=%q omit_script=%q dnt=%q", gotURL, gotOmitScript, gotDNT)
	}
}

// Catches accepting a resolver response for a different post, which would
// silently attach unrelated evidence to a claim.
func TestOEmbedStatusProviderRejectsMismatchedID(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"url": "https://x.com/a/status/99", "author_url": "https://x.com/a", "html": "<blockquote><p>wrong</p></blockquote>",
		})
	}))
	defer s.Close()

	_, err := NewOEmbedStatusProvider(s.URL, 4096).FetchStatus(context.Background(), "42")
	if err == nil || !strings.Contains(err.Error(), "returned status") {
		t.Fatalf("err=%v", err)
	}
}

// Catches an embed endpoint bypassing the configured response bound.
func TestOEmbedStatusProviderRejectsOversizedResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1025)))
	}))
	defer s.Close()

	_, err := NewOEmbedStatusProvider(s.URL, 1024).FetchStatus(context.Background(), "42")
	if err == nil || !strings.Contains(err.Error(), "exceeds 1024 bytes") {
		t.Fatalf("err=%v", err)
	}
}

// Catches treating a leaf-only resolver as complete thread context.
func TestSocialContextPropagatesIncompleteLeaf(t *testing.T) {
	p := fakeStatusProvider{statuses: map[string]SocialStatus{
		"3": {ID: "3", Text: "heap disclosure claim", Incomplete: true},
	}}
	got := EnrichSocialContext(context.Background(), p, RawItem{URL: "https://x.com/a/status/3"}, 6)
	if got.Discovery == nil || got.Discovery.ContextComplete {
		t.Fatalf("leaf-only context must be incomplete: %+v", got.Discovery)
	}
}

func TestSocialContextPropagatesIncompleteQuoteAndUntraversedQuoteAncestry(t *testing.T) {
	p := fakeStatusProvider{statuses: map[string]SocialStatus{
		"3": {ID: "3", Text: "leaf", QuoteID: "2"},
		"2": {ID: "2", URL: "https://x.com/a/status/2", Text: "quoted", ParentID: "1", Incomplete: true},
	}}
	got := EnrichSocialContext(context.Background(), p, RawItem{URL: "https://x.com/a/status/3"}, 6)
	if got.Discovery == nil || got.Discovery.ContextComplete {
		t.Fatalf("quote ancestry must be incomplete: %+v", got.Discovery)
	}
}

// Catches one network call per post and loss of ancestry when the thread
// endpoint returns the complete conversation in a single bounded response.
func TestThreadStatusProviderReconstructsAndCachesFourPostThread(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("url") != "https://x.com/i/status/4" || r.URL.Query().Get("thread") != "full" || r.URL.Query().Get("replies") != "off" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"provider": "fxtwitter",
			"warnings": []string{},
			"posts": []map[string]any{
				{"id": "1", "url": "https://x.com/julianor/status/1", "author": map[string]any{"screen_name": "julianor"}, "text": "Broccoli CVE-2026-111497 update", "created_at": "Sun Oct 25 15:00:49 +0000 2026"},
				{"id": "2", "url": "https://x.com/julianor/status/2", "author": map[string]any{"screen_name": "julianor"}, "text": "Brotli decompression can expose heap memory"},
				{"id": "3", "url": "https://x.com/julianor/status/3", "author": map[string]any{"screen_name": "julianor"}, "text": "OG image bots can disclose their heap"},
				{"id": "4", "url": "https://x.com/julianor/status/4", "author": map[string]any{"screen_name": "julianor"}, "text": "In our tests the bot sent heap memory to the server"},
			},
		})
	}))
	defer s.Close()

	p := NewThreadStatusProvider(s.URL, 64<<10)
	got := EnrichSocialContext(context.Background(), p, RawItem{URL: "https://x.com/julianor/status/4", Content: "indexed snippet"}, 6)
	if got.Discovery == nil || !got.Discovery.ContextComplete || len(got.Discovery.ParentURLs) != 3 {
		t.Fatalf("discovery=%+v", got.Discovery)
	}
	if !strings.Contains(got.Content, "CVE-2026-111497") || strings.Index(got.Content, "CVE-2026-111497") > strings.Index(got.Content, "In our tests") {
		t.Fatalf("content not chronological: %q", got.Content)
	}
	if calls != 1 {
		t.Fatalf("upstream calls=%d want=1", calls)
	}
	parent, err := p.FetchStatus(context.Background(), "2")
	if err != nil || parent.ParentID != "1" || calls != 1 {
		t.Fatalf("cached parent=%+v calls=%d err=%v", parent, calls, err)
	}
}

func TestThreadStatusProviderSortsChronologicallyBeforeInferringParents(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"posts": []map[string]any{
			{"id": "3", "url": "https://x.com/a/status/3", "text": "third", "created_timestamp": 3},
			{"id": "1", "url": "https://x.com/a/status/1", "text": "first", "created_timestamp": 1},
			{"id": "2", "url": "https://x.com/a/status/2", "text": "second", "created_timestamp": 2},
		}})
	}))
	defer s.Close()

	p := NewThreadStatusProvider(s.URL, 4096, StatusProviderOptions{DailyBudget: 10, CacheEntries: 8})
	got := EnrichSocialContext(context.Background(), p, RawItem{URL: "https://x.com/a/status/3"}, 6)
	if got.Discovery == nil || !got.Discovery.ContextComplete || strings.Index(got.Content, "first") > strings.Index(got.Content, "third") {
		t.Fatalf("thread was not reconstructed chronologically: discovery=%+v content=%q", got.Discovery, got.Content)
	}
}

func TestThreadStatusProviderCapsResponseAndCacheEntries(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts := make([]map[string]any, 9)
		for i := range posts {
			id := string(rune('1' + i))
			posts[i] = map[string]any{"id": id, "url": "https://x.com/a/status/" + id, "text": id, "created_timestamp": i + 1}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"posts": posts})
	}))
	defer s.Close()

	p := NewThreadStatusProvider(s.URL, 64<<10, StatusProviderOptions{DailyBudget: 10, CacheEntries: 4})
	_, err := p.FetchStatus(context.Background(), "9")
	if err == nil || !strings.Contains(err.Error(), "more than 8 posts") {
		t.Fatalf("err=%v", err)
	}
	if len(p.cache) != 0 {
		t.Fatalf("oversized thread populated cache: %d", len(p.cache))
	}
}

func TestStatusProviderBudgetAndRetryAfterPreventRepeatedCalls(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"url": "https://x.com/a/status/2", "author_url": "https://x.com/a", "html": "<blockquote><p>ok</p></blockquote>"})
	}))
	defer s.Close()

	p := NewOEmbedStatusProvider(s.URL, 4096, StatusProviderOptions{DailyBudget: 10})
	if _, err := p.FetchStatus(context.Background(), "1"); err == nil || !IsRetryableStatusError(err) {
		t.Fatalf("first err=%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.FetchStatus(ctx, "2"); err == nil {
		t.Fatal("expected budget/backoff rejection")
	}
	if calls != 1 {
		t.Fatalf("upstream calls=%d want=1", calls)
	}
}

func TestStatusProviderDailyBudgetQueuesExcessWithoutCallingUpstream(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		id, _, _ := ParseXStatusURL(r.URL.Query().Get("url"))
		_ = json.NewEncoder(w).Encode(map[string]any{"url": "https://x.com/a/status/" + id, "author_url": "https://x.com/a", "html": "<blockquote><p>ok</p></blockquote>"})
	}))
	defer s.Close()

	p := NewOEmbedStatusProvider(s.URL, 4096, StatusProviderOptions{DailyBudget: 1, RequestInterval: time.Nanosecond})
	if _, err := p.FetchStatus(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.FetchStatus(context.Background(), "2"); err == nil || !IsRetryableStatusError(err) {
		t.Fatalf("second err=%v", err)
	}
	if calls != 1 {
		t.Fatalf("upstream calls=%d want=1", calls)
	}
}

func TestThreadStatusProviderEvictsOldCacheEntries(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _, _ := ParseXStatusURL(r.URL.Query().Get("url"))
		_ = json.NewEncoder(w).Encode(map[string]any{"posts": []map[string]any{{"id": id, "url": "https://x.com/a/status/" + id, "text": id}}})
	}))
	defer s.Close()

	p := NewThreadStatusProvider(s.URL, 4096, StatusProviderOptions{DailyBudget: 10, RequestInterval: time.Nanosecond, CacheEntries: 2})
	for _, id := range []string{"1", "2", "3"} {
		if _, err := p.FetchStatus(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if len(p.cache) != 2 || len(p.cacheOrder) != 2 {
		t.Fatalf("cache=%d order=%d", len(p.cache), len(p.cacheOrder))
	}
	if _, exists := p.cache["1"]; exists {
		t.Fatal("oldest cache entry was not evicted")
	}
}

// Catches poisoning the cache when the thread response omits the requested ID.
func TestThreadStatusProviderRejectsMismatchedThread(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"posts": []map[string]any{{"id": "99", "url": "https://x.com/a/status/99", "text": "wrong"}}})
	}))
	defer s.Close()

	_, err := NewThreadStatusProvider(s.URL, 4096).FetchStatus(context.Background(), "42")
	if err == nil || !strings.Contains(err.Error(), "did not contain requested status") {
		t.Fatalf("err=%v", err)
	}
}

// Catches an optional thread provider preventing the official leaf fallback.
func TestThreadProviderFailureFallsBackToOEmbedProvider(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	defer s.Close()

	chain := NewProviderChain([]StatusProvider{
		NewThreadStatusProvider(s.URL, 4096),
		fakeStatusProvider{statuses: map[string]SocialStatus{"42": {ID: "42", Text: "leaf", Incomplete: true}}},
	})
	got, err := chain.FetchStatus(context.Background(), "42")
	if err != nil || got.Text != "leaf" || !got.Incomplete {
		t.Fatalf("status=%+v err=%v", got, err)
	}
}

// Catches a thread endpoint bypassing the configured response bound.
func TestThreadStatusProviderRejectsOversizedResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1025)))
	}))
	defer s.Close()

	_, err := NewThreadStatusProvider(s.URL, 1024).FetchStatus(context.Background(), "42")
	if err == nil || !strings.Contains(err.Error(), "exceeds 1024 bytes") {
		t.Fatalf("err=%v", err)
	}
}

func TestJulianoThreadReconstruction(t *testing.T) {
	p := fakeStatusProvider{statuses: map[string]SocialStatus{
		"3": {ID: "3", URL: "https://x.com/julianor/status/3", Author: "julianor", Text: "final Brotli detail", ParentID: "2", PublishedAt: time.Now()},
		"2": {ID: "2", URL: "https://x.com/julianor/status/2", Author: "julianor", Text: "In our tests a malicious Brotli stream leaks heap bytes", ParentID: "1"},
		"1": {ID: "1", URL: "https://x.com/julianor/status/1", Author: "julianor", Text: "Broccoli CVE-2026-111497"},
	}}
	item := RawItem{Title: "final Brotli detail", Content: "final Brotli detail", URL: "https://x.com/julianor/status/3", Discovery: &DiscoveryContext{Platform: "x", OriginalURL: "https://x.com/julianor/status/3"}}
	if IsRelevantDiscoveryCandidate(item) {
		t.Fatal("last reply should be insufficient alone")
	}
	got := EnrichSocialContext(context.Background(), p, item, 6)
	if !strings.Contains(got.Content, "CVE-2026-111497") || !strings.Contains(got.Content, "In our tests") || got.Discovery == nil || !got.Discovery.ContextComplete || len(got.Discovery.ParentURLs) != 2 {
		t.Fatalf("got=%+v", got)
	}
	if !IsRelevantDiscoveryCandidate(got) {
		t.Fatal("reconstructed thread should pass discovery gate")
	}
}

func TestSocialContextStopsAtCycleAndDepth(t *testing.T) {
	p := fakeStatusProvider{statuses: map[string]SocialStatus{"1": {ID: "1", ParentID: "2"}, "2": {ID: "2", ParentID: "1"}}}
	got := EnrichSocialContext(context.Background(), p, RawItem{URL: "https://x.com/a/status/1"}, 2)
	if got.Discovery == nil || got.Discovery.ContextComplete {
		t.Fatalf("cycle must be incomplete: %+v", got.Discovery)
	}
}
