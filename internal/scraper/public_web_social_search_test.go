package scraper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
)

// Catches regressions where the Brave adapter omits authentication, maps the
// query incorrectly, or accepts non-status web results as social candidates.
func TestBraveSocialSearchMapsRequestAndCanonicalizesStatusResults(t *testing.T) {
	var gotToken, gotAccept, gotQuery, gotCount, gotFreshness string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Subscription-Token")
		gotAccept = r.Header.Get("Accept")
		gotQuery = r.URL.Query().Get("q")
		gotCount = r.URL.Query().Get("count")
		gotFreshness = r.URL.Query().Get("freshness")
		_ = json.NewEncoder(w).Encode(map[string]any{"web": map[string]any{"results": []map[string]any{
			{"url": "https://mobile.x.com/julianor/status/2114371610048393394?s=20", "title": "Broccoli CVE-2026-111497", "description": "Brotli decompression can expose heap memory", "page_age": "2026-10-27T08:00:00Z"},
			{"url": "https://example.com/advisory", "title": "CVE-2026-111497", "description": "not an X status"},
		}}})
	}))
	defer s.Close()

	scr := NewPublicWebSocialSearch(config.PublicWebSocialSearchConfig{
		Enabled: true, Provider: "brave", Endpoint: s.URL, APIKey: "secret", Limit: 25,
		QueryGroups: [][]string{{"CVE-2026-111497", "Brotli"}}, ResponseLimit: 64 << 10,
	})
	items, err := scr.Poll(context.Background(), time.Now().Add(-12*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "secret" || gotAccept != "application/json" {
		t.Fatalf("headers token=%q accept=%q", gotToken, gotAccept)
	}
	if gotQuery != `site:x.com ("CVE-2026-111497" OR "Brotli")` || gotCount != "20" || gotFreshness != "pd" {
		t.Fatalf("query=%q count=%q freshness=%q", gotQuery, gotCount, gotFreshness)
	}
	if len(items) != 1 || items[0].URL != "https://x.com/i/status/2114371610048393394" || items[0].Discovery == nil {
		t.Fatalf("items=%+v", items)
	}
	if items[0].Discovery.DiscoveryURL == "" || items[0].PublishedAt.Format(time.RFC3339) != "2026-10-27T08:00:00Z" {
		t.Fatalf("provenance=%+v published=%v", items[0].Discovery, items[0].PublishedAt)
	}
}

// Catches unbounded reads from a compromised or misconfigured search endpoint.
func TestBraveSearchRejectsOversizedResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1025)))
	}))
	defer s.Close()

	p := NewBraveSearchProvider(s.URL, "secret", 1024)
	_, err := p.Search(context.Background(), "CVE", time.Now(), 10)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1024 bytes") {
		t.Fatalf("err=%v", err)
	}
}

// Catches silently enabling Brave without credentials and burning poll cycles.
func TestBraveSearchRequiresAPIKey(t *testing.T) {
	scr := NewPublicWebSocialSearch(config.PublicWebSocialSearchConfig{Enabled: true, Provider: "brave", Endpoint: "https://search.example.test"})
	_, err := scr.Poll(context.Background(), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("err=%v", err)
	}
}

func TestBraveSearchRejectsCrossOriginRedirectWithoutLeakingKey(t *testing.T) {
	redirectCalls := 0
	var leakedToken string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCalls++
		leakedToken = r.Header.Get("X-Subscription-Token")
		_ = json.NewEncoder(w).Encode(map[string]any{"web": map[string]any{"results": []map[string]any{}}})
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	_, err := NewBraveSearchProvider(source.URL, "do-not-leak", 4096).Search(context.Background(), "CVE", time.Now(), 10)
	if err == nil {
		t.Fatal("expected cross-origin redirect rejection")
	}
	if redirectCalls != 0 || leakedToken != "" {
		t.Fatalf("redirect calls=%d leaked token=%q", redirectCalls, leakedToken)
	}
}

func TestSocialPublicWebSearchBuildsBoundedQueryAndFilters(t *testing.T) {
	var query string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("q")
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]string{{"url": "https://x.com/julianor/status/2114371617463611732", "title": "CVE-2026-111497 Broccoli", "snippet": "In our tests Brotli leaks heap bytes", "published_at": "2026-10-27T10:00:00Z"}, {"url": "https://example.com/no", "title": "noise", "snippet": "hello"}}})
	}))
	defer s.Close()
	scr := NewPublicWebSocialSearch(config.PublicWebSocialSearchConfig{Enabled: true, Endpoint: s.URL, Limit: 10, QueryGroups: [][]string{{"CVE", "0day"}}})
	items, err := scr.Poll(context.Background(), time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Discovery == nil || items[0].Discovery.Platform != "x" {
		t.Fatalf("items=%+v", items)
	}
	if !strings.Contains(query, "site:x.com") || !strings.Contains(query, "CVE") {
		t.Fatalf("query=%q", query)
	}
}

func TestSocialPublicWebSearchDisabledWithoutEndpoint(t *testing.T) {
	items, err := NewPublicWebSocialSearch(config.PublicWebSocialSearchConfig{Enabled: true}).Poll(context.Background(), time.Time{})
	if err != nil || len(items) != 0 {
		t.Fatalf("items=%v err=%v", items, err)
	}
}

func TestPublicWebSocialSearchBuildsAutonomousHotAnchorQuery(t *testing.T) {
	var query string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("q")
		_ = json.NewEncoder(w).Encode(map[string]any{"web": map[string]any{"results": []map[string]any{}}})
	}))
	defer s.Close()

	scr := NewPublicWebSocialSearch(config.PublicWebSocialSearchConfig{Enabled: true, Provider: "brave", Endpoint: s.URL, APIKey: "secret", Limit: 20})
	scr.ObserveDiscoveryItems([]RawItem{{
		Source: "nvd", Title: "CVE-2026-111497 affects Brotli decompression",
		Content: "Malformed Brotli streams can cause memory disclosure during decompression.", BodyCVEsAreSubjects: true,
	}})
	if _, err := scr.Poll(context.Background(), time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, `"CVE-2026-111497"`) || !strings.Contains(query, `"decompression"`) {
		t.Fatalf("hot-anchor query=%q", query)
	}
	if strings.Contains(query, "211437161") {
		t.Fatalf("query assumed a known status ID: %q", query)
	}
}
