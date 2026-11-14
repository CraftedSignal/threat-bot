package scraper

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
)

// TestLiveJulianoBrotliDiscovery is opt-in because it verifies external
// provider contracts, not deterministic unit behavior. It exercises the exact
// status that motivated autonomous rumour discovery.
func TestLiveJulianoBrotliDiscovery(t *testing.T) {
	if os.Getenv("LIVE_SOCIAL_DISCOVERY_TEST") != "1" {
		t.Skip("set LIVE_SOCIAL_DISCOVERY_TEST=1 to query public providers")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const (
		leafID = "2114371617463611732"
		rootID = "2114371610048393394"
	)

	t.Run("official oEmbed resolves leaf but fails closed", func(t *testing.T) {
		status, err := NewOEmbedStatusProvider("https://publish.x.com/oembed", 256<<10).FetchStatus(ctx, leafID)
		if err != nil {
			t.Fatal(err)
		}
		if !status.Incomplete || !strings.Contains(status.Text, "heap memory") || !strings.Contains(status.Text, "In our tests") {
			t.Fatalf("unexpected leaf: %+v", status)
		}
	})

	t.Run("thread resolver recovers the CVE and mechanism", func(t *testing.T) {
		provider := NewThreadStatusProvider("https://x-lookup.mynameistito.com/api/convert", 256<<10)
		item := RawItem{
			SourceID: "live:" + leafID,
			Source:   "live-test",
			Title:    "Brotli heap disclosure through OG image requests",
			URL:      "https://x.com/julianor/status/" + leafID,
			Content:  "indexed X status",
			Discovery: &DiscoveryContext{
				Platform: "x", OriginalURL: "https://x.com/julianor/status/" + leafID,
			},
		}
		got := EnrichSocialContext(ctx, provider, item, 6)
		if got.Discovery == nil || !got.Discovery.ContextComplete || len(got.Discovery.ParentURLs) != 3 {
			t.Fatalf("incomplete thread: %+v", got.Discovery)
		}
		for _, phrase := range []string{"CVE-2026-111497", "Brotli decompression", "OG image", "heap memory"} {
			if !strings.Contains(got.Content, phrase) {
				t.Fatalf("thread missing %q: %s", phrase, got.Content)
			}
		}
		if !IsRelevantDiscoveryCandidate(got) {
			t.Fatalf("resolved thread did not pass the cheap relevance gate: %s", got.Content)
		}
	})

	t.Run("Brave discovers the indexed thread root", func(t *testing.T) {
		apiKey := strings.TrimSpace(os.Getenv("BRAVE_SEARCH_API_KEY"))
		if apiKey == "" {
			t.Skip("BRAVE_SEARCH_API_KEY is unavailable; provider contract is covered by httptest")
		}
		scraper := NewPublicWebSocialSearch(config.PublicWebSocialSearchConfig{
			Enabled: true, Provider: "brave", Endpoint: "https://api.search.brave.com/res/v1/web/search",
			APIKey: apiKey, Limit: 20, ResponseLimit: 256 << 10,
		})
		scraper.ObserveDiscoveryItems([]RawItem{{
			Source: "nvd", Title: "CVE-2026-111497 affects Brotli decompression",
			Content: "Malformed Brotli streams can cause memory disclosure during decompression.", BodyCVEsAreSubjects: true,
		}})
		items, err := scraper.Poll(ctx, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			if strings.HasSuffix(item.URL, "/"+rootID) {
				return
			}
		}
		t.Fatalf("Brave did not return root status %s: %+v", rootID, items)
	})
}
