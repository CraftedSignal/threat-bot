package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
)

func TestMastodonTagDiscoveryFansInFiltersAndDeduplicates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		fmt.Fprintf(w, `<?xml version="1.0"?><rss version="2.0"><channel><item><guid>same</guid><link>%s/@alice/1</link><title>CVE-2026-111497 heap leak reproduced</title><description>proof of concept</description><pubDate>Tue, 27 Oct 2026 10:00:00 GMT</pubDate></item><item><guid>noise</guid><link>%s/@bob/2</link><title>lunch</title><description>hello</description></item></channel></rss>`, srvURL(r), srvURL(r))
	}))
	defer srv.Close()
	s := NewMastodonTagDiscovery(config.MastodonDiscoveryConfig{Instances: []string{srv.URL}, Tags: []string{"cve", "infosec"}, CandidateCap: 10})
	items, err := s.Poll(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Discovery == nil || items[0].Discovery.Platform != "mastodon" {
		t.Fatalf("items=%+v", items)
	}
}

func srvURL(r *http.Request) string { return "http://" + r.Host }
