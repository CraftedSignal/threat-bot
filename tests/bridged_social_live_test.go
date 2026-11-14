package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// The whole bridged-social design rests on one claim: promoting the outbound
// story link to RawItem.URL means ContentEnricher fetches the real report, so a
// one-sentence LinkedIn post clears the thin-content gate with the article's
// text behind it. Unit tests cannot prove that — the SSRF guard correctly
// refuses to fetch httptest's loopback address, so the enrichment leg needs a
// genuinely public destination.
//
// This test reaches the live internet and is therefore skipped by default. Run
// it deliberately:
//
//	THREAT_BOT_NETWORK_TESTS=1 go test ./tests/ -run Live -v
//
// Destination URLs come from threat-bot's own RSS sources rather than being
// hardcoded, so the test cannot rot into 404s and it samples the kind of host
// ronin66 actually links to.
func TestIntegrationBridgedSocialLiveEnrichment(t *testing.T) {
	if os.Getenv("THREAT_BOT_NETWORK_TESTS") != "1" {
		t.Skip("network test; set THREAT_BOT_NETWORK_TESTS=1 to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// Real destinations, discovered live from sources threat-bot already polls.
	sources := []scraper.Scraper{
		scraper.NewDFIRReport(),
		scraper.NewTalos(),
		scraper.NewBleepingComputer(),
		scraper.NewSchneier(),
	}

	var enriched int
	for _, src := range sources {
		t.Run(src.Name(), func(t *testing.T) {
			// Wide window: DFIR Report publishes roughly monthly, so a 30-day
			// lookback skips it for no good reason.
			items, err := src.Poll(ctx, time.Now().Add(-120*24*time.Hour))
			if err != nil {
				t.Skipf("could not reach %s to obtain a destination URL: %v", src.Name(), err)
			}
			if len(items) == 0 || items[0].URL == "" {
				t.Skipf("%s returned no usable item", src.Name())
			}
			storyURL := items[0].URL

			// A bridge feed as RSS.app renders it: <link> is the auth-walled
			// LinkedIn permalink, and the story is a bare URL in the body.
			const permalink = "https://www.linkedin.com/posts/ronin66-research_activity-7443341347564052480-krVt"
			body := fmt.Sprintf(
				`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>`+
					`<title>ronin66 bridge</title><link>https://rss.app/feeds/abc.xml</link><description>b</description>`+
					`<item><title>Ronin66 Research on LinkedIn: worth your time</title>`+
					`<link>%s</link><guid>%s</guid><pubDate>%s</pubDate>`+
					`<description><![CDATA[<p>Solid writeup, worth your time. %s</p>]]></description>`+
					`</item></channel></rss>`,
				permalink, permalink, time.Now().Add(-time.Hour).Format(time.RFC1123Z), storyURL)

			bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/rss+xml")
				fmt.Fprint(w, body)
			}))
			defer bridge.Close()

			got, err := scraper.NewBridgedSocial("ronin66", bridge.URL, "linkedin.com").
				Poll(ctx, time.Now().Add(-24*time.Hour))
			if err != nil {
				t.Fatalf("Poll: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d items, want 1", len(got))
			}
			item := got[0]

			if item.URL != storyURL {
				t.Fatalf("URL = %q, want the promoted story link %q", item.URL, storyURL)
			}
			if item.Metadata["permalink"] != permalink {
				t.Errorf("permalink lost from Metadata: %q", item.Metadata["permalink"])
			}

			// Before enrichment the post is a sentence — it would be dropped by
			// the < 100 char thin-content gate.
			before := len(strings.TrimSpace(item.Content))
			pipeline.NewContentEnricher().Enrich(ctx, &item)
			after := len(strings.TrimSpace(item.Content))

			t.Logf("story=%s", storyURL)
			t.Logf("content %d -> %d bytes (thin gate 100, enrich threshold 500)", before, after)

			if after <= before {
				t.Errorf("enrichment added nothing: %d -> %d bytes for %s", before, after, storyURL)
				return
			}
			if after < 100 {
				t.Errorf("still below the thin-content gate after enrichment: %d bytes", after)
				return
			}
			// Byte growth alone would also be satisfied by swallowing a page of
			// script and markup, which would then be fed to the LLM as if it
			// were prose. htmlToText must have stripped it.
			for _, junk := range []string{"<script", "</script>", "schema.org", "<div", "function("} {
				if strings.Contains(item.Content, junk) {
					t.Errorf("enriched content still contains %q — htmlToText did not clean the page", junk)
				}
			}
			enriched++
		})
	}

	if enriched == 0 {
		t.Fatal("no destination enriched successfully; the design's core assumption does not hold")
	}
	t.Logf("enriched %d/%d live destinations", enriched, len(sources))
}
