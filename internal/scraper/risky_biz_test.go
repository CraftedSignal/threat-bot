package scraper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const riskyBizPodcastFixture = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <title>Risky Business</title>
  <item>
    <title>Risky Business #847 -- Oops! Claude&apos;s accidental hacking spree</title>
    <link>https://risky.biz/RB847/</link>
    <guid isPermaLink="true">https://risky.biz/RB847/</guid>
    <pubDate>Wed, 05 Aug 2026 16:10:19 +1000</pubDate>
    <description><![CDATA[
      <p>On this week’s show Patrick Gray and James Wilson discuss the week’s cybersecurity news, including:</p>
      <ul>
        <li>Accidental AI agent hacking sprees</li>
        <li>A ColdCard wallet flaw led to millions in Bitcoin theft</li>
      </ul>
      <p>This episode is also available on <a href="https://youtu.be/-zj6abxxnBE">YouTube</a></p>
      <h3 class="panel-title">Show notes</h3>
      <ul>
        <li><a href="https://therecord.media/openai-says-rogue-agent-behind-hugging-face-hack-broke-into-additional-services">OpenAI says rogue agent behind Hugging Face hack broke into additional services | therecord.media</a></li>
        <li><a href="https://www.bleepingcomputer.com/news/security/coldcard-wallet-rng-flaw-likely-linked-to-88-million-bitcoin-theft">COLDCARD wallet RNG flaw likely linked to $88 million Bitcoin theft | BleepingComputer</a></li>
        <li><a href="/relative-link/">Relative link should be ignored</a></li>
      </ul>
    ]]></description>
  </item>
  <item>
    <title>Risky Business #846 -- Older episode</title>
    <link>https://risky.biz/RB846/</link>
    <guid isPermaLink="true">https://risky.biz/RB846/</guid>
    <pubDate>Wed, 29 Jul 2026 16:10:19 +1000</pubDate>
    <description><![CDATA[<p>Old episode description.</p>]]></description>
  </item>
</channel>
</rss>`

func TestRiskyBizScraper(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(riskyBizPodcastFixture))
	}))
	defer srv.Close()

	s := NewRiskyBiz()
	s.feedURL = srv.URL

	// Since 2026-08-01: only the 2026-08-05 episode should be processed.
	items, err := s.Poll(context.Background(), time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	if len(items) != 2 {
		t.Fatalf("expected 2 show note items, got %d", len(items))
	}

	// First show note.
	if items[0].Title != "OpenAI says rogue agent behind Hugging Face hack broke into additional services | therecord.media" {
		t.Errorf("unexpected title: %s", items[0].Title)
	}
	if items[0].Source != "risky-biz" {
		t.Errorf("unexpected source: %s", items[0].Source)
	}
	if items[0].URL != "https://therecord.media/openai-says-rogue-agent-behind-hugging-face-hack-broke-into-additional-services" {
		t.Errorf("unexpected URL: %s", items[0].URL)
	}
	if !strings.Contains(items[0].Content, "Episode context:") {
		t.Errorf("missing episode context in content: %s", items[0].Content)
	}
	if !strings.Contains(items[0].Content, "Show note:") {
		t.Errorf("missing show note label in content: %s", items[0].Content)
	}
	if !strings.HasPrefix(items[0].SourceID, "risky-biz:20260805:") {
		t.Errorf("unexpected source ID: %s", items[0].SourceID)
	}

	// Second show note.
	if items[1].Title != "COLDCARD wallet RNG flaw likely linked to $88 million Bitcoin theft | BleepingComputer" {
		t.Errorf("unexpected title: %s", items[1].Title)
	}
	if items[1].URL != "https://www.bleepingcomputer.com/news/security/coldcard-wallet-rng-flaw-likely-linked-to-88-million-bitcoin-theft" {
		t.Errorf("unexpected URL: %s", items[1].URL)
	}

	// Relative link should have been skipped.
	for _, it := range items {
		if strings.Contains(it.URL, "/relative-link/") {
			t.Errorf("relative link should not be emitted: %s", it.URL)
		}
	}
}

func TestRiskyBizScraper_NoShowNotes(t *testing.T) {
	feed := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <item>
    <title>Episode without show notes</title>
    <link>https://risky.biz/RB000/</link>
    <pubDate>Wed, 05 Aug 2026 16:10:19 +1000</pubDate>
    <description><![CDATA[<p>Just a description, no show notes.</p>]]></description>
  </item>
</channel>
</rss>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(feed))
	}))
	defer srv.Close()

	s := NewRiskyBiz()
	s.feedURL = srv.URL

	items, err := s.Poll(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 items when there are no show notes, got %d", len(items))
	}
}

func TestSlugifyRBP(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"OpenAI says rogue agent | therecord.media", "openai-says-rogue-agent-therecord-media"},
		{"COLDCARD wallet RNG flaw $88 million", "coldcard-wallet-rng-flaw-88-million"},
		{"  leading and trailing  ", "leading-and-trailing"},
	}
	for _, c := range cases {
		got := slugifyRBP(c.in)
		if got != c.want {
			t.Errorf("slugifyRBP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
