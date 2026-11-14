package scraper

import (
	"strings"
	"testing"
	"time"
)

const riskyBizFixture = `
<h2>Breaches, hacks, and security incidents</h2>
<p><strong>JDownloader got hacked:</strong> The JDownloader website was modified to serve a RAT. <a href="https://jdownloader.org/incident_8.5.2026.html">The incident</a> took place last week.</p>
<p><strong>Canvas breached by ShinyHunters:</strong> The student management platform was compromised. [<a href="https://techcrunch.com/canvas">TechCrunch</a>]</p>
<h2>Sponsor section</h2>
<p>This sponsor content should be skipped entirely.</p>
<h2>Malware technical reports</h2>
<p><strong>New Linux backdoor PamDOORa discovered:</strong> Targets PAM authentication stack on Linux servers. [<a href="https://malware.example.com/pamdoora">Analysis</a>]</p>
<h2>Risky Business Podcasts</h2>
<p>Podcast section, must be skipped.</p>
`

func TestParseRiskyBizStories(t *testing.T) {
	pub := time.Date(2026, 5, 11, 0, 47, 19, 0, time.UTC)
	items, err := parseRiskyBizStories(riskyBizFixture, "https://news.risky.biz/bulletin-fcc/", pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}

	// Story 1
	if items[0].Title != "JDownloader got hacked" {
		t.Errorf("item[0].Title = %q, want %q", items[0].Title, "JDownloader got hacked")
	}
	if items[0].Source != "risky-biz-bulletin" {
		t.Errorf("item[0].Source = %q, want %q", items[0].Source, "risky-biz-bulletin")
	}
	if items[0].URL != "https://news.risky.biz/bulletin-fcc/" {
		t.Errorf("item[0].URL = %q", items[0].URL)
	}
	if !strings.Contains(items[0].Content, "[Section: Breaches, hacks, and security incidents]") {
		t.Errorf("item[0].Content missing section label, got: %s", items[0].Content)
	}
	if !strings.Contains(items[0].Content, "https://jdownloader.org/incident_8.5.2026.html") {
		t.Errorf("item[0].Content missing source URL")
	}
	if items[0].SourceID != "risky-biz-bulletin:20260511:jdownloader-got-hacked" {
		t.Errorf("item[0].SourceID = %q", items[0].SourceID)
	}

	// Story 2
	if items[1].Title != "Canvas breached by ShinyHunters" {
		t.Errorf("item[1].Title = %q", items[1].Title)
	}
	if !strings.Contains(items[1].Content, "[Section: Breaches, hacks, and security incidents]") {
		t.Errorf("item[1].Content missing section label")
	}

	// Story 3 — from Malware section, sponsor skipped
	if items[2].Title != "New Linux backdoor PamDOORa discovered" {
		t.Errorf("item[2].Title = %q", items[2].Title)
	}
	if !strings.Contains(items[2].Content, "[Section: Malware technical reports]") {
		t.Errorf("item[2].Content missing section label, got: %s", items[2].Content)
	}
}

func TestParseRiskyBizStories_EmptyContent(t *testing.T) {
	items, err := parseRiskyBizStories("", "https://news.risky.biz/", time.Now())
	if err != nil {
		t.Fatalf("unexpected error on empty content: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("expected 0 items for empty content, got %d", len(items))
	}
}

func TestSlugifyRBB(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"JDownloader got hacked", "jdownloader-got-hacked"},
		{"Hello, World! 123", "hello-world-123"},
		{"  leading and trailing  ", "leading-and-trailing"},
	}
	for _, c := range cases {
		got := slugifyRBB(c.in)
		if got != c.want {
			t.Errorf("slugifyRBB(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
