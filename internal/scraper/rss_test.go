package scraper

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const testRSSFeed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <title>Test Feed</title>
  <item>
    <title>New Vulnerability in Widget</title>
    <link>https://example.com/advisory-1</link>
    <description>A critical vulnerability was discovered.</description>
    <pubDate>Mon, 16 Feb 2026 10:00:00 GMT</pubDate>
    <guid>advisory-1</guid>
  </item>
  <item>
    <title>Old Item</title>
    <link>https://example.com/old</link>
    <description>This is old.</description>
    <pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate>
    <guid>old-item</guid>
  </item>
</channel>
</rss>`

func TestRSSScraper(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(testRSSFeed))
	}))
	defer srv.Close()

	s := NewRSS("test-feed", srv.URL)

	// Since 2025-01-01: only the 2026 item should pass, the 2024 item is filtered.
	items, err := s.Poll(context.Background(), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 item (old item filtered), got %d", len(items))
	}
	if items[0].Title != "New Vulnerability in Widget" {
		t.Errorf("unexpected title: %s", items[0].Title)
	}
	if items[0].Source != "test-feed" {
		t.Errorf("unexpected source: %s", items[0].Source)
	}

	// Since epoch: both items should pass.
	allItems, err := s.Poll(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(allItems) != 2 {
		t.Fatalf("expected 2 items with zero since, got %d", len(allItems))
	}
}

func TestSOCRadarUsesCyberThreatIntelligenceCategoryFeed(t *testing.T) {
	s := NewSOCRadar()
	if s.Name() != "socradar" {
		t.Fatalf("Name() = %q, want socradar", s.Name())
	}
	if s.url != "https://socradar.io/blog/category/cyber-threat-intelligence/feed/" {
		t.Fatalf("feed URL = %q, want the Cyber Threat Intelligence category RSS feed", s.url)
	}
}

func TestSOCRadarLiveFeed(t *testing.T) {
	if os.Getenv("SOCRADAR_LIVE_TEST") != "1" {
		t.Skip("set SOCRADAR_LIVE_TEST=1 to fetch the public SOCRadar RSS feed")
	}
	items, err := NewSOCRadar().Poll(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("SOCRadar feed poll failed: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("SOCRadar feed returned no items in the last 30 days")
	}
}

func TestCISAScraperUsesOfficialCSAFDistributionWithoutRequestingBlockedRSS(t *testing.T) {
	const advisory = `{
  "document": {
    "title": "Example Control System",
    "tracking": {
      "id": "ICSA-26-307-01",
      "initial_release_date": "2026-11-03T06:00:00Z",
      "current_release_date": "2026-11-03T06:00:00Z"
    },
    "notes": [{"category":"summary","title":"Summary","text":"Remote attackers can execute commands."}],
    "references": [
      {"category":"self","summary":"JSON","url":"https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-307-01.json"},
      {"category":"self","summary":"Web Version","url":"https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01"}
    ]
  },
  "vulnerabilities": [{
    "cve":"CVE-2026-12345",
    "title":"Example command injection",
    "notes":[{"category":"summary","title":"Description","text":"Unsanitized input reaches a shell."}]
  }]
}`

	rssRequests := 0
	s := NewCISA()
	s.parser.Client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch r.URL.Path {
		case "/cybersecurity-advisories/all.xml":
			rssRequests++
			return testHTTPResponse(r, http.StatusForbidden, "Access Denied"), nil
		case "/cisagov/CSAF/develop/csaf_files/IT/white/changes.csv",
			"/cisagov/CSAF/develop/csaf_files/VA/white/changes.csv":
		case "/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv":
			body = "2026/icsa-26-307-01.json,2026-11-03T06:00:00Z\n"
		case "/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-307-01.json":
			body = advisory
		default:
			return testHTTPResponse(r, http.StatusNotFound, r.URL.String()), nil
		}
		return testHTTPResponse(r, http.StatusOK, body), nil
	})

	items, err := s.Poll(context.Background(), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("CISA poll: %v", err)
	}
	if rssRequests != 0 {
		t.Fatalf("blocked RSS endpoint requests = %d, want 0 when CSAF succeeds", rssRequests)
	}
	if len(items) != 1 {
		t.Fatalf("CISA items = %d, want 1", len(items))
	}
	item := items[0]
	if item.Source != "cisa" || item.SourceID != "cisa:https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01" {
		t.Fatalf("CISA identity = (%q, %q)", item.Source, item.SourceID)
	}
	if item.URL != "https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01" {
		t.Fatalf("CISA URL = %q", item.URL)
	}
	if item.Title != "Example Control System" || !strings.Contains(item.Content, "CVE-2026-12345") || !strings.Contains(item.Content, "Remote attackers") {
		t.Fatalf("unexpected CISA content: %#v", item)
	}
}

func TestCISAScraperFallsBackToRSSWhenOfficialCSAFDistributionIsUnavailable(t *testing.T) {
	rssRequests := 0
	s := NewCISA()
	s.parser.Client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/cisagov/CSAF/develop/csaf_files/IT/white/changes.csv":
			return testHTTPResponse(r, http.StatusServiceUnavailable, "temporary outage"), nil
		case "/cybersecurity-advisories/all.xml":
			rssRequests++
			return testHTTPResponse(r, http.StatusOK, testRSSFeed), nil
		default:
			return testHTTPResponse(r, http.StatusNotFound, r.URL.String()), nil
		}
	})

	items, err := s.Poll(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("CISA RSS fallback: %v", err)
	}
	if rssRequests != 1 || len(items) != 2 {
		t.Fatalf("RSS requests=%d items=%d, want one fallback request with two items", rssRequests, len(items))
	}
	if items[0].Source != "cisa" {
		t.Fatalf("fallback source = %q, want cisa", items[0].Source)
	}
}

func TestCISAScraperBoundsEachPollAndDrainsOldestChangesFirst(t *testing.T) {
	const maxItems = 100
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var changes strings.Builder
	for i := 0; i < maxItems+1; i++ {
		_, _ = fmt.Fprintf(&changes, "2026/advisory-%03d.json,%s\n", i, base.Add(time.Duration(i)*time.Minute).Format(time.RFC3339))
	}

	documentRequests := 0
	s := NewCISA()
	s.parser.Client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/cisagov/CSAF/develop/csaf_files/IT/white/changes.csv":
			return testHTTPResponse(r, http.StatusOK, changes.String()), nil
		case "/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv",
			"/cisagov/CSAF/develop/csaf_files/VA/white/changes.csv":
			return testHTTPResponse(r, http.StatusOK, ""), nil
		}
		if strings.HasPrefix(r.URL.Path, "/cisagov/CSAF/develop/csaf_files/IT/white/2026/advisory-") {
			documentRequests++
			filename := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			id := strings.ToUpper(strings.TrimSuffix(filename, ".json"))
			body := fmt.Sprintf(`{"document":{"title":"Advisory %s","tracking":{"id":%q}}}`, id, id)
			return testHTTPResponse(r, http.StatusOK, body), nil
		}
		return testHTTPResponse(r, http.StatusNotFound, r.URL.String()), nil
	})

	items, err := s.Poll(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("CISA poll: %v", err)
	}
	if len(items) != maxItems || documentRequests != maxItems {
		t.Fatalf("items=%d document requests=%d, want a %d-item request bound", len(items), documentRequests, maxItems)
	}
	wantNewest := base.Add((maxItems - 1) * time.Minute)
	if got := items[len(items)-1].PublishedAt; !got.Equal(wantNewest) {
		t.Fatalf("last bounded item = %s, want oldest batch through %s", got, wantNewest)
	}
}

func TestCISAScraperDeduplicatesAdvisoryRepublishedAcrossCSAFAreas(t *testing.T) {
	documentRequests := 0
	s := NewCISA()
	s.parser.Client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/cisagov/CSAF/develop/csaf_files/IT/white/changes.csv":
			return testHTTPResponse(r, http.StatusOK, "2026/va-26-225-01.json,2026-08-13T06:00:00Z\n"), nil
		case "/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv":
			return testHTTPResponse(r, http.StatusOK, ""), nil
		case "/cisagov/CSAF/develop/csaf_files/VA/white/changes.csv":
			return testHTTPResponse(r, http.StatusOK, "2026/va-26-225-01.json,2026-10-22T17:14:18Z\n"), nil
		case "/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-225-01.json":
			documentRequests++
			return testHTTPResponse(r, http.StatusOK, `{"document":{"title":"IT copy","tracking":{"id":"VA-26-225-01"}}}`), nil
		case "/cisagov/CSAF/develop/csaf_files/VA/white/2026/va-26-225-01.json":
			documentRequests++
			return testHTTPResponse(r, http.StatusOK, `{"document":{"title":"VA copy","tracking":{"id":"VA-26-225-01"}}}`), nil
		default:
			return testHTTPResponse(r, http.StatusNotFound, r.URL.String()), nil
		}
	})

	items, err := s.Poll(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("CISA poll: %v", err)
	}
	if len(items) != 1 || documentRequests != 1 {
		t.Fatalf("items=%d document requests=%d, want one logical advisory", len(items), documentRequests)
	}
	if items[0].Title != "VA copy" || items[0].Metadata["csaf_area"] != "VA" {
		t.Fatalf("deduplicated advisory = %#v, want newest distribution copy", items[0])
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testHTTPResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestRSSScraperReusesConditionalValidators(t *testing.T) {
	requests := 0
	lastModified := "Mon, 19 Oct 2026 10:00:00 GMT"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
				t.Fatalf("first request unexpectedly conditional: %#v", r.Header)
			}
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("ETag", `"feed-v1"`)
			w.Header().Set("Last-Modified", lastModified)
			_, _ = w.Write([]byte(testRSSFeed))
			return
		}
		if got := r.Header.Get("If-None-Match"); got != `"feed-v1"` {
			t.Errorf("If-None-Match = %q", got)
		}
		if got := r.Header.Get("If-Modified-Since"); got != lastModified {
			t.Errorf("If-Modified-Since = %q", got)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	s := NewRSS("test-feed", srv.URL)
	if items, err := s.Poll(context.Background(), time.Time{}); err != nil || len(items) != 2 {
		t.Fatalf("first poll items=%d err=%v", len(items), err)
	}
	if items, err := s.Poll(context.Background(), time.Time{}); err != nil || len(items) != 2 {
		t.Fatalf("conditional poll items=%d err=%v", len(items), err)
	}
}

func TestRSSScraperDoesNotSaveValidatorsAfterParseFailure(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 2 && r.Header.Get("If-None-Match") != "" {
			t.Fatalf("validator from failed parse was reused: %q", r.Header.Get("If-None-Match"))
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("ETag", `"bad-v1"`)
		if requests == 1 {
			_, _ = w.Write([]byte(`<not-a-feed>`))
			return
		}
		_, _ = w.Write([]byte(testRSSFeed))
	}))
	defer srv.Close()

	s := NewRSS("test-feed", srv.URL)
	if _, err := s.Poll(context.Background(), time.Time{}); err == nil {
		t.Fatal("expected parse failure")
	}
	if _, err := s.Poll(context.Background(), time.Time{}); err != nil {
		t.Fatalf("second poll: %v", err)
	}
}

func TestRSSScraperBoundsUpstreamErrorBody(t *testing.T) {
	body := "<html>" + strings.Repeat("upstream failure details ", 500) + "</html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	_, err := NewRSS("test-feed", srv.URL).Poll(context.Background(), time.Time{})
	if err == nil {
		t.Fatal("expected upstream HTTP error")
	}
	if got := len(err.Error()); got > 900 {
		t.Fatalf("error length = %d, want a bounded alert-safe value: %s", got, err)
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("bounded error does not disclose truncation: %s", err)
	}
}

func TestAllRSSSources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(testRSSFeed))
	}))
	defer srv.Close()

	// Verify every RSS source constructor produces a valid scraper
	// that can parse a feed and return items.
	sources := map[string]Scraper{
		"cisa":                     NewCISA(),
		"dfir-report":              NewDFIRReport(),
		"isc-stormcast":            NewISCStormCast(),
		"talos":                    NewTalos(),
		"mandiant":                 NewMandiant(),
		"unit42":                   NewUnit42(),
		"microsoft-threat-intel":   NewMicrosoftThreatIntel(),
		"sophos-xops":              NewSophosXOps(),
		"huntress":                 NewHuntress(),
		"arctic-wolf":              NewArcticWolf(),
		"checkpoint":               NewCheckPoint(),
		"crowdstrike":              NewCrowdStrike(),
		"eset":                     NewESET(),
		"volexity":                 NewVolexity(),
		"wiz":                      NewWiz(),
		"the-hacker-news":          NewHackerNews(),
		"dark-reading":             NewDarkReading(),
		"databreaches":             NewDataBreaches(),
		"hackread":                 NewHackRead(),
		"databreachtoday":          NewDataBreachToday(),
		"krebs-breaches":           NewKrebsBreaches(),
		"schneier":                 NewSchneier(),
		"securelist":               NewSecurelist(),
		"oss-security":             NewOSSSec(),
		"watchtowr":                NewWatchTowr(),
		"mozilla-security":         NewMozillaSecurity(),
		"ars-security":             NewArsSecurity(),
		"infosec-exchange-cve":     NewInfosecExchangeCVE(),
		"ncsc-uk":                  NewNCSC(),
		"ncsc-nl":                  NewNCSCNL(),
		"anssi":                    NewANSSI(),
		"bsi":                      NewBSI(),
		"cert-eu":                  NewCERTEU(),
		"jpcert":                   NewJPCERT(),
		"bleepingcomputer":         NewBleepingComputer(),
		"therecord":                NewTheRecord(),
		"securityweek":             NewSecurityWeek(),
		"ccb-belgium":              NewCCB(),
		"sentinelone-labs":         NewSentinelLabs(),
		"bitdefender":              NewBitdefender(),
		"fortiguard":               NewFortiGuard(),
		"proofpoint":               NewProofpoint(),
		"rapid7":                   NewRapid7(),
		"red-canary":               NewRedCanary(),
		"recorded-future":          NewRecordedFuture(),
		"flashpoint":               NewFlashpoint(),
		"intel471":                 NewIntel471(),
		"greynoise":                NewGreyNoise(),
		"cofense":                  NewCofense(),
		"any-run":                  NewAnyRun(),
		"qualys-threat-research":   NewQualysThreatResearch(),
		"malware-traffic-analysis": NewMalwareTrafficAnalysis(),
		"objective-see":            NewObjectiveSee(),
		"attackiq":                 NewAttackIQ(),
		"fbi-cyber":                NewFBICyber(),
		"cccs":                     NewCCCS(),
		"acsc":                     NewACSC(),
		"ms-isac":                  NewMSISAC(),
		"google-tag":               NewGoogleTAG(),
		// exploit-db and sploitus use custom scrapers (not *RSS) — tested separately.
		"socprime": NewSocPrime(),
	}

	for name, source := range sources {
		t.Run(name, func(t *testing.T) {
			if source.Name() != name {
				t.Errorf("expected name %q, got %q", name, source.Name())
			}

			// Poll against mock server to verify parsing works.
			s := NewRSS(name, srv.URL)
			items, err := s.Poll(context.Background(), time.Time{})
			if err != nil {
				t.Fatalf("Poll failed: %v", err)
			}
			if len(items) != 2 {
				t.Errorf("expected 2 items from mock feed, got %d", len(items))
			}
		})
	}
}

func TestMandiantUsesPublishedGoogleThreatIntelligenceFeed(t *testing.T) {
	const want = "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v"
	if got := NewMandiant().url; got != want {
		t.Fatalf("Mandiant feed URL = %q, want %q", got, want)
	}
}

func TestMSISACDeclaresLinkedAdvisoriesAuthoritative(t *testing.T) {
	source := NewMSISAC()
	if !source.authoritativeArticleCVEs {
		t.Fatal("MS-ISAC summaries must fetch the linked advisory before CVE extraction")
	}
}

func TestMSRCDeclaresLinkedAdvisoriesAuthoritative(t *testing.T) {
	source := NewMSRC()
	if !source.authoritativeArticleCVEs {
		t.Fatal("MSRC summaries must fetch the linked advisory before CVE extraction")
	}
}

func TestRSSScraperSetsAcceptHeader(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(testRSSFeed))
	}))
	defer srv.Close()

	s := NewRSS("test-feed", srv.URL)
	_, err := s.Poll(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	if gotAccept != "application/rss+xml, application/xml, text/xml, */*" {
		t.Errorf("expected Accept header for RSS content types, got %q", gotAccept)
	}
}

func TestRSSScraperUsesExtendedTLSHandshakeTimeout(t *testing.T) {
	s := NewRSS("test-feed", "https://example.com/feed.xml")
	transport, ok := s.parser.Client.Transport.(*uaTransport)
	if !ok {
		t.Fatalf("expected *uaTransport, got %T", s.parser.Client.Transport)
	}
	httpTransport, ok := transport.rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected HTTP transport, got %T", transport.rt)
	}
	if httpTransport.TLSHandshakeTimeout < 30*time.Second {
		t.Fatalf("expected TLS handshake timeout >= 30s, got %s", httpTransport.TLSHandshakeTimeout)
	}

}

func TestBleepingComputerUsesBotUserAgent(t *testing.T) {
	s := NewBleepingComputer()
	transport, ok := s.parser.Client.Transport.(*uaTransport)
	if !ok {
		t.Fatalf("expected *uaTransport, got %T", s.parser.Client.Transport)
	}
	if transport.ua != userAgent {
		t.Fatalf("expected BleepingComputer to use bot UA, got %q", transport.ua)
	}
}
