package scraper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/mmcdole/gofeed"
)

func TestIsExpectedUpstreamScraperErrorUsesStatusCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "rate limit", err: statusErrorf(429, "NVD API HTTP 429: error code: 1015"), want: true},
		// Logged at ERROR in prod on 2026-10-26, which fired a Slack alert.
		{name: "wrapped Cloudflare timeout", err: fmt.Errorf("nvd: poll: %w", statusErrorf(524, "NVD API HTTP 524: error code: 524")), want: true},
		{name: "bot block", err: statusErrorf(403, "parsing feed https://hackread.com/feed/: http error: 403 Forbidden: "), want: true},
		{name: "not found", err: statusErrorf(404, "CISA KEV: HTTP 404"), want: false},
		{name: "bad request", err: statusErrorf(400, "NVD API HTTP 400: invalid pubStartDate"), want: false},
		{name: "gofeed rate limit", err: fmt.Errorf("poll: %w", gofeed.HTTPError{StatusCode: 429, Status: "429 Too Many Requests"}), want: true},
		{name: "gofeed not found", err: gofeed.HTTPError{StatusCode: 404, Status: "404 Not Found"}, want: false},
		// A status that appears only in the message text decides nothing.
		{name: "status only in text", err: errors.New("NVD API HTTP 503: maintenance"), want: false},
		{name: "feed replaced by a challenge page", err: errors.New("parsing feed https://example.test/feed: Failed to detect feed type"), want: true},
		{name: "local failure", err: errors.New("decode local cache: checksum mismatch"), want: false},
	}
	for _, tt := range tests {
		if got := isExpectedUpstreamScraperError(tt.err); got != tt.want {
			t.Errorf("%s: isExpectedUpstreamScraperError(%q) = %v, want %v", tt.name, tt.err, got, tt.want)
		}
	}
}

// statusTransport answers every request with its status code, as an upstream
// outage or block would.
type statusTransport int

func (code statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: int(code),
		Status:     fmt.Sprintf("%d %s", int(code), http.StatusText(int(code))),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("<html>upstream error page</html>")),
		Request:    req,
	}, nil
}

func TestScraperPollErrorsCarryTheResponseStatus(t *testing.T) {
	// Reddit spaces requests 11s apart process-wide; shrink that for the test.
	origInterval := redditMinInterval
	redditMinInterval = time.Millisecond
	redditNextAllowed = time.Time{}
	t.Cleanup(func() {
		redditMinInterval = origInterval
		redditNextAllowed = time.Time{}
	})

	noToken := func() string { return "" }
	scrapers := map[string]func(*http.Client) Scraper{
		"rss": func(c *http.Client) Scraper {
			r := NewRSS("bsi", "https://feed.example.test/rss.xml")
			r.parser.Client = c
			return r
		},
		"reddit": func(c *http.Client) Scraper {
			r := NewRedditNetSec()
			r.parser.Client = c
			return r
		},
		"nvd": func(c *http.Client) Scraper {
			n := NewNVD()
			n.client, n.pageDelay = c, time.Millisecond
			return n
		},
		"cisa-kev": func(c *http.Client) Scraper {
			s := NewCISAKEV(nil)
			s.client = c
			return s
		},
		"circl-misp": func(c *http.Client) Scraper {
			s := NewCIRCLMISP()
			s.client = c
			return s
		},
		"ghsa": func(c *http.Client) Scraper {
			s := NewGHSA(noToken)
			s.client = c
			return s
		},
		"pwn-watch": func(c *http.Client) Scraper {
			s := NewPwnWatch()
			s.client = c
			return s
		},
		"ransomware-live": func(c *http.Client) Scraper {
			s := NewRansomwareLive()
			s.client = c
			return s
		},
		"abuse.ch": func(c *http.Client) Scraper {
			s := NewAbuseCH("key")
			s.client = c
			return s
		},
		"mastodon": func(c *http.Client) Scraper {
			s := NewMastodonTagDiscovery(config.MastodonDiscoveryConfig{Enabled: true, Instances: []string{"https://infosec.example.test"}, Tags: []string{"cve"}}).(*MastodonTagDiscovery)
			s.client = c
			return s
		},
		"brave search": func(c *http.Client) Scraper {
			s := NewPublicWebSocialSearch(config.PublicWebSocialSearchConfig{Enabled: true, Provider: "brave", Endpoint: "https://search.example.test", APIKey: "key", Limit: 5, QueryGroups: [][]string{{"CVE"}}})
			s.provider.(*BraveSearchProvider).client = c
			return s
		},
		"legacy search": func(c *http.Client) Scraper {
			s := NewPublicWebSocialSearch(config.PublicWebSocialSearchConfig{Enabled: true, Endpoint: "https://search.example.test", Limit: 5, QueryGroups: [][]string{{"CVE"}}})
			s.provider.(*legacyJSONSearchProvider).client = c
			return s
		},
	}
	since := time.Now().Add(-24 * time.Hour)
	for name, build := range scrapers {
		for code, want := range map[int]bool{http.StatusServiceUnavailable: true, http.StatusNotFound: false} {
			t.Run(fmt.Sprintf("%s/%d", name, code), func(t *testing.T) {
				_, err := build(&http.Client{Transport: statusTransport(code)}).Poll(context.Background(), since)
				if err == nil {
					t.Fatal("poll succeeded against an error response")
				}
				if got := isExpectedUpstreamScraperError(err); got != want {
					t.Fatalf("isExpectedUpstreamScraperError(%q) = %v, want %v", err, got, want)
				}
			})
		}
	}
}
