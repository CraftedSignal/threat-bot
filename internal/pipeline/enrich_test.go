package pipeline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

type enrichRoundTrip func(*http.Request) (*http.Response, error)

func (f enrichRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestContentEnricherFetchesArticleLinkedFromRSSExcerpt(t *testing.T) {
	excerpt := strings.Repeat("Security context. ", 60) + "Read full article"
	if !shouldEnrich(scraper.RawItem{Content: excerpt}) {
		t.Fatal("RSS excerpt linking to a full article must be enriched even when it exceeds the thin-content threshold")
	}
	if shouldEnrich(scraper.RawItem{Content: strings.Repeat("Complete analysis. ", 60)}) {
		t.Fatal("substantive feed content without a full-article marker must not trigger another fetch")
	}
	if shouldEnrich(scraper.RawItem{Content: excerpt, Enriched: true}) {
		t.Fatal("already enriched content must not be fetched twice")
	}
}

func TestContentEnricherAddsNVDLinkedVendorAdvisoryToThinItem(t *testing.T) {
	const advisoryURL = "https://example.com/security/CVE-2026-109618"
	var requested string
	enricher := NewContentEnricher()
	enricher.client = &http.Client{Transport: enrichRoundTrip(func(req *http.Request) (*http.Response, error) {
		requested = req.URL.String()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader("<html><body><p>Fixed in release 7.4.1-90080-1. Upgrade to the fixed release.</p></body></html>"))}, nil
	})}

	item := scraper.RawItem{Source: "nvd", Content: "A short NVD description.", Metadata: map[string]string{
		"vendor_advisory_urls": `["` + advisoryURL + `"]`,
	}}
	enricher.Enrich(context.Background(), &item)
	if requested != advisoryURL {
		t.Fatalf("requested URL = %q, want vendor advisory %q", requested, advisoryURL)
	}
	if !strings.Contains(item.Content, "Fixed in release 7.4.1-90080-1") || !strings.Contains(item.Content, advisoryURL) {
		t.Fatalf("vendor advisory evidence was not appended with provenance: %q", item.Content)
	}
}

func TestContentEnricherFetchesDeclaredAdvisoryExcerptAndPreservesSubjectCVEs(t *testing.T) {
	article := `<html><body><main><p>PHP is affected by CVE-2026-109618 and CVE-2026-109619.</p><p>` + strings.Repeat("Apply the vendor update. ", 40) + `</p></main></body></html>`
	enricher := NewContentEnricher()
	enricher.client = &http.Client{Transport: enrichRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/html"}},
			Body:       io.NopCloser(strings.NewReader(article)),
		}, nil
	})}

	item := scraper.RawItem{
		URL:                 "https://example.com/advisory",
		Content:             strings.Repeat("Long RSS summary without identifiers. ", 30),
		NeedsFullArticle:    true,
		BodyCVEsAreSubjects: true,
	}
	enricher.Enrich(context.Background(), &item)

	if !item.Enriched || item.NeedsFullArticle {
		t.Fatalf("advisory enrichment state = enriched:%v needs_full:%v", item.Enriched, item.NeedsFullArticle)
	}
	got := subjectCVEs(item)
	if strings.Join(got, ",") != "CVE-2026-109618,CVE-2026-109619" {
		t.Fatalf("subject CVEs = %v", got)
	}
}

func TestContentEnricherFetchTextRetriesBrowserUAOnForbidden(t *testing.T) {
	var userAgents []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgents = append(userAgents, r.UserAgent())
		if r.UserAgent() == enrichUserAgent {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !strings.Contains(r.UserAgent(), "Mozilla/5.0") {
			t.Fatalf("unexpected fallback UA %q", r.UserAgent())
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><p>Apache Log4j remote code execution mitigation guidance.</p></body></html>")
	}))
	defer srv.Close()

	enricher := NewContentEnricher()
	// This server intentionally listens on loopback; keep this test's trusted
	// local transport instead of exercising the production SSRF guard.
	enricher.client.Transport = srv.Client().Transport
	text, err := enricher.fetchText(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchText returned error: %v", err)
	}
	if !strings.Contains(text, "Apache Log4j remote code execution mitigation guidance.") {
		t.Fatalf("unexpected text: %q", text)
	}
	if len(userAgents) != 2 {
		t.Fatalf("expected initial request and browser-UA retry, got %#v", userAgents)
	}
}

func TestContentEnricherRejectsRedirectToPrivateAddress(t *testing.T) {
	var requests []string
	enricher := NewContentEnricher()
	enricher.client.Transport = enrichRoundTrip(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		if req.URL.Hostname() == "public.example" {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"http://127.0.0.1/private"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}
		t.Fatalf("request reached unsafe redirect target: %s", req.URL)
		return nil, fmt.Errorf("unexpected request")
	})

	_, err := enricher.fetchText(context.Background(), "https://public.example/article")
	if err == nil {
		t.Fatal("expected private redirect target to be rejected")
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %v, want only the initial public URL", requests)
	}
}

func TestNewContentEnricherWiresSafeOutboundTransport(t *testing.T) {
	client := NewContentEnricher().client
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatalf("production transport = %T, want a guarded *http.Transport", client.Transport)
	}
	conn, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("production transport allowed a loopback connection")
	}
}

func TestContentEnricherDistinguishesNoAdditionalEvidenceFromFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		required bool
		status   int
		wantErr  bool
		wantAdd  bool
	}{
		{name: "optional shorter page", body: "Security Update Guide. Enable JavaScript to run this app.", status: http.StatusOK},
		{name: "required shorter article", body: "Fixed in version 1.2.3.", required: true, status: http.StatusOK, wantAdd: true},
		{name: "optional empty page", status: http.StatusOK, wantErr: true},
		{name: "required empty page", required: true, status: http.StatusOK, wantErr: true},
		{name: "optional upstream failure", status: http.StatusServiceUnavailable, wantErr: true},
		{name: "required upstream failure", required: true, status: http.StatusServiceUnavailable, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			e := NewContentEnricher()
			e.client.Transport = enrichRoundTrip(func(*http.Request) (*http.Response, error) {
				requests++
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader("<html><body>" + tc.body + "</body></html>"))}, nil
			})
			original := strings.Repeat("Existing feed evidence. ", 8)
			item := scraper.RawItem{Source: "msrc", URL: "https://example.com/fixture-advisory", Content: original, NeedsFullArticle: tc.required}
			errs := e.Enrich(context.Background(), &item)
			if (len(errs) != 0) != tc.wantErr {
				t.Fatalf("errors = %v, want error %v", errs, tc.wantErr)
			}
			if tc.wantAdd {
				if !strings.Contains(item.Content, tc.body) || item.NeedsFullArticle {
					t.Fatalf("required evidence was not appended: %+v", item)
				}
			} else if item.Content != original || item.NeedsFullArticle != tc.required {
				t.Fatalf("existing evidence or requirement changed: %+v", item)
			}
			e.Enrich(context.Background(), &item)
			if requests != 1 {
				t.Fatalf("fetched twice in one processing pass: %d requests", requests)
			}
		})
	}
}
