package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Break caught: replacing the JSON integration with the summary RSS feed, or
// emitting one item per change, loses the stable incident snapshot and floods
// dedup with repeated updates for the same incident.
func TestPwnWatchPollEmitsOneCorroborationItemPerChangedIncident(t *testing.T) {
	var changesRequests atomic.Int32
	var incidentRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/changes.json":
			request := changesRequests.Add(1)
			if request == 2 {
				if got := r.Header.Get("If-None-Match"); got != `"changes-v1"` {
					t.Errorf("If-None-Match = %q, want changes validator", got)
				}
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"changes-v1"`)
			fmt.Fprint(w, `{
  "site": "https://pwn.watch",
  "generatedAt": "2026-10-23T08:00:00Z",
  "changes": [
    {"incident":"connectwise-cloud-backup-m365-hijack","date":"2026-10-23"},
    {"incident":"connectwise-cloud-backup-m365-hijack","date":"2026-10-23"},
    {"incident":"old-incident","date":"2026-10-01"}
  ]
}`)
		case "/i/connectwise-cloud-backup-m365-hijack.json":
			incidentRequests.Add(1)
			fmt.Fprintf(w, `{
  "slug": "connectwise-cloud-backup-m365-hijack",
  "title": "ConnectWise Cloud Backup shut down after M365 app-identity hijack",
  "url": %q,
  "status": "live",
  "severity": "critical",
  "patchStatus": "partial",
  "product": "ConnectWise Cloud Backup / Microsoft 365 app identity",
  "cveIds": [],
  "affectedVersions": ["Cloud Backup service (shut down)"],
  "fixedVersions": [],
  "startedAt": "2026-10-17",
  "updatedAt": "2026-10-23T07:53:48Z",
  "summary": "ConnectWise disabled Cloud Backup after a compromised credential let attackers authenticate as the application.",
  "tags": ["connectwise", "microsoft-365"],
  "sources": [
    {"kind":"writeup","title":"Microsoft investigation","url":"https://www.microsoft.com/security/connectwise","publisher":"Microsoft","date":"2026-10-21"},
    {"kind":"writeup","title":"Huntress investigation","url":"https://www.huntress.com/blog/connectwise","publisher":"Huntress","date":"2026-10-22"}
  ],
  "timeline": [
    {"date":"2026-10-21","title":"Microsoft attributes the campaign to Storm-0940.","sourceUrl":"https://www.microsoft.com/security/connectwise"}
  ],
  "agentBrief": "THIS GENERATED BRIEF MUST NOT BE INGESTED"
}`, server.URL+"/i/connectwise-cloud-backup-m365-hijack")
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	scraper := newPwnWatch(server.Client(), server.URL+"/changes.json", server.URL+"/i")
	items, err := scraper.Poll(context.Background(), time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want one incident snapshot", len(items))
	}
	item := items[0]
	if item.SourceID != "pwn-watch:connectwise-cloud-backup-m365-hijack:2026-10-23T07:53:48Z" {
		t.Fatalf("source id = %q", item.SourceID)
	}
	if item.Source != "pwn-watch" || !item.CorroborationOnly || !item.BodyCVEsAreSubjects {
		t.Fatalf("source policy not preserved: %#v", item)
	}
	if !item.PublishedAt.Equal(time.Date(2026, 10, 23, 7, 53, 48, 0, time.UTC)) {
		t.Fatalf("published at = %s", item.PublishedAt)
	}
	for _, want := range []string{
		"Patch status: partial",
		"ConnectWise Cloud Backup / Microsoft 365 app identity",
		"Microsoft attributes the campaign to Storm-0940.",
		"https://www.huntress.com/blog/connectwise",
	} {
		if !strings.Contains(item.Content, want) {
			t.Errorf("content missing %q:\n%s", want, item.Content)
		}
	}
	if strings.Contains(item.Content, "THIS GENERATED BRIEF") {
		t.Fatal("agentBrief was ingested instead of structured incident data")
	}
	metadataURLs := strings.Join([]string{item.Metadata["source_url_000"], item.Metadata["source_url_001"]}, " ")
	if !strings.Contains(metadataURLs, "microsoft.com") || !strings.Contains(metadataURLs, "huntress.com") {
		t.Fatalf("underlying source URLs missing from metadata: %#v", item.Metadata)
	}
	referenceURLs := strings.Join([]string{item.Metadata["reference_url_000"], item.Metadata["reference_url_001"]}, " ")
	if !strings.Contains(referenceURLs, "microsoft.com") || !strings.Contains(referenceURLs, "huntress.com") {
		t.Fatalf("eligible public references missing from metadata: %#v", item.Metadata)
	}
	if incidentRequests.Load() != 1 {
		t.Fatalf("incident requests = %d, want one for duplicate changes", incidentRequests.Load())
	}

	items, err = scraper.Poll(context.Background(), time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 || changesRequests.Load() != 2 || incidentRequests.Load() != 1 {
		t.Fatalf("conditional poll returned %d items; changes=%d incidents=%d", len(items), changesRequests.Load(), incidentRequests.Load())
	}
}

func TestPwnWatchRawItemBoundsPublicReferencesWithoutLosingDedupURLs(t *testing.T) {
	incident := pwnWatchIncident{Slug: "large-incident", Title: "Large incident"}
	for i := 0; i < 20; i++ {
		incident.Sources = append(incident.Sources, pwnWatchIncidentSource{
			Kind: "advisory", URL: fmt.Sprintf("https://vendor.example/advisory/%02d", i),
		})
	}
	item := pwnWatchRawItem(incident, time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC))
	if got := countMetadataPrefix(item.Metadata, "source_url_"); got != 20 {
		t.Fatalf("dedup source URLs = %d, want all 20", got)
	}
	if got := countMetadataPrefix(item.Metadata, "reference_url_"); got != pwnWatchMaxReferenceURLs {
		t.Fatalf("public references = %d, want cap %d", got, pwnWatchMaxReferenceURLs)
	}

	incident.Sources = incident.Sources[:0]
	for i := 0; i < 5; i++ {
		incident.Sources = append(incident.Sources, pwnWatchIncidentSource{
			Kind: "news", URL: fmt.Sprintf("https://news.example/article/%02d", i),
		})
	}
	item = pwnWatchRawItem(incident, time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC))
	if got := countMetadataPrefix(item.Metadata, "reference_url_"); got != pwnWatchFallbackReference {
		t.Fatalf("news-only fallback references = %d, want %d", got, pwnWatchFallbackReference)
	}
}

// Production regression: historical incident snapshots sometimes expose
// updatedAt as YYYY-MM-DD rather than RFC3339. Same-day snapshots must remain
// eligible even when the runner's since cursor is later than midnight.
func TestPwnWatchPollAcceptsDateOnlyIncidentUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/changes.json":
			fmt.Fprint(w, `{"changes":[{"incident":"ahsay-ahsaycbs-cve-2026-105134","date":"2026-10-14"}]}`)
		case "/i/ahsay-ahsaycbs-cve-2026-105134.json":
			fmt.Fprint(w, `{
  "slug":"ahsay-ahsaycbs-cve-2026-105134",
  "title":"AhsayCBS vulnerability",
  "url":"https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134",
  "updatedAt":"2026-10-14",
  "summary":"Ahsay published a security update.",
  "sources":[{"kind":"advisory","url":"https://www.ahsay.com/security/advisory"}]
}`)
		default:
			t.Fatalf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	scraper := newPwnWatch(server.Client(), server.URL+"/changes.json", server.URL+"/i")
	items, err := scraper.Poll(context.Background(), time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want date-only incident to remain eligible that day", len(items))
	}
	if !items[0].PublishedAt.Equal(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("published at = %s", items[0].PublishedAt)
	}
	wantPrefix := "pwn-watch:ahsay-ahsaycbs-cve-2026-105134:2026-10-14:"
	if !strings.HasPrefix(items[0].SourceID, wantPrefix) {
		t.Fatalf("source ID = %q, want content-versioned date-only prefix %q", items[0].SourceID, wantPrefix)
	}
}

func countMetadataPrefix(metadata map[string]string, prefix string) int {
	count := 0
	for key := range metadata {
		if strings.HasPrefix(key, prefix) {
			count++
		}
	}
	return count
}
