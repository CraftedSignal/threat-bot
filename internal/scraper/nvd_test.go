package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNVD_Poll(t *testing.T) {
	now := time.Now().UTC()
	response := nvdResponse{
		TotalResults: 2,
		Vulnerabilities: []nvdVulnerability{
			{
				CVE: nvdCVE{
					ID:               "CVE-2026-0001",
					SourceIdentifier: "security@synology.com",
					Published:        now.Format("2006-01-02T15:04:05.000"),
					References: []nvdReference{
						{URL: "https://www.synology.com/security/CVE-2026-0001"},
						{URL: "https://research.example/post", Tags: []string{"Third Party Advisory"}},
					},
					Descriptions: []nvdDescription{
						{Lang: "en", Value: "Critical RCE vulnerability"},
					},
					Metrics: &nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CVSSData: struct {
								BaseScore float64 `json:"baseScore"`
							}{BaseScore: 9.8}},
						},
					},
				},
			},
			{
				CVE: nvdCVE{
					ID:        "CVE-2026-0002",
					Published: now.Format("2006-01-02T15:04:05.000"),
					Descriptions: []nvdDescription{
						{Lang: "en", Value: "Low severity info leak"},
					},
					Metrics: &nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CVSSData: struct {
								BaseScore float64 `json:"baseScore"`
							}{BaseScore: 3.1}},
						},
					},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("lastModStartDate") {
			json.NewEncoder(w).Encode(nvdResponse{})
			return
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()

	n := &NVD{client: srv.Client()}
	items, err := n.pollFrom(context.Background(), now.Add(-24*time.Hour), srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// Only the critical CVE (CVSS >= 7.0) should be returned.
	if len(items) != 1 {
		t.Fatalf("expected 1 item (low CVSS filtered), got %d", len(items))
	}
	if items[0].Metadata["cve"] != "CVE-2026-0001" {
		t.Errorf("expected CVE-2026-0001, got %q", items[0].Metadata["cve"])
	}
	if got := items[0].Metadata["vendor_advisory_urls"]; got != `["https://www.synology.com/security/CVE-2026-0001"]` {
		t.Errorf("vendor advisory references = %q", got)
	}
}

func TestNVDMetadataDoesNotTreatCoordinatorCNAHostAsVendorAdvisory(t *testing.T) {
	for _, tc := range []struct {
		cna, host string
	}{
		{"secalert@redhat.com", "access.redhat.com"},
		{"security@debian.org", "security-tracker.debian.org"},
		{"report@snyk.io", "security.snyk.io"},
		{"security@mozilla.org", "www.mozilla.org"},
	} {
		t.Run(tc.cna, func(t *testing.T) {
			cve := nvdCVE{
				SourceIdentifier: tc.cna,
				References: []nvdReference{
					{URL: "https://" + tc.host + "/advisory/CVE-2026-9999"},
					{URL: "https://" + tc.host + "/advisory/CVE-2026-9998", Tags: []string{"Vendor Advisory"}},
				},
			}
			metadata := nvdItemMetadata(cve, "", nil)
			if got := metadata["vendor_advisory_urls"]; got != `["https://`+tc.host+`/advisory/CVE-2026-9998"]` {
				t.Fatalf("vendor advisory URLs = %s, want only explicit Vendor Advisory tag", got)
			}
		})
	}
}

func TestNVDFetchItemsQueriesEachCVEByID(t *testing.T) {
	published := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)
	var mu sync.Mutex
	var queried []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("cveId")
		mu.Lock()
		queried = append(queried, id)
		mu.Unlock()
		if id == "CVE-2026-503503" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		vulns := []nvdVulnerability{}
		if id == "CVE-2026-118252" {
			vulns = append(vulns, secondaryScoredCVE(id, published, 8.1))
		}
		json.NewEncoder(w).Encode(nvdResponse{TotalResults: len(vulns), Vulnerabilities: vulns})
	}))
	defer srv.Close()

	// A CVE NVD no longer lists and a failed request must not stop the rest.
	n := &NVD{client: srv.Client(), pageDelay: time.Millisecond}
	items, err := n.fetchItemsFrom(context.Background(), srv.URL, []string{"nvd:CVE-2026-999999", "nvd:CVE-2026-503503", "nvd:CVE-2026-118252"})
	if err == nil || !strings.Contains(err.Error(), "nvd:CVE-2026-503503") {
		t.Fatalf("err = %v, want the failed CVE reported", err)
	}
	if len(items) != 1 || items[0].SourceID != "nvd:CVE-2026-118252" || !items[0].PublishedAt.Equal(published) {
		t.Fatalf("items = %+v, want the one CVE NVD lists", items)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(queried, []string{"CVE-2026-999999", "CVE-2026-503503", "CVE-2026-118252"}) {
		t.Fatalf("queried cveIds %q, want each requested CVE once", queried)
	}
}

// fakeNVD mimics the NVD API 2.0 query handling the sweep depends on: boolean
// filters are presence flags, isVulnerable needs a cpeName, and results page
// through startIndex.
func fakeNVD(t *testing.T, sweep []nvdVulnerability) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has("lastModStartDate") {
			json.NewEncoder(w).Encode(nvdResponse{})
			return
		}
		if q.Has("isVulnerable") && q.Get("cpeName") == "" {
			w.Header().Set("message", "The cpeName parameter must have a value when isVulnerable is used.")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var vulns []nvdVulnerability
		if !q.Has("cvssV3Severity") && !q.Has("hasCertAlerts") {
			vulns = sweep
		}
		start, perPage := 0, len(vulns)
		fmt.Sscan(q.Get("startIndex"), &start)
		fmt.Sscan(q.Get("resultsPerPage"), &perPage)
		end := min(start+perPage, len(vulns))
		page := []nvdVulnerability{}
		if start < end {
			page = vulns[start:end]
		}
		json.NewEncoder(w).Encode(nvdResponse{TotalResults: len(vulns), Vulnerabilities: page})
	}))
}

func secondaryScoredCVE(id string, published time.Time, score float64) nvdVulnerability {
	return nvdVulnerability{CVE: nvdCVE{
		ID:           id,
		Published:    published.Format("2006-01-02T15:04:05.000"),
		Descriptions: []nvdDescription{{Lang: "en", Value: "Linux kernel flaw scored by the CNA"}},
		Metrics: &nvdMetrics{CvssMetricV31: []nvdCvssMetric{{CVSSData: struct {
			BaseScore float64 `json:"baseScore"`
		}{BaseScore: score}}}},
	}}
}

// CVEs still awaiting NVD analysis only carry a secondary score, so the
// severity-filtered passes miss them and only the sweep finds them.
func TestNVD_PollSweepsCVEsAwaitingAnalysis(t *testing.T) {
	now := time.Now().UTC()
	srv := fakeNVD(t, []nvdVulnerability{secondaryScoredCVE("CVE-2026-31431", now, 7.8)})
	defer srv.Close()

	n := &NVD{client: srv.Client()}
	items, err := n.pollFrom(context.Background(), now.Add(-2*time.Hour), srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 || items[0].Metadata["cve"] != "CVE-2026-31431" {
		t.Fatalf("expected the secondary-scored CVE from the sweep, got %+v", items)
	}
}

func TestNVD_PollSweepPagesThroughResults(t *testing.T) {
	now := time.Now().UTC()
	var sweep []nvdVulnerability
	for i := range nvdResultsPerPage + 5 {
		sweep = append(sweep, secondaryScoredCVE(fmt.Sprintf("CVE-2026-9%04d", i), now, 3.0))
	}
	sweep = append(sweep, secondaryScoredCVE("CVE-2026-31431", now, 7.8))
	srv := fakeNVD(t, sweep)
	defer srv.Close()

	n := &NVD{client: srv.Client(), pageDelay: time.Millisecond}
	items, err := n.pollFrom(context.Background(), now.Add(-2*time.Hour), srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 || items[0].Metadata["cve"] != "CVE-2026-31431" {
		t.Fatalf("expected the high CVE from the second sweep page, got %+v", items)
	}
}

func TestNVDPollIncludesOlderModifiedCVEAndPrefersUpdatedRecord(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	since := now.Add(-time.Hour)
	old := secondaryScoredCVE("CVE-2024-4242", now.AddDate(-2, 0, 0), 8.1)
	old.CVE.LastModified = now.Add(-5 * time.Minute).Format("2006-01-02T15:04:05.000")
	old.CVE.Descriptions[0].Value = "Corrected affected version from vendor advisory"
	duplicate := secondaryScoredCVE("CVE-2026-4243", now.Add(-30*time.Minute), 9.8)
	duplicate.CVE.LastModified = now.Add(-20 * time.Minute).Format("2006-01-02T15:04:05.000")
	updated := duplicate
	updated.CVE.Descriptions = []nvdDescription{{Lang: "en", Value: "Newly corrected advisory content"}}
	updated.CVE.LastModified = now.Add(-time.Minute).Format("2006-01-02T15:04:05.000")
	modifiedRequests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has("lastModStartDate") {
			modifiedRequests++
			if q.Has("pubStartDate") || q.Has("pubEndDate") {
				t.Error("modified query must not require recent publication")
			}
			if q.Get("lastModStartDate") != since.Format("2006-01-02T15:04:05.000") || q.Get("lastModEndDate") == "" || q.Has("noRejected") {
				t.Errorf("modified window filters = %v", q)
			}
			json.NewEncoder(w).Encode(nvdResponse{TotalResults: 2, Vulnerabilities: []nvdVulnerability{old, updated}})
			return
		}
		json.NewEncoder(w).Encode(nvdResponse{TotalResults: 1, Vulnerabilities: []nvdVulnerability{duplicate}})
	}))
	defer srv.Close()
	items, err := (&NVD{client: srv.Client(), pageDelay: time.Millisecond}).pollFrom(context.Background(), since, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if modifiedRequests != 1 || len(items) != 2 {
		t.Fatalf("modified requests=%d items=%+v; want one modified query and both CVEs", modifiedRequests, items)
	}
	byID := map[string]RawItem{}
	for _, item := range items {
		byID[item.SourceID] = item
	}
	if got := byID["nvd:CVE-2024-4242"]; !got.PublishedAt.Equal(now.AddDate(-2, 0, 0)) || !got.UpdatedAt.Equal(now.Add(-5*time.Minute)) {
		t.Fatalf("old modified CVE dates not preserved: %+v", got)
	}
	if got := byID["nvd:CVE-2026-4243"]; !strings.Contains(got.Content, "Newly corrected") || !got.UpdatedAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("publication query hid newer correction: %+v", got)
	}
}

func TestNVDModifiedSweepPagesAndPreservesCorrectionScores(t *testing.T) {
	now := time.Now().UTC()
	var queried []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !q.Has("lastModStartDate") {
			json.NewEncoder(w).Encode(nvdResponse{})
			return
		}
		queried = append(queried, q.Get("startIndex"))
		var page []nvdVulnerability
		if q.Get("startIndex") == "0" {
			for i := range 2000 {
				page = append(page, secondaryScoredCVE(fmt.Sprintf("CVE-2024-7%04d", i), now.AddDate(-1, 0, 0), 3.1))
			}
		} else {
			page = []nvdVulnerability{secondaryScoredCVE("CVE-2024-31431", now.AddDate(-1, 0, 0), 7.8)}
		}
		json.NewEncoder(w).Encode(nvdResponse{TotalResults: 2001, Vulnerabilities: page})
	}))
	defer srv.Close()
	items, err := (&NVD{client: srv.Client(), pageDelay: time.Millisecond}).pollFrom(context.Background(), now.Add(-time.Hour), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(queried, []string{"0", "2000"}) || len(items) != 2001 || items[len(items)-1].SourceID != "nvd:CVE-2024-31431" {
		t.Fatalf("modified pages=%v items=%+v", queried, items)
	}
	for _, item := range items[:2000] {
		if !item.CorroborationOnly {
			t.Fatal("low-score modified record may open a new brief")
		}
	}
}

func TestNVDModifiedSweepRetainsDowngradesAndRetractions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.Query().Has("lastModStartDate") {
			json.NewEncoder(w).Encode(nvdResponse{})
			return
		}
		if r.URL.Query().Has("noRejected") || r.URL.Query().Has("cvssV3Severity") {
			t.Errorf("correction query filters retractions: %s", r.URL.RawQuery)
		}
		fmt.Fprintf(w, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-4242","published":"2024-01-01T00:00:00.000","lastModified":%q,"vulnStatus":"Modified","descriptions":[{"lang":"en","value":"Vendor corrects impact to a low severity information disclosure."}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":3.1}}]}}},{"cve":{"id":"CVE-2024-4243","published":"2024-01-01T00:00:00.000","lastModified":%q,"vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"This CVE record has been rejected by its CNA."}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]}}}]}`, now.Format("2006-01-02T15:04:05.000"), now.Format("2006-01-02T15:04:05.000"))
	}))
	defer srv.Close()
	items, err := (&NVD{client: srv.Client(), pageDelay: time.Millisecond}).pollFrom(context.Background(), now.Add(-time.Hour), srv.URL)
	if err != nil || len(items) != 2 {
		t.Fatalf("corrections missing: items=%+v err=%v", items, err)
	}
	for _, item := range items {
		if !item.CorroborationOnly || !item.UpdatedAt.Equal(now) || item.Metadata["vuln_status"] == "" {
			t.Fatalf("unsafe correction metadata: %+v", item)
		}
	}
}

func TestNVDModifiedSweepFailureCannotReportCompletePoll(t *testing.T) {
	for _, mode := range []string{"http-error", "page-cap"} {
		t.Run(mode, func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !r.URL.Query().Has("lastModStartDate") {
					json.NewEncoder(w).Encode(nvdResponse{})
					return
				}
				requests++
				if mode == "http-error" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				json.NewEncoder(w).Encode(nvdResponse{TotalResults: 10001})
			}))
			defer srv.Close()
			_, err := (&NVD{client: srv.Client(), pageDelay: time.Millisecond}).pollFrom(context.Background(), time.Now().Add(-time.Hour), srv.URL)
			if err == nil || !strings.Contains(err.Error(), "modified") {
				t.Fatalf("incomplete modified sweep reported success: %v", err)
			}
			if requests == 0 || requests > 5 {
				t.Fatalf("modified request count=%d, want bounded 1..5", requests)
			}
		})
	}
}
