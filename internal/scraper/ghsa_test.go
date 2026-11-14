package scraper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGHSA_Poll(t *testing.T) {
	now := time.Now().UTC()

	advisories := []ghsaAdvisory{
		{
			GHSAID:      "GHSA-abcd-1234-efgh",
			CVEID:       "CVE-2026-5678",
			Summary:     "Critical RCE in foo-lib",
			Description: "A remote code execution vulnerability",
			Severity:    "critical",
			HTMLURL:     "https://github.com/advisories/GHSA-abcd-1234-efgh",
			PublishedAt: now.Format(time.RFC3339),
			Vulnerabilities: []ghsaVulnerability{
				{
					Package: struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					}{Ecosystem: "npm", Name: "foo-lib"},
					VulnerableVersionRange: "< 2.0.0",
					PatchedVersions:        "2.0.0",
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(advisories)
	}))
	defer srv.Close()

	g := &GHSA{
		client:  srv.Client(),
		tokenFn: func() string { return "" },
	}

	items, err := g.pollSeverityFrom(context.Background(), now.Add(-24*time.Hour), "critical", srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Metadata["ghsa"] != "GHSA-abcd-1234-efgh" {
		t.Errorf("expected GHSA-abcd-1234-efgh, got %q", items[0].Metadata["ghsa"])
	}
	if items[0].Metadata["cve"] != "CVE-2026-5678" {
		t.Errorf("expected CVE-2026-5678, got %q", items[0].Metadata["cve"])
	}
}

func TestGHSA_StructuredAdvisoryFactsInMetadata(t *testing.T) {
	now := time.Now().UTC()
	score := 8.8
	adv := ghsaAdvisory{
		GHSAID:      "GHSA-aaaa-bbbb-cccc",
		Summary:     "RCE in foo",
		Severity:    "high",
		HTMLURL:     "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
		PublishedAt: now.Format(time.RFC3339),
		Vulnerabilities: []ghsaVulnerability{
			{VulnerableVersionRange: ">= 1.0.0, < 1.4.2", PatchedVersions: "1.4.2"},
		},
	}
	adv.Vulnerabilities[0].Package.Ecosystem = "npm"
	adv.Vulnerabilities[0].Package.Name = "foo"
	adv.CVSS.Score = &score
	adv.CVSS.VectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]ghsaAdvisory{adv})
	}))
	defer srv.Close()
	g := &GHSA{client: srv.Client(), tokenFn: func() string { return "" }}
	items, err := g.pollSeverityFrom(context.Background(), now.Add(-time.Hour), "high", srv.URL)
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	md := items[0].Metadata
	if want := "npm/foo | vulnerable: >= 1.0.0, < 1.4.2 | patched: 1.4.2"; md["affected_packages"] != want {
		t.Errorf("affected_packages = %q, want %q", md["affected_packages"], want)
	}
	if md["cvss"] != "8.8" {
		t.Errorf("cvss = %q, want 8.8", md["cvss"])
	}
	if md["cvss_vector"] != adv.CVSS.VectorString {
		t.Errorf("cvss_vector = %q", md["cvss_vector"])
	}
}
