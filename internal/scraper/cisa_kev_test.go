package scraper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCISAKEV_Poll(t *testing.T) {
	today := time.Now().UTC().Format("2006-01-02")
	old := time.Now().Add(-30 * 24 * time.Hour).UTC().Format("2006-01-02")

	catalog := kevCatalog{
		Title:          "Test KEV",
		CatalogVersion: "1",
		Count:          2,
		Vulnerabilities: []kevVulnerability{
			{
				CVEID:             "CVE-2026-1234",
				VendorProject:     "Acme",
				Product:           "Widget",
				VulnerabilityName: "RCE in Widget",
				DateAdded:         today,
				ShortDescription:  "Remote code execution",
				RequiredAction:    "Apply updates",
				DueDate:           today,
			},
			{
				CVEID:             "CVE-2025-9999",
				VendorProject:     "OldCo",
				Product:           "Legacy",
				VulnerabilityName: "Old vuln",
				DateAdded:         old,
				ShortDescription:  "Old vulnerability",
				RequiredAction:    "Mitigate",
				DueDate:           old,
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(catalog)
	}))
	defer srv.Close()

	c := NewCISAKEV(nil)
	c.client, c.url = srv.Client(), srv.URL

	items, err := c.Poll(context.Background(), time.Now().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item (old filtered), got %d", len(items))
	}
	if items[0].Metadata["cve"] != "CVE-2026-1234" {
		t.Errorf("expected CVE-2026-1234, got %q", items[0].Metadata["cve"])
	}
	if items[0].Source != "cisa-kev" {
		t.Errorf("expected source 'cisa-kev', got %q", items[0].Source)
	}
}
