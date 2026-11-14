package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCIRCLMISP_Poll(t *testing.T) {
	now := time.Now().UTC()
	ts := fmt.Sprintf("%d", now.Unix())
	oldTs := fmt.Sprintf("%d", now.Add(-48*time.Hour).Unix())

	manifest := map[string]mispManifestEntry{
		"uuid-new": {
			Info:          "New phishing campaign",
			Timestamp:     json.Number(ts),
			ThreatLevelID: json.Number("2"),
			Orgc:          mispOrg{Name: "CIRCL"},
			Tag:           []mispTag{{Name: "tlp:white"}},
		},
		"uuid-old": {
			Info:          "Old event",
			Timestamp:     json.Number(oldTs),
			ThreatLevelID: json.Number("3"),
			Orgc:          mispOrg{Name: "CIRCL"},
		},
	}

	event := mispEvent{}
	event.Event.Info = "New phishing campaign"
	event.Event.Attributes = []mispAttribute{
		{Category: "Network activity", Type: "ip-dst", Value: "10.0.0.1", Comment: "C2 server"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/uuid-new.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(event)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &CIRCLMISP{client: srv.Client()}
	items, err := c.pollFrom(context.Background(), now.Add(-24*time.Hour), srv.URL+"/manifest.json", srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// Only the new event should be returned (old filtered by since).
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Source != "circl-misp" {
		t.Errorf("expected source 'circl-misp', got %q", items[0].Source)
	}
}
