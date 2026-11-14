package scraper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSplunkESCU_Poll(t *testing.T) {
	now := time.Now().UTC()

	commits := []ghCommit{
		{
			SHA: "def12345abc67890def12345abc67890def12345",
			Commit: struct {
				Author struct {
					Date time.Time `json:"date"`
				} `json:"author"`
				Message string `json:"message"`
			}{
				Author: struct {
					Date time.Time `json:"date"`
				}{Date: now},
				Message: "Add detection for credential dumping",
			},
		},
	}

	detail := ghCommitDetail{
		Files: []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		}{
			{Filename: "detections/endpoint/credential_dump.yml", Status: "added"},
			{Filename: "stories/credential_access.yml", Status: "modified"},
		},
	}

	ruleContent := "name: Credential Dumping via Mimikatz\nsearch: index=main sourcetype=sysmon"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/splunk/security_content/commits", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("path") != "" {
			json.NewEncoder(w).Encode(commits)
		}
	})
	mux.HandleFunc("/repos/splunk/security_content/commits/def12345abc67890def12345abc67890def12345", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(detail)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ruleContent))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &SplunkESCU{
		client:  srv.Client(),
		tokenFn: func() string { return "" },
	}

	items, err := s.pollFrom(context.Background(), now.Add(-24*time.Hour), srv.URL, srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item (non-detection file filtered), got %d", len(items))
	}
	if items[0].Source != "splunk-escu" {
		t.Errorf("expected source 'splunk-escu', got %q", items[0].Source)
	}
}
