package scraper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestElastic_Poll(t *testing.T) {
	now := time.Now().UTC()

	commits := []ghCommit{
		{
			SHA: "eee12345fff67890eee12345fff67890eee12345",
			Commit: struct {
				Author struct {
					Date time.Time `json:"date"`
				} `json:"author"`
				Message string `json:"message"`
			}{
				Author: struct {
					Date time.Time `json:"date"`
				}{Date: now},
				Message: "New lateral movement rule",
			},
		},
	}

	detail := ghCommitDetail{
		Files: []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		}{
			{Filename: "rules/windows/lateral_movement.toml", Status: "added"},
			{Filename: "rules/windows/old_rule.toml", Status: "removed"},
		},
	}

	ruleContent := `[rule]\nname = "Lateral Movement via PsExec"`

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/elastic/detection-rules/commits", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("path") != "" {
			json.NewEncoder(w).Encode(commits)
		}
	})
	mux.HandleFunc("/repos/elastic/detection-rules/commits/eee12345fff67890eee12345fff67890eee12345", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(detail)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ruleContent))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	e := &Elastic{
		client:  srv.Client(),
		tokenFn: func() string { return "" },
	}

	items, err := e.pollFrom(context.Background(), now.Add(-24*time.Hour), srv.URL, srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// Only the added .toml should be included (removed is filtered).
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Source != "elastic" {
		t.Errorf("expected source 'elastic', got %q", items[0].Source)
	}
}
