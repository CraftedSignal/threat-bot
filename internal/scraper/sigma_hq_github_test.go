package scraper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSigmaHQ_Poll(t *testing.T) {
	now := time.Now().UTC()

	commits := []ghCommit{
		{
			SHA: "abc12345def67890abc12345def67890abc12345",
			Commit: struct {
				Author struct {
					Date time.Time `json:"date"`
				} `json:"author"`
				Message string `json:"message"`
			}{
				Author: struct {
					Date time.Time `json:"date"`
				}{Date: now},
				Message: "Add new detection rule",
			},
		},
	}

	detail := ghCommitDetail{
		Files: []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		}{
			{Filename: "rules/windows/process_creation/test_rule.yml", Status: "added"},
			{Filename: "README.md", Status: "modified"},
		},
	}

	sigmaYAML := `title: Test Detection Rule
id: 12345678-abcd-1234-efgh-123456789012
status: test
description: Detects test activity
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\test.exe'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059
`

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/SigmaHQ/sigma/commits", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/SigmaHQ/sigma/commits" && r.URL.Query().Get("path") != "" {
			json.NewEncoder(w).Encode(commits)
		} else {
			json.NewEncoder(w).Encode(detail)
		}
	})
	mux.HandleFunc("/repos/SigmaHQ/sigma/commits/abc12345def67890abc12345def67890abc12345", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(detail)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Serve raw sigma rule content.
		w.Write([]byte(sigmaYAML))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &SigmaHQ{
		client:  srv.Client(),
		tokenFn: func() string { return "" },
	}

	items, err := s.pollFrom(ctx(t), now.Add(-24*time.Hour), srv.URL, srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item (non-rule file filtered), got %d", len(items))
	}
	if items[0].Source != "sigma-hq" {
		t.Errorf("expected source 'sigma-hq', got %q", items[0].Source)
	}
	if items[0].SigmaRule == nil {
		t.Fatal("expected SigmaRule to be set")
	}
	if items[0].SigmaRule.Title != "Test Detection Rule" {
		t.Errorf("expected title 'Test Detection Rule', got %q", items[0].SigmaRule.Title)
	}
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
