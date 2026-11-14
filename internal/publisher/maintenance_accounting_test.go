package publisher

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMarkdownMaintenanceReportsEveryUnreadableSegment(t *testing.T) {
	for _, operation := range []string{"backfill", "drift"} {
		t.Run(operation, func(t *testing.T) {
			visited := map[string]bool{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				name := strings.TrimPrefix(r.URL.Path, "/repos/CraftedSignal/threat-feed/contents/output/briefs/")
				if strings.HasSuffix(r.URL.Path, "/contents/output/briefs") {
					json.NewEncoder(w).Encode([]map[string]string{{"name": "missing.json", "type": "file"}, {"name": "unreadable.json", "type": "file"}, {"name": "invalid.json", "type": "file"}, {"name": "decrypt.json", "type": "file"}})
					return
				}
				visited[name] = true
				switch name {
				case "missing.json":
					w.WriteHeader(http.StatusNotFound)
				case "unreadable.json":
					w.WriteHeader(http.StatusForbidden)
				case "invalid.json":
					json.NewEncoder(w).Encode(map[string]string{"sha": "invalid", "content": base64.StdEncoding.EncodeToString([]byte("invalid JSON"))})
				case "decrypt.json":
					json.NewEncoder(w).Encode(map[string]string{"sha": "decrypt", "content": base64.StdEncoding.EncodeToString([]byte(`{"version":"1","content":"invalid ciphertext"}`))})
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			p := testPublisher(srv)
			var logs bytes.Buffer
			p.logger = slog.New(slog.NewTextHandler(&logs, nil))
			var err error
			if operation == "backfill" {
				err = p.BackfillMarkdown()
			} else {
				_, err = p.CheckDriftMarkdown()
			}
			if err == nil {
				t.Error("maintenance reported success after omitting unreadable segments")
			}
			for _, name := range []string{"missing.json", "unreadable.json", "invalid.json", "decrypt.json"} {
				if !visited[name] {
					t.Errorf("maintenance stopped before inspecting %s", name)
				}
				if err != nil && !strings.Contains(err.Error(), name) {
					t.Errorf("aggregate error omitted %s: %v", name, err)
				}
			}
			if strings.Contains(logs.String(), "backfill complete") {
				t.Errorf("incomplete maintenance logged success: %s", logs.String())
			}
		})
	}
}
