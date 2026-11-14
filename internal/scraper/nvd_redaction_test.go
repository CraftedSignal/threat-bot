package scraper

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNVDSupplementalFailureLogsOnlyBoundedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cvssV3Severity") == "" && r.URL.Query().Get("lastModStartDate") == "" {
			http.Error(w, "BENIGN_NVD_BODY_SENTINEL", http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprint(w, `{"vulnerabilities":[],"totalResults":0}`)
	}))
	defer server.Close()
	var logs bytes.Buffer
	scraper := &NVD{client: server.Client(), logger: slog.New(slog.NewJSONHandler(&logs, nil)), pageDelay: time.Nanosecond}
	if _, err := scraper.pollFrom(context.Background(), time.Now().Add(-time.Hour), server.URL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "SENTINEL") {
		t.Fatal("NVD supplemental sweep exposed provider response content")
	}
	if !strings.Contains(logs.String(), "403") {
		t.Fatal("bounded HTTP status was lost")
	}
}
