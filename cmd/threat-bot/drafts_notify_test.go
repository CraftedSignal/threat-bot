package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

const notifyDraftYAML = `id: brief-2026-11-17-cve-2026-4242
slug: 2026-11-cve-2026-4242
title: WidgetServer remote code execution (CVE-2026-4242)
summary: CVE-2026-4242 lets unauthenticated attackers run code on WidgetServer.
severity: high
published_at: "2026-11-17T23:29:44Z"
content: |
  CVE-2026-4242 lets unauthenticated attackers run code on WidgetServer.

  ## Recommendation
  Upgrade WidgetServer to 4.2.1, which fixes CVE-2026-4242.
references:
  - https://vendor.example/advisories/cve-2026-4242
affected_vendors: [Acme]
affected_products: [WidgetServer]
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://sensors.example/report
  observed_at: "2026-11-18T00:00:00Z"
cves:
  - id: CVE-2026-4242
`

func TestDraftsNotifyUpdatePreviewsAndSendsThePublicProjection(t *testing.T) {
	var posts [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		_, _ = body.ReadFrom(r.Body)
		posts = append(posts, body.Bytes())
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte("db:\n  path: "+filepath.Join(dir, "state.db")+"\npublish:\n  site_url: https://feed.example\nnotifier:\n  url: "+server.URL+"\n  dispatch_token: t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := flagConfig
	flagConfig = config
	defer func() { flagConfig = previous }()
	db, err := storage.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.CreateDraft(&storage.Draft{ID: "d", Status: storage.StatusApproved, Source: "nvd", BriefYAML: notifyDraftYAML, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runDraftsNotifyUpdate(context.Background(), db, []string{"--id", "d", "--summary", "exploited:true"}, &out); err != nil {
		t.Fatal(err)
	}
	// No KEV listing, named actor or exploitation signal: the published type
	// is advisory. What matters is that it is the published type, not empty.
	if len(posts) != 0 || !strings.Contains(out.String(), "Preview only") || !strings.Contains(out.String(), `"type": "advisory"`) {
		t.Fatalf("preview sent or lacks the public type:\n%s", out.String())
	}
	out.Reset()
	if err := runDraftsNotifyUpdate(context.Background(), db, []string{"--id", "d", "--summary", "exploited:true", "--send"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(posts) != 1 {
		t.Fatalf("posts=%d", len(posts))
	}
	var payload struct {
		Briefs []map[string]any `json:"briefs"`
	}
	if err := json.Unmarshal(posts[0], &payload); err != nil || len(payload.Briefs) != 1 {
		t.Fatalf("payload %s: %v", posts[0], err)
	}
	sent := payload.Briefs[0]
	if sent["type"] != "advisory" || sent["is_update"] != true || sent["exploited"] != true || sent["update_summary"] != "exploited:true" {
		t.Fatalf("sent payload: %+v", sent)
	}
	draft, _ := db.GetDraft("d")
	if draft.LastL3Dispatch == nil {
		t.Fatal("dispatch not recorded")
	}
	if err := runDraftsNotifyUpdate(context.Background(), db, []string{"--id", "d"}, &out); err == nil {
		t.Fatal("missing summary accepted")
	}
}
