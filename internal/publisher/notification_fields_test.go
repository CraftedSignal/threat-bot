package publisher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// A draft as merges leave it: no public type, vendors and products under
// affected_*, exploitation evidence from a news merge. Shaped like the
// Java4Shell draft whose 2026-11-19 update notification reached no email
// subscriber, because the payload's type was empty.
const notificationDraftYAML = `id: brief-2026-11-17-cve-2026-4242
slug: 2026-11-cve-2026-4242
title: WidgetServer remote code execution (CVE-2026-4242)
summary: CVE-2026-4242 lets unauthenticated attackers run code on WidgetServer.
severity: high
published_at: "2026-11-17T23:29:44Z"
content: |
  CVE-2026-4242 lets unauthenticated attackers run code on WidgetServer.

  ## Recommendation
  Upgrade WidgetServer to 4.2.1, which fixes CVE-2026-4242, and restrict the management port to administrator networks until it is patched.
references:
  - https://vendor.example/advisories/cve-2026-4242
tags: [rce, widgetserver]
affected_vendors: [Acme]
affected_products: ["WidgetServer (>= 4.0.0, < 4.2.1)"]
threat_actor: Storm-1234
has_poc: true
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://sensors.example/report
  observed_at: "2026-11-18T00:00:00Z"
  confidence: medium
cves:
  - id: CVE-2026-4242
    cvss: 9.8
    kev: false
    kev_status: "false"
`

// The projection must equal the published front matter, field by field: the
// notifier matches update and new-brief notifications with the same filters.
func TestPublicNotificationFieldsEqualPublishedFrontmatter(t *testing.T) {
	var p *Publisher // the method must not need publisher state
	fields, err := p.PublicNotificationFields(notificationDraftYAML)
	if err != nil {
		t.Fatal(err)
	}
	// Compare with what the live publish path writes, not with the helper
	// the projection uses, so drift in either side fails here.
	live := New("example/feed", "", func() string { return "" }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	prepared, err := live.prepareBrief(notificationDraftYAML)
	if err != nil {
		t.Fatal(err)
	}
	_, content, _, publish, err := RenderPublicBriefMarkdown(*prepared, nil)
	if err != nil || !publish {
		t.Fatalf("fixture not publishable: publish=%v err=%v", publish, err)
	}
	raw, ok := renderedFrontmatter(content)
	if !ok {
		t.Fatal("no front matter")
	}
	var published publicBriefFrontmatter
	if err := yaml.Unmarshal(raw, &published); err != nil {
		t.Fatal(err)
	}
	if fields.Type == "" || fields.Type != published.Type || !slices.Equal(fields.Severities, published.Severities) ||
		!slices.Equal(fields.Vendors, published.Vendors) || !slices.Equal(fields.Products, published.Products) ||
		!slices.Equal(fields.Actors, published.Actors) || !slices.Equal(fields.Tags, published.Tags) ||
		fields.Exploited != published.Exploited || fields.HasPOC != published.HasPOC || fields.Slug != published.Slug {
		t.Fatalf("projection differs from the published front matter:\nprojection %+v\npublished  type=%q sev=%v vendors=%v products=%v actors=%v tags=%v exploited=%v poc=%v",
			fields, published.Type, published.Severities, published.Vendors, published.Products, published.Actors, published.Tags, published.Exploited, published.HasPOC)
	}
	if fields.Type != "threat" || !slices.Equal(fields.Vendors, []string{"Acme"}) || !slices.Equal(fields.Products, []string{"WidgetServer"}) ||
		!fields.Exploited || !fields.HasPOC || len(fields.Actors) == 0 {
		t.Fatalf("unexpected public fields: %+v", fields)
	}
}

func TestPublisherBuffersCompatibleDuplicateCVERowsAsOneCanonicalRecord(t *testing.T) {
	raw := strings.Replace(notificationDraftYAML,
		`cves:
  - id: CVE-2026-4242
    cvss: 9.8
    kev: false
    kev_status: "false"
`,
		`cves:
  - id: CVE-2026-4242
    cvss: 9.8
    kev: false
    kev_status: "false"
  - id: " cve-2026-4242 "
    epss: 0.7
    epss_percentile: 0.9
    kev: true
    kev_status: "true"
`, 1)
	if raw == notificationDraftYAML {
		t.Fatal("test fixture did not add the compatible partial CVE row")
	}
	p := New("example/feed", "", func() string { return "" }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.Publish(raw); err != nil {
		t.Fatalf("compatible duplicate CVE rows failed publication: %v", err)
	}
	if len(p.pending) != 1 || len(p.pending[0].CVEs) != 1 {
		t.Fatalf("publisher buffered duplicate CVE rows: %+v", p.pending)
	}
	cve := p.pending[0].CVEs[0]
	if cve.ID != "CVE-2026-4242" || cve.CVSS != 9.8 || cve.EPSS != 0.7 || cve.EPSSPercentile != 0.9 || !cve.KEV || cve.KEVStatus != "true" {
		t.Fatalf("publisher lost compatible CVE metadata: %+v", cve)
	}
}

func TestPublisherAcceptsAutomatedExploitationWithdrawalWithLegacyQualityGaps(t *testing.T) {
	raw := strings.Replace(notificationDraftYAML, "  ## Recommendation\n  Upgrade WidgetServer to 4.2.1, which fixes CVE-2026-4242, and restrict the management port to administrator networks until it is patched.\n", "  The advisory includes a proof of concept.\n", 1)
	raw = strings.Replace(raw, "exploited: true\nexploitation_evidence:\n  status: confirmed_active\n  source_url: https://sensors.example/report\n  observed_at: \"2026-11-18T00:00:00Z\"\n  confidence: medium\n", "exploited: false\nexploitation_evidence:\n  status: unknown\n", 1)
	raw += `updates:
  - level: L1
    summary: "exploitation evidence corrected: an exploit-code listing is not exploitation"
    sources: [threat-bot]
    source_urls: []
`
	p := New("example/feed", "", func() string { return "" }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.ValidatePublication(raw); err != nil {
		t.Fatalf("publisher rejected safe exploitation withdrawal: consistency=%v err=%v", pipeline.ValidatePublicationConsistency(raw), err)
	}
	if err := p.Publish(raw); err != nil {
		t.Fatalf("publisher did not buffer safe exploitation withdrawal: %v", err)
	}
	if len(p.pending) != 1 {
		t.Fatalf("pending publications = %d, want 1", len(p.pending))
	}
}

type recordedNotifications struct {
	mu    sync.Mutex
	posts []map[string][]map[string]any
}

// An update notification sent through the real publisher must carry the
// public type and fields, so a subscription filtering on type, vendor or
// product matches it. End to end: KEV reconciliation of a published draft.
func TestUpdateNotificationsCarryThePublicProjection(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	draft := strings.Replace(notificationDraftYAML, "exploited: true\nexploitation_evidence:\n  status: confirmed_active\n  source_url: https://sensors.example/report\n  observed_at: \"2026-11-18T00:00:00Z\"\n  confidence: medium\n", "exploitation_evidence:\n  status: unknown\n", 1)
	if err := db.CreateDraft(&storage.Draft{ID: "d", Status: storage.StatusApproved, Source: "nvd", BriefYAML: draft, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var got recordedNotifications
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string][]map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("payload: %v", err)
		}
		got.mu.Lock()
		got.posts = append(got.posts, payload)
		got.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	catalog := scraper.NewKEVCatalog()
	if err := catalog.ReplaceEntries(map[string]string{"CVE-2026-4242": time.Now().UTC().Format("2006-01-02")}); err != nil {
		t.Fatal(err)
	}
	pub := New("example/feed", "", func() string { return "" }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p := pipeline.New(pipeline.Config{DB: db, LLMClient: noopPublisherLLM{}, KEV: catalog, Publisher: pub, NotifierURL: server.URL, NotifierToken: "t", SiteURL: "https://feed.example", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	result, err := p.ReconcileExploitation(context.Background(), pipeline.ExploitationReconcileOptions{NotifyWithin: pipeline.KEVNotifyWithin})
	if err != nil || result.Updated != 1 || result.Notified != 1 {
		t.Fatalf("reconciliation: %+v err=%v", result, err)
	}
	got.mu.Lock()
	defer got.mu.Unlock()
	if len(got.posts) != 1 || len(got.posts[0]["briefs"]) != 1 {
		t.Fatalf("want one notification, got %+v", got.posts)
	}
	sent := got.posts[0]["briefs"][0]
	if sent["type"] != "threat" || sent["severity"] != "high" || sent["exploited"] != true || sent["has_poc"] != true || sent["is_update"] != true {
		t.Fatalf("update notification lacks the public fields: %+v", sent)
	}
	if vendors, _ := sent["vendors"].([]any); len(vendors) != 1 || vendors[0] != "Acme" {
		t.Fatalf("vendors not projected: %+v", sent["vendors"])
	}
	if products, _ := sent["products"].([]any); len(products) != 1 || products[0] != "WidgetServer" {
		t.Fatalf("products not projected: %+v", sent["products"])
	}
	if sent["url"] != "https://feed.example/briefs/2026-11-cve-2026-4242/" {
		t.Fatalf("url: %v", sent["url"])
	}
}

type noopPublisherLLM struct{}

func (noopPublisherLLM) Generate(context.Context, string, string) (string, error) { return "", nil }
func (noopPublisherLLM) GenerateJSON(context.Context, string, string, any) error  { return nil }
func (noopPublisherLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return nil
}

// A brief the publisher does not publish has no public page, so it must not
// notify: its projection reports ErrBriefNotPublished.
func TestPublicNotificationFieldsRefusesUnpublishedBriefs(t *testing.T) {
	generic := strings.NewReplacer("affected_vendors: [Acme]\n", "", "affected_products: [\"WidgetServer (>= 4.0.0, < 4.2.1)\"]\n", "").Replace(notificationDraftYAML)
	if strings.Contains(generic, "affected_vendors") || strings.Contains(generic, "affected_products") {
		t.Fatal("fixture still names a vendor or product")
	}
	var p *Publisher
	if _, err := p.PublicNotificationFields(generic); !errors.Is(err, pipeline.ErrBriefNotPublished) {
		t.Fatalf("generic CVE brief projected for notification: %v", err)
	}
}
