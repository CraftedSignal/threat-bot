package pipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

const kevReconcileBriefYAML = `id: brief-2026-04-widget-rce
slug: 2026-04-widget-rce
title: WidgetServer remote code execution (CVE-2026-4242)
summary: CVE-2026-4242 lets unauthenticated attackers run code on WidgetServer.
content: |
  CVE-2026-4242 lets unauthenticated attackers run code on WidgetServer.

  ## Recommendation
  Upgrade WidgetServer to 4.2.1, which fixes CVE-2026-4242, and restrict the management port to administrator networks until it is patched.
severity: high
published_at: "2026-04-11T12:00:00Z"
affected_vendors: [Acme]
affected_products: [WidgetServer]
cves:
  - id: CVE-2026-4242
    cvss: 9.8
    kev: false
    kev_status: "false"
  - id: CVE-2026-4243
    kev_status: "false"
exploitation_evidence:
  status: unknown
`

func kevTestCatalog(t *testing.T, added map[string]string) *scraper.KEVCatalog {
	t.Helper()
	catalog := scraper.NewKEVCatalog()
	if err := catalog.ReplaceEntries(added); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestReconcileExploitationMarksListedCVEsAndExploitation(t *testing.T) {
	catalog := map[string]string{"CVE-2026-4242": "2026-11-18"}
	out, listed, _, changed, err := reconcileExploitation(kevReconcileBriefYAML, catalog)
	if err != nil || !changed || len(listed) != 1 || listed[0] != "CVE-2026-4242" {
		t.Fatalf("changed=%v listed=%v err=%v", changed, listed, err)
	}
	var doc struct {
		Exploited bool `yaml:"exploited"`
		Evidence  struct {
			Status     string `yaml:"status"`
			SourceURL  string `yaml:"source_url"`
			Confidence string `yaml:"confidence"`
			ObservedAt string `yaml:"observed_at"`
		} `yaml:"exploitation_evidence"`
		CVEs []struct {
			ID        string `yaml:"id"`
			KEV       bool   `yaml:"kev"`
			KEVStatus string `yaml:"kev_status"`
		} `yaml:"cves"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Exploited || doc.Evidence.Status != "confirmed_active" || doc.Evidence.SourceURL != kevCatalogURL || doc.Evidence.Confidence != "high" || doc.Evidence.ObservedAt != "2026-11-18T00:00:00Z" {
		t.Fatalf("exploitation not recorded from the catalog: %+v", doc)
	}
	if !doc.CVEs[0].KEV || doc.CVEs[0].KEVStatus != "true" || doc.CVEs[1].KEV || doc.CVEs[1].KEVStatus != "false" {
		t.Fatalf("KEV flags wrong: %+v", doc.CVEs)
	}
	if _, _, _, again, _ := reconcileExploitation(out, catalog); again {
		t.Fatal("second pass changed an already reconciled brief")
	}
}

func TestReconcileExploitationKeepsExistingExploitationEvidence(t *testing.T) {
	brief := strings.Replace(kevReconcileBriefYAML, "exploitation_evidence:\n  status: unknown\n",
		"exploited: true\nexploitation_evidence:\n  status: confirmed_active\n  source_url: https://vendor.example/advisory\n  confidence: medium\n", 1)
	out, _, _, changed, err := reconcileExploitation(brief, map[string]string{"CVE-2026-4242": "2026-11-18"})
	if err != nil || !changed {
		t.Fatalf("stale KEV flag not refreshed: changed=%v err=%v", changed, err)
	}
	if !strings.Contains(out, "source_url: https://vendor.example/advisory") || strings.Contains(out, kevCatalogURL) {
		t.Fatalf("existing confirmed evidence replaced:\n%s", out)
	}
}

func TestReconcileExploitationStructuresBareCVEIDs(t *testing.T) {
	brief := "id: b\ntitle: t\ncves: [CVE-2026-4242, CVE-2026-1]\n"
	out, listed, _, changed, err := reconcileExploitation(brief, map[string]string{"CVE-2026-4242": ""})
	if err != nil || !changed || len(listed) != 1 {
		t.Fatalf("changed=%v listed=%v err=%v", changed, listed, err)
	}
	if !strings.Contains(out, "id: CVE-2026-4242\n      kev: true") && !strings.Contains(out, "kev: true") {
		t.Fatalf("bare ID not flagged:\n%s", out)
	}
	if strings.Contains(out, "observed_at") {
		t.Fatalf("undated listing invented an observation date:\n%s", out)
	}
	if _, _, _, changed, _ := reconcileExploitation("id: b\ncves: [CVE-2026-1]\n", map[string]string{"CVE-2026-4242": ""}); changed {
		t.Fatal("brief without a KEV CVE changed")
	}
}

type recordedDispatch struct {
	mu    sync.Mutex
	posts []dispatchPayload
}

func (r *recordedDispatch) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var payload dispatchPayload
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Errorf("dispatch body: %v", err)
		}
		r.mu.Lock()
		r.posts = append(r.posts, payload)
		r.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
}

func kevReconcilePipeline(t *testing.T, db *storage.DB, catalog *scraper.KEVCatalog, notifierURL string) *Pipeline {
	t.Helper()
	p := newDedupTestPipeline(t, db)
	p.logger = quietLogger()
	p.cveVerifier = NewCVEVerifier(nil, catalog)
	p.notifierURL, p.notifierToken, p.siteURL = notifierURL, "token", "https://feed.example"
	return p
}

// A CVE CISA lists after its brief was published reached the brief only
// through a merge of the CISA KEV item, and held merges blocked it: LiteLLM
// (CVE-2026-40217) and REDCap stayed "not exploited" after CISA's 2026-11-18
// listing, as did 197 older briefs.
func TestReconcileKEVMarksPublishedBriefsAndNotifiesOnlyRecentListings(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	recent := strings.NewReplacer("brief-2026-04-widget-rce", "brief-recent", "2026-04-widget-rce", "recent").Replace(kevReconcileBriefYAML)
	old := strings.NewReplacer("brief-2026-04-widget-rce", "brief-old", "2026-04-widget-rce", "old", "CVE-2026-4242", "CVE-2021-0001").Replace(kevReconcileBriefYAML)
	drafts := []storage.Draft{
		{ID: "recent", Status: storage.StatusApproved, Source: "nvd", BriefYAML: recent},
		{ID: "old", Status: storage.StatusApproved, Source: "nvd", BriefYAML: old},
		{ID: "pending", Status: storage.StatusPending, Source: "nvd", BriefYAML: kevReconcileBriefYAML},
		{ID: "unrelated", Status: storage.StatusApproved, Source: "nvd", BriefYAML: strings.ReplaceAll(kevReconcileBriefYAML, "CVE-2026-4242", "CVE-2026-9")},
	}
	for i := range drafts {
		drafts[i].CreatedAt = now.Add(-time.Duration(i) * time.Hour)
		if err := db.CreateDraft(&drafts[i]); err != nil {
			t.Fatal(err)
		}
	}
	var dispatched recordedDispatch
	server := dispatched.server(t)
	defer server.Close()
	catalog := kevTestCatalog(t, map[string]string{"CVE-2026-4242": "2026-11-18", "CVE-2021-0001": "2021-11-03"})
	p := kevReconcilePipeline(t, db, catalog, server.URL)

	first, err := p.ReconcileExploitation(context.Background(), ExploitationReconcileOptions{Limit: 1, NotifyWithin: 7 * 24 * time.Hour, Now: now})
	if err != nil || first.Updated != 1 || !first.More || first.Candidates != 2 {
		t.Fatalf("first pass: %+v err=%v", first, err)
	}
	second, err := p.ReconcileExploitation(context.Background(), ExploitationReconcileOptions{Limit: 1, NotifyWithin: 7 * 24 * time.Hour, Now: now})
	if err != nil || second.Updated != 1 || second.More {
		t.Fatalf("second pass: %+v err=%v", second, err)
	}
	third, err := p.ReconcileExploitation(context.Background(), ExploitationReconcileOptions{Limit: 1, NotifyWithin: 7 * 24 * time.Hour, Now: now})
	if err != nil || third.Updated != 0 || third.More {
		t.Fatalf("reconciliation is not idempotent: %+v err=%v", third, err)
	}

	for _, id := range []string{"recent", "old"} {
		draft, err := db.GetDraft(id)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(draft.BriefYAML, "exploited: true") || !strings.Contains(draft.BriefYAML, kevCatalogURL) || draft.UpdateCount != 1 {
			t.Fatalf("%s not marked exploited with an update record (updates=%d):\n%s", id, draft.UpdateCount, draft.BriefYAML)
		}
	}
	for _, id := range []string{"pending", "unrelated"} {
		draft, err := db.GetDraft(id)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(draft.BriefYAML, "exploited: true") {
			t.Fatalf("%s changed although it is not an approved KEV brief", id)
		}
	}
	dispatched.mu.Lock()
	defer dispatched.mu.Unlock()
	if len(dispatched.posts) != 1 || len(dispatched.posts[0].Briefs) != 1 {
		t.Fatalf("want exactly one update notification (recent listing only), got %+v", dispatched.posts)
	}
	sent := dispatched.posts[0].Briefs[0]
	if sent.Slug != "recent" || !sent.Exploited || !sent.IsUpdate || !strings.Contains(sent.UpdateSummary, "CVE-2026-4242") {
		t.Fatalf("notification payload wrong: %+v", sent)
	}
}

// Prose that contradicts a KEV listing cannot be published as exploited; the
// brief stays unchanged and is counted for editorial review.
func TestReconcileKEVHoldsBriefWhosePublicationContractFails(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	brief := strings.Replace(kevReconcileBriefYAML, "  Upgrade WidgetServer", "  There is no known exploitation. Upgrade WidgetServer", 1)
	if err := db.CreateDraft(&storage.Draft{ID: "negated", Status: storage.StatusApproved, Source: "nvd", BriefYAML: brief, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	p := kevReconcilePipeline(t, db, kevTestCatalog(t, map[string]string{"CVE-2026-4242": "2026-11-18"}), "")
	result, err := p.ReconcileExploitation(context.Background(), ExploitationReconcileOptions{})
	if err != nil || result.Updated != 0 || result.Held != 1 {
		t.Fatalf("contradicting prose not held: %+v err=%v", result, err)
	}
	draft, _ := db.GetDraft("negated")
	if draft.BriefYAML != brief {
		t.Fatal("held brief was modified")
	}
}

// Until the catalog loads, membership is unknown and nothing may change.
func TestReconcileKEVWaitsForTheCatalog(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	if err := db.CreateDraft(&storage.Draft{ID: "d", Status: storage.StatusApproved, Source: "nvd", BriefYAML: kevReconcileBriefYAML, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	p := kevReconcilePipeline(t, db, scraper.NewKEVCatalog(), "")
	if result, err := p.ReconcileExploitation(context.Background(), ExploitationReconcileOptions{}); err != nil || result != (ExploitationReconcileResult{}) {
		t.Fatalf("unloaded catalog changed state: %+v err=%v", result, err)
	}
}

// A sploitus PoC listing was the only "evidence" behind nine published
// exploited briefs (React RCE and the Android November bulletin among them),
// none of whose text claims exploitation. A KEV listing still wins.
func TestReconcileExploitationWithdrawsListingOnlyEvidence(t *testing.T) {
	listingOnly := strings.Replace(kevReconcileBriefYAML, "exploitation_evidence:\n  status: unknown\n",
		"exploited: true\npriority_signals: [active_exploitation, watchlist_match]\nexploitation_evidence:\n  status: confirmed_active\n  source_url: https://sploitus.com/exploit?id=2BB2A750\n  confidence: medium\n", 1)
	out, listed, corrected, changed, err := reconcileExploitation(listingOnly, map[string]string{"CVE-2099-0001": ""})
	if err != nil || !changed || !corrected || len(listed) != 0 {
		t.Fatalf("listing-only exploitation not withdrawn: changed=%v corrected=%v listed=%v err=%v", changed, corrected, listed, err)
	}
	for _, gone := range []string{"exploited: true", "sploitus.com", "active_exploitation"} {
		if strings.Contains(out, gone) {
			t.Fatalf("%q survived the correction:\n%s", gone, out)
		}
	}
	if !strings.Contains(out, "watchlist_match") {
		t.Fatalf("unrelated priority signal dropped:\n%s", out)
	}

	out, listed, corrected, changed, err = reconcileExploitation(listingOnly, map[string]string{"CVE-2026-4242": "2026-10-27"})
	if err != nil || !changed || !corrected || len(listed) != 1 || !strings.Contains(out, kevCatalogURL) || !strings.Contains(out, "exploited: true") {
		t.Fatalf("KEV listing must replace listing-only evidence: listed=%v err=%v\n%s", listed, err, out)
	}
}

func TestReconcileExploitationDoesNotAddPrioritySignals(t *testing.T) {
	brief := strings.Replace(kevReconcileBriefYAML, "exploitation_evidence:\n  status: unknown\n",
		"exploited: true\nexploitation_evidence:\n  status: confirmed_active\n  source_url: https://www.exploit-db.com/exploits/1\n", 1)
	out, _, corrected, changed, err := reconcileExploitation(brief, map[string]string{"CVE-2099-0001": ""})
	if err != nil || !changed || !corrected {
		t.Fatalf("changed=%v corrected=%v err=%v", changed, corrected, err)
	}
	if strings.Contains(out, "priority_signals") {
		t.Fatalf("correction added priority_signals:\n%s", out)
	}
}

func TestExploitListingIsNeverExploitationEvidence(t *testing.T) {
	for _, raw := range []string{"https://sploitus.com/exploit?id=X", "https://www.exploit-db.com/exploits/1", "https://packetstormsecurity.com/files/1"} {
		if !ExploitCodeListingURL(raw) {
			t.Errorf("%s not recognised as an exploit-code listing", raw)
		}
	}
	for _, raw := range []string{"https://www.greynoise.io/blog/x", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "not a url"} {
		if ExploitCodeListingURL(raw) {
			t.Errorf("%s wrongly treated as an exploit-code listing", raw)
		}
	}
	brief := &briefYAML{ID: "b", Title: "t", ExploitationEvidence: &ExploitationEvidence{Status: "confirmed_active", SourceURL: "https://sploitus.com/exploit?id=X"}, PrioritySignals: []string{"active_exploitation"}}
	if err := normalizeExploitationEvidence(brief); err != nil || brief.Exploited || brief.ExploitationEvidence.Status != "unknown" || len(brief.PrioritySignals) != 0 {
		t.Fatalf("validation kept listing-only exploitation: %+v err=%v", brief, err)
	}
	item := scraper.RawItem{Source: "sploitus", URL: "https://sploitus.com/exploit?id=X", Title: "Exploit used in attacks", Content: "This exploit was used in attacks."}
	if mergeAppliesExploitation(item, &ExtractionResult{ActiveExploitation: true, ExploitationEvidence: "This exploit was used in attacks."}) {
		t.Fatal("an exploit tracker merge recorded exploitation")
	}
}
