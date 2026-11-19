package pipeline

import (
	"context"
	"encoding/json"
	"errors"
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

// Exploitation news reached subscribers only from a short list of vendor
// sources, so Java4Shell's attempts (reported by SecurityWeek and GreyNoise)
// could never notify. Unlisted sources stay suppressed.
func TestL3UpdateDispatchAllowsExploitationReporters(t *testing.T) {
	for source, want := range map[string]int{"greynoise": 1, "securityweek": 1, "the-hacker-news": 1, "reddit": 0, "sploitus": 0} {
		t.Run(source, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			if err := db.CreateDraft(&storage.Draft{ID: "d", Status: storage.StatusApproved, Source: "nvd", BriefYAML: strings.Replace(kevReconcileBriefYAML, "exploitation_evidence:\n  status: unknown\n", "exploited: true\n", 1), CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			var dispatched recordedDispatch
			server := dispatched.server(t)
			defer server.Close()
			p := kevReconcilePipeline(t, db, kevTestCatalog(t, map[string]string{"CVE-2099-0001": ""}), server.URL)
			p.maybeDispatchL3Update(context.Background(), "d", "exploited:true", source, p.siteURL)
			dispatched.mu.Lock()
			defer dispatched.mu.Unlock()
			if len(dispatched.posts) != want {
				t.Fatalf("%s: %d dispatches, want %d", source, len(dispatched.posts), want)
			}
		})
	}
}

// A draft still carrying listing-only evidence must take a later attributed
// confirmation, not keep the sploitus URL that publication withdraws.
func TestMergeExploitationStateReplacesListingOnlyEvidence(t *testing.T) {
	base := map[string]any{"exploited": true, "exploitation_evidence": map[string]any{"status": "confirmed_active", "source_url": "https://sploitus.com/exploit?id=X"}}
	incoming := map[string]any{"exploited": true, "exploitation_evidence": map[string]any{"status": "confirmed_active", "source_url": "https://news.example/attacks", "confidence": "high"}}
	if !mergeExploitationState(base, incoming) {
		t.Fatal("attributed confirmation not merged")
	}
	if got := base["exploitation_evidence"].(map[string]any)["source_url"]; got != "https://news.example/attacks" {
		t.Fatalf("listing URL kept: %v", got)
	}
	// Two attributed confirmations keep the first source.
	if mergeExploitationState(base, map[string]any{"exploitation_evidence": map[string]any{"status": "confirmed_active", "source_url": "https://other.example/x"}}) {
		t.Fatal("equal-rank attributed evidence replaced the first source")
	}
}

// A listing-only state is withdrawn silently only when nothing in the brief
// claims exploitation. If its text says it is exploited, the text may rest on
// a source the brief never cited, so a person decides; a KEV listing settles
// it either way.
func TestReconcileExploitationHoldsListingOnlyClaimsTheTextMakes(t *testing.T) {
	brief := strings.Replace(kevReconcileBriefYAML, "exploitation_evidence:\n  status: unknown\n",
		"exploited: true\nexploitation_evidence:\n  status: confirmed_active\n  source_url: https://sploitus.com/exploit?id=X\n", 1)
	claims := strings.Replace(brief, "CVE-2026-4242 lets unauthenticated attackers run code on WidgetServer.\n", "CVE-2026-4242 is actively exploited in the wild against WidgetServer.\n", 1)
	if out, _, _, changed, err := reconcileExploitation(claims, map[string]string{"CVE-2099-1": ""}); !errors.Is(err, errListingClaimNeedsReview) || changed || out != claims {
		t.Fatalf("contradicting text withdrawn silently: changed=%v err=%v", changed, err)
	}
	if _, listed, _, changed, err := reconcileExploitation(claims, map[string]string{"CVE-2026-4242": "2026-11-18"}); err != nil || !changed || len(listed) != 1 {
		t.Fatalf("KEV listing must settle the claim: changed=%v listed=%v err=%v", changed, listed, err)
	}
	negated := strings.Replace(brief, "  Upgrade WidgetServer", "  There is no known exploitation in the wild. Upgrade WidgetServer", 1)
	if _, _, corrected, _, err := reconcileExploitation(negated, map[string]string{"CVE-2099-1": ""}); err != nil || !corrected {
		t.Fatalf("negated text must not block the withdrawal: corrected=%v err=%v", corrected, err)
	}
}

// A brief listing a KEV CVE twice must flag every entry.
func TestReconcileExploitationFlagsDuplicateCVEEntries(t *testing.T) {
	brief := strings.Replace(kevReconcileBriefYAML, "  - id: CVE-2026-4243\n", "  - id: CVE-2026-4242\n    kev: false\n  - id: CVE-2026-4243\n", 1)
	out, listed, _, _, err := reconcileExploitation(brief, map[string]string{"CVE-2026-4242": "2026-11-18"})
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
	if strings.Count(out, "kev: true") != 2 || strings.Contains(out, "kev: false\n  - id: CVE-2026-4243") {
		t.Fatalf("duplicate KEV entry left unflagged:\n%s", out)
	}
}

// A CAS write: an operator edit between the scan and the write must survive.
func TestReconcileExploitationNeverOverwritesConcurrentEdits(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	if err := db.CreateDraft(&storage.Draft{ID: "d", Status: storage.StatusApproved, Source: "nvd", BriefYAML: kevReconcileBriefYAML, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(kevReconcileBriefYAML, "severity: high", "severity: critical", 1)
	if err := db.RecordDraftUpdateIfUnchanged("d", "not the stored yaml", edited, storage.UpdateEvent{At: time.Now()}, "", false); !errors.Is(err, storage.ErrDraftChanged) {
		t.Fatalf("stale expectation accepted: %v", err)
	}
	if err := db.RecordDraftUpdateIfUnchanged("d", kevReconcileBriefYAML, edited, storage.UpdateEvent{At: time.Now()}, "", false); err != nil {
		t.Fatalf("matching expectation refused: %v", err)
	}
	draft, _ := db.GetDraft("d")
	if draft.BriefYAML != edited || draft.UpdateCount != 1 {
		t.Fatalf("conditional update not applied: count=%d", draft.UpdateCount)
	}
}

// Catching up an old KEV listing is not news. A merge whose only L3 change is
// such a flag must not notify; a recent listing or new exploitation must.
func TestMergeNotifiesOnlyForRecentKEVListings(t *testing.T) {
	now := time.Now().UTC()
	p := kevReconcilePipeline(t, nil, kevTestCatalog(t, map[string]string{
		"CVE-2021-0001": "2021-11-03",
		"CVE-2026-0002": now.AddDate(0, 0, -1).Format("2006-01-02"),
	}), "")
	set := func(ids ...string) map[string]bool {
		out := map[string]bool{}
		for _, id := range ids {
			out[id] = true
		}
		return out
	}
	pre := briefSignals{kevSet: set(), severity: "high"}
	if !p.onlyStaleKEVNews(pre, briefSignals{kevSet: set("CVE-2021-0001"), exploited: true, severity: "high"}) {
		t.Fatal("a 2021 KEV listing caught up by a merge was treated as news")
	}
	if p.onlyStaleKEVNews(pre, briefSignals{kevSet: set("CVE-2026-0002"), exploited: true, severity: "high"}) {
		t.Fatal("a listing from yesterday was suppressed")
	}
	if p.onlyStaleKEVNews(pre, briefSignals{kevSet: set(), exploited: true, severity: "high"}) {
		t.Fatal("exploitation reported by a source was suppressed")
	}
	if p.onlyStaleKEVNews(pre, briefSignals{kevSet: set("CVE-2021-0001"), exploited: true, severity: "critical"}) {
		t.Fatal("an escalation to critical was suppressed")
	}
}
