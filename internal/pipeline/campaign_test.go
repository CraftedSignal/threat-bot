package pipeline

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

func TestMatchCampaignFamily(t *testing.T) {
	if matchCampaignFamily("New ClickFix campaign targets macOS") != "clickfix" {
		t.Error("should match clickfix")
	}
	if matchCampaignFamily("Shai-Hulud worm returns") != "shai-hulud" {
		t.Error("should match shai-hulud")
	}
	if matchCampaignFamily("Prototype pollution in some lib") != "" {
		t.Error("a generic weakness class must NOT match a campaign family")
	}
}

func TestCampaignPublicationRejectionLeavesPendingDraftForReview(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.campaignConsolidation = true
	p.autoPublish = true
	p.publisher = &rejectingPublicationValidator{}
	var logs bytes.Buffer
	p.logger = slog.New(slog.NewTextHandler(&logs, nil))
	item := scraper.RawItem{SourceID: "rss:clickfix-contract", Source: "bleepingcomputer", Title: "ClickFix delivers malware via fake fixes", Content: "ClickFix campaign report"}
	if !p.routeToCampaign(context.Background(), item, &ExtractionResult{}) {
		t.Fatal("campaign sighting should be consumed")
	}
	entries, err := db.FindByVendorCycle("campaign|clickfix")
	if err != nil || len(entries) != 1 {
		t.Fatalf("find campaign draft: entries=%v err=%v", entries, err)
	}
	draft, err := db.GetDraft(entries[0].DraftID)
	if err != nil || draft == nil || draft.Status != storage.StatusPending {
		t.Fatalf("rejected candidate should remain pending: draft=%v err=%v", draft, err)
	}
	if strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "held for editorial review") {
		t.Fatalf("unexpected publication logs: %s", logs.String())
	}
}

func TestCampaignConsolidation(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.campaignConsolidation = true

	mk := func(id, title string) (scraper.RawItem, *ExtractionResult) {
		return scraper.RawItem{SourceID: "rss:" + id, Source: "bleepingcomputer", Title: title, Content: "Report about " + title},
			&ExtractionResult{}
	}

	// Two separate ClickFix reports → one umbrella brief.
	i1, e1 := mk("1", "ClickFix delivers CastleLoader via fake fixes")
	if !p.routeToCampaign(context.Background(), i1, e1) {
		t.Fatal("first ClickFix sighting should create an umbrella")
	}
	i2, e2 := mk("2", "ClickFix now targets macOS with infostealers")
	if !p.routeToCampaign(context.Background(), i2, e2) {
		t.Fatal("second ClickFix sighting should fold into the umbrella")
	}

	entries, err := db.FindByVendorCycle("campaign|clickfix")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	ids := map[string]bool{}
	for _, e := range entries {
		ids[e.DraftID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("want exactly one ClickFix umbrella, got %d (%v)", len(ids), ids)
	}
	var draftID string
	for id := range ids {
		draftID = id
	}
	d, _ := db.GetDraft(draftID)
	if d == nil || !strings.Contains(d.BriefYAML, "ClickFix Campaign") {
		t.Fatalf("umbrella brief expected, got: %v", d)
	}

	// A non-family report is not folded.
	inp, enp := mk("3", "Some unrelated SQL injection in a plugin")
	if p.routeToCampaign(context.Background(), inp, enp) {
		t.Fatal("non-family item must not be rolled up")
	}

	// Articles that only mention a family in passing (an ICS intrusion listing
	// ClickFix among initial-access vectors) are separate stories; folding them
	// in filled the ClickFix umbrella with FortiGate, WAGO and Siemens.
	passing := scraper.RawItem{SourceID: "rss:5", Source: "thehackernews", Title: "Hackers breach Polish power plant",
		Content: "Initial access included ClickFix lures and exposed FortiGate VPNs."}
	if p.routeToCampaign(context.Background(), passing, &ExtractionResult{}) {
		t.Fatal("a passing mention in the body must not be rolled up")
	}

	// Inert when the flag is off.
	p.campaignConsolidation = false
	i4, e4 := mk("4", "ClickFix variant spotted")
	if p.routeToCampaign(context.Background(), i4, e4) {
		t.Fatal("campaign consolidation must be inert when off")
	}
}

// An umbrella tracks a technique or malware family, so the brands a sighting
// names (lures, impersonated apps, stealer targets, abused hosting, payload
// tooling) are not its affected vendors/products. Unioning them per sighting
// grew the ClickFix umbrella to 31 vendors and 52 products. OS, IOCs, CVEs and
// references still fold in.
func TestCampaignMergeKeepsVendorProductScope(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.campaignConsolidation = true

	first := scraper.RawItem{SourceID: "rss:1", Source: "bleepingcomputer", Title: "ClickFix delivers CastleLoader via fake fixes", Content: "Report about ClickFix."}
	if !p.routeToCampaign(context.Background(), first, &ExtractionResult{}) {
		t.Fatal("first ClickFix sighting should create an umbrella")
	}
	sighting := scraper.RawItem{SourceID: "rss:2", Source: "bleepingcomputer", URL: "https://example.com/clickfix-zoom",
		Title: "ClickFix lures pose as Zoom and Calendly invites", Content: "Fake meeting invites lead to ClickFix."}
	extraction := &ExtractionResult{
		AffectedVendors:  []string{"Zoom", "Calendly"},
		AffectedProducts: []string{"Zoom", "Calendly", "Google Chrome"},
		AffectedOS:       []string{"macOS"},
	}
	if !p.routeToCampaign(context.Background(), sighting, extraction) {
		t.Fatal("second ClickFix sighting should fold into the umbrella")
	}

	entries, err := db.FindByVendorCycle("campaign|clickfix")
	if err != nil || len(entries) == 0 {
		t.Fatalf("find umbrella: %v", err)
	}
	d, err := db.GetDraft(entries[0].DraftID)
	if err != nil || d == nil {
		t.Fatalf("load umbrella: %v", err)
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(d.BriefYAML), &fm); err != nil {
		t.Fatalf("parse umbrella: %v", err)
	}
	if got := yamlStringList(fm["affected_vendors"]); len(got) != 0 {
		t.Errorf("sighting widened umbrella vendors: %q", got)
	}
	if got := yamlStringList(fm["affected_products"]); len(got) != 0 {
		t.Errorf("sighting widened umbrella products: %q", got)
	}
	if got := yamlStringList(fm["affected_os"]); !stringListContainsFold(got, "macOS") {
		t.Errorf("affected OS should still fold in, got %q", got)
	}
	if got := yamlStringList(fm["references"]); !stringListContainsFold(got, sighting.URL) {
		t.Errorf("sighting reference should still fold in, got %q", got)
	}
}
