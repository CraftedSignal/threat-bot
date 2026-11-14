package pipeline

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestInitialCampaignPublicationRetainsDurableIntentOnQueueFailure(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	pub := &recoveryPublisher{fail: true}
	p.publisher, p.autoPublish, p.campaignConsolidation = pub, true, true
	item := scraper.RawItem{SourceID: "research:clickfix", Source: "research", Title: "ClickFix campaign activity", URL: "https://research.example/clickfix", Content: strings.Repeat("Observed ClickFix social engineering campaign delivers malicious commands. ", 4)}
	if !p.routeToCampaign(context.Background(), item, &ExtractionResult{Summary: "ClickFix social engineering"}) {
		t.Fatal("fixture did not create campaign")
	}
	intents, err := db.ListPublicationIntents()
	if err != nil || len(intents) != 1 {
		t.Fatalf("created campaign lost durable publication intent: %+v %v", intents, err)
	}
	if !intents[0].CompleteDraft {
		t.Fatal("initial campaign intent lost draft completion metadata")
	}
	pub.fail = false
	if err := p.recoverPublicationIntents(); err != nil {
		t.Fatal(err)
	}
	if pub.drafts != 1 || pub.payload != intents[0].BriefYAML {
		t.Fatalf("restart did not queue exact initial campaign: %+v", pub)
	}
	left, _ := db.ListPublicationIntents()
	if len(left) != 0 {
		t.Fatal("accepted campaign intent was not CAS-acknowledged")
	}
}

func TestInitialRoundupPublicationRetainsFinalEnrichedIntent(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	pub := &recoveryPublisher{fail: true}
	p.publisher, p.autoPublish, p.roundupConsolidation = pub, true, true
	item := scraper.RawItem{SourceID: "msrc:CVE-2026-4242", Source: "msrc", Title: "Microsoft security update CVE-2026-4242", URL: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-4242", Content: strings.Repeat("Microsoft Windows Server 2022 is affected by CVE-2026-4242. Apply Microsoft's security update. ", 3)}
	extraction := &ExtractionResult{CVEs: []string{"CVE-2026-4242"}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Windows Server 2022"}, Summary: "Microsoft Windows Server 2022 security update for CVE-2026-4242."}
	if !p.routeToRoundup(context.Background(), item, extraction) {
		t.Fatal("fixture did not create roundup")
	}
	intents, err := db.ListPublicationIntents()
	if err != nil || len(intents) != 1 {
		t.Fatalf("roundup lost durable publication: %+v %v", intents, err)
	}
	intent := intents[0]
	if !intent.CompleteDraft || !strings.Contains(intent.BriefYAML, "## CVE-2026-4242") || !strings.Contains(intent.BriefYAML, "Windows Server 2022") || !strings.Contains(intent.BriefYAML, "posted roundup") {
		t.Fatalf("roundup intent retained placeholder rather than final enriched snapshot: %+v", intent)
	}
	draft, err := db.GetDraft(intent.DraftID)
	if err != nil || draft.BriefYAML != intent.BriefYAML {
		t.Fatalf("roundup YAML/intent diverged: %+v %v", draft, err)
	}
	pub.fail = false
	if err := p.recoverPublicationIntents(); err != nil {
		t.Fatal(err)
	}
	if pub.drafts != 1 || pub.payload != intent.BriefYAML {
		t.Fatalf("recovery did not queue exact roundup snapshot: %+v", pub)
	}
}

func TestTemplatePublicationCannotQueueAnIncompleteInitialSnapshot(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Publisher: &recoveryPublisher{}, AutoPublish: true, Logger: quietLogger()})
	queue, err := p.createTemplateDraft(&storage.Draft{ID: "incomplete", Status: storage.StatusPending, BriefYAML: recoveryBase, CreatedAt: time.Now()})
	if err != nil || queue {
		t.Fatalf("incomplete template became publishable: queue=%v err=%v", queue, err)
	}
	intents, err := db.ListPublicationIntents()
	if err != nil || len(intents) != 0 {
		t.Fatalf("invalid placeholder obtained recovery intent: %+v %v", intents, err)
	}
}

func TestCorrelatedPublicationRetainsDurableIntentWithExactMetadata(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	for _, id := range []string{"a", "b"} {
		raw := fmt.Sprintf("id: brief-%s\nslug: corpus-%s\ntitle: Grounded actor advisory\nsummary: Credential theft campaign.\nseverity: high\npublished_at: \"2026-11-14T00:00:00Z\"\nthreat_actor: APT29\ncontent: Credential theft activity requires review of authentication records.\nprivate_evidence: {source_hash: exact-evidence}\n", id, id)
		if err := db.CreateDraft(&storage.Draft{ID: id, Status: storage.StatusApproved, BriefYAML: raw, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	pub := &recoveryPublisher{fail: true}
	p := New(Config{DB: db, Publisher: pub, AutoPublish: true, EnableCorrelation: true, Logger: quietLogger()})
	updated, err := p.correlator.Run(context.Background())
	if err != nil || len(updated) != 2 {
		t.Fatalf("correlation fixture failed: %v %v", updated, err)
	}
	intents, err := db.ListPublicationIntents()
	if err != nil || len(intents) != 2 {
		t.Fatalf("correlation changed YAML without durable intents: %+v %v", intents, err)
	}
	for _, intent := range intents {
		if !strings.Contains(intent.BriefYAML, "private_evidence:") || !strings.Contains(intent.BriefYAML, "exact-evidence") {
			t.Fatal("correlation rewrote and lost evidence metadata")
		}
	}
	if err := p.recoverPublicationIntents(); err == nil {
		t.Fatal("failed queue silently completed correlation")
	}
	pub.fail = false
	if err := p.recoverPublicationIntents(); err != nil {
		t.Fatal(err)
	}
	if pub.updates != 2 {
		t.Fatalf("correlation recovery queued %d updates", pub.updates)
	}
	left, _ := db.ListPublicationIntents()
	if len(left) != 0 {
		t.Fatal("accepted correlated updates were not CAS-acknowledged")
	}
}
