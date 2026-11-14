package pipeline

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func mergeDeferClient(extraction *ExtractionResult, failure string, assemblies *int) shutdownStageLLM {
	return shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			(*assemblies)++
			return "", errors.New("unexpected brief assembly after unavailable merge assessment")
		},
		generateJSON: func(_ context.Context, _, system string, out any) error {
			switch system {
			case extractionSystemPrompt:
				*out.(*ExtractionResult) = *cloneExtraction(extraction)
			case qualitySystemPrompt:
				*out.(*QualityScore) = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
			case mergeRelevanceSystemPrompt, roundupContentRelevanceSystemPrompt:
				if failure == "provider error" {
					return errors.New("relevance provider unavailable")
				}
			default:
				return fmt.Errorf("unexpected JSON stage %q", system)
			}
			return nil
		},
	}
}

func assertDeferredSourceState(t *testing.T, db *storage.DB, item scraper.RawItem, before *storage.Draft) {
	t.Helper()
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Error("unavailable relevance assessment permanently marked the source seen")
	}
	wantDrafts := 0
	if before != nil {
		wantDrafts = 1
		after, err := db.GetDraft(before.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Errorf("deferred source changed the existing draft:\nbefore: %+v\nafter: %+v", before, after)
		}
	}
	drafts := 0
	for _, status := range []string{storage.StatusPending, storage.StatusApproved, storage.StatusRejected} {
		for _, err := range db.DraftsWithStatus(status) {
			if err != nil {
				t.Fatal(err)
			}
			drafts++
		}
	}
	if drafts != wantDrafts {
		t.Errorf("draft count = %d, want %d without a duplicate", drafts, wantDrafts)
	}
	for label, query := range map[string]func() ([]storage.ContentIndexEntry, error){
		"title":      func() ([]storage.ContentIndexEntry, error) { return db.FindByTitleHash(NormalizeTitleHash(item.Title)) },
		"source URL": func() ([]storage.ContentIndexEntry, error) { return db.FindBySourceURLHash(SourceURLHash(item.URL)) },
	} {
		entries, err := query()
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("deferred source advanced the %s index: %+v", label, entries)
		}
	}
}

func TestProcessItemDefersUnavailableDedupUpdate(t *testing.T) {
	for _, stage := range []string{"pre-extraction", "post-extraction"} {
		for _, failure := range []string{"no client", "provider error", "missing decision"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				db := mustOpenTestDB(t)
				defer db.Close()
				p := newDedupTestPipeline(t, db)
				const existingYAML = "id: brief-existing\nslug: existing-widget\ntitle: WidgetServer CVE-2026-9999\nsummary: A WidgetServer vulnerability was disclosed.\nseverity: high\npublished_at: \"2026-10-01T00:00:00Z\"\ncontent: |\n  WidgetServer permits unauthenticated code execution.\n\n  ## Recommendation\n  Inventory WidgetServer installations and consult the vendor advisory for fixed releases.\ncves: [CVE-2026-9999]\naffected_vendors: [Acme]\naffected_products: [WidgetServer]\n"
				if err := db.CreateDraft(&storage.Draft{ID: "draft-existing", Status: storage.StatusApproved, Source: "nvd", BriefYAML: existingYAML, CreatedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
				if err := db.IndexContent(&storage.ContentIndexEntry{
					CVEID: "CVE-2026-9999", DraftID: "draft-existing", SourceID: "nvd:original", Source: "nvd",
					CVEContext: `{"has_exploit":false,"has_patch":false,"active_exploitation":false}`, CreatedAt: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
				extraction := &ExtractionResult{CVEs: []string{"CVE-2026-9999"}, AffectedVendors: []string{"Acme"}, AffectedProducts: []string{"WidgetServer"}}
				item := scraper.RawItem{
					SourceID: "new:widget-exploit", Source: "exploit-db", URL: "https://research.example/widget-exploit", Enriched: true,
					Title: "Public exploit for WidgetServer", Content: strings.Repeat("A public proof-of-concept exploit is available for the WidgetServer vulnerability. ", 10),
				}
				wantPreDecision := DedupNew
				if stage == "pre-extraction" {
					item.Source = "cisa-kev"
					item.Title = "Public exploit for WidgetServer CVE-2026-9999"
					wantPreDecision = DedupUpdate
				}
				if decision, _, _ := p.dedup.CheckPreExtraction(item); decision != wantPreDecision {
					t.Fatalf("fixture pre-extraction decision = %v, want %v", decision, wantPreDecision)
				}
				if decision, _ := p.dedup.CheckPostExtraction(item, extraction); decision != DedupUpdate {
					t.Fatalf("fixture post-extraction decision = %v, want update", decision)
				}
				before, err := db.GetDraft("draft-existing")
				if err != nil {
					t.Fatal(err)
				}
				assemblies := 0
				client := mergeDeferClient(extraction, failure, &assemblies)
				p.extractor, p.assembler, p.quality = NewThreatExtractor(client), NewBriefAssembler(client), NewQualityGate(client, 1)
				p.llmClient = client
				if failure == "no client" {
					p.llmClient = nil
				}
				err = p.processItem(context.Background(), item)
				if stage == "pre-extraction" && !errors.Is(err, errMergeRelevanceUnavailable) {
					t.Errorf("pre-extraction update error = %v, want wrapped relevance-unavailable error", err)
				} else if stage == "post-extraction" && err != nil {
					t.Errorf("post-extraction update did not stop this pass: %v", err)
				}
				if assemblies != 0 {
					t.Errorf("deferred update attempted %d duplicate brief assemblies", assemblies)
				}
				assertDeferredSourceState(t, db, item, before)
			})
		}
	}
}

func TestRouteToRoundupDefersUnavailableContentAssessment(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, failure := range []string{"no client", "provider error", "missing decision"} {
			t.Run(fmt.Sprintf("existing=%v/%s", existing, failure), func(t *testing.T) {
				db := mustOpenTestDB(t)
				defer db.Close()
				p := newDedupTestPipeline(t, db)
				p.roundupConsolidation = true
				var before *storage.Draft
				if existing {
					first, extraction := msrcItem("first", "CVE-2026-1000")
					if !p.routeToRoundup(context.Background(), first, extraction) {
						t.Fatal("fixture did not create the initial roundup")
					}
					entries, err := db.FindByVendorCycle(vendorCycleKey("Microsoft", time.Now().UTC()))
					if err != nil || len(entries) != 1 {
						t.Fatalf("roundup index = %+v, %v", entries, err)
					}
					before, err = db.GetDraft(entries[0].DraftID)
					if err != nil {
						t.Fatal(err)
					}
				}
				item, extraction := msrcItem("deferred", "CVE-2026-1001")
				item.URL = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1001"
				assemblies := 0
				p.llmClient = mergeDeferClient(extraction, failure, &assemblies)
				if failure == "no client" {
					p.llmClient = nil
				}
				if !p.routeToRoundup(context.Background(), item, extraction) {
					t.Error("unavailable roundup assessment fell through to standalone processing")
				}
				assertDeferredSourceState(t, db, item, before)
			})
		}
	}
}

func TestRouteToCampaignDefersUnavailableMergeAssessment(t *testing.T) {
	for _, failure := range []string{"no client", "provider error", "missing decision"} {
		t.Run(failure, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			p := newDedupTestPipeline(t, db)
			p.campaignConsolidation = true
			first := scraper.RawItem{SourceID: "campaign:first", Source: "bleepingcomputer", Title: "ClickFix delivers malware", URL: "https://news.example/first-clickfix"}
			if !p.routeToCampaign(context.Background(), first, &ExtractionResult{}) {
				t.Fatal("fixture did not create the initial campaign")
			}
			entries, err := db.FindByVendorCycle("campaign|clickfix")
			if err != nil || len(entries) != 1 {
				t.Fatalf("campaign index = %+v, %v", entries, err)
			}
			before, err := db.GetDraft(entries[0].DraftID)
			if err != nil {
				t.Fatal(err)
			}
			item := scraper.RawItem{SourceID: "campaign:deferred", Source: "research", Title: "ClickFix targets macOS", URL: "https://research.example/new-clickfix"}
			extraction := &ExtractionResult{AffectedOS: []string{"macOS"}}
			assemblies := 0
			p.llmClient = mergeDeferClient(extraction, failure, &assemblies)
			if failure == "no client" {
				p.llmClient = nil
			}
			if !p.routeToCampaign(context.Background(), item, extraction) {
				t.Error("unavailable campaign assessment fell through to standalone processing")
			}
			assertDeferredSourceState(t, db, item, before)
		})
	}
}

func TestRouteToRoundupDefersUnavailableMergeAssessment(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true
	// A legacy cycle index can point at a draft without the roundup tag. Its
	// content filter can succeed while the merge itself still needs relevance.
	legacy := strings.Replace(buildRoundupBriefYAML("Microsoft", time.Now().UTC(), "CVE-2026-1000"), "tags:\n  - roundup\n", "", 1)
	if err := db.CreateDraft(&storage.Draft{ID: "legacy-roundup", Status: storage.StatusPending, BriefYAML: legacy, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{DraftID: "legacy-roundup", SourceID: "msrc:original", Source: "msrc", VendorCycleKey: vendorCycleKey("Microsoft", time.Now().UTC()), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	before, err := db.GetDraft("legacy-roundup")
	if err != nil {
		t.Fatal(err)
	}
	p.llmClient = shutdownStageLLM{generateJSON: func(ctx context.Context, prompt, system string, out any) error {
		if system == roundupContentRelevanceSystemPrompt {
			return (dedupRelevanceLLM{}).GenerateJSON(ctx, prompt, system, out)
		}
		return errors.New("merge relevance provider unavailable")
	}}
	item, extraction := msrcItem("deferred", "CVE-2026-1000")
	item.URL = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1000"
	if !p.routeToRoundup(context.Background(), item, extraction) {
		t.Error("unavailable roundup merge assessment fell through to standalone processing")
	}
	assertDeferredSourceState(t, db, item, before)
}
