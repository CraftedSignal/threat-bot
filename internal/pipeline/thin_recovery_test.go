package pipeline

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

const recoveryBase = "id: brief-canonical-widget\nslug: canonical-widget\ntitle: WidgetServer security advisory\nsummary: WidgetServer permits attachment deletion.\nseverity: high\npublished_at: \"2026-10-01T00:00:00Z\"\naffected_vendors: [Acme]\naffected_products: [WidgetServer]\nreferences: [https://vendor.example/original]\n"
const recoveryNarrative = "content: |\n  ## Overview\n  WidgetServer permits attachment deletion through an administrator rename operation.\n\n  ## Recommendation\n  Restrict attachment renaming to trusted administrators until the vendor provides remediation.\naction_plan:\n  immediate_actions:\n    - action: Restrict attachment renaming to trusted administrators.\n      evidence: The vendor identifies administrator renaming as the vulnerable operation.\n"

func TestThinDraftRecoveryRebuildsCanonicalNarrative(t *testing.T) {
	for _, stage := range []string{"pre", "post", "retry"} {
		t.Run(stage, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			if err := db.CreateDraft(&storage.Draft{ID: "canonical", Status: storage.StatusApproved, Source: "nvd", SourceIDs: `["vendor:original"]`, BriefYAML: recoveryBase, CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			entry := &storage.ContentIndexEntry{DraftID: "canonical", SourceID: "vendor:original", Source: "nvd", TitleHash: NormalizeTitleHash("WidgetServer security advisory"), ProductFingerprintHash: ProductFingerprint([]string{"Acme"}, []string{"WidgetServer"}), CreatedAt: time.Now()}
			if err := db.IndexContent(entry); err != nil {
				t.Fatal(err)
			}
			quality, assemblies, checks := 0, 0, 0
			reject := stage == "retry"
			client := recoveryClient(&quality, &assemblies, &checks, &reject)
			cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, RetryBackoff: -time.Second, MaxGroundingAttempts: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			item := scraper.RawItem{SourceID: "research:richer", Source: "research", Title: "WidgetServer security advisory", URL: "https://vendor.example/corrected", Content: strings.Repeat("Acme confirms WidgetServer attachment deletion through an administrator rename operation. Restrict attachment renaming to trusted administrators until the vendor provides remediation. ", 3), Enriched: true}
			if stage == "post" {
				item.Title = "Administrator rename operation permits attachment deletion"
			}
			p := New(cfg)
			if err := p.processItem(context.Background(), item); err != nil {
				t.Fatal(err)
			}
			if stage == "retry" {
				before, err := db.GetDraft("canonical")
				if err != nil || before.BriefYAML != recoveryBase {
					t.Fatalf("rejected grounding changed canonical draft: %+v %v", before, err)
				}
				seen, _ := db.HasSeen(item.SourceID)
				if seen {
					t.Fatal("rejected rebuild consumed source")
				}
				cp, err := db.GetProcessingCheckpoint(item.SourceID)
				if err != nil || cp == nil || cp.InputKey != p.processingInputKey(item) {
					t.Fatalf("missing durable rebuild candidate: %+v %v", cp, err)
				}
				var saved map[string]any
				if err := yaml.Unmarshal([]byte(cp.Payload), &saved); err != nil {
					t.Fatal(err)
				}
				if saved["rebuilddraftid"] != "canonical" {
					t.Fatalf("checkpoint lost canonical target: %+v", saved)
				}
				reject = false
				if err := New(cfg).processItem(context.Background(), item); err != nil {
					t.Fatal(err)
				}
				updated, err := db.GetDraft("canonical")
				if err != nil || updated.BriefYAML != recoveryBase {
					t.Fatalf("repeatedly rejected recovery changed the canonical brief: %v\n%s", err, updated.BriefYAML)
				}
				if _, quarantined, err := db.PipelineQuarantineReason(item.SourceID); err != nil || !quarantined {
					t.Fatalf("repeatedly rejected recovery was not quarantined: %v", err)
				}
				seen, _ = db.HasSeen(item.SourceID)
				if !seen {
					t.Fatal("quarantined recovery remained eligible for paid retries")
				}
				if assemblies != 1 || checks != 2 {
					t.Fatalf("repeated recovery bought more paid work: assemblies=%d checks=%d", assemblies, checks)
				}
				return
			}
			if quality != 1 || assemblies != 1 || checks == 0 {
				t.Fatalf("recovery bypassed/repeated full pipeline: quality=%d assembly=%d grounding=%d", quality, assemblies, checks)
			}
			updated, err := db.GetDraft("canonical")
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := yaml.Unmarshal([]byte(updated.BriefYAML), &doc); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(fmt.Sprint(doc["content"]), "administrator rename operation") || doc["id"] != "brief-canonical-widget" || doc["slug"] != "canonical-widget" || fmt.Sprint(doc["published_at"]) != "2026-10-01T00:00:00Z" {
				t.Fatalf("canonical narrative/identity not recovered: %s", updated.BriefYAML)
			}
			if err := p.validatePublication(updated.BriefYAML); err != nil {
				t.Fatalf("recovered brief fails final gate: %v", err)
			}
			count := 0
			for _, status := range []string{storage.StatusPending, storage.StatusApproved, storage.StatusRejected} {
				for _, err := range db.DraftsWithStatus(status) {
					if err != nil {
						t.Fatal(err)
					}
					count++
				}
			}
			if count != 1 {
				t.Fatalf("rebuild created %d drafts, want single canonical", count)
			}
			seen, _ := db.HasSeen(item.SourceID)
			if !seen {
				t.Fatal("completed rebuild source remained unseen")
			}
		})
	}
}

func recoveryClient(quality, assemblies, checks *int, reject *bool) shutdownStageLLM {
	return shutdownStageLLM{
		generate: func(_ context.Context, _, system string) (string, error) {
			if !strings.HasPrefix(system, groundingRepairSystemPrompt) {
				(*assemblies)++
			}
			return recoveryBase + recoveryNarrative, nil
		},
		generateJSON: func(ctx context.Context, prompt, system string, out any) error {
			switch system {
			case qualitySystemPrompt:
				(*quality)++
				*out.(*QualityScore) = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
			case extractionSystemPrompt:
				*out.(*ExtractionResult) = ExtractionResult{AffectedVendors: []string{"Acme"}, AffectedProducts: []string{"WidgetServer"}, Summary: "WidgetServer attachment deletion through administrator renaming."}
			case groundingSystem:
				(*checks)++
				result := out.(*GroundingResult)
				result.Grounded = !*reject
				if *reject {
					result.Issues = []string{"unsupported claim"}
				}
			case mergeRelevanceSystemPrompt:
				return (dedupRelevanceLLM{}).GenerateJSON(ctx, prompt, system, out)
			default:
				return fmt.Errorf("unexpected model stage %s", system)
			}
			return nil
		},
	}
}

func TestChangedSourceCorrectionIsHeldWithoutConsumingRevision(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	old := recoveryBase + strings.ReplaceAll(recoveryNarrative, "administrator rename operation", "unauthenticated upload")
	if err := db.CreateDraft(&storage.Draft{ID: "canonical", Status: storage.StatusApproved, Source: "research", SourceIDs: `["vendor:original","research:corroboration"]`, BriefYAML: old, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{DraftID: "canonical", SourceID: "vendor:original", Source: "research", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSeenRevision("vendor:original", "research", "WidgetServer", "old"); err != nil {
		t.Fatal(err)
	}
	quality, assemblies, checks := 0, 0, 0
	reject := false
	client := recoveryClient(&quality, &assemblies, &checks, &reject)
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 1, RetryBackoff: -time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{SourceID: "vendor:original", Source: "research", Revision: "corrected", Title: "WidgetServer corrected security advisory", URL: "https://vendor.example/corrected", Content: strings.Repeat("Acme confirms WidgetServer attachment deletion through an administrator rename operation. Restrict attachment renaming to trusted administrators. ", 3), Enriched: true}
	_ = p.processItem(context.Background(), item)
	updated, err := db.GetDraft("canonical")
	if err != nil || updated.BriefYAML != old {
		t.Fatalf("source correction silently unioned stale claims: %+v %v", updated, err)
	}
	seen, err := db.HasSeenRevision(item.SourceID, item.Revision)
	if err != nil || seen {
		t.Fatalf("unapplied correction consumed: seen=%v err=%v", seen, err)
	}
	reason, ok, err := db.PipelineQuarantineReason(item.SourceID)
	if err != nil || !ok || !strings.Contains(reason, "correction") {
		t.Fatalf("missing explicit correction review hold: %q %v", reason, err)
	}
	// A rebuilt narrative could only be held, so the hold carries the revised
	// evidence without paying for quality, assembly or grounding.
	if quality != 0 || assemblies != 0 || checks != 0 {
		t.Fatalf("correction paid for a rebuild that could only be held: quality=%d assembly=%d grounding=%d", quality, assemblies, checks)
	}
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if quality != 0 || assemblies != 0 || checks != 0 {
		t.Fatalf("editorial hold repeated model work: quality=%d assembly=%d grounding=%d", quality, assemblies, checks)
	}
}

func TestNVDSourceDowngradeIsHeldBeforeThinContentCanConsumeIt(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	old := recoveryBase + recoveryNarrative
	if err := db.CreateDraft(&storage.Draft{ID: "canonical", Status: storage.StatusApproved, Source: "nvd", SourceIDs: `["nvd:CVE-2026-4242"]`, BriefYAML: old, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{DraftID: "canonical", SourceID: "nvd:CVE-2026-4242", Source: "nvd", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSeenRevision("nvd:CVE-2026-4242", "nvd", "Widget", "old"); err != nil {
		t.Fatal(err)
	}
	p := New(Config{DB: db, LLMClient: noopLLM{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{SourceID: "nvd:CVE-2026-4242", Source: "nvd", Revision: "rejected", Title: "CVE-2026-4242", Content: "This record has been rejected.", CorroborationOnly: true, Enriched: true, Metadata: map[string]string{"vuln_status": "Rejected"}}
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	seen, err := db.HasSeenRevision(item.SourceID, item.Revision)
	if err != nil || seen {
		t.Fatalf("NVD retraction consumed: seen=%v err=%v", seen, err)
	}
	after, err := db.GetDraft("canonical")
	if err != nil || after.BriefYAML != old {
		t.Fatalf("NVD retraction changed canonical without editorial review: %+v %v", after, err)
	}
	reason, ok, err := db.PipelineQuarantineReason(item.SourceID)
	if err != nil || !ok || !strings.Contains(reason, "retract") {
		t.Fatalf("NVD retraction lost editorial hold: %q %v", reason, err)
	}
}
