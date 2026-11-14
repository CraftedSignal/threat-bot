package pipeline

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

const mergeReviewYAML = "id: brief-existing\nslug: existing-widget\ntitle: WidgetServer CVE-2026-9999\nsummary: A WidgetServer vulnerability was disclosed.\nseverity: high\npublished_at: \"2026-10-01T00:00:00Z\"\ncontent: |\n  WidgetServer permits unauthenticated code execution.\n\n  ## Recommendation\n  Inventory WidgetServer installations and consult the vendor advisory for fixed releases.\ncves: [CVE-2026-9999]\naffected_vendors: [Acme]\naffected_products: [WidgetServer]\n"

func seedMergeReview(t *testing.T, db *storage.DB) scraper.RawItem {
	t.Helper()
	if err := db.CreateDraft(&storage.Draft{ID: "draft-existing", Status: storage.StatusApproved, Source: "nvd", BriefYAML: mergeReviewYAML, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{CVEID: "CVE-2026-9999", DraftID: "draft-existing", SourceID: "nvd:original", Source: "nvd", CVEContext: `{"has_exploit":false,"has_patch":false,"active_exploitation":false}`, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return scraper.RawItem{SourceID: "research:patch-review", Source: "cisa-kev", URL: "https://research.example/patch-review", Enriched: true, Title: "Public exploit for WidgetServer CVE-2026-9999", Content: strings.Repeat("The November update patches WidgetServer CVE-2026-9999. SMB and Print Spooler remain persistent risk context. ", 10)}
}

func mergeReviewPipeline(t *testing.T, db *storage.DB, checks, extractions *int, checkerErr error) *Pipeline {
	t.Helper()
	client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) {
		return "", errors.New("unexpected standalone assembly after refused merge")
	}, generateJSON: func(_ context.Context, _, system string, out any) error {
		switch system {
		case extractionSystemPrompt:
			*extractions++
			*out.(*ExtractionResult) = ExtractionResult{CVEs: []string{"CVE-2026-9999"}, AffectedVendors: []string{"Acme"}, AffectedProducts: []string{"WidgetServer", "SMB", "Print Spooler"}}
		case qualitySystemPrompt:
			*out.(*QualityScore) = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
		case mergeRelevanceSystemPrompt:
			*out.(*mergeRelevanceLLMResponse) = mergeRelevanceLLMResponse{Merge: boolPtr(true), ReferenceRelevant: boolPtr(true), POCRelevant: boolPtr(false), CVEs: []string{"CVE-2026-9999"}, AffectedVendors: []string{"Acme"}, AffectedProducts: []string{"WidgetServer", "SMB", "Print Spooler"}}
		default:
			*checks++
			if checkerErr != nil {
				return checkerErr
			}
			result, ok := out.(*GroundingResult)
			if !ok {
				return fmt.Errorf("unexpected stage %q / %T", system, out)
			}
			*result = GroundingResult{Issues: []string{"affected_products: SMB and Print Spooler are contextual risk, not November patched products"}}
		}
		return nil
	}}
	p := newDedupTestPipeline(t, db)
	p.logger = quietLogger()
	p.llmClient = client
	p.extractor = NewThreatExtractor(client)
	p.quality = NewQualityGate(client, 1)
	p.grounding = NewGroundingChecker(client).WithLogger(quietLogger())
	p.maxGroundingAttempts = 2
	return p
}

func TestMergeClaimsRejectionHeldAcrossDatabaseRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	item := seedMergeReview(t, db)
	before, _ := db.GetDraft("draft-existing")
	checks, extractions := 0, 0
	p := mergeReviewPipeline(t, db, &checks, &extractions, nil)
	var logs bytes.Buffer
	p.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatalf("completed editorial rejection reported as provider outage: %v", err)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("rejected evidence was not retained: cp=%v err=%v", cp, err)
	}
	var saved processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.ReviewHold || saved.Extraction == nil || len(saved.Issues) == 0 {
		t.Fatalf("incomplete editorial evidence: %+v", saved)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p = mergeReviewPipeline(t, db, &checks, &extractions, nil)
	p.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	for range 3 {
		if err := p.processItem(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	if checks != 1 || extractions != 1 {
		t.Fatalf("unchanged held source repeated paid work: checks=%d extractions=%d", checks, extractions)
	}
	if count := strings.Count(logs.String(), "merge candidate held for editorial review"); count != 1 {
		t.Fatalf("unchanged hold repeated warnings: count=%d logs=%s", count, logs.String())
	}
	assertDeferredSourceState(t, db, item, before)
	summary, err := db.ProcessingSummary(time.Now().Add(-time.Hour))
	if err != nil || summary.ErrorPasses != 0 || summary.PendingPublicationIntents != 0 {
		t.Fatalf("editorial rejection became failure/publication: %+v %v", summary, err)
	}
}

func TestPostExtractionMergeRejectionDoesNotFallThrough(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	item := seedMergeReview(t, db)
	before, _ := db.GetDraft("draft-existing")
	checks, extractions := 0, 0
	p := mergeReviewPipeline(t, db, &checks, &extractions, nil)
	extraction := &ExtractionResult{CVEs: []string{"CVE-2026-9999"}, AffectedProducts: []string{"SMB"}}
	if !p.handlePostExtractionDedup(context.Background(), item, extraction, nil) {
		t.Fatal("completed claims rejection fell through to standalone assembly")
	}
	assertDeferredSourceState(t, db, item, before)
}

func TestMergeCheckpointWriteFailureCannotConsumeSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-failure.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	item := seedMergeReview(t, db)
	before, _ := db.GetDraft("draft-existing")
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`CREATE TRIGGER fail_merge_checkpoint BEFORE INSERT ON processing_checkpoints BEGIN SELECT RAISE(FAIL,'checkpoint unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	checks, extractions := 0, 0
	p := mergeReviewPipeline(t, db, &checks, &extractions, nil)
	if err := p.processItem(context.Background(), item); !errors.Is(err, errMergeRelevanceUnavailable) || !strings.Contains(err.Error(), "checkpoint unavailable") {
		t.Fatalf("durability failure allowed fallback instead of deferring source: %v", err)
	}
	assertDeferredSourceState(t, db, item, before)
	if checks != 0 {
		t.Fatalf("paid assessment started before durable reservation: %d", checks)
	}
}

func TestMergeEditorialHoldInvalidation(t *testing.T) {
	for _, change := range []string{"source", "policy", "target claim", "timestamp only", "source poll timestamp", "format only"} {
		t.Run(change, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			item := seedMergeReview(t, db)
			checks, extractions := 0, 0
			p := mergeReviewPipeline(t, db, &checks, &extractions, nil)
			var logs bytes.Buffer
			p.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			if err := p.processItem(context.Background(), item); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "source":
				item.Content += " Corrected November product scope."
			case "policy":
				p.processingPolicy += "new semantic policy"
			case "target claim":
				if err := db.UpdateDraftYAML("draft-existing", strings.Replace(mergeReviewYAML, "A WidgetServer vulnerability was disclosed.", "A corrected WidgetServer vulnerability scope was disclosed.", 1)); err != nil {
					t.Fatal(err)
				}
			case "timestamp only":
				if err := db.UpdateDraftYAML("draft-existing", mergeReviewYAML+"lastmod: 2026-11-14T12:00:00Z\nupdate_count: 22\n"); err != nil {
					t.Fatal(err)
				}
			case "source poll timestamp":
				item.UpdatedAt = time.Now().Add(time.Hour)
			case "format only":
				if err := db.UpdateDraftYAML("draft-existing", strings.Replace(mergeReviewYAML, "affected_products: [WidgetServer]", "affected_products:\n  - WidgetServer", 1)); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.processItem(context.Background(), item); err != nil {
				t.Fatal(err)
			}
			want := 2
			if change == "timestamp only" || change == "source poll timestamp" || change == "format only" {
				want = 1
			}
			if checks != want {
				t.Fatalf("%s: checks=%d want %d", change, checks, want)
			}
			if warnings := strings.Count(logs.String(), "merge candidate held for editorial review"); warnings != want {
				t.Fatalf("%s: review warnings=%d want %d", change, warnings, want)
			}
		})
	}
}

func TestMergeCancellationDoesNotReserveAssessment(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	item := seedMergeReview(t, db)
	checks, extractions := 0, 0
	p := mergeReviewPipeline(t, db, &checks, &extractions, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.mergeIntoDraft(ctx, "draft-existing", &ExtractionResult{}, item); !errors.Is(err, context.Canceled) || errors.Is(err, errMergeRelevanceUnavailable) {
		t.Fatalf("cancellation misclassified: %v", err)
	}
	if cp, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || cp != nil {
		t.Fatalf("cancellation reserved paid work: %+v %v", cp, err)
	}
	if checks != 0 {
		t.Fatalf("canceled assessment called model %d times", checks)
	}
}

func TestMergeProviderRetryHasDurableBackoffAndBudget(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	item := seedMergeReview(t, db)
	checks, extractions := 0, 0
	providerErr := errors.New("grounding provider unavailable")
	p := mergeReviewPipeline(t, db, &checks, &extractions, providerErr)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := p.processItem(context.Background(), item); !errors.Is(err, providerErr) {
			t.Fatalf("genuine provider error lost: %v", err)
		}
		if err := p.processItem(context.Background(), item); err != nil {
			t.Fatalf("backoff did not defer: %v", err)
		}
		cp, err := db.GetProcessingCheckpoint(item.SourceID)
		if err != nil || cp == nil {
			t.Fatalf("retry checkpoint absent: %v", err)
		}
		if attempt == 1 {
			cp.RetryAt = time.Now().Add(-time.Second)
			if err := db.PutProcessingCheckpoint(*cp); err != nil {
				t.Fatal(err)
			}
			p = mergeReviewPipeline(t, db, &checks, &extractions, providerErr)
		}
	}
	for range 3 {
		if err := p.processItem(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	if checks != 2 || extractions != 1 {
		t.Fatalf("retry did not reuse durable extraction/budget: checks=%d extractions=%d", checks, extractions)
	}
	if seen, _ := db.HasSeen(item.SourceID); seen {
		t.Fatal("exhausted assessment source was discarded instead of held")
	}
	if reason, ok, _ := db.PipelineQuarantineReason(item.SourceID); !ok || !strings.Contains(reason, "after 2 attempts") {
		t.Fatalf("no bounded review disposition: %q", reason)
	}
}

func TestMergeClaimsRejectionHasDistinctType(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	item := seedMergeReview(t, db)
	checks, extractions := 0, 0
	p := mergeReviewPipeline(t, db, &checks, &extractions, nil)
	err := p.mergeIntoDraft(context.Background(), "draft-existing", &ExtractionResult{CVEs: []string{"CVE-2026-9999"}, AffectedProducts: []string{"SMB"}}, item)
	var rejected *MergeClaimsRejectedError
	if !errors.As(err, &rejected) || errors.Is(err, errMergeRelevanceUnavailable) || errors.Is(err, errMergeNotRelevant) {
		t.Fatalf("completed claims verdict has wrong classification: %v", err)
	}
}

func TestMergeClaimsRejectionKeepsUmbrellaSourceUnseen(t *testing.T) {
	for _, route := range []string{"roundup", "campaign"} {
		t.Run(route, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			seed := newDedupTestPipeline(t, db)
			var item scraper.RawItem
			var extraction *ExtractionResult
			var indexKey string
			if route == "roundup" {
				seed.roundupConsolidation = true
				first, firstExtraction := msrcItem("first", "CVE-2026-1000")
				if !seed.routeToRoundup(context.Background(), first, firstExtraction) {
					t.Fatal("fixture did not create a roundup")
				}
				item, extraction = msrcItem("held", "CVE-2026-1001")
				indexKey = vendorCycleKey("Microsoft", time.Now().UTC())
			} else {
				seed.campaignConsolidation = true
				first := scraper.RawItem{SourceID: "campaign:first", Source: "research", Title: "ClickFix targets workstations", URL: "https://research.example/first"}
				if !seed.routeToCampaign(context.Background(), first, &ExtractionResult{}) {
					t.Fatal("fixture did not create a campaign")
				}
				item = scraper.RawItem{SourceID: "campaign:held", Source: "research", Title: "ClickFix targets macOS", URL: "https://research.example/held"}
				extraction = &ExtractionResult{AffectedOS: []string{"macOS"}}
				indexKey = "campaign|clickfix"
			}
			entries, err := db.FindByVendorCycle(indexKey)
			if err != nil || len(entries) != 1 {
				t.Fatalf("fixture index: %+v, %v", entries, err)
			}
			before, err := db.GetDraft(entries[0].DraftID)
			if err != nil {
				t.Fatal(err)
			}
			checks, extractions := 0, 0
			p := mergeReviewPipeline(t, db, &checks, &extractions, nil)
			baseClient := p.llmClient
			p.llmClient = shutdownStageLLM{generateJSON: func(ctx context.Context, prompt, system string, out any) error {
				if system == roundupContentRelevanceSystemPrompt {
					return (dedupRelevanceLLM{}).GenerateJSON(ctx, prompt, system, out)
				}
				return baseClient.GenerateJSON(ctx, prompt, system, out)
			}}
			p.roundupConsolidation, p.campaignConsolidation = true, true
			handled := false
			if route == "roundup" {
				handled = p.routeToRoundup(context.Background(), item, extraction)
			} else {
				handled = p.routeToCampaign(context.Background(), item, extraction)
			}
			if !handled {
				t.Fatal("editorial rejection fell through to standalone processing")
			}
			cp, err := db.GetProcessingCheckpoint(item.SourceID)
			if err != nil || cp == nil {
				t.Fatalf("missing held evidence: %+v, %v", cp, err)
			}
			var state processingCandidate
			if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
				t.Fatal(err)
			}
			if !state.ReviewHold || checks != 1 {
				t.Fatalf("completed grounding rejection not held: held=%v checks=%d", state.ReviewHold, checks)
			}
			assertDeferredSourceState(t, db, item, before)
		})
	}
}

func TestMergeUnavailableHoldDoesNotExposeProviderBody(t *testing.T) {
	const marker = "benign-provider-body-sentinel"
	db := mustOpenTestDB(t)
	defer db.Close()
	item := seedMergeReview(t, db)
	checks, extractions := 0, 0
	providerErr := &llm.HTTPError{StatusCode: 503, Body: marker}
	p := mergeReviewPipeline(t, db, &checks, &extractions, providerErr)
	p.maxGroundingAttempts = 1
	var logs bytes.Buffer
	p.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	err := p.processItem(context.Background(), item)
	if !errors.Is(err, providerErr) {
		t.Fatalf("provider error identity lost: %v", err)
	}
	reason, ok, err := db.PipelineQuarantineReason(item.SourceID)
	if err != nil || !ok {
		t.Fatalf("missing durable disposition: %q, %v", reason, err)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("missing held checkpoint: %+v, %v", cp, err)
	}
	if strings.Contains(reason+cp.Payload+logs.String(), marker) {
		t.Fatal("provider response body reached hold evidence or logs")
	}
}

func TestMergeHoldVisibilityRepairsAfterRestartWithoutAssessment(t *testing.T) {
	for _, fail := range []string{"quarantine", "history"} {
		t.Run(fail, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "review-repair.db")
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			item := seedMergeReview(t, db)
			before, err := db.GetDraft("draft-existing")
			if err != nil {
				t.Fatal(err)
			}
			conn, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			trigger := `CREATE TRIGGER fail_review BEFORE INSERT ON pipeline_quarantine BEGIN SELECT RAISE(FAIL,'review persistence unavailable'); END`
			if fail == "history" {
				trigger = `CREATE TRIGGER fail_review BEFORE INSERT ON processing_history WHEN NEW.stage='merge_editorial' BEGIN SELECT RAISE(FAIL,'review persistence unavailable'); END`
			}
			if _, err := conn.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			checks, extractions := 0, 0
			p := mergeReviewPipeline(t, db, &checks, &extractions, nil)
			if err := p.processItem(context.Background(), item); err == nil || !strings.Contains(err.Error(), "review persistence unavailable") {
				t.Fatalf("initial review persistence failure lost: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			p = mergeReviewPipeline(t, db, &checks, &extractions, nil)
			var logs bytes.Buffer
			p.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			if err := p.processItem(context.Background(), item); err == nil || !strings.Contains(err.Error(), "review persistence unavailable") {
				t.Fatalf("held resume silently lost review visibility failure: %v", err)
			}
			if _, err := conn.Exec("DROP TRIGGER fail_review"); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if err := p.processItem(context.Background(), item); err != nil {
					t.Fatal(err)
				}
			}
			if checks != 1 || extractions != 1 {
				t.Fatalf("visibility repair repeated model work: checks=%d extractions=%d", checks, extractions)
			}
			if reason, ok, err := db.PipelineQuarantineReason(item.SourceID); err != nil || !ok || !strings.Contains(reason, "held for editorial review") {
				t.Fatalf("quarantine visibility not repaired: %q, %v", reason, err)
			}
			var events int
			if err := conn.QueryRow(`SELECT COUNT(*) FROM processing_history WHERE source_id=? AND stage='merge_editorial' AND outcome='held'`, item.SourceID).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if events != 1 || strings.Count(logs.String(), "merge candidate held for editorial review") != 1 {
				t.Fatalf("review repair was not idempotent: events=%d logs=%s", events, logs.String())
			}
			cp, err := db.GetProcessingCheckpoint(item.SourceID)
			if err != nil || cp == nil {
				t.Fatalf("held checkpoint lost: %+v, %v", cp, err)
			}
			var state processingCandidate
			if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
				t.Fatal(err)
			}
			if !state.ReviewHold || state.MergeAttempts != 1 {
				t.Fatalf("visibility repair consumed held work: %+v", state)
			}
			assertDeferredSourceState(t, db, item, before)
		})
	}
}
