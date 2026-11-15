package pipeline

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

type claimRetryLLM struct {
	checks, extractions, qualities, assemblies int
	claimErr                                   error
	grounded                                   bool
	beforeCheck                                func(context.Context)
	prompts                                    []string
}

func (c *claimRetryLLM) Generate(context.Context, string, string) (string, error) {
	c.assemblies++
	return "", errors.New("unexpected assembly of a held claim")
}
func (c *claimRetryLLM) GenerateJSON(_ context.Context, _, _ string, out any) error {
	switch value := out.(type) {
	case *QualityScore:
		c.qualities++
		*value = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
	case *ExtractionResult:
		c.extractions++
		*value = ExtractionResult{AffectedProducts: []string{"Example Harbor"}, Summary: "A researcher reports a heap disclosure.", ClaimAssessment: &ClaimAssessment{Claim: "Example Harbor discloses heap memory", Likelihood: "unlikely", Status: "unverified", Gaps: []string{"Not independently confirmed"}}}
	default:
		return errors.New("unexpected JSON stage")
	}
	return nil
}
func (c *claimRetryLLM) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	if system != groundingClaimsSystem {
		return errors.New("claim checkpoint entered full brief validation")
	}
	c.checks++
	c.prompts = append(c.prompts, prompt)
	if c.beforeCheck != nil {
		c.beforeCheck(ctx)
	}
	if c.claimErr != nil {
		return c.claimErr
	}
	report := out.(*groundingReport)
	if !c.grounded {
		report.Issues = []groundingIssue{{Kind: groundingKindUnsupported, Field: "claim_assessment.claim", Reason: "The source does not establish the asserted heap disclosure"}}
	}
	return nil
}

func claimRetryItem() scraper.RawItem {
	return scraper.RawItem{SourceID: "claim:durable", Source: "public-web-social-search", URL: "https://social.example/research/1", Title: "Example Harbor memory observations", Content: strings.Repeat("A researcher discusses uncertain memory observations in Example Harbor. ", 8), Enriched: true, Discovery: &scraper.DiscoveryContext{Platform: "x", OriginalURL: "https://social.example/research/1", ContextComplete: true}}
}

func TestDiscoveryClaimRequestSurvivesCheckpointSerialization(t *testing.T) {
	p := New(Config{Logger: quietLogger()})
	var extraction ExtractionResult
	client := &claimRetryLLM{}
	if err := client.GenerateJSON(context.Background(), "", "", &extraction); err != nil {
		t.Fatal(err)
	}
	first, err := p.discoveryClaimRequestDigest(claimRetryItem(), &extraction)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(extraction)
	if err != nil {
		t.Fatal(err)
	}
	var restored ExtractionResult
	if err := yaml.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	second, err := p.discoveryClaimRequestDigest(claimRetryItem(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		a, _ := json.Marshal(extraction)
		b, _ := json.Marshal(restored)
		t.Fatalf("checkpoint serialization changes request identity: original=%s restored=%s", a, b)
	}
}

func assertClaimUnconsumed(t *testing.T, db *storage.DB, item scraper.RawItem, pub *shutdownTestPublisher) {
	t.Helper()
	if seen, err := db.HasSeen(item.SourceID); err != nil || seen {
		t.Fatalf("held claim consumed: seen=%v err=%v", seen, err)
	}
	queued, err := db.NextIngestionCandidates(10)
	if err != nil || len(queued) != 1 {
		t.Fatalf("held claim queue removed: count=%d err=%v", len(queued), err)
	}
	if pub.publishes != 0 {
		t.Fatalf("unsupported claim published %d times", pub.publishes)
	}
}

// The regression is a lost negative-work checkpoint, not a cached positive
// verdict: real processing and SQLite are retained; only inference is fake.
func TestDiscoveryClaimRejectionSurvivesRedeliveryAndDatabaseRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claims.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	item := claimRetryItem()
	payload, _ := json.Marshal(item)
	if err := db.CommitIngestion(item.Source, time.Time{}, []storage.IngestionCandidate{{SourceID: item.SourceID, Source: item.Source, Revision: item.ContentRevision(), Payload: string(payload)}}); err != nil {
		t.Fatal(err)
	}
	client, pub := &claimRetryLLM{}, &shutdownTestPublisher{}
	for delivery := range 3 {
		p := New(Config{DB: db, LLMClient: client, Publisher: pub, AutoPublish: true, QualityThreshold: 1, ProcessingPolicy: "provider/region/main/fast/repair", Logger: quietLogger()})
		item.UpdatedAt = time.Unix(int64(delivery+1), 0)
		if err := p.Process(context.Background(), []scraper.RawItem{item}); err != nil {
			t.Fatal(err)
		}
		assertClaimUnconsumed(t, db, item, pub)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		db, err = storage.Open(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer db.Close()
	if client.checks != 1 || client.extractions != 1 || client.qualities != 1 || client.assemblies != 0 {
		t.Fatalf("unchanged rejected claim purchased repeated work: checks=%d extraction=%d quality=%d assembly=%d", client.checks, client.extractions, client.qualities, client.assemblies)
	}
	if checkpoint, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || checkpoint == nil {
		t.Fatalf("rejected claim has no durable assessment: checkpoint=%v err=%v", checkpoint, err)
	}
}

func TestDiscoveryClaimSemanticChangesRetryFactualAssessment(t *testing.T) {
	for _, change := range []string{"source", "beyond_checker_truncation", "model", "policy", "extraction"} {
		t.Run(change, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			client, item := &claimRetryLLM{}, claimRetryItem()
			if change == "beyond_checker_truncation" {
				item.Content = strings.Repeat("A synthetic source observation. ", 3000) + "old"
			}
			cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, ProcessingPolicy: "provider/model-v1", Logger: quietLogger()}
			_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
			switch change {
			case "source":
				item.Content += " Actual new evidence changes the reported impact."
			case "beyond_checker_truncation":
				item.Content = strings.TrimSuffix(item.Content, "old") + "new"
			case "model":
				cfg.ProcessingPolicy = "provider/model-v2"
			case "policy":
				cfg.QualityThreshold = 2
			case "extraction":
				cp, err := db.GetProcessingCheckpoint(item.SourceID)
				if err != nil || cp == nil {
					t.Fatalf("no persisted extraction: %v", err)
				}
				var state processingCandidate
				if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
					t.Fatal(err)
				}
				state.Extraction.ClaimAssessment.Claim = "Example Harbor causes a different memory fault"
				raw, _ := yaml.Marshal(state)
				cp.Payload = string(raw)
				if err := db.PutProcessingCheckpoint(*cp); err != nil {
					t.Fatal(err)
				}
			}
			_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
			if client.checks != 2 {
				t.Fatalf("%s change reused stale factual hold: checks=%d", change, client.checks)
			}
			if change == "beyond_checker_truncation" && client.prompts[0] != client.prompts[1] {
				t.Fatal("fixture did not isolate evidence beyond checker truncation")
			}
		})
	}
}

type claimRetrySocialProvider struct {
	content string
	fail    bool
}

func (p *claimRetrySocialProvider) FetchStatus(_ context.Context, id string) (scraper.SocialStatus, error) {
	if p.fail {
		return scraper.SocialStatus{}, errors.New("temporary source outage")
	}
	return scraper.SocialStatus{ID: id, URL: "https://x.com/research/status/1", Text: p.content}, nil
}

func TestDiscoveryClaimRefreshesActualEvidenceAndPreservesHoldDuringOutage(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	item := claimRetryItem()
	item.URL = "https://x.com/research/status/1"
	item.Discovery.OriginalURL = item.URL
	provider := &claimRetrySocialProvider{content: "Initial researcher source observations."}
	client := &claimRetryLLM{}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, SocialProvider: provider, Logger: quietLogger()}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	provider.fail = true
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	if client.checks != 1 {
		t.Fatalf("refresh outage purchased fresh factual work: %d", client.checks)
	}
	provider.fail = false
	provider.content = "Researcher corrects the actual source evidence and scope."
	for range 3 {
		_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	}
	if client.checks != 2 {
		t.Fatalf("fresh source evidence was missed or repeatedly invalidated: checks=%d want2", client.checks)
	}
}

func expireClaimRetry(t *testing.T, db *storage.DB, id string) *storage.ProcessingCheckpoint {
	t.Helper()
	cp, err := db.GetProcessingCheckpoint(id)
	if err != nil || cp == nil {
		t.Fatalf("no durable claim retry: %v", err)
	}
	cp.RetryAt = time.Now().Add(-time.Second)
	if err := db.PutProcessingCheckpoint(*cp); err != nil {
		t.Fatal(err)
	}
	return cp
}

func TestDiscoveryClaimOutageBurstIsBoundedAndRecoveryRemainsScheduled(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client, item := &claimRetryLLM{claimErr: errors.New("429 provider unavailable")}, claimRetryItem()
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, MaxGroundingAttempts: 2, RetryBackoff: time.Minute, Logger: quietLogger()}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	for range 10 {
		_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	}
	if client.checks != 1 {
		t.Fatalf("unbounded first outage burst: checks=%d", client.checks)
	}
	expireClaimRetry(t, db, item.SourceID)
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil || cp.RetryAt.Before(time.Now().Add(59*time.Minute)) || cp.RetryAt.After(time.Now().Add(time.Hour+time.Second)) {
		t.Fatalf("failed burst lacks durable recovery window: %v", err)
	}
	for range 10 {
		_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	}
	if client.checks != 2 {
		t.Fatalf("exhausted burst still purchases work: checks=%d", client.checks)
	}
	expireClaimRetry(t, db, item.SourceID)
	client.claimErr, client.grounded = nil, true
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	if client.checks != 3 {
		t.Fatalf("exhaustion permanently suppressed recovery: checks=%d", client.checks)
	}
	if seen, _ := db.HasSeen(item.SourceID); !seen {
		t.Fatal("recovery never reached ordinary rumour gate")
	}
}

func TestDiscoveryClaimCancellationNeverCreatesFactualHold(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, item := &claimRetryLLM{claimErr: context.Canceled, beforeCheck: func(context.Context) { cancel() }}, claimRetryItem()
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, RetryBackoff: time.Minute, Logger: quietLogger()}
	if err := New(cfg).Process(ctx, []scraper.RawItem{item}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil || !cp.RetryAt.After(time.Now()) {
		t.Fatalf("cancellation did not preserve bounded retry: %v", err)
	}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	if client.checks != 1 {
		t.Fatal("cancelled call retried immediately after restart")
	}
	expireClaimRetry(t, db, item.SourceID)
	client.claimErr, client.beforeCheck, client.grounded = nil, nil, true
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	if client.checks != 2 {
		t.Fatal("cancelled claim permanently held as false")
	}
}

func TestDiscoveryClaimReservationFailurePreventsPaidCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claims.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if _, err := sqlDB.Exec(`CREATE TRIGGER fail_claim_checkpoint BEFORE INSERT ON processing_checkpoints BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END`); err != nil {
		t.Fatal(err)
	}
	client := &claimRetryLLM{}
	err = New(Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger()}).processItem(context.Background(), claimRetryItem())
	if err == nil || !strings.Contains(err.Error(), "checkpoint failure") || client.checks != 0 {
		t.Fatalf("paid before durable reservation: checks=%d err=%v", client.checks, err)
	}
}

func TestDiscoveryClaimHoldWriteFailureRetainsReservationAndReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claims.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	client := &claimRetryLLM{beforeCheck: func(context.Context) {
		if _, err := sqlDB.Exec(`CREATE TRIGGER fail_claim_hold BEFORE INSERT ON processing_checkpoints BEGIN SELECT RAISE(ABORT, 'injected hold failure'); END`); err != nil {
			t.Fatal(err)
		}
	}}
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger()})
	err = p.processItem(context.Background(), claimRetryItem())
	if err == nil || !strings.Contains(err.Error(), "hold failure") {
		t.Fatalf("hold storage error swallowed: %v", err)
	}
	if _, err := sqlDB.Exec(`DROP TRIGGER fail_claim_hold`); err != nil {
		t.Fatal(err)
	}
	_ = p.processItem(context.Background(), claimRetryItem())
	if client.checks != 1 {
		t.Fatalf("lost hold write purchased immediate duplicate: checks=%d", client.checks)
	}
}

func TestDiscoveryClaimUnknownStageNeverEntersBriefValidator(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client, item := &claimRetryLLM{}, claimRetryItem()
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger()}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil {
		t.Fatal("no initial checkpoint")
	}
	var state processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
		t.Fatal(err)
	}
	state.Stage = "future_claim_stage_v2"
	raw, _ := yaml.Marshal(state)
	cp.Payload = string(raw)
	if !IsClaimAssessmentCheckpoint(cp.Payload) {
		t.Fatal("scheduler would prefetch an unknown explicit stage")
	}
	if err := db.PutProcessingCheckpoint(*cp); err != nil {
		t.Fatal(err)
	}
	err = New(cfg).processItem(context.Background(), item)
	if err == nil || client.checks != 1 || client.assemblies != 0 {
		t.Fatalf("unknown stage escaped into paid/brief processing: checks=%d assembly=%d err=%v", client.checks, client.assemblies, err)
	}
	if seen, _ := db.HasSeen(item.SourceID); seen {
		t.Fatal("unknown stage consumed")
	}
}

func TestDiscoveryClaimProviderFailureBacksOffAndRecovers(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client, item := &claimRetryLLM{claimErr: errors.New("429 temporarily unavailable")}, claimRetryItem()
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger(), RetryBackoff: time.Minute}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil || !cp.RetryAt.After(time.Now()) {
		t.Fatalf("transient failure lacks durable backoff: cp=%v err=%v", cp, err)
	}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	if client.checks != 1 {
		t.Fatalf("provider outage retried before backoff: %d", client.checks)
	}
	cp.RetryAt = time.Now().Add(-time.Second)
	if err := db.PutProcessingCheckpoint(*cp); err != nil {
		t.Fatal(err)
	}
	client.claimErr, client.grounded = nil, true
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	if client.checks != 2 {
		t.Fatalf("provider recovery permanently frozen: %d", client.checks)
	}
	// A supported but below-likelihood claim follows the existing rumour gate.
	if seen, err := db.HasSeen(item.SourceID); err != nil || !seen {
		t.Fatalf("recovered supported claim did not reach ordinary rumour gate: seen=%v err=%v", seen, err)
	}
	if client.assemblies != 0 {
		t.Fatal("below-gate rumour assembled")
	}
}
