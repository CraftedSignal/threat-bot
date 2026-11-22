package pipeline

import (
	"context"
	"errors"
	"fmt"
	"github.com/craftedsignal/threat-bot/internal/llm"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

func TestGroundingRetryResumesCandidateAcrossPipelineRestart(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	assemblies, repairs, checks := 0, 0, 0
	client := shutdownStageLLM{
		generate: func(_ context.Context, _, system string) (string, error) {
			if strings.HasPrefix(system, groundingRepairSystemPrompt) {
				repairs++
			} else {
				assemblies++
			}
			return validWindowsPathBriefYAML, nil
		},
		generateJSON: func(_ context.Context, _, _ string, out any) error {
			checks++
			r := out.(*GroundingResult)
			r.Grounded = false
			r.Issues = []string{"unsupported claim"}
			return nil
		},
	}
	item := scraper.RawItem{SourceID: "resume:1", Source: "cisa-kev", Title: "Vendor security advisory", Content: strings.Repeat("Confirmed vendor notice. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 3, MaxGroundingAttempts: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RetryBackoff: -time.Second}
	if err := New(cfg).processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	second := item
	second.UpdatedAt = time.Now()
	if err := New(cfg).processItem(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if assemblies != 1 || repairs != 2 || checks != 3 {
		t.Fatalf("full rebuild on retry: assemblies=%d repairs=%d checks=%d", assemblies, repairs, checks)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil || cp.InputKey != New(cfg).processingInputKey(second) {
		t.Fatalf("checkpoint absent: %v %v", cp, err)
	}
	cfg.ProcessingPolicy = "changed model or policy"
	if err := New(cfg).processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if assemblies != 2 {
		t.Fatalf("policy change reused stale candidate: assemblies=%d", assemblies)
	}
}

func TestRepeatedGroundingFindingAcrossEvidenceRevisionQuarantines(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	assemblies, repairs, checks := 0, 0, 0
	issue := "affected_products: missing source-supported fact for TeamCity: Missing the affected version bound."
	client := shutdownStageLLM{
		generate: func(_ context.Context, _, system string) (string, error) {
			if strings.HasPrefix(system, groundingRepairSystemPrompt) {
				repairs++
			} else {
				assemblies++
			}
			return validWindowsPathBriefYAML, nil
		},
		generateJSON: func(_ context.Context, _, _ string, out any) error {
			checks++
			r := out.(*GroundingResult)
			r.Grounded = false
			r.Issues = []string{issue}
			return nil
		},
	}
	item := scraper.RawItem{
		SourceID:  "resume:changed-evidence-grounding",
		Source:    "cisa-kev",
		Title:     "TeamCity security advisory",
		Content:   strings.Repeat("Confirmed vendor advisory about TeamCity. ", 30),
		Enriched:  true,
		SigmaRule: &scraper.SigmaRule{Title: "Rule"},
	}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 3, MaxGroundingAttempts: 5, Logger: quietLogger(), RetryBackoff: -time.Second}
	if err := New(cfg).processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	changed := item
	changed.Content += "\nA newer source revision repeats the same affected-version scope."
	if err := New(cfg).processItem(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	if reason, ok, err := db.PipelineQuarantineReason(item.SourceID); err != nil || !ok || !strings.Contains(reason, "after 1 attempts") {
		t.Fatalf("same product-level grounding finding restarted its retry budget across a source revision: quarantined=%v reason=%q err=%v", ok, reason, err)
	}
	if assemblies != 2 || repairs != 2 || checks != 4 {
		t.Fatalf("unexpected calls across changed evidence: assemblies=%d repairs=%d checks=%d", assemblies, repairs, checks)
	}
}

func TestChangedEnrichmentRetainsReplacementCheckpointWithSameFeedRevision(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	issue := "affected_products: missing source-supported fact for TeamCity: Missing a version."
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return validWindowsPathBriefYAML, nil },
		generateJSON: func(_ context.Context, _, _ string, out any) error {
			r := out.(*GroundingResult)
			r.Grounded = false
			r.Issues = []string{issue}
			return nil
		},
	}
	item := scraper.RawItem{SourceID: "resume:same-feed-revision", Source: "cisa-kev", Title: "Vendor advisory", Content: strings.Repeat("Confirmed source evidence. ", 30), Revision: "feed-revision-1", Enriched: true, SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 3, MaxGroundingAttempts: 5, Logger: quietLogger(), RetryBackoff: -time.Second}
	if err := New(cfg).processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	changed := item
	changed.Content += "\nAdditional independently refreshed evidence."
	if New(cfg).processingInputKey(item) != New(cfg).processingInputKey(changed) {
		t.Fatal("fixture must exercise a replacement with the same input key")
	}
	issue = "affected_products: missing source-supported fact for YouTrack: Missing a version."
	if err := New(cfg).processItem(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("new retained candidate was deleted: %v", err)
	}
	var state processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
		t.Fatal(err)
	}
	if state.Item.Content != changed.Content || len(state.GroundingIssueHistory) != 2 {
		t.Fatalf("replacement candidate or grounding history lost: content=%q history=%v", state.Item.Content, state.GroundingIssueHistory)
	}
}

func TestChangedEvidenceDoesNotCarryLegacyFindingHistory(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return validWindowsPathBriefYAML, nil },
		generateJSON: func(_ context.Context, _, _ string, out any) error {
			r := out.(*GroundingResult)
			r.Grounded = false
			r.Issues = []string{"affected_products: missing source-supported fact for YouTrack: Missing a version."}
			return nil
		},
	}
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, MaxGroundingAttempts: 5, Logger: quietLogger(), RetryBackoff: -time.Second})
	item := scraper.RawItem{SourceID: "resume:legacy-evidence", Source: "cisa-kev", Title: "Vendor advisory", Content: strings.Repeat("Confirmed source evidence. ", 30), Revision: "feed-revision-1", Enriched: true, SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	state := processingCandidate{Item: item, Extraction: &ExtractionResult{}, BriefYAML: validWindowsPathBriefYAML, GroundingIssueHistory: []string{"affected_products:teamcity"}}
	if err := p.saveCandidate(p.processingInputKey(item), state, time.Time{}); err != nil {
		t.Fatal(err)
	}
	item.Content += "\nNew independently refreshed evidence."
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("replacement checkpoint missing: %v", err)
	}
	if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.GroundingIssueHistory) != 1 || !strings.HasSuffix(state.GroundingIssueHistory[0], ":youtrack") {
		t.Fatalf("legacy history crossed the evidence-policy change: %v", state.GroundingIssueHistory)
	}
}

func TestFailedChangedEvidenceRebuildPreservesGroundingHistory(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	failAssembly := false
	issue := "affected_products: missing source-supported fact for TeamCity: Missing the affected version bound."
	client := shutdownStageLLM{
		generate: func(_ context.Context, _, system string) (string, error) {
			if strings.HasPrefix(system, groundingRepairSystemPrompt) {
				return validWindowsPathBriefYAML, nil
			}
			if failAssembly {
				return "", errors.New("temporary assembly outage")
			}
			return validWindowsPathBriefYAML, nil
		},
		generateJSON: func(_ context.Context, _, _ string, out any) error {
			r := out.(*GroundingResult)
			r.Grounded = false
			r.Issues = []string{issue}
			return nil
		},
	}
	item := scraper.RawItem{SourceID: "resume:failed-evidence-rebuild", Source: "cisa-kev", Title: "TeamCity security advisory", Content: strings.Repeat("Confirmed vendor advisory about TeamCity. ", 30), Enriched: true, SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 3, MaxGroundingAttempts: 5, Logger: quietLogger(), RetryBackoff: -time.Second}
	if err := New(cfg).processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	oldInputKey := New(cfg).processingInputKey(item)
	changed := item
	changed.Content += "\nA newer source revision repeats the same affected-version scope."
	failAssembly = true
	if err := New(cfg).processItem(context.Background(), changed); err == nil || !strings.Contains(err.Error(), "temporary assembly outage") {
		t.Fatalf("changed-evidence rebuild error = %v, want temporary assembly outage", err)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil || cp.InputKey != oldInputKey {
		t.Fatalf("interrupted rebuild lost prior checkpoint: checkpoint=%+v err=%v", cp, err)
	}
	var prior processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &prior); err != nil || len(prior.GroundingIssueHistory) != 1 {
		t.Fatalf("interrupted rebuild lost grounding history: history=%v err=%v", prior.GroundingIssueHistory, err)
	}
	failAssembly = false
	if err := New(cfg).processItem(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	if reason, ok, err := db.PipelineQuarantineReason(item.SourceID); err != nil || !ok || !strings.Contains(reason, "after 1 attempts") {
		t.Fatalf("same finding restarted after interrupted rebuild: quarantined=%v reason=%q err=%v", ok, reason, err)
	}
}

func TestProviderErrorsConsumeDurableGroundingBudget(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	checks, assemblies := 0, 0
	client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) {
		assemblies++
		return validWindowsPathBriefYAML, nil
	}, generateJSON: func(context.Context, string, string, any) error { checks++; return fmt.Errorf("provider unavailable") }}
	item := scraper.RawItem{SourceID: "budget:provider", Source: "cisa-kev", Title: "Vendor notice", Content: strings.Repeat("Confirmed vendor notice. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 3, MaxGroundingAttempts: 2, RetryBackoff: -time.Second, Logger: quietLogger()}
	for range 5 {
		_ = New(cfg).processItem(context.Background(), item)
	}
	if checks != 2 || assemblies != 1 {
		t.Fatalf("unbounded paid retries: checks=%d assemblies=%d", checks, assemblies)
	}
	if seen, _ := db.HasSeenRevision(item.SourceID, item.ContentRevision()); !seen {
		t.Fatal("exhausted revision remains automatically retryable")
	}
	if reason, ok, _ := db.PipelineQuarantineReason(item.SourceID); !ok || !strings.Contains(reason, "after 2 attempts") {
		t.Fatalf("missing review reason: %s", reason)
	}
}
func TestChangedEnrichedEvidenceInvalidatesCandidate(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: quietLogger()})
	a := scraper.RawItem{SourceID: "article:1", Content: "Original feed summary"}
	a.Revision = a.ContentRevision()
	b := a
	a.Content += "\nOriginal page scope"
	b.Content += "\nCorrected page scope"
	if p.processingInputKey(a) != p.processingInputKey(b) {
		t.Fatal("lost feed checkpoint locator")
	}
	if p.processingKey(a) == p.processingKey(b) {
		t.Fatal("corrected article reused stale candidate")
	}
}
func TestPendingExtractionDoesNotAssembleOrConsumeSource(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	assemblies := 0
	client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) {
		assemblies++
		return validWindowsPathBriefYAML, nil
	}, generateJSON: func(_ context.Context, _, system string, out any) error {
		if system == extractionSystemPrompt {
			return &llm.PendingBatchError{Keys: []string{"paid"}}
		}
		if q, ok := out.(*QualityScore); ok {
			*q = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
		}
		return nil
	}}
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger()})
	item := scraper.RawItem{SourceID: "batch:pending", Source: "cisa-kev", Title: "Vendor notice", Content: strings.Repeat("Concrete process telemetry evidence. ", 20), Enriched: true}
	var pending *llm.PendingBatchError
	if err := p.processItem(context.Background(), item); !errors.As(err, &pending) {
		t.Fatalf("pending extraction swallowed: %v", err)
	}
	if seen, _ := db.HasSeen(item.SourceID); seen || assemblies != 0 {
		t.Fatalf("paid work duplicated/consumed: seen=%v assemblies=%d", seen, assemblies)
	}
}

func TestArticleRefreshOutagePreservesCandidateAndBudget(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	assemblies := 0
	failFetch := false
	client := shutdownStageLLM{generate: func(_ context.Context, _, system string) (string, error) {
		if !strings.HasPrefix(system, groundingRepairSystemPrompt) {
			assemblies++
		}
		return validWindowsPathBriefYAML, nil
	}, generateJSON: func(_ context.Context, _, _ string, out any) error {
		r := out.(*GroundingResult)
		r.Grounded = false
		r.Issues = []string{"unsupported claim"}
		return nil
	}}
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 1, MaxGroundingAttempts: 3, RetryBackoff: -time.Second, Logger: quietLogger()})
	p.enricher.client = &http.Client{Transport: enrichRoundTrip(func(*http.Request) (*http.Response, error) {
		if failFetch {
			return nil, fmt.Errorf("temporary article fetch outage")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader("<html><body>" + strings.Repeat("Confirmed Windows process creation detection facts. ", 30) + "</body></html>"))}, nil
	})}
	item := scraper.RawItem{SourceID: "audit:refresh", Source: "cisa-kev", Title: "Vendor notice", URL: "https://example.com/advisory", Content: strings.Repeat("Brief vendor notice. ", 10), NeedsFullArticle: true, SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if assemblies != 1 {
		t.Fatalf("bad initial fixture assemblies=%d", assemblies)
	}
	failFetch = true
	if err := p.processItem(context.Background(), item); err != nil {
		t.Logf("refresh deferred as expected: %v", err)
	}
	if assemblies != 1 {
		t.Fatalf("transient enrichment outage invalidated a validated candidate and reset budget; assemblies=%d want1", assemblies)
	}
}

func TestTimestampOnlySourceUpdateDoesNotRegenerateCompletedEvidence(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	calls := 0
	client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) {
		calls++
		return "", errors.New("unexpected generation")
	}, generateJSON: func(context.Context, string, string, any) error { calls++; return errors.New("unexpected model call") }}
	p := New(Config{DB: db, LLMClient: client, Logger: quietLogger()})
	item := scraper.RawItem{SourceID: "article:timestamp", Source: "feed", Title: "Same evidence", Content: strings.Repeat("Complete source evidence. ", 30), Enriched: true}
	if err := p.markSeen(item); err != nil {
		t.Fatal(err)
	}
	item.UpdatedAt = time.Now()
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("timestamp-only source update spent %d AI calls", calls)
	}
	if seen, _ := db.HasSeenRevision(item.SourceID, item.ContentRevision()); !seen {
		t.Fatal("new signal not acknowledged")
	}
}
