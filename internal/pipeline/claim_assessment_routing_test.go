package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

func TestDiscoveryClaimResumeHonorsNewDedupSkip(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	item, client := claimRetryItem(), &claimRetryLLM{claimErr: errors.New("429")}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger()}
	p := New(cfg)
	_ = p.Process(context.Background(), []scraper.RawItem{item})
	expireClaimRetry(t, db, item.SourceID)
	if err := db.IndexContent(&storage.ContentIndexEntry{TitleHash: NormalizeTitleHash(item.Title), DraftID: "already-covered", SourceID: "other:accepted", Source: "abuse-ch", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if decision, _, _ := p.dedup.CheckPreExtraction(item); decision != DedupSkip {
		t.Fatalf("fixture dedup=%v", decision)
	}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	if client.checks != 1 {
		t.Fatalf("resumed claim ignored DedupSkip and purchased checker again: %d calls", client.checks)
	}
	if seen, _ := db.HasSeen(item.SourceID); !seen {
		t.Fatal("already-covered source did not follow normal DedupSkip completion")
	}
}

type claimRoutingLLM struct {
	claimRetryLLM
	mergeCalls int
}

func (c *claimRoutingLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	if system == mergeRelevanceSystemPrompt {
		c.mergeCalls++
		return errors.New("merge relevance temporarily unavailable")
	}
	return c.claimRetryLLM.GenerateJSON(ctx, prompt, system, out)
}

func TestDiscoveryClaimResumeRoutesNewMergeThroughOrdinaryAssessment(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	item, client := claimRetryItem(), &claimRoutingLLM{claimRetryLLM: claimRetryLLM{claimErr: errors.New("429")}}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger()}
	p := New(cfg)
	_ = p.Process(context.Background(), []scraper.RawItem{item})
	expireClaimRetry(t, db, item.SourceID)
	complete := strings.Replace(recoveryBase+recoveryNarrative, "https://vendor.example/original", item.URL, 1)
	if err := db.CreateDraft(&storage.Draft{ID: "new-merge-target", Status: storage.StatusApproved, Source: "original", BriefYAML: complete, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{DraftID: "new-merge-target", SourceID: "other:accepted", Source: "original", SourceURLHash: SourceURLHash(item.URL), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	decision, _, entries := p.dedup.CheckPreExtraction(item)
	if decision != DedupMerge || p.draftRebuildTarget(item, decision, entries) != "" {
		t.Fatalf("fixture does not select an ordinary merge: decision=%v", decision)
	}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	if client.mergeCalls != 1 || client.checks != 1 || client.extractions != 1 || client.assemblies != 0 {
		t.Fatalf("resume bypassed merge or lost saved extraction: merges=%d checks=%d extraction=%d assembly=%d", client.mergeCalls, client.checks, client.extractions, client.assemblies)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("merge assessment not retained: %v", err)
	}
	var state processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
		t.Fatal(err)
	}
	if state.MergeDraftID != "new-merge-target" || state.Extraction == nil {
		t.Fatal("ordinary merge checkpoint lost target/extraction")
	}
	if seen, _ := db.HasSeen(item.SourceID); seen {
		t.Fatal("unavailable merge assessment consumed source")
	}
	target, _ := db.GetDraft("new-merge-target")
	if target.BriefYAML != complete {
		t.Fatal("unavailable merge changed approved draft")
	}
}

func TestDiscoveryClaimResumeRefreshesAndClearsRebuildTarget(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	item, client := claimRetryItem(), &claimRetryLLM{claimErr: errors.New("429")}
	cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, Logger: quietLogger()}
	p := New(cfg)
	_ = p.Process(context.Background(), []scraper.RawItem{item})
	expireClaimRetry(t, db, item.SourceID)
	if err := db.CreateDraft(&storage.Draft{ID: "late-canonical", Status: storage.StatusApproved, Source: "original", BriefYAML: recoveryBase, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{TitleHash: NormalizeTitleHash(item.Title), DraftID: "late-canonical", SourceID: "other:accepted", Source: "original", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	decision, _, entries := p.dedup.CheckPreExtraction(item)
	if decision != DedupMerge || p.draftRebuildTarget(item, decision, entries) != "late-canonical" {
		t.Fatalf("fixture rebuild routing failed: %v", decision)
	}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	cp := expireClaimRetry(t, db, item.SourceID)
	var state processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
		t.Fatal(err)
	}
	if state.RebuildDraftID != "late-canonical" {
		t.Fatalf("resume lost new canonical rebuild target: %q", state.RebuildDraftID)
	}
	if err := db.UpdateDraftStatus("late-canonical", storage.StatusRejected, "replaced by editor"); err != nil {
		t.Fatal(err)
	}
	_ = New(cfg).Process(context.Background(), []scraper.RawItem{item})
	cp, _ = db.GetProcessingCheckpoint(item.SourceID)
	if err := yaml.Unmarshal([]byte(cp.Payload), &state); err != nil {
		t.Fatal(err)
	}
	if state.RebuildDraftID != "" {
		t.Fatalf("resume retained stale rejected canonical target: %q", state.RebuildDraftID)
	}
	if seen, _ := db.HasSeen(item.SourceID); seen {
		t.Fatal("provider outage/rebuild target change consumed source")
	}
	if client.extractions != 1 || client.qualities != 1 || client.assemblies != 0 {
		t.Fatal("routing change repeated paid preparation or bypassed failed claim check")
	}
}
