package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

type completenessPipelineLLM struct {
	noopLLM
	t                 *testing.T
	initial, repaired string
	rejectFinal       bool
	checks, repairs   int
}

func (c *completenessPipelineLLM) GenerateStructured(_ context.Context, prompt, system string, _ *llm.Schema, out any) error {
	for _, fact := range []string{"2.3", "2.4", "PR:L"} {
		if !strings.Contains(prompt, fact) {
			c.t.Errorf("check/repair omitted primary fact %s", fact)
		}
	}
	if report, ok := out.(*groundingReport); ok {
		if system != groundingSystem {
			return fmt.Errorf("complete candidate used partial-claim policy")
		}
		c.checks++
		if c.checks <= 2 || c.rejectFinal {
			*report = syntheticOmissionReport(c.t, "CVE-2099-4001", "Update Example Harbor to at least 2.4.")
		}
		return nil
	}
	if system != groundingRepairSystemPrompt {
		return fmt.Errorf("unexpected model step")
	}
	c.repairs++
	if c.checks < 2 || c.rejectFinal {
		return structuredFromText(c.initial, out)
	}
	return structuredFromText(c.repaired, out)
}

func syntheticCompletenessBrief(t *testing.T, complete bool) string {
	t.Helper()
	content := "## Overview\nExample Harbor permits unauthorized configuration changes with low privileges.\n\n## Recommendation\nConsult the Example Harbor advisory for remediation."
	if complete {
		content = "## Overview\nExample Harbor through 2.3 permits unauthorized configuration changes with low privileges and no user interaction.\n\n## Recommendation\nUpgrade Example Harbor to the fixed release 2.4."
	}
	raw, err := yaml.Marshal(map[string]any{
		"id": "brief-synthetic-harbor", "slug": "synthetic-harbor", "title": "Example Harbor advisory (CVE-2099-4001)",
		"summary": "Example Harbor permits unauthorized configuration changes with low privileges.", "severity": "medium",
		"published_at": "2026-11-14T00:00:00Z", "content": content,
		"affected_vendors": []string{"ExampleCo"}, "affected_products": []string{"Example Harbor"},
		"references": []string{"https://vendor.example/harbor"}, "exploitation_evidence": map[string]string{"status": "unknown"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func completenessVerifier(t *testing.T) *CVEVerifier {
	t.Helper()
	var record struct {
		Containers struct {
			CNA cnaSourceRecord `json:"cna"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(syntheticCompletenessCNA(t), &record); err != nil {
		t.Fatal(err)
	}
	facts, gap := record.Containers.CNA.sourceFacts("CVE-2099-4001")
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CachedAt: time.Now(), CNAChecked: true, CNAFacts: facts, CNAGap: gap}
	return v
}

func TestSourceCompletenessBoundedRepairSurvivesDatabaseRestart(t *testing.T) {
	for _, rejectFinal := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject_final_%v", rejectFinal), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			client := &completenessPipelineLLM{t: t, initial: syntheticCompletenessBrief(t, false), repaired: syntheticCompletenessBrief(t, true), rejectFinal: rejectFinal}
			cfg := Config{DB: db, LLMClient: client, Logger: quietLogger(), MaxGroundingAttempts: 2, RetryBackoff: -time.Second}
			setup := func() *Pipeline {
				p := New(cfg)
				p.cveVerifier = completenessVerifier(t)
				p.cveEnricher = NewCVEEnricher(p.cveVerifier)
				return p
			}
			p := setup()
			item := scraper.RawItem{SourceID: "completeness:synthetic", Source: "nvd", Title: "Example Harbor CVE-2099-4001", URL: "https://vendor.example/harbor", Content: "Example Harbor permits configuration changes with low privileges (CVE-2099-4001).", Enriched: true}
			state := processingCandidate{Item: item, BriefYAML: client.initial, Score: 5, Confidence: 1, Extraction: &ExtractionResult{CVEs: []string{"CVE-2099-4001"}, AffectedProducts: []string{"Example Harbor"}}}
			if err := p.processCandidate(context.Background(), p.processingInputKey(item), state); err != nil {
				t.Fatal(err)
			}
			if client.checks != 2 || client.repairs != 1 {
				t.Fatalf("initial budget changed: checks=%d repairs=%d", client.checks, client.repairs)
			}
			cp, err := db.GetProcessingCheckpoint(item.SourceID)
			if err != nil || cp == nil {
				t.Fatalf("unresolved omission lost checkpoint: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			cfg.DB = db
			p = setup()
			for range 3 {
				if err := p.processItem(context.Background(), item); err != nil {
					t.Fatal(err)
				}
			}
			if client.checks != 3 || client.repairs != 2 {
				t.Fatalf("restart rebuilt or exceeded budget: checks=%d repairs=%d", client.checks, client.repairs)
			}
			drafts := 0
			for draft, rowErr := range db.ActiveDraftsSince(time.Time{}) {
				if rowErr != nil {
					t.Fatal(rowErr)
				}
				drafts++
				for _, fact := range []string{"2.3", "2.4", "low privileges"} {
					if !strings.Contains(draft.BriefYAML, fact) {
						t.Errorf("accepted repair lost %s", fact)
					}
				}
			}
			if rejectFinal {
				if drafts != 0 {
					t.Fatal("incomplete repair became a draft")
				}
				if _, held, err := db.PipelineQuarantineReason(item.SourceID); err != nil || !held {
					t.Fatalf("exhausted omission was not retained: %v", err)
				}
			} else if drafts != 1 {
				t.Fatalf("supported completeness repair produced %d drafts", drafts)
			}
		})
	}
}
