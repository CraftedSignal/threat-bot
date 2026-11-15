package pipeline

import (
	"context"
	"encoding/json"
	"errors"
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
	holdFirstRepair   bool
	malformedEvidence bool
	rejectCorrection  bool
	corrections       int
}

func (c *completenessPipelineLLM) GenerateStructured(_ context.Context, prompt, system string, _ *llm.Schema, out any) error {
	for _, fact := range []string{"2.3", "2.4", "PR:L"} {
		if !strings.Contains(prompt, fact) {
			c.t.Errorf("check/repair omitted primary fact %s", fact)
		}
	}
	if evidence, ok := out.(*materialOmissionEvidenceReport); ok {
		c.corrections++
		quote := "Update Example Harbor to at least 2.4."
		if c.rejectCorrection {
			quote = ""
		}
		evidence.Evidence = []materialOmissionEvidence{{Subject: "CVE-2099-4001", SourceQuote: quote}}
		return nil
	}
	if report, ok := out.(*groundingReport); ok {
		if system != groundingSystem {
			return fmt.Errorf("complete candidate used partial-claim policy")
		}
		c.checks++
		if c.checks == 1 || (c.holdFirstRepair && c.checks == 2) || c.rejectFinal {
			*report = syntheticOmissionReport(c.t, "CVE-2099-4001", "Update Example Harbor to at least 2.4.")
			if c.malformedEvidence {
				report.Issues[0].Subject, report.Issues[0].SourceQuote = "Example Harbor plugin", ""
			}
		}
		return nil
	}
	if system != groundingRepairSystemPrompt {
		return fmt.Errorf("unexpected model step")
	}
	c.repairs++
	if (c.holdFirstRepair && c.checks < 2) || c.rejectFinal {
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
			client := &completenessPipelineLLM{t: t, initial: syntheticCompletenessBrief(t, false), repaired: syntheticCompletenessBrief(t, true), rejectFinal: rejectFinal, holdFirstRepair: true}
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

func TestSourceCompletenessEvidenceCorrectionPreservesBoundedRepair(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		rejectFinal, malformed, rejectCorrection bool
		checks, repairs, corrections             int
	}{
		{"supported repair", false, false, false, 2, 1, 0},
		{"still incomplete", true, false, false, 2, 1, 0},
		{"corrected evidence", false, true, false, 2, 1, 1},
		{"corrected recheck evidence", true, true, false, 2, 1, 2},
		{"unverifiable evidence", false, true, true, 1, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			client := &completenessPipelineLLM{t: t, initial: syntheticCompletenessBrief(t, false), repaired: syntheticCompletenessBrief(t, true), rejectFinal: tc.rejectFinal, malformedEvidence: tc.malformed, rejectCorrection: tc.rejectCorrection}
			p := New(Config{DB: db, LLMClient: client, Logger: quietLogger(), MaxGroundingAttempts: 1})
			p.cveVerifier = completenessVerifier(t)
			p.cveEnricher = NewCVEEnricher(p.cveVerifier)
			item := scraper.RawItem{SourceID: "completeness:synthetic", Source: "nvd", Title: "Example Harbor CVE-2099-4001", URL: "https://vendor.example/harbor", Content: "Example Harbor permits configuration changes with low privileges (CVE-2099-4001).", Enriched: true}
			state := processingCandidate{Item: item, BriefYAML: client.initial, Score: 5, Confidence: 1, Extraction: &ExtractionResult{CVEs: []string{"CVE-2099-4001"}, AffectedProducts: []string{"Example Harbor"}}}
			err := p.processCandidate(context.Background(), p.processingInputKey(item), state)
			if tc.rejectCorrection {
				var contract *omissionEvidenceContractError
				if !errors.As(err, &contract) {
					t.Fatalf("unverifiable checker evidence must create typed hold: %v", err)
				}
				cp, cpErr := db.GetProcessingCheckpoint(item.SourceID)
				if cpErr != nil || cp == nil {
					t.Fatalf("missing contract checkpoint: %+v %v", cp, cpErr)
				}
				var held processingCandidate
				if err := yaml.Unmarshal([]byte(cp.Payload), &held); err != nil || !p.groundingFailureHeld(held) {
					t.Fatalf("unverifiable evidence was not durably held: %v", err)
				}
				if err := p.processCandidate(context.Background(), p.processingInputKey(item), held); err != nil {
					t.Fatal(err)
				}
				if seen, _ := db.HasSeen(item.SourceID); seen {
					t.Fatal("invalid checker output consumed source")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if client.checks != tc.checks || client.repairs != tc.repairs || client.corrections != tc.corrections {
				t.Fatalf("bounded repair calls changed: checks=%d repairs=%d evidence corrections=%d", client.checks, client.repairs, client.corrections)
			}
			drafts := 0
			for draft, err := range db.ActiveDraftsSince(time.Time{}) {
				if err != nil {
					t.Fatal(err)
				}
				drafts++
				for _, fact := range []string{"2.3", "2.4", "low privileges"} {
					if !strings.Contains(draft.BriefYAML, fact) {
						t.Errorf("accepted repair lost %s", fact)
					}
				}
			}
			if tc.rejectFinal || tc.rejectCorrection {
				if drafts != 0 {
					t.Fatal("incomplete or unsupported evidence repair became a draft")
				}
			} else if drafts != 1 {
				t.Fatalf("supported repair produced %d drafts", drafts)
			}
		})
	}
}
