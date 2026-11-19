package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// Missing evidence must not become an instruction to invent a fixed release.
// The checker can correct its evidence once; an unchanged malformed finding
// then stays durably held without buying another checker/repair on every poll.
func TestPrimaryEvidenceBookkeepingFailureStaysHeldAcrossRestart(t *testing.T) {
	const id = "CVE-2099-4001"
	const gap = "unknown: usable remediation is not present in retained CNA evidence; this does not establish the absence of a fixed release"
	for _, quote := range []string{
		"CVE Program source for " + id + ": https://cveawg.mitre.org/api/cve/" + id,
		id + " coverage: " + gap,
	} {
		t.Run(strings.SplitN(quote, ":", 2)[0], func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			checks, corrections, repairs := 0, 0, 0
			client := referenceTestLLM{respond: func(_ context.Context, _, system string, _ *llm.Schema, out any) error {
				if system == materialOmissionEvidenceSystem {
					corrections++
					return llm.DecodeStructured(`{"evidence":[]}`, out)
				}
				if system == groundingRepairSystemPrompt {
					repairs++
					return errors.New("bookkeeping cannot justify an invented repair")
				}
				checks++
				if system != groundingSystem {
					return fmt.Errorf("unexpected model stage %q", system)
				}
				*out.(*groundingReport) = groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: id, SourceQuote: quote, Reason: "Missing fixed release."}}}
				return nil
			}}
			cfg := Config{DB: db, LLMClient: client, Logger: quietLogger(), RetryBackoff: -time.Second}
			setup := func() *Pipeline {
				p := New(cfg)
				meta := verifiedAssemblyMeta(id, "Example Harbor", "Example Harbor permits unauthorized configuration changes with low privileges.")
				meta.CNAFacts[0].Kind, meta.CNAGap = "description", gap
				p.cveVerifier.cache[id] = meta
				return p
			}
			item := scraper.RawItem{SourceID: "metadata:" + id, Source: "research", Title: "Example Harbor advisory (" + id + ")", URL: "https://vendor.example/harbor", Content: strings.Repeat("Example Harbor permits configuration changes with low privileges. ", 3), Enriched: true}
			item.Revision = item.ContentRevision()
			p := setup()
			state := processingCandidate{Item: item, BriefYAML: syntheticCompletenessBrief(t, false)}
			err := p.processCandidate(context.Background(), p.processingInputKey(item), state)
			var contract interface{ FailureKind() string }
			if !errors.As(err, &contract) || contract.FailureKind() != "omission_evidence_contract" {
				t.Fatalf("missing typed evidence hold: %v", err)
			}
			for range 3 {
				if err := setup().processItem(context.Background(), item); err != nil {
					t.Fatal(err)
				}
			}
			if checks != 1 || corrections != 1 || repairs != 0 {
				t.Fatalf("unchanged metadata bought model work: checks=%d corrections=%d repairs=%d", checks, corrections, repairs)
			}
			cp, err := db.GetProcessingCheckpoint(item.SourceID)
			if err != nil || cp == nil {
				t.Fatalf("held work lost: checkpoint=%v err=%v", cp, err)
			}
			var held processingCandidate
			if err := yaml.Unmarshal([]byte(cp.Payload), &held); err != nil {
				t.Fatal(err)
			}
			if held.GroundingFailure == nil || held.GroundingFailure.Kind != "omission_evidence_contract" {
				t.Fatal("evidence failure was not persisted")
			}
			if seen, err := db.HasSeen(item.SourceID); err != nil || seen {
				t.Fatalf("held source consumed: seen=%v err=%v", seen, err)
			}
			if _, quarantined, err := db.PipelineQuarantineReason(item.SourceID); err != nil || quarantined {
				t.Fatalf("malformed finding became factual rejection: quarantine=%v err=%v", quarantined, err)
			}
		})
	}
}

// Re-checking a held finding needs the primary CVE record. When that lookup
// is unavailable, the hold is kept and retried after a durable delay, like
// any other source outage, instead of failing the item on every poll.
func TestHeldEvidenceRefreshOutageDefersDurably(t *testing.T) {
	const id = "CVE-2099-4001"
	db := mustOpenTestDB(t)
	defer db.Close()
	client := referenceTestLLM{respond: func(_ context.Context, _, system string, _ *llm.Schema, out any) error {
		if system == materialOmissionEvidenceSystem {
			return llm.DecodeStructured(`{"evidence":[]}`, out)
		}
		*out.(*groundingReport) = groundingReport{Issues: []groundingIssue{{Kind: groundingKindMaterialOmission, Field: "content", Subject: id, SourceQuote: "CVE Program source for " + id + ": https://cveawg.mitre.org/api/cve/" + id, Reason: "Missing fixed release."}}}
		return nil
	}}
	var logs bytes.Buffer
	cfg := Config{DB: db, LLMClient: client, Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	p := New(cfg)
	meta := verifiedAssemblyMeta(id, "Example Harbor", "Example Harbor permits unauthorized configuration changes with low privileges.")
	p.cveVerifier.cache[id] = meta
	item := scraper.RawItem{SourceID: "metadata:" + id, Source: "research", Title: "Example Harbor advisory (" + id + ")", URL: "https://vendor.example/harbor", Content: strings.Repeat("Example Harbor permits configuration changes with low privileges. ", 3), Enriched: true}
	item.Revision = item.ContentRevision()
	state := processingCandidate{Item: item, BriefYAML: syntheticCompletenessBrief(t, false)}
	_ = p.processCandidate(context.Background(), p.processingInputKey(item), state)

	// A new process cannot reach the CVE Program to rehydrate the record.
	restarted := New(cfg)
	restarted.cveVerifier.client = &http.Client{Transport: &mockNVDTransport{handler: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("CVE Program unavailable")
	}}}
	logs.Reset()
	if err := restarted.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), `"msg":"pipeline error"`) || restarted.Decisions(time.Hour).Failed != 0 {
		t.Fatalf("held evidence refresh outage paged as a failed pipeline: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"msg":"source evidence refresh deferred"`) || !strings.Contains(logs.String(), `"error_class":"source_unavailable"`) {
		t.Fatalf("held evidence refresh outage not deferred: %s", logs.String())
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil {
		t.Fatalf("held candidate lost: %v", err)
	}
	var held processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &held); err != nil {
		t.Fatal(err)
	}
	if held.GroundingFailure == nil || !held.sourceRefreshDeferred(restarted.processingInputKey(item)) {
		t.Fatal("hold or durable refresh deadline not preserved")
	}
}
