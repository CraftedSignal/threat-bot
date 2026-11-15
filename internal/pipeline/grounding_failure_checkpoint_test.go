package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// Removing the durable typed hold would repeat a full check after every
// restart. Changed evidence or configured model/policy must release the hold.
func TestGroundingContractFailureHeldAcrossCheckpointRestart(t *testing.T) {
	for _, change := range []string{"unchanged", "timestamp", "source", "model"} {
		t.Run(change, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			checks, corrections, fresh := 0, 0, 0
			client := referenceTestLLM{respond: func(_ context.Context, _, system string, _ *llm.Schema, out any) error {
				if system == materialOmissionEvidenceSystem {
					corrections++
					return llm.DecodeStructured(`{"evidence":[]}`, out)
				}
				if system != groundingSystem {
					t.Fatalf("unexpected stage: %s", system)
				}
				checks++
				return llm.DecodeStructured(`{"issues":[{"kind":"material_omission","field":"content","subject":"Windows","source_quote":"invented fix","reason":"Missing fixed release."}]}`, out)
			}}
			// Fresh policy/evidence should rebuild, stopping at the offline quality
			// provider rather than invoking a live model or network dependency.
			freshErr := errors.New("fresh input requested")
			all := groundingCheckpointLLM{referenceTestLLM: client, quality: func() error { fresh++; return freshErr }}
			cfg := Config{DB: db, LLMClient: all, Logger: quietLogger(), QualityThreshold: 1, RetryBackoff: -time.Second, MaxGroundingAttempts: 1, ProcessingPolicy: "model-one"}
			p := New(cfg)
			item := scraper.RawItem{SourceID: "held:contract", Source: "research", Title: "Windows security notice", Content: strings.Repeat("Windows requires low privileges. ", 20), Enriched: true}
			item.Revision = item.ContentRevision()
			state := processingCandidate{Item: item, BriefYAML: strings.Replace(validWindowsPathBriefYAML, "rules:\n", "affected_products: [Windows]\nrules:\n", 1)}
			err := p.processCandidate(context.Background(), p.processingInputKey(item), state)
			var failure interface {
				FailureKind() string
				RequestDigest() string
			}
			if !errors.As(err, &failure) {
				t.Fatalf("missing typed evidence failure: %v", err)
			}
			cp, err := db.GetProcessingCheckpoint(item.SourceID)
			if err != nil || cp == nil {
				t.Fatalf("missing checkpoint: %+v %v", cp, err)
			}
			var saved map[string]any
			if err := yaml.Unmarshal([]byte(cp.Payload), &saved); err != nil {
				t.Fatal(err)
			}
			hold, ok := saved["groundingfailure"].(map[string]any)
			if !ok || hold["kind"] != "omission_evidence_contract" || hold["requestdigest"] != failure.RequestDigest() || len(strings.TrimSpace(stringValue(hold["contextdigest"]))) != 64 {
				t.Fatalf("typed failure/digests not persisted: %+v", saved["groundingfailure"])
			}
			if seen, _ := db.HasSeen(item.SourceID); seen {
				t.Fatal("contract hold consumed the source")
			}
			if _, quarantined, _ := db.PipelineQuarantineReason(item.SourceID); quarantined {
				t.Fatal("contract failure quarantined as factual rejection")
			}
			switch change {
			case "source":
				item.Content += "Corrected primary advisory."
				item.Revision = ""
			case "model":
				cfg.ProcessingPolicy = "model-two"
			case "timestamp":
				item.UpdatedAt = time.Now()
			}
			for range 3 {
				err = New(cfg).processItem(context.Background(), item)
				if change == "source" || change == "model" {
					if !errors.Is(err, freshErr) {
						t.Fatalf("changed input did not rebuild: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if checks != 1 || corrections != 1 {
				t.Fatalf("unchanged failure repeated checker calls: checks=%d corrections=%d", checks, corrections)
			}
			if (change == "source" || change == "model") && fresh != 3 {
				t.Fatalf("input change did not release hold: %d", fresh)
			}
			if (change == "unchanged" || change == "timestamp") && fresh != 0 {
				t.Fatalf("held input rebuilt: %d", fresh)
			}
		})
	}
}
func stringValue(v any) string { s, _ := v.(string); return s }

type groundingCheckpointLLM struct {
	referenceTestLLM
	quality func() error
}

func (c groundingCheckpointLLM) GenerateJSON(context.Context, string, string, any) error {
	return c.quality()
}

// A verifier's in-memory cache is empty after restart. Load primary evidence
// before comparing the hold; absence of that cache is not changed evidence.
func TestGroundingContractHoldRefreshesPrimaryEvidenceBeforeResume(t *testing.T) {
	for _, mode := range []string{"same", "changed", "outage", "cna outage"} {
		t.Run(mode, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			checks := 0
			client := referenceTestLLM{respond: func(_ context.Context, _, system string, _ *llm.Schema, out any) error {
				if system == materialOmissionEvidenceSystem {
					return llm.DecodeStructured(`{"evidence":[]}`, out)
				}
				checks++
				return llm.DecodeStructured(`{"issues":[{"kind":"material_omission","field":"content","subject":"Example Harbor","source_quote":"invented","reason":"Missing fixed release."}]}`, out)
			}}
			cfg := Config{DB: db, LLMClient: client, Logger: quietLogger(), MaxGroundingAttempts: 1, RetryBackoff: -time.Second}
			item := scraper.RawItem{SourceID: "primary:hold", Source: "nvd", Title: "Example Harbor CVE-2099-4001", Content: syntheticCompletenessSource, Enriched: true}
			brief := strings.ReplaceAll(mergeReviewYAML, "WidgetServer", "Example Harbor")
			brief = strings.ReplaceAll(brief, "CVE-2026-9999", "CVE-2099-4001")
			transport := func(primary string, fail bool) *http.Client {
				return &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
					if fail || mode == "cna outage" && req.URL.Host == "cveawg.mitre.org" && checks > 0 {
						return nil, errors.New("temporary primary source outage")
					}
					rec := httptest.NewRecorder()
					if req.URL.Host == "cveawg.mitre.org" {
						_, _ = rec.Write([]byte(primary))
					} else {
						_, _ = rec.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2099-4001"}}]}`))
					}
					return rec.Result(), nil
				}}}
			}
			primary := string(syntheticCompletenessCNA(t))
			p := New(cfg)
			p.cveVerifier.client = transport(primary, false)
			state := processingCandidate{Item: item, BriefYAML: brief}
			var contract *omissionEvidenceContractError
			if err := p.processCandidate(context.Background(), p.processingInputKey(item), state); !errors.As(err, &contract) {
				t.Fatalf("initial typed hold absent: %v", err)
			}
			if mode == "changed" {
				primary = strings.ReplaceAll(primary, "2.4", "2.5")
			}
			restarted := New(cfg)
			restarted.cveVerifier.client = transport(primary, mode == "outage")
			err := restarted.processItem(context.Background(), item)
			if mode == "same" && (err != nil || checks != 1) {
				t.Fatalf("same primary evidence paid for a new check: calls=%d err=%v", checks, err)
			}
			if mode == "changed" && (checks != 2 || !errors.As(err, &contract)) {
				t.Fatalf("changed primary evidence failed to reopen bounded check: calls=%d err=%v", checks, err)
			}
			if (mode == "outage" || mode == "cna outage") && (err == nil || checks != 1) {
				t.Fatalf("primary outage consumed paid retry instead of retaining hold: calls=%d err=%v", checks, err)
			}
			if seen, _ := db.HasSeen(item.SourceID); seen {
				t.Fatal("primary refresh consumed held source")
			}
		})
	}
}
