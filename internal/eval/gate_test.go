package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// TestEvalGate is mandatory, deterministic publication-contract evaluation.
// It makes no model requests and makes no claim about model extraction F1.
func TestEvalGate(t *testing.T) {
	t.Run("synthetic-extraction-replay", testSyntheticExtractionReplayGate)
	corpus, err := LoadBriefQualityCorpus(filepath.Join("testdata", "brief_quality"))
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{"manual": true, "outbox": true, "backfill": true, "update": true}
	for _, route := range corpus.Baseline.RequiredRoutes {
		if !routes[route] {
			t.Fatalf("required quality route %s has no runner", route)
		}
	}
	accepted, rejected, correctAccept, correctReject := 0, 0, 0, 0
	for _, c := range corpus.Cases {
		for _, route := range corpus.Baseline.RequiredRoutes {
			t.Run(c.ID+"/"+route, func(t *testing.T) {
				logger := slog.New(slog.NewTextHandler(io.Discard, nil))
				pub := publisher.New("fixture/repo", "unused", func() string { return "" }, logger)
				var gateErr error
				switch route {
				case "manual":
					gateErr = pub.ValidatePublication(string(c.Candidate))
				case "backfill":
					b, err := publisher.ParseBriefYAML(string(c.Candidate))
					gateErr = err
					if err == nil {
						_, _, _, publish, err := publisher.RenderPublicBriefMarkdown(*b, nil)
						gateErr = err
						if !publish && err == nil {
							gateErr = fmt.Errorf("candidate suppressed by public render gate")
						}
					}
				case "outbox", "update":
					db, err := storage.Open(filepath.Join(t.TempDir(), "outbox.db"))
					if err != nil {
						t.Fatal(err)
					}
					defer db.Close()
					pub = publisher.New("fixture/repo", "unused", func() string { return "" }, logger, publisher.WithOutbox(db))
					var previous []storage.OutboxRow
					if route == "update" {
						// Start with an independently authored publishable snapshot of
						// the same identity, then try the candidate as its replacement.
						valid, err := os.ReadFile(filepath.Join("testdata", "brief_quality", "valid-notice.json"))
						if err != nil {
							t.Fatal(err)
						}
						var original, candidate map[string]any
						if err := yaml.Unmarshal(valid, &original); err != nil {
							t.Fatal(err)
						}
						if err := yaml.Unmarshal(c.Candidate, &candidate); err != nil {
							t.Fatal(err)
						}
						original["id"], original["slug"] = candidate["id"], candidate["slug"]
						initial, err := yaml.Marshal(original)
						if err != nil {
							t.Fatal(err)
						}
						if err := pub.PublishDraft(string(initial), "fixture-draft", ""); err != nil {
							t.Fatal(err)
						}
						previous, err = db.ListPublishOutbox()
						if err != nil {
							t.Fatal(err)
						}
					}
					gateErr = pub.PublishDraft(string(c.Candidate), "fixture-draft", "")
					rows, err := db.ListPublishOutbox()
					if err != nil {
						t.Fatal(err)
					}
					if gateErr != nil && route == "update" && !reflect.DeepEqual(rows, previous) {
						t.Fatal("rejected update replaced the previous durable publication snapshot")
					}
					if gateErr != nil && route == "outbox" && len(rows) != 0 {
						t.Fatal("rejected candidate entered durable publication outbox")
					}
					if gateErr == nil && len(rows) != 1 {
						t.Fatal("accepted candidate was not durably queued")
					}
					if gateErr != nil && route == "outbox" {
						if _, err := db.UpsertPublishOutbox("legacy-invalid", storage.OutboxKindBrief, string(c.Candidate)); err != nil {
							t.Fatal(err)
						}
					}
					restarted := publisher.New("fixture/repo", "unused", func() string { return "" }, logger, publisher.WithOutbox(db))
					restored, err := restarted.RestoreOutbox()
					if err != nil {
						t.Fatal(err)
					}
					if gateErr != nil && route == "outbox" && restored != 0 {
						t.Fatal("restart bypassed candidate publication gate")
					}
					if (gateErr == nil || route == "update") && restored != 1 {
						t.Fatal("restart lost valid publication")
					}
				}
				if c.Expected == "accept" {
					accepted++
					if gateErr == nil {
						correctAccept++
					} else {
						t.Errorf("labelled valid candidate rejected: %v", gateErr)
					}
				} else {
					rejected++
					if gateErr != nil {
						correctReject++
					} else {
						t.Error("labelled failure candidate accepted")
					}
					if gateErr != nil && c.RejectContains != "" && !strings.Contains(strings.ToLower(gateErr.Error()), strings.ToLower(c.RejectContains)) {
						t.Errorf("failure did not reach intended safeguard %q: %v", c.RejectContains, gateErr)
					}
				}
			})
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatal("required corpus must include positive and negative candidates")
	}
	if float64(correctAccept)/float64(accepted) < corpus.Baseline.MinimumAcceptanceRecall {
		t.Errorf("acceptance recall %d/%d below committed baseline", correctAccept, accepted)
	}
	if float64(correctReject)/float64(rejected) < corpus.Baseline.MinimumRejectionRecall {
		t.Errorf("rejection recall %d/%d below committed baseline", correctReject, rejected)
	}
	t.Run("repair-omission", func(t *testing.T) { testCorpusRepairOmission(t, corpus) })
}

// authoredRepairClient is a deterministic adversarial test double. It does not
// impersonate a captured model response or assess source grounding itself.
type authoredRepairClient struct {
	candidate, source string
	calls             int
}

func (c *authoredRepairClient) Generate(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("unexpected text generation")
}
func (c *authoredRepairClient) GenerateJSON(context.Context, string, string, any) error {
	return fmt.Errorf("unexpected JSON generation")
}
func (c *authoredRepairClient) GenerateStructured(_ context.Context, prompt, _ string, _ *llm.Schema, out any) error {
	c.calls++
	if !strings.Contains(prompt, c.source) {
		return fmt.Errorf("repair did not receive the committed source")
	}
	return llm.DecodeStructured(c.candidate, out)
}

func testCorpusRepairOmission(t *testing.T, corpus *BriefQualityCorpus) {
	var original, omission BriefQualityCase
	for _, c := range corpus.Cases {
		if c.ID == "valid-notice" {
			original = c
		}
		if c.ID == "repair-omits-body" {
			omission = c
		}
	}
	if len(original.Candidate) == 0 || len(omission.Candidate) == 0 {
		t.Fatal("required repair candidates missing")
	}
	var candidate map[string]any
	if err := yaml.Unmarshal(omission.Candidate, &candidate); err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	client := &authoredRepairClient{candidate: string(response), source: string(omission.Source)}
	repaired, err := pipeline.NewGroundingChecker(client).Repair(context.Background(), "Authored Widget advisory", string(omission.Source), string(original.Candidate), []string{"Remove unsupported narrative"})
	if err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 {
		t.Fatalf("repair calls = %d, want 1", client.calls)
	}
	pub := publisher.New("fixture/repo", "unused", func() string { return "" }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := pub.ValidatePublication(repaired); err == nil || !strings.Contains(strings.ToLower(err.Error()), "content") {
		t.Fatalf("real repair output with omitted body escaped publication gate: %v", err)
	}
}

func TestEvalGateCannotSkipRequiredInputs(t *testing.T) {
	t.Cleanup(func() {
		if t.Skipped() {
			t.Error("the required deterministic quality gate was skipped")
		}
	})
	TestEvalGate(t)
}

func TestQualityCorpusMissingRequiredInputsFails(t *testing.T) {
	for _, missing := range []string{"corpus.json", "baseline.json", "notice-without-guidance.json", "widget-source.json"} {
		t.Run(missing, func(t *testing.T) {
			dir := t.TempDir()
			entries, err := os.ReadDir(filepath.Join("testdata", "brief_quality"))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.IsDir() || entry.Name() == missing {
					continue
				}
				data, err := os.ReadFile(filepath.Join("testdata", "brief_quality", entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, entry.Name()), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadBriefQualityCorpus(dir); err == nil {
				t.Fatalf("missing %s silently disabled mandatory evaluation", missing)
			}
		})
	}
}
