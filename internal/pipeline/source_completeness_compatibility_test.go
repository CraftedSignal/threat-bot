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

// These keys were obtained by executing deployed ca9db25's frozen implementation,
// including its actual JSON schema serialization and complete prompt inputs.
// Deliberate future policy changes must also define checkpoint migration behavior.
func TestSourceCompletenessCheckpointPolicyTransition(t *testing.T) {
	const policyFingerprint = "acdb15a355a759ce3fd800419dad982b30ee66cb6f83d91eaca2171000187833"
	const evidenceFingerprint = "9463bbb8c5652445d6dc25074e309901be277dc2bf372670241f2f309f85002d"
	const inputFingerprint = "21ffc8ae7d60e286a095a9f2a550dd44fb5314c183f4dc40746bbee7b31e94d6"
	// Reach the quality stage on invalidation rather than the thin-source filter.
	item := scraper.RawItem{SourceID: "fixture:compatibility", Source: "fixture", Title: "Example Harbor advisory", URL: "https://vendor.example/harbor", Content: strings.Repeat("Synthetic source material for checkpoint compatibility. ", 3), Enriched: true}
	for _, tc := range []struct {
		name     string
		deployed bool
	}{
		{name: "deployed policy requires fresh validation", deployed: true},
		{name: "current policy resumes editorial hold"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			calls := 0
			freshWork := errors.New("fresh quality evaluation requested")
			client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) {
				calls++
				return "", errors.New("unexpected model call")
			}, generateJSON: func(_ context.Context, _, system string, _ any) error {
				calls++
				if system != qualitySystemPrompt {
					t.Fatalf("unexpected model stage %q", system)
				}
				return freshWork
			}}
			p := New(Config{DB: db, Logger: quietLogger(), LLMClient: client})
			p.processingPolicy = "fixture-provider/model/settings"
			if p.processingPolicyKey() == policyFingerprint || p.processingKey(item) == evidenceFingerprint || p.processingInputKey(item) == inputFingerprint {
				t.Fatal("corrected repair schema must invalidate the deployed policy fingerprint")
			}
			state := processingCandidate{PolicyKey: policyFingerprint, EvidenceKey: evidenceFingerprint, Item: item, ReviewHold: true, BriefYAML: "retained synthetic editorial candidate"}
			checkpointKey := inputFingerprint
			if !tc.deployed {
				state.PolicyKey, state.EvidenceKey = p.processingPolicyKey(), p.processingKey(item)
				checkpointKey = p.processingInputKey(item)
			}
			raw, err := yaml.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.PutProcessingCheckpoint(storage.ProcessingCheckpoint{SourceID: item.SourceID, InputKey: checkpointKey, Payload: string(raw), RetryAt: time.Time{}}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.RecordGroundingAttempt(item.SourceID); err != nil {
				t.Fatal(err)
			}
			processErr := p.processItem(context.Background(), item)
			cp, err := db.GetProcessingCheckpoint(item.SourceID)
			if tc.deployed {
				if !errors.Is(processErr, freshWork) || calls != 1 || err != nil || cp != nil {
					t.Fatalf("old policy must request fresh validation: calls=%d processErr=%v checkpointErr=%v", calls, processErr, err)
				}
				if attempts, err := db.RecordGroundingAttempt(item.SourceID); err != nil || attempts != 1 {
					t.Fatalf("new policy did not reset the repair budget: attempts=%d err=%v", attempts, err)
				}
				if seen, err := db.HasSeen(item.SourceID); err != nil || seen {
					t.Fatalf("policy transition consumed held source: seen=%v err=%v", seen, err)
				}
				return
			}
			if processErr != nil || err != nil || cp == nil || cp.InputKey != checkpointKey {
				t.Fatalf("current held checkpoint was invalidated: processErr=%v checkpointErr=%v", processErr, err)
			}
			var restored processingCandidate
			if err := yaml.Unmarshal([]byte(cp.Payload), &restored); err != nil {
				t.Fatal(err)
			}
			if !restored.ReviewHold || restored.BriefYAML != state.BriefYAML {
				t.Fatal("current editorial hold was rebuilt")
			}
			if calls != 0 {
				t.Fatalf("held candidate made %d model calls", calls)
			}
			if attempts, err := db.RecordGroundingAttempt(item.SourceID); err != nil || attempts != 2 {
				t.Fatalf("held checkpoint changed reserved attempt budget: attempts=%d err=%v", attempts, err)
			}
			if seen, err := db.HasSeen(item.SourceID); err != nil || seen {
				t.Fatalf("held source consumed: seen=%v err=%v", seen, err)
			}
		})
	}
}
