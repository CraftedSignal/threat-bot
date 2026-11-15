package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// These keys were obtained by executing deployed ca9db25's frozen implementation,
// including its actual JSON schema serialization and complete prompt inputs.
// Deliberate future policy changes must also define checkpoint migration behavior.
func TestSourceCompletenessResumesDeployedPolicyCheckpoint(t *testing.T) {
	const policyFingerprint = "acdb15a355a759ce3fd800419dad982b30ee66cb6f83d91eaca2171000187833"
	const evidenceFingerprint = "f4f00006199f76fe24d6ede5e65c1836f102a10d2dcd86cc1ba79592ea8d2d05"
	const inputFingerprint = "d3bd6411e70ae1e21f3653d219458a43282a094e3f25ff664c6f02ec544a06f9"
	item := scraper.RawItem{SourceID: "fixture:compatibility", Source: "fixture", Title: "Example Harbor advisory", URL: "https://vendor.example/harbor", Content: "Synthetic source material for checkpoint compatibility.", Enriched: true}
	db := mustOpenTestDB(t)
	defer db.Close()
	calls := 0
	client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) {
		calls++
		return "", errors.New("unexpected model call")
	}, generateJSON: func(context.Context, string, string, any) error { calls++; return errors.New("unexpected model call") }}
	p := New(Config{DB: db, Logger: quietLogger(), LLMClient: client})
	p.processingPolicy = "fixture-provider/model/settings"
	if p.processingPolicyKey() != policyFingerprint || p.processingKey(item) != evidenceFingerprint || p.processingInputKey(item) != inputFingerprint {
		t.Fatal("runtime policy no longer matches the deployed checkpoint contract")
	}
	state := processingCandidate{PolicyKey: policyFingerprint, EvidenceKey: evidenceFingerprint, Item: item, ReviewHold: true, BriefYAML: "retained synthetic editorial candidate"}
	raw, err := yaml.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutProcessingCheckpoint(storage.ProcessingCheckpoint{SourceID: item.SourceID, InputKey: inputFingerprint, Payload: string(raw), RetryAt: time.Time{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordGroundingAttempt(item.SourceID); err != nil {
		t.Fatal(err)
	}
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	cp, err := db.GetProcessingCheckpoint(item.SourceID)
	if err != nil || cp == nil || cp.InputKey != inputFingerprint {
		t.Fatalf("deployed held checkpoint was invalidated: %v", err)
	}
	var restored processingCandidate
	if err := yaml.Unmarshal([]byte(cp.Payload), &restored); err != nil {
		t.Fatal(err)
	}
	if !restored.ReviewHold || restored.BriefYAML != state.BriefYAML {
		t.Fatal("deployed editorial hold was rebuilt")
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
}
