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

// These keys were obtained by executing the frozen deployed v2 implementation,
// including its actual JSON schema serialization and complete prompt inputs.
// Deliberate future policy changes must also define checkpoint migration behavior.
func TestSourceCompletenessResumesDeployedPolicyCheckpoint(t *testing.T) {
	const policyFingerprint = "6de0d89e534eda20c3c973211105c6e0b041c349337fa67b80e7f808e4111980"
	const evidenceFingerprint = "ee7d19503cfde672a3ae1de5004b2507a6d10ceb617bae4f0a07590dc923adb0"
	const inputFingerprint = "dcdb24657206117d535fe416cc55741ec2b85562c21fea8c9804f2ef4d041865"
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
