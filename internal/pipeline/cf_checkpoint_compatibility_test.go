package pipeline

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// This is the actual YAML checkpoint produced by executing the immutable private
// cf127895fdc29c7ceb7e7ba888a4e1874b4d8b19 implementation, not a public
// checkpoint relabeled with a private hash. Its source and model settings are
// deliberately synthetic: the source below, fixture-provider/model/settings,
// and a checker returning an unsupported Windows omission followed by an empty
// correction. The frozen policy was evidence-quality-2026-11-15-v3; the public
// v4 schema/prompt contract must request fresh validation without consuming it.
const cf127CheckpointPayload = `policykey: 086bf079` + `578cd56e` + `8f5f2ec1` + `cc209ccf` + `c44a9dfb` + `dba075cb` + `0f812ea3` + `526404cc
evidencekey: 8dd6c628` + `55fabb58` + `9553652c` + `c835de69` + `ba9fe9c2` + `5aca2ea9` + `ea8b68d8` + `4f7f8be3
attemptid: ""
item:
    sourceid: fixture:cf127-checkpoint
    source: fixture
    title: Windows security notice
    url: ""
    content: 'Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. Windows requires low privileges. '
    publishedat: 0001-01-01T00:00:00Z
    updatedat: 0001-01-01T00:00:00Z
    revision: 8f449f0b0e3a0cec5adca14cddd4de109c8571a2c8e53700f699c8866a310abc
    metadata: {}
    discovery: null
    sigmarule: null
    needsfullarticle: false
    bodycvesaresubjects: false
    corroborationonly: false
    enriched: true
extraction: null
precves: []
score: 0
confidence: 0
briefyaml: |
    affected_products:
        - Windows
    content: Review Windows process creation telemetry for the binary path described by the source.
    exploitation_evidence:
        status: unknown
    id: brief-2026-10-windows-path
    published_at: "2026-10-19T08:00:00Z"
    references: []
    severity: medium
    severity_basis:
        kind: model_inference
        value: medium
    slug: 2026-10-windows-path
    summary: Detects a Windows binary path.
    tags: []
    title: Windows Path Detection
issues: []
rebuilddraftid: ""
reviewhold: false
mergedraftid: ""
mergetargetkey: ""
mergeattempts: 0
groundingfailure:
    kind: omission_evidence_contract
    requestdigest: d263a257d1fbb36224c3359f67e671594c107355648f9e95c3860a6cc8292f92
    contextdigest: 646bb34e39fc4843302cdb630d4a92f2166f5f05eee45ebe0dc6988f5e3acdea
    evidencedigest: 3d866f50f80b73d8f6d3a9491d01f4a8ec91f02c28e138c032cd5499fa5bf8e1
    detail: evidence correction returned 0 entries for 1 rejected omissions
`

func TestFrozenCF127ContractCheckpointPolicyTransition(t *testing.T) {
	const policyFingerprint = "086bf079578cd56e8f5f2ec1cc209ccfc44a9dfbdba075cb0f812ea3526404cc"
	const evidenceFingerprint = "8dd6c62855fabb589553652cc835de69ba9fe9c25aca2ea9ea8b68d84f7f8be3"
	const inputFingerprint = "17b8baec9f2417c7bfb5bc6f029668ca03d4a5959c253def3fa3250da5310ebd"
	const modelPolicy = "fixture-provider/model/settings"
	const payloadDigest = "2e304f0071e70e1fb64e8e05d9d60cfd6cec468bb6bd57417c0da6e198149dab"
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(cf127CheckpointPayload))); got != payloadDigest {
		t.Fatal("frozen cf127 checkpoint bytes changed; rederive them from the immutable source")
	}
	var held processingCandidate
	if err := yaml.Unmarshal([]byte(cf127CheckpointPayload), &held); err != nil {
		t.Fatal(err)
	}
	if held.PolicyKey != policyFingerprint || held.EvidenceKey != evidenceFingerprint ||
		held.GroundingFailure == nil || held.GroundingFailure.Kind != "omission_evidence_contract" {
		t.Fatal("frozen checkpoint no longer represents the deployed cf127 contract hold")
	}
	if held.Item.Revision != held.Item.ContentRevision() {
		t.Fatal("frozen cf127 source revision no longer matches its synthetic source")
	}
	db := mustOpenTestDB(t)
	defer db.Close()
	qualityCalls, unexpectedCalls := 0, 0
	freshWork := errors.New("fresh quality evaluation requested")
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) {
			unexpectedCalls++
			return "", errors.New("unexpected model call")
		},
		generateJSON: func(_ context.Context, _, system string, _ any) error {
			if system != qualitySystemPrompt {
				unexpectedCalls++
				return errors.New("unexpected structured model stage")
			}
			qualityCalls++
			return freshWork
		},
	}
	p := New(Config{DB: db, Logger: quietLogger(), LLMClient: client, ProcessingPolicy: modelPolicy, MaxGroundingAttempts: 1, RetryBackoff: -time.Second})
	item := held.Item
	if p.processingPolicyKey() == policyFingerprint || p.processingKey(item) == evidenceFingerprint || p.processingInputKey(item) == inputFingerprint {
		t.Fatal("public policy must invalidate the actual deployed cf127 fingerprint")
	}
	if err := db.PutProcessingCheckpoint(storage.ProcessingCheckpoint{SourceID: item.SourceID, InputKey: inputFingerprint, Payload: cf127CheckpointPayload, RetryAt: time.Time{}}); err != nil {
		t.Fatal(err)
	}
	if attempts, err := db.RecordGroundingAttempt(item.SourceID); err != nil || attempts != 1 {
		t.Fatalf("could not seed deployed repair budget: attempts=%d err=%v", attempts, err)
	}
	processErr := p.processItem(context.Background(), item)
	if !errors.Is(processErr, freshWork) || qualityCalls != 1 || unexpectedCalls != 0 {
		t.Fatalf("cf127 hold bypassed fresh validation: quality=%d unexpected=%d err=%v", qualityCalls, unexpectedCalls, processErr)
	}
	if checkpoint, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || checkpoint != nil {
		t.Fatalf("obsolete cf127 hold was retained: checkpoint=%v err=%v", checkpoint != nil, err)
	}
	if attempts, err := db.RecordGroundingAttempt(item.SourceID); err != nil || attempts != 1 {
		t.Fatalf("new policy did not reset the repair budget: attempts=%d err=%v", attempts, err)
	}
	if seen, err := db.HasSeenRevision(item.SourceID, item.Revision); err != nil || seen {
		t.Fatalf("policy migration consumed the source revision: seen=%v err=%v", seen, err)
	}
	if seen, err := db.HasSeen(item.SourceID); err != nil || seen {
		t.Fatalf("policy migration consumed the source: seen=%v err=%v", seen, err)
	}
	if _, quarantined, err := db.PipelineQuarantineReason(item.SourceID); err != nil || quarantined {
		t.Fatalf("policy migration treated an old contract hold as a factual rejection: quarantined=%v err=%v", quarantined, err)
	}
}
