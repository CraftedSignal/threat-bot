package main

import (
	"reflect"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestParseRejectArgsAcceptsReasonAfterDraftID(t *testing.T) {
	for _, args := range [][]string{
		{"draft-1", "--reason", "Superseded"},
		{"--reason=Superseded", "draft-1"},
	} {
		ids, reason, err := parseRejectArgs(args)
		if err != nil || !reflect.DeepEqual(ids, []string{"draft-1"}) || reason != "Superseded" {
			t.Fatalf("parse %v: ids=%v reason=%q err=%v", args, ids, reason, err)
		}
	}
	if _, _, err := parseRejectArgs([]string{"draft-1", "--reason"}); err == nil {
		t.Fatal("missing reason accepted")
	}
	if _, _, err := parseRejectArgs([]string{"draft-1", "--reason", "--unexpected"}); err == nil {
		t.Fatal("flag was accepted as reason")
	}
}

func TestHarvestGoldenExamples(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	yaml := `id: brief-x
title: t
ttps:
  - tactic_id: "TA0001"
    technique_id: "T1566"
    evidence: "spearphishing email observed"
    confidence: 0.9
  - tactic_id: "TA0002"
    technique_id: "T1059"
    evidence: ""
`
	harvestGoldenExamples(db, yaml, "cisa")
	got, err := db.GoldenExamples()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Only the TTP with non-empty evidence is harvested.
	if len(got) != 1 {
		t.Fatalf("want 1 harvested, got %d: %+v", len(got), got)
	}
	if got[0].Technique != "T1566" || got[0].Source != "cisa" {
		t.Errorf("unexpected: %+v", got[0])
	}
}
