package eval

import (
	"context"
	"testing"
)

func TestReplayClientRoundTrip(t *testing.T) {
	fix := map[string]string{
		FixtureKey("prompt-1", "sys"): `{"techniques":["T1566"]}`,
	}
	rc := NewReplayClient(fix)
	var out struct {
		Techniques []string `json:"techniques"`
	}
	if err := rc.GenerateJSON(context.Background(), "prompt-1", "sys", &out); err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	if len(out.Techniques) != 1 || out.Techniques[0] != "T1566" {
		t.Errorf("got %+v", out)
	}
}

func TestReplayClientMissingKeyErrors(t *testing.T) {
	rc := NewReplayClient(map[string]string{})
	var out map[string]any
	if err := rc.GenerateJSON(context.Background(), "nope", "sys", &out); err == nil {
		t.Error("expected error for missing fixture")
	}
}
