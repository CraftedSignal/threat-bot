package pipeline

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// A refused merge is a correct relevance decision, not a failure.
func TestLogMergeFailureLevels(t *testing.T) {
	var buf bytes.Buffer
	p := &Pipeline{logger: slog.New(slog.NewTextHandler(&buf, nil))}

	refusal := fmt.Errorf("merge: source %q is %w to draft d: no shared CVEs", "s", errMergeNotRelevant)
	p.logMergeFailure("roundup merge failed", refusal, "draft_id", "d")
	if out := buf.String(); strings.Contains(out, "WARN") || !strings.Contains(out, "level=INFO") {
		t.Fatalf("refusal logged as %q, want INFO", out)
	}

	buf.Reset()
	p.logMergeFailure("roundup merge failed", errors.New("database is locked"), "draft_id", "d")
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "database is locked") {
		t.Fatalf("real failure logged as %q, want WARN", out)
	}
}

// A policy refusal to merge into a vendor roundup is deterministic, not a failure.
func TestLogMergeFailureNonAuthoritativeRoundupSourceIsInfo(t *testing.T) {
	var buf bytes.Buffer
	p := &Pipeline{logger: slog.New(slog.NewTextHandler(&buf, nil))}

	refusal := fmt.Errorf("merge: %w %q cannot update %s roundup", errNonAuthoritativeRoundupSource, "sploitus", "Microsoft")
	if !errors.Is(refusal, errNonAuthoritativeRoundupSource) {
		t.Fatal("errors.Is must match the sentinel")
	}
	p.logMergeFailure("DedupUpdate merge failed, will create new draft", refusal, "draft_id", "d")
	out := buf.String()
	if strings.Contains(out, "level=WARN") || !strings.Contains(out, "level=INFO") || !strings.Contains(out, "policy") {
		t.Fatalf("policy refusal logged as %q, want INFO mentioning policy", out)
	}
}
