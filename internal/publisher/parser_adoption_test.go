package publisher

import (
	"log/slog"
	"strings"
	"testing"
)

func TestParserAdoptionPublicationGate(t *testing.T) {
	brief := &BundleBrief{ID: "parser-adoption", Rules: []BundleRule{
		{Title: "Warning only", LogSource: BundleLogSource{Category: "process_creation", Product: "windows"}, Detection: map[string]any{"selection": map[string]any{"CommandLine": "-dump"}, "condition": "selection"}},
		{Title: "Oversized", LogSource: BundleLogSource{Category: "process_creation", Product: "windows"}, Detection: map[string]any{"selection": map[string]any{"CommandLine": strings.Repeat("x", 1<<20)}, "condition": "selection"}},
	}}
	p := &Publisher{logger: slog.Default()}
	got := p.validRules(brief)
	if len(got) != 1 || got[0].Title != "Warning only" {
		t.Fatalf("published rules: %v", got)
	}
}

func TestParserAdoptionRejectsMalformedAuthoredValues(t *testing.T) {
	brief := &BundleBrief{ID: "parser-authored-values", Rules: []BundleRule{
		{Title: "Boolean existence", LogSource: BundleLogSource{Category: "process_creation", Product: "windows"}, Detection: map[string]any{"selection": map[string]any{"CommandLine|exists": true}, "condition": "selection"}},
		{Title: "Textual existence", LogSource: BundleLogSource{Category: "process_creation", Product: "windows"}, Detection: map[string]any{"selection": map[string]any{"CommandLine|exists": "true"}, "condition": "selection"}},
		{Title: "Empty selection", LogSource: BundleLogSource{Category: "process_creation", Product: "windows"}, Detection: map[string]any{"selection": map[string]any{}, "condition": "selection"}},
		{Title: "Empty value list", LogSource: BundleLogSource{Category: "process_creation", Product: "windows"}, Detection: map[string]any{"selection": map[string]any{"CommandLine": []any{}}, "condition": "selection"}},
	}}
	p := &Publisher{logger: slog.Default()}
	got := p.validRules(brief)
	if len(got) != 1 || got[0].Title != "Boolean existence" {
		t.Fatalf("expected only valid authored values to publish, got %+v", got)
	}
}
