package pipeline

import (
	"strings"
	"testing"
)

func TestParserAdoptionSigmaValidationGate(t *testing.T) {
	warningOnly := &briefRule{
		Title: "Warning only", LogSource: briefLogSource{Category: "process_creation", Product: "windows"},
		Detection: map[string]any{"selection": map[string]any{"CommandLine": "-dump"}, "condition": "selection"},
	}
	var notes []string
	validateSigmaRule(warningOnly, &notes)
	if warningOnly.Detection == nil {
		t.Fatalf("warning-only rule rejected: %q", notes)
	}

	oversized := &briefRule{
		Title: "Oversized", LogSource: briefLogSource{Category: "process_creation", Product: "windows"},
		Detection: map[string]any{"selection": map[string]any{"CommandLine": strings.Repeat("x", 1<<20)}, "condition": "selection"},
	}
	notes = nil
	validateSigmaRule(oversized, &notes)
	if oversized.Detection != nil || !strings.Contains(strings.Join(notes, " "), "limit") {
		t.Fatalf("limit rule was not rejected: detection=%v notes=%q", oversized.Detection != nil, notes)
	}
}

func TestParserAdoptionRejectsMalformedAuthoredValues(t *testing.T) {
	for name, selection := range map[string]map[string]any{
		"empty selection":    {},
		"empty value list":   {"CommandLine": []any{}},
		"textual existence":  {"CommandLine|exists": "true"},
		"scalar conjunction": {"CommandLine|contains|all": "-dump"},
	} {
		t.Run(name, func(t *testing.T) {
			rule := &briefRule{
				Title: "Malformed authored value", LogSource: briefLogSource{Category: "process_creation", Product: "windows"},
				Detection: map[string]any{"selection": selection, "condition": "selection"},
			}
			var notes []string
			validateSigmaRule(rule, &notes)
			if rule.Detection != nil || !strings.Contains(strings.Join(notes, " "), "invalid Sigma") {
				t.Fatalf("malformed authored value was not rejected: detection=%v notes=%q", rule.Detection != nil, notes)
			}
		})
	}
}
