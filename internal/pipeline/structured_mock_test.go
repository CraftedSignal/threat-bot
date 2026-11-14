package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"gopkg.in/yaml.v3"
)

// Most pipeline tests script what the model "says" as a YAML brief. Since brief
// generation is schema-constrained, a mock answers GenerateStructured by
// converting that YAML into the JSON the model would have produced under the
// schema (structuredFromText) and decoding it exactly as the real client does.

// structuredFromText decodes a scripted answer, JSON or YAML, into out.
func structuredFromText(text string, out any) error {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "{") {
		return llm.DecodeStructured(trimmed, out)
	}
	trimmed = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(trimmed, "```yaml"), "```"), "```"))
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(trimmed), &doc); err != nil {
		return err
	}
	if _, isDetection := out.(*generatedDetection); isDetection {
		if inner, ok := doc["detection"].(map[string]any); ok && len(doc) == 1 {
			doc = inner
		}
		encoded, err := json.Marshal(detectionWire(doc))
		if err != nil {
			return err
		}
		return llm.DecodeStructured(string(encoded), out)
	}
	if rules, ok := doc["rules"].([]any); ok {
		for _, r := range rules {
			rule, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if detection, ok := rule["detection"].(map[string]any); ok {
				rule["detection"] = detectionWire(detection)
			}
			if tests, ok := rule["tests"].(map[string]any); ok {
				for _, kind := range []string{"positive", "negative"} {
					cases, _ := tests[kind].([]any)
					for _, c := range cases {
						if cm, ok := c.(map[string]any); ok {
							cm["data"] = testRowsWire(cm["data"])
						}
					}
				}
			}
		}
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return llm.DecodeStructured(string(encoded), out)
}

func detectionWire(detection map[string]any) map[string]any {
	out := map[string]any{"selections": []any{}}
	var names []string
	for key := range detection {
		names = append(names, key)
	}
	sort.Strings(names)
	var selections []any
	for _, name := range names {
		value := detection[name]
		switch name {
		case "condition", "timeframe":
			out[name] = fmt.Sprint(value)
			continue
		}
		var fields []any
		switch v := value.(type) {
		case map[string]any:
			var keys []string
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				field, modifier, _ := strings.Cut(k, "|")
				fields = append(fields, map[string]any{"field": field, "modifier": modifier, "values": stringValues(v[k])})
			}
		case []any:
			fields = append(fields, map[string]any{"field": "", "values": stringValues(v)})
		default:
			fields = append(fields, map[string]any{"field": "", "values": stringValues(v)})
		}
		selections = append(selections, map[string]any{"name": name, "fields": fields})
	}
	out["selections"] = selections
	return out
}

func stringValues(v any) []any {
	if list, ok := v.([]any); ok {
		out := make([]any, 0, len(list))
		for _, item := range list {
			out = append(out, fmt.Sprint(item))
		}
		return out
	}
	return []any{fmt.Sprint(v)}
}

func testRowsWire(data any) []any {
	rows, _ := data.([]any)
	var out []any
	for _, r := range rows {
		row, ok := r.(map[string]any)
		if !ok {
			continue
		}
		var keys []string
		for k := range row {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var fields []any
		for _, k := range keys {
			fields = append(fields, map[string]any{"field": k, "value": fmt.Sprint(row[k])})
		}
		out = append(out, map[string]any{"fields": fields})
	}
	return out
}

var errUnexpectedStructured = errors.New("unexpected GenerateStructured call")

func (s *scriptedLLM) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	text, err := s.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	return structuredFromText(text, out)
}

func (s *briefScriptedLLM) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	text, err := s.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	return structuredFromText(text, out)
}

func (c shutdownTestLLM) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	text, err := c.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	return structuredFromText(text, out)
}

func (c shutdownStageLLM) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	if report, ok := out.(*groundingReport); ok {
		return groundingReportFromLegacy(ctx, c.generateJSON, prompt, system, report)
	}
	text, err := c.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	return structuredFromText(text, out)
}

func (*sameIncidentMockLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return errUnexpectedStructured
}
func (m *qualityMockLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return errUnexpectedStructured
}
func (pendingRumourLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return errUnexpectedStructured
}
func (f *pipelinePrefetchFake) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return errUnexpectedStructured
}
func (m *inferMockLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return errUnexpectedStructured
}
func (mergeRelevanceMockLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return errUnexpectedStructured
}
func (roundupContentMockLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return errUnexpectedStructured
}
func (m *mockLLM) GenerateStructured(context.Context, string, string, *llm.Schema, any) error {
	return errUnexpectedStructured
}

// wireJSON is the JSON a schema-constrained model would answer with for the
// scripted YAML brief.
func wireJSON(t interface{ Fatal(args ...any) }, text string) string {
	var out map[string]any
	var generated generatedBrief
	if err := structuredFromText(text, &generated); err != nil {
		t.Fatal(err)
	}
	_ = out
	encoded, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// groundingReportFromLegacy lets tests that script the grounding verdict as a
// GroundingResult answer the structured check: every scripted issue becomes an
// unsupported claim quoting the brief's first line.
func groundingReportFromLegacy(ctx context.Context, fn func(context.Context, string, string, any) error, prompt, system string, report *groundingReport) error {
	var legacy GroundingResult
	if err := fn(ctx, prompt, system, &legacy); err != nil {
		return err
	}
	quote := ""
	if _, brief, ok := strings.Cut(prompt, "## Generated Brief (YAML)\n"); ok {
		quote = strings.TrimSpace(strings.SplitN(strings.TrimSpace(brief), "\n", 2)[0])
	}
	for _, issue := range legacy.Issues {
		report.Issues = append(report.Issues, groundingIssue{Kind: groundingKindUnsupported, Field: "brief", Reason: issue, BriefQuote: quote})
	}
	return nil
}
