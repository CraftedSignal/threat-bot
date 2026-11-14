package pipeline

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/sigma"
	"gopkg.in/yaml.v3"
)

// scriptedLLM returns its replies in order and records the prompts it got.
type scriptedLLM struct {
	replies []string
	prompts []string
}

func (s *scriptedLLM) Generate(_ context.Context, prompt, _ string) (string, error) {
	s.prompts = append(s.prompts, prompt)
	if len(s.prompts) > len(s.replies) {
		return "", fmt.Errorf("unexpected LLM call %d", len(s.prompts))
	}
	return s.replies[len(s.prompts)-1], nil
}

func (s *scriptedLLM) GenerateJSON(context.Context, string, string, any) error { return nil }

const repairBrief = `id: brief-2026-10-09-repair
slug: 2026-10-repair
title: Repair
summary: A test
severity: high
published_at: "2026-10-09T10:00:00Z"
content: test
rules:
  - title: Valid
    logsource: {category: process_creation, product: windows}
    detection:
      selection:
        Image|endswith: '\tool.exe'
      condition: selection
  - title: Invented modifier
    logsource: {category: process_creation, product: windows}
    detection:
      selection:
        CommandLine|strlen: 500
`

func ruleDetections(t *testing.T, briefYAML string) map[string]map[string]any {
	t.Helper()
	var brief struct {
		Rules []struct {
			Title     string         `yaml:"title"`
			Detection map[string]any `yaml:"detection"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(briefYAML), &brief); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, rule := range brief.Rules {
		out[rule.Title] = rule.Detection
	}
	return out
}

// The parser's errors go back to the LLM until the rule is valid, each
// attempt building on the previous one.
func TestRepairRulesFeedsParserErrorsBack(t *testing.T) {
	llm := &scriptedLLM{replies: []string{
		"```yaml\ndetection:\n  selection:\n    CommandLine|re: '^.{500,}$'\n  condition: selection and not filter\n```",
		"selection:\n  CommandLine|re: '^.{500,}$'\ncondition: selection\n",
	}}
	repaired, notes, err := NewBriefAssembler(llm).RepairRules(context.Background(), repairBrief)
	if err != nil {
		t.Fatal(err)
	}

	if len(llm.prompts) != 2 {
		t.Fatalf("expected 2 repair calls, got %d", len(llm.prompts))
	}
	if !strings.Contains(llm.prompts[0], "strlen") || !strings.Contains(llm.prompts[1], "selection and not filter") {
		t.Fatalf("repair prompts do not carry the rule and its errors:\n%s\n---\n%s", llm.prompts[0], llm.prompts[1])
	}
	detections := ruleDetections(t, repaired)
	if problems, warnings := sigma.CheckDetection(detections["Invented modifier"]); problems != nil || warnings != nil {
		t.Fatalf("repaired rule still has problems %q and warnings %q", problems, warnings)
	}
	if detections["Invented modifier"]["condition"] != "selection" {
		t.Fatalf("repaired detection is not the LLM's last reply: %v", detections["Invented modifier"])
	}
	if detections["Valid"]["condition"] != "selection" {
		t.Fatalf("valid rule changed: %v", detections["Valid"])
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "Invented modifier") {
		t.Fatalf("expected one note about the repaired rule, got %q", notes)
	}
}

// A rule the LLM cannot fix stays as it was, and validation rejects it.
func TestRepairRulesLeavesUnfixableRulesForValidation(t *testing.T) {
	llm := &scriptedLLM{replies: []string{"not: [a mapping", "selection:\n  CommandLine|length: 500\n"}}
	repaired, notes, err := NewBriefAssembler(llm).RepairRules(context.Background(), repairBrief)
	if err != nil {
		t.Fatal(err)
	}
	if repaired != repairBrief || len(notes) != 1 || !strings.Contains(notes[0], "still invalid") {
		t.Fatalf("expected the brief unchanged with a still-invalid note, got notes %q", notes)
	}

	cleaned, _, err := NewBriefValidator().Validate(repaired)
	if err != nil {
		t.Fatal(err)
	}
	detections := ruleDetections(t, cleaned)
	if _, kept := detections["Invented modifier"]; kept || len(detections) != 1 {
		t.Fatalf("expected validation to drop the invalid rule, got %v", detections)
	}
}

const parameterBrief = `id: brief-2026-10-09-parameter
slug: 2026-10-parameter
title: Parameter
summary: A test
severity: high
published_at: "2026-10-09T10:00:00Z"
content: test
rules:
  - title: Dump flag
    logsource: {category: process_creation, product: linux}
    detection:
      selection:
        Image|endswith: /mkpassdb
        CommandLine: -dump
      condition: selection
    level: high
`

// A valid rule the parser warns about goes to the LLM too, so an exact
// command-line parameter becomes |contains before publishing.
func TestRepairRulesFixesExactCommandLineParameters(t *testing.T) {
	llm := &scriptedLLM{replies: []string{"selection:\n  Image|endswith: /mkpassdb\n  CommandLine|contains: -dump\ncondition: selection\n"}}
	repaired, notes, err := NewBriefAssembler(llm).RepairRules(context.Background(), parameterBrief)
	if err != nil {
		t.Fatal(err)
	}
	if len(llm.prompts) != 1 || !strings.Contains(llm.prompts[0], "CommandLine|contains") {
		t.Fatalf("expected one repair call carrying the warning, got %q", llm.prompts)
	}
	selection, _ := ruleDetections(t, repaired)["Dump flag"]["selection"].(map[string]any)
	if selection["CommandLine|contains"] != "-dump" || len(notes) != 1 || !strings.Contains(notes[0], "repaired") {
		t.Fatalf("expected the |contains repair to replace the rule, got %v (notes %q)", selection, notes)
	}
}

// A valid rule the LLM cannot clear of warnings stays as written and is
// still published: it is valid Sigma.
func TestRepairRulesKeepsValidRulesTheLLMCannotImprove(t *testing.T) {
	llm := &scriptedLLM{replies: []string{
		"selection:\n  CommandLine|strlen: 5\ncondition: selection\n",
		"selection:\n  CommandLine: -dump\ncondition: selection\n",
	}}
	repaired, notes, err := NewBriefAssembler(llm).RepairRules(context.Background(), parameterBrief)
	if err != nil {
		t.Fatal(err)
	}
	if repaired != parameterBrief || len(notes) != 1 || !strings.Contains(notes[0], "kept as written") {
		t.Fatalf("expected the brief unchanged with a kept-as-written note, got notes %q", notes)
	}
	cleaned, _, err := NewBriefValidator().Validate(repaired)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := ruleDetections(t, cleaned)["Dump flag"]; !kept {
		t.Fatal("expected validation to keep the valid rule")
	}
}

// The example rules the brief prompt teaches from must be valid Sigma.
func TestBriefPromptExampleRulesAreValidSigma(t *testing.T) {
	section := briefSystemPrompt[strings.Index(briefSystemPrompt, "EXAMPLE SIGMA RULES"):]
	examples := 0
	for _, block := range strings.Split(section, "\nExample ")[1:] {
		var lines []string
		for _, line := range strings.Split(block, "\n")[1:] {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "  ") {
				break
			}
			lines = append(lines, strings.TrimPrefix(line, "  "))
		}
		var rule struct {
			Title     string          `yaml:"title"`
			LogSource sigma.LogSource `yaml:"logsource"`
			Detection map[string]any  `yaml:"detection"`
		}
		if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &rule); err != nil {
			t.Fatalf("example %d is not YAML: %v", examples+1, err)
		}
		if problems := sigma.Problems(rule.Title, rule.LogSource, rule.Detection); problems != nil {
			t.Errorf("example %q is not valid Sigma: %q", rule.Title, problems)
		}
		if _, warnings := sigma.CheckDetection(rule.Detection); warnings != nil {
			t.Errorf("example %q draws warnings: %q", rule.Title, warnings)
		}
		examples++
	}
	if examples == 0 {
		t.Fatal("no example rules found in the brief prompt")
	}
}

// A modifier alias the LLM wrote (Field|regex) is rewritten to its Sigma
// form before validation, without spending a repair call.
func TestRepairRulesNormalizesModifierAliases(t *testing.T) {
	brief := `id: brief-2026-10-09-alias
slug: 2026-10-alias
title: Alias
summary: A test
severity: high
published_at: "2026-10-09T10:00:00Z"
content: test
rules:
  - title: Alias
    logsource: {category: process_creation, product: linux}
    detection:
      selection:
        CommandLine|regex: '^find .* -perm'
      condition: selection
`
	llmStub := &scriptedLLM{}
	a := &BriefAssembler{client: llmStub}
	out, _, err := a.RepairRules(context.Background(), brief)
	if err != nil {
		t.Fatal(err)
	}
	if len(llmStub.prompts) != 0 {
		t.Fatalf("no LLM call expected, got %d", len(llmStub.prompts))
	}
	if !strings.Contains(out, "CommandLine|re:") || strings.Contains(out, "|regex") {
		t.Fatalf("alias not normalized:\n%s", out)
	}
}
