package pipeline

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/sigma"
	"gopkg.in/yaml.v3"
)

// maxRuleRepairs bounds the LLM calls spent fixing one Sigma rule.
const maxRuleRepairs = 2

const ruleRepairSystemPrompt = `You fix Sigma detection rules that a Sigma parser found problems in: errors make a rule invalid, warnings mark a rule that likely does not match what it means to. You get one rule and its problems. Reply with the corrected detection block in the structured form the response schema defines: the named selections (each a list of field, modifier and values) and the condition, plus timeframe when the rule counts events. The rule is shown in Sigma YAML: a key such as CommandLine|contains with its value(s) is one match with field CommandLine, modifier contains and those values; a key without a modifier has no modifier. Keep the rule's intent, selection names and field names; change only what the problems require.

` + sigmaSyntax

const ruleRepairPrompt = `Rule:
%s
Problems the Sigma parser found:
%s`

// repairContext is the part of a rule the LLM sees when repairing it.
type repairContext struct {
	Title       any `yaml:"title,omitempty"`
	Description any `yaml:"description,omitempty"`
	LogSource   any `yaml:"logsource,omitempty"`
	Detection   any `yaml:"detection,omitempty"`
	Tests       any `yaml:"tests,omitempty"`
}

// RepairRules asks the LLM to fix each rule in the brief whose detection
// sigma-parser rejects or warns about, feeding back the parser's findings
// until the rule is clean or maxRuleRepairs attempts are spent. A repair
// replaces the rule when it is clean, or when it makes an invalid rule
// valid; otherwise the rule stays as written and validation decides.
func (a *BriefAssembler) RepairRules(ctx context.Context, briefYAML string) (string, []string, error) {
	var brief map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &brief); err != nil {
		return briefYAML, nil, nil
	}
	rules, _ := brief["rules"].([]any)
	var notes []string
	repaired := false
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		detection, _ := rule["detection"].(map[string]any)
		// Alias modifiers (Field|regex) are rewritten deterministically; no
		// LLM call is needed for them.
		if sigma.NormalizeModifierAliases(detection) {
			repaired = true
			notes = append(notes, fmt.Sprintf("rule %q: normalized Sigma modifier aliases", rule["title"]))
		}
		problems, warnings := sigma.CheckDetection(detection)
		if len(problems)+len(warnings) == 0 {
			continue
		}
		title, _ := rule["title"].(string)
		fixed, attempts, fixedProblems, fixedWarnings, err := a.repairDetection(ctx, rule, append(problems, warnings...))
		if err != nil {
			return briefYAML, notes, err
		}
		switch {
		case fixed != nil && len(fixedProblems) == 0 && (len(fixedWarnings) == 0 || len(problems) > 0):
			rule["detection"] = fixed
			repaired = true
			note := fmt.Sprintf("rule %q: repaired Sigma in %d attempt(s)", title, attempts)
			if len(fixedWarnings) > 0 {
				note += "; still warns: " + strings.Join(fixedWarnings, "; ")
			}
			notes = append(notes, note)
		case len(problems) > 0:
			notes = append(notes, fmt.Sprintf("rule %q: still invalid Sigma after %d repair attempt(s): %s", title, attempts, strings.Join(append(fixedProblems, fixedWarnings...), "; ")))
		default:
			notes = append(notes, fmt.Sprintf("rule %q: kept as written; still warns after %d repair attempt(s): %s", title, attempts, strings.Join(warnings, "; ")))
		}
	}
	if !repaired {
		return briefYAML, notes, nil
	}
	out, err := yaml.Marshal(brief)
	if err != nil {
		return briefYAML, append(notes, fmt.Sprintf("re-encoding repaired brief: %v", err)), nil
	}
	return string(out), notes, nil
}

// repairDetection asks the LLM for a corrected detection block, feeding each
// attempt's problems into the next. It returns the last detection the LLM
// gave, the attempts made, and that detection's remaining errors and
// warnings.
func (a *BriefAssembler) repairDetection(ctx context.Context, rule map[string]any, findings []string) (map[string]any, int, []string, []string, error) {
	current := maps.Clone(rule)
	var detection map[string]any
	var problems, warnings []string
	attempts := 0
	for attempts < maxRuleRepairs && len(findings) > 0 {
		attempts++
		ruleYAML, err := yaml.Marshal(repairContext{
			Title:       current["title"],
			Description: current["description"],
			LogSource:   current["logsource"],
			Detection:   current["detection"],
			Tests:       current["tests"],
		})
		if err != nil {
			return nil, attempts, []string{fmt.Sprintf("encoding rule for repair: %v", err)}, nil, nil
		}
		var reply generatedDetection
		err = a.client.GenerateStructured(ctx, fmt.Sprintf(ruleRepairPrompt, ruleYAML, "- "+strings.Join(findings, "\n- ")), ruleRepairSystemPrompt, detectionResponseSchema, &reply)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return detection, attempts, problems, warnings, ctxErr
			}
			var finish *llm.FinishReasonError
			var output *llm.OutputError
			if errors.As(err, &finish) || errors.As(err, &output) {
				findings = []string{fmt.Sprintf("the previous reply was not a usable detection block: %v", err)}
				continue
			}
			return detection, attempts, append(problems, fmt.Sprintf("repair call failed: %v", err)), warnings, nil
		}
		next := reply.rebuild()
		if len(next) == 0 {
			findings = []string{"the previous reply was not a usable detection block: it had no selections or condition"}
			continue
		}
		sigma.NormalizeModifierAliases(next)
		detection = next
		current["detection"] = next
		problems, warnings = sigma.CheckDetection(next)
		findings = append(append([]string(nil), problems...), warnings...)
	}
	if detection == nil {
		return nil, attempts, findings, nil, nil
	}
	return detection, attempts, problems, warnings, nil
}
