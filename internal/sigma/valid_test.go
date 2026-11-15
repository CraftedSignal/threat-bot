package sigma

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func detection(t *testing.T, src string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := yaml.Unmarshal([]byte(src), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// An exact command-line value that can only be a parameter never matches: it
// is valid Sigma, so it is a warning rather than a problem.
func TestCheckDetectionWarnsAboutExactCommandLineParameters(t *testing.T) {
	problems, warnings := CheckDetection(detection(t, "selection:\n  CommandLine: -dump\ncondition: selection\n"))
	if problems != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "CommandLine|contains") {
		t.Fatalf("expected one |contains warning and no problems, got %q / %q", problems, warnings)
	}
	if problems := Problems("T", LogSource{Category: "process_creation", Product: "linux"}, detection(t, "selection:\n  CommandLine: -dump\ncondition: selection\n")); problems != nil {
		t.Fatalf("warnings must not reject a rule, got problems %q", problems)
	}
	if _, warnings := CheckDetection(detection(t, "selection:\n  CommandLine: 'mkpassdb -dump'\ncondition: selection\n")); warnings != nil {
		t.Fatalf("a whole command line drew warnings %q", warnings)
	}
}

func TestProblems(t *testing.T) {
	processCreation := LogSource{Category: "process_creation", Product: "windows"}
	valid := detection(t, `
selection:
  Image|endswith: '\powershell.exe'
  CommandLine|contains|all: ['-nop', '-w hidden']
filter:
  ParentImage|endswith: '\explorer.exe'
condition: selection and not filter
`)
	if problems := Problems("PowerShell", processCreation, valid); problems != nil {
		t.Fatalf("valid rule reported %q", problems)
	}

	// The mistakes LLM-written rules make most: no condition, invented
	// modifiers, undefined selections, conditions Sigma has no syntax for.
	for name, tc := range map[string]struct {
		title     string
		logSource LogSource
		detection string
		want      string
	}{
		"missing condition":   {"T", processCreation, "selection:\n  Image|endswith: x.exe\n", "condition"},
		"invented modifier":   {"T", processCreation, "selection:\n  CommandLine|strlen: 500\ncondition: selection\n", "strlen"},
		"undefined selection": {"T", processCreation, "selection:\n  Image: x.exe\ncondition: selection and not filter\n", "filter"},
		"sequence condition":  {"T", processCreation, "a:\n  Image: x.exe\nb:\n  Image: y.exe\ncondition: a followed by b\n", "followed"},
		"no detection":        {"T", processCreation, "", "detection"},
		"no log source":       {"T", LogSource{}, "selection:\n  Image: x.exe\ncondition: selection\n", "logsource"},
		"no title":            {" ", processCreation, "selection:\n  Image: x.exe\ncondition: selection\n", "title"},
	} {
		t.Run(name, func(t *testing.T) {
			var det map[string]any
			if tc.detection != "" {
				det = detection(t, tc.detection)
			}
			problems := Problems(tc.title, tc.logSource, det)
			if !strings.Contains(strings.Join(problems, "; "), tc.want) {
				t.Fatalf("problems %q do not mention %q", problems, tc.want)
			}
		})
	}
}

func TestParserAdoptionLimitIsProblemButWarningIsNot(t *testing.T) {
	logSource := LogSource{Category: "process_creation", Product: "windows"}
	warningOnly := detection(t, "selection:\n  CommandLine: -dump\ncondition: selection\n")
	if problems, warnings := CheckDetection(warningOnly); len(problems) != 0 || len(warnings) == 0 {
		t.Fatalf("warning-only detection: problems=%q warnings=%q", problems, warnings)
	}
	if problems := Problems("Warning only", logSource, warningOnly); len(problems) != 0 {
		t.Fatalf("warning-only rule rejected: %q", problems)
	}

	oversized := map[string]any{"selection": map[string]any{"CommandLine": strings.Repeat("x", 1<<20)}, "condition": "selection"}
	problems, warnings := CheckDetection(oversized)
	if len(problems) == 0 || len(warnings) != 0 || !strings.Contains(strings.Join(problems, " "), "limit") {
		t.Fatalf("limit detection: problems=%q warnings=%q", problems, warnings)
	}
	if problems := Problems("Oversized", logSource, oversized); len(problems) == 0 {
		t.Fatal("oversized detection was accepted")
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
			detection := map[string]any{"selection": selection, "condition": "selection"}
			if problems := Problems("Malformed authored value", LogSource{Category: "process_creation", Product: "windows"}, detection); len(problems) == 0 {
				t.Fatal("malformed authored value was accepted")
			}
		})
	}
}

func TestTimeframeProblemsFollowSigmaParser(t *testing.T) {
	const selection = "selection:\n  Image: example.exe\ncondition: selection\n"
	const typeProblem = "detection.timeframe' must be a string"
	const emptyProblem = "detection.timeframe' must not be empty"
	const unitProblem = "detection.timeframe' must include a time unit"
	logSource := LogSource{Category: "process_creation", Product: "windows"}
	for _, tc := range []struct {
		name, timeframe, wantProblem string
	}{
		{"integer", "timeframe: 60\n", typeProblem},
		{"float", "timeframe: 1.5\n", typeProblem},
		{"boolean", "timeframe: true\n", typeProblem},
		{"null", "timeframe: null\n", typeProblem},
		{"sequence", "timeframe: [5m]\n", typeProblem},
		{"mapping", "timeframe: {duration: 5m}\n", typeProblem},
		{"empty string", "timeframe: ''\n", emptyProblem},
		{"whitespace string", "timeframe: ' '\n", emptyProblem},
		{"numeric string", "timeframe: '60'\n", unitProblem},
		{"numeric exponent", "timeframe: '1e3'\n", unitProblem},
		{"trimmed numeric", "timeframe: ' 60 '\n", unitProblem},
		{"minutes", "timeframe: 5m\n", ""},
		{"months", "timeframe: 3M\n", ""},
		{"absent", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := selection + tc.timeframe
			input := detection(t, source)
			original := detection(t, source)
			problems, warnings := CheckDetection(input)
			if tc.wantProblem == "" {
				if len(problems) != 0 || len(warnings) != 0 {
					t.Fatalf("valid timeframe: problems=%q warnings=%q", problems, warnings)
				}
			} else if !strings.Contains(strings.Join(problems, "; "), tc.wantProblem) || len(warnings) != 0 {
				t.Fatalf("invalid timeframe: problems=%q warnings=%q, want problem containing %q", problems, warnings, tc.wantProblem)
			}
			if got := Problems("Timeframe", logSource, input); !reflect.DeepEqual(got, problems) {
				t.Fatalf("Problems=%q, CheckDetection problems=%q", got, problems)
			}
			if !reflect.DeepEqual(input, original) {
				t.Fatalf("validation mutated detection: got %#v, want %#v", input, original)
			}
		})
	}

	warningOnly := detection(t, "selection:\n  CommandLine: -dump\ncondition: selection\ntimeframe: 5m\n")
	problems, warnings := CheckDetection(warningOnly)
	if len(problems) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "CommandLine|contains") {
		t.Fatalf("valid timeframe with warning: problems=%q warnings=%q", problems, warnings)
	}
	if got := Problems("Timeframe warning", logSource, warningOnly); len(got) != 0 {
		t.Fatalf("warning became a problem: %q", got)
	}
}
