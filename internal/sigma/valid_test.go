package sigma

import (
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
