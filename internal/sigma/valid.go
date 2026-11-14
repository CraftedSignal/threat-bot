package sigma

import (
	"fmt"
	"strings"

	sigmaparser "github.com/craftedsignal/sigma-parser"
	"gopkg.in/yaml.v3"
)

// Problems returns why a Sigma rule is not valid Sigma, or nil when it is:
// a rule needs a title, a log source and a detection block sigma-parser
// accepts.
func Problems(title string, logSource LogSource, detection map[string]any) []string {
	var problems []string
	if strings.TrimSpace(title) == "" {
		problems = append(problems, "missing title")
	}
	if logSource == (LogSource{}) {
		problems = append(problems, "logsource needs a category, product or service")
	}
	detectionProblems, _ := CheckDetection(detection)
	return append(problems, detectionProblems...)
}

// CheckDetection returns why a Sigma detection block is not valid Sigma, and
// what it likely does not match as meant, such as CommandLine: -NoProfile,
// which only matches a command line that is exactly -NoProfile. Both are as
// sigma-parser reports them.
func CheckDetection(detection map[string]any) (problems, warnings []string) {
	if len(detection) == 0 {
		return []string{"missing detection block"}, nil
	}
	doc, err := yaml.Marshal(map[string]any{"detection": detection})
	if err != nil {
		return []string{fmt.Sprintf("detection cannot be encoded as YAML: %v", err)}, nil
	}
	result := sigmaparser.ExtractConditions(string(doc))
	return result.Errors, result.Warnings
}
