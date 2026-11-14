package pipeline

import (
	"fmt"
	"strings"

	feedcontract "github.com/craftedsignal/threat-bot/pkg/publicfeed"
)

// publicationQualityIssues is deliberately independent of the model's self
// assessment and grounding. A factual registry paragraph can still omit the
// information a defender needs. Run this on the final publication snapshot.
func publicationQualityIssues(brief map[string]any) []string {
	var issues []string
	content := publicationString(brief["content"])
	summary := publicationString(brief["summary"])
	visible := strings.Join([]string{publicationString(brief["title"]), summary, content}, "\n")
	plan, _ := asStringMap(brief["action_plan"])
	issues = append(issues, feedcontract.ContentQualityIssues(feedcontract.ContentQualityInput{
		Summary: summary, Content: content, HasCVE: len(publicationCVEs(brief["cves"], visible)) > 0, ActionPlan: plan,
	})...)
	for _, product := range yamlStringList(brief["affected_products"]) {
		if strings.Contains(product, "|") {
			issues = append(issues, fmt.Sprintf("product label requires a canonical name without a marketplace feature list: %q", product))
		}
	}
	if qa, ok := asStringMap(brief["qa_status"]); ok {
		verdict := strings.ToLower(publicationString(qa["verdict"]))
		if verdict == "do_not_publish" || verdict == "fail" || len(yamlAnyList(qa["unsupported_claims"])) > 0 || len(yamlAnyList(qa["format_gaps"])) > 0 {
			issues = append(issues, "QA assessment has unresolved publication blockers")
		}
	}
	return issues
}

func meaningfulPublicationText(value any) bool { return feedcontract.MeaningfulText(value) }
func hasPublicationTelemetry(value any) bool   { return feedcontract.HasTelemetry(value) }
