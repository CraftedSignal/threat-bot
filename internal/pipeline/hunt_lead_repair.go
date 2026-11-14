package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

const huntLeadRepairSystem = `You are a threat hunting assistant. A threat brief names source-supported ATT&CK techniques but gives defenders no rule or hunt lead to look for them. Write hunt leads grounded only in the supplied source.

Respond with JSON only: {"hunt_leads": [{"lead": "...", "technique_id": "T1234", "data_needed": ["..."], "priority": "high|medium|low", "confidence": "high|medium|low", "disposition": "hunt_now|defer|close_gap_first|convert_to_detection", "evidence": "..."}]}

Name the product-native telemetry in data_needed, describe the behavioral search or grouping in lead, and quote or closely tie evidence to the source. Cover every listed technique. Do not invent event IDs, field names, or thresholds the source does not provide.`

type huntLeadSuggestion struct {
	Lead        string   `json:"lead"`
	TechniqueID string   `json:"technique_id"`
	DataNeeded  []string `json:"data_needed"`
	Priority    string   `json:"priority"`
	Confidence  string   `json:"confidence"`
	Disposition string   `json:"disposition"`
	Evidence    string   `json:"evidence"`
}

type huntLeadRepairResult struct {
	HuntLeads []huntLeadSuggestion `json:"hunt_leads"`
}

// repairMissingHuntLead makes one attempt to give a brief that names TTPs but
// has no rule or hunt lead a hunt lead covering them. It reports whether the
// brief was changed. Any failure leaves the brief as it was, so the caller
// holds it for review as before; there is no second attempt.
func (p *Pipeline) repairMissingHuntLead(ctx context.Context, item scraper.RawItem, briefYAML string) (string, bool) {
	var brief map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &brief); err != nil || !lacksDetectionCoverage(brief) {
		return briefYAML, false
	}

	techniques := map[string]bool{}
	var listed []string
	for _, entry := range briefTTPs(brief) {
		ttp, ok := asStringMap(entry)
		if !ok {
			continue
		}
		id := strings.ToUpper(publicationString(ttp["technique_id"]))
		if id == "" || techniques[id] {
			continue
		}
		techniques[id] = true
		listed = append(listed, fmt.Sprintf("- %s: %s (evidence: %s)", id, publicationString(ttp["technique_name"]), publicationString(ttp["evidence"])))
	}

	source := item.Title + "\n\n" + item.Content
	if len(source) > maxSourceLen {
		source = truncateUTF8(source, maxSourceLen)
	}
	prompt := fmt.Sprintf("## Source\n%s\n\n## Brief title\n%s\n\n## Techniques needing a hunt lead\n%s\n\nWrite hunt leads covering these techniques.", source, publicationString(brief["title"]), strings.Join(listed, "\n"))

	var result huntLeadRepairResult
	if err := p.llmClient.GenerateJSON(ctx, prompt, huntLeadRepairSystem, &result); err != nil {
		p.logger.Info("hunt lead repair unavailable; holding brief for review", "source_id", item.SourceID, "error", err)
		return briefYAML, false
	}

	var leads []any
	for _, s := range result.HuntLeads {
		if strings.TrimSpace(s.Lead) == "" || !techniques[strings.ToUpper(strings.TrimSpace(s.TechniqueID))] {
			continue
		}
		lead := map[string]any{"lead": strings.TrimSpace(s.Lead), "technique_id": strings.ToUpper(strings.TrimSpace(s.TechniqueID))}
		for key, value := range map[string]string{"priority": s.Priority, "confidence": s.Confidence, "disposition": s.Disposition, "evidence": s.Evidence} {
			if strings.TrimSpace(value) != "" {
				lead[key] = strings.TrimSpace(value)
			}
		}
		if len(s.DataNeeded) > 0 {
			lead["data_needed"] = s.DataNeeded
		}
		leads = append(leads, lead)
	}
	if len(leads) == 0 {
		p.logger.Info("hunt lead repair produced no lead covering the TTPs; holding brief for review", "source_id", item.SourceID)
		return briefYAML, false
	}

	plan, _ := asStringMap(brief["action_plan"])
	if plan == nil {
		plan = map[string]any{}
	}
	plan["hunt_leads"] = leads
	brief["action_plan"] = plan
	encoded, err := yaml.Marshal(brief)
	if err != nil {
		return briefYAML, false
	}
	validated, _, err := p.validator.Validate(string(encoded))
	if err != nil || lacksDetectionCoverageYAML(validated) {
		p.logger.Info("hunt lead repair did not validate; holding brief for review", "source_id", item.SourceID)
		return briefYAML, false
	}
	return validated, true
}

func lacksDetectionCoverageYAML(briefYAML string) bool {
	var brief map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &brief); err != nil {
		return true
	}
	return lacksDetectionCoverage(brief)
}

// repairMissingHuntLeadGrounded is repairMissingHuntLead plus a grounding check
// of the repaired brief against the same source. The lead, evidence and
// data_needed text is model-written, so it must not clear the review hold
// unless it is grounded. When the check fails or errors, the brief is returned
// exactly as it was and is held for review.
func (p *Pipeline) repairMissingHuntLeadGrounded(ctx context.Context, item scraper.RawItem, briefYAML string) (string, bool) {
	repaired, ok := p.repairMissingHuntLead(ctx, item, briefYAML)
	if !ok {
		return briefYAML, false
	}
	result, err := p.grounding.Check(ctx, item.Title, groundingSource(item), huntLeadGroundingView(repaired, item.URL))
	if err != nil || !result.Grounded {
		var issues []string
		if result != nil {
			issues = result.Issues
		}
		p.logger.Info("hunt lead repair not grounded; holding brief for review", "source_id", item.SourceID, "error", err, "issues", issues)
		return briefYAML, false
	}
	return repaired, true
}

// huntLeadGroundingView is the grounding view of only what the repair added:
// the brief title and its action_plan.hunt_leads. The rest of the enriched
// brief carries fields the pipeline added deterministically (CVE data,
// references, severity), which are not in the source text and would fail a
// whole-brief check even though the repair did not write them.
func huntLeadGroundingView(repairedYAML, itemURL string) string {
	var brief map[string]any
	if err := yaml.Unmarshal([]byte(repairedYAML), &brief); err != nil || brief == nil {
		return groundingView(repairedYAML, itemURL)
	}
	plan, _ := asStringMap(brief["action_plan"])
	minimal := map[string]any{
		"title":       brief["title"],
		"action_plan": map[string]any{"hunt_leads": plan["hunt_leads"]},
	}
	out, err := yaml.Marshal(minimal)
	if err != nil {
		return groundingView(repairedYAML, itemURL)
	}
	return string(out)
}
