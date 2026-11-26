package pipeline

import (
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// The grounding checker rejects any claim the source does not state. The
// writer prompts must not demand such claims: a summary naming an actor,
// technique and impact, ATT&CK mappings for undescribed behavior, an escalated
// severity or an inferred OS each failed the first check and was rarely
// repaired (ttps 35%, severity 3%, affected_os 0% of findings).
func TestWriterPromptsDoNotDemandUnsupportedInference(t *testing.T) {
	for _, source := range []string{"sploitus", "nvd", "sigma-hq"} {
		prompt := assemblySystemPrompt(scraper.RawItem{Source: source})
		for _, banned := range []string{
			"summarizing the threat, actor, technique, and impact",
			"Only include TTPs that match the observed attack behavior",
		} {
			if strings.Contains(prompt, banned) {
				t.Errorf("%s writer prompt still demands inference: %q", source, banned)
			}
		}
		for _, rule := range []string{
			"Include a technique only for attacker behavior the source itself describes",
			"never extend one CVE's prerequisites or impact to other CVEs or products",
			"When the source is a detection rule or analytic",
			"Never infer an OS from the product",
			"an exploit-tracker listing, public exploit code",
		} {
			if !strings.Contains(prompt, rule) {
				t.Errorf("%s writer prompt lacks rule %q", source, rule)
			}
		}
	}
	if strings.Contains(briefPrompt, "Extract all threat data") || !strings.Contains(briefPrompt, "Machine-extracted candidates") {
		t.Error("assembly user prompt must treat extracted tactics/techniques as candidates, not facts to copy")
	}
	for name, desc := range map[string]string{
		"summary":  briefResponseSchema.Properties["summary"].Description,
		"severity": briefResponseSchema.Properties["severity"].Description,
		"ttps":     briefResponseSchema.Properties["ttps"].Description,
	} {
		if desc == "" || strings.Contains(desc, "actor, technique and impact") {
			t.Errorf("schema %s description %q must not demand inference", name, desc)
		}
	}
}
