package pipeline

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// The profile may remove examples/format duplication, but cannot change the
// structured contract or discard fields accepted on representative fixtures.
func TestAdvisoryAssemblyUsesCompactProfileWithFullSchema(t *testing.T) {
	for _, fixture := range []string{goldenBriefJSON, mergeReviewYAML, ioUringBriefYAML} {
		for _, source := range []string{"nvd", "ghsa", "cisa-kev", "research"} {
			t.Run(source+fixture[:12], func(t *testing.T) {
				var system string
				client := referenceTestLLM{respond: func(_ context.Context, _, got string, schema *llm.Schema, out any) error {
					system = got
					if !reflect.DeepEqual(schema, briefResponseSchema) {
						t.Fatal("advisory reduced the required field contract")
					}
					return structuredFromText(fixture, out)
				}}
				item := scraper.RawItem{Source: source, SourceID: source + ":CVE-2026-9999", Title: "Vendor notice", Content: "Vendor notice with exact primary-source evidence."}
				brief, err := NewBriefAssembler(client).Assemble(context.Background(), item, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				if source == "research" {
					if system != briefSystemPrompt {
						t.Fatal("CVE-looking news source incorrectly selected advisory profile")
					}
				} else {
					if len(system)*100 > len(briefSystemPrompt)*80 {
						t.Fatalf("advisory did not remove redundant formatting/examples: %d >= 80%% of %d", len(system), len(briefSystemPrompt))
					}
					// Every substantive requirement paragraph after the examples remains
					// byte-for-byte, as do all syntax, source and quality requirements.
					for _, marker := range []string{"QUALITY REQUIREMENTS:", "LOG SOURCE SELECTION", "IOCs:", "TTPs:", "Detection handoff:", "Source assessment, QA, and action plan:", "Priority signals (priority_signals):", "Threat actor (threat_actor):", "Affected assets (affected_vendors / affected_products / affected_os):", "General:"} {
						start := strings.Index(briefSystemPrompt, marker)
						if start < 0 {
							t.Fatalf("missing baseline marker %s", marker)
						}
						if !strings.Contains(system, strings.SplitN(briefSystemPrompt[start:], "\n\n", 2)[0]) {
							t.Fatalf("compact profile lost substantive guidance %s", marker)
						}
					}
					if !strings.Contains(system, sigmaSyntax) || !strings.Contains(system, sigmaStructureGuidance) {
						t.Fatal("compact profile lost detection syntax guidance")
					}
					t.Logf("assembly system prompt bytes full=%d advisory=%d reduction=%.1f%%", len(briefSystemPrompt), len(system), 100*(1-float64(len(system))/float64(len(briefSystemPrompt))))
				}
				var actual map[string]any
				if err := yaml.Unmarshal([]byte(brief), &actual); err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"id", "slug", "title", "summary", "severity", "content"} {
					if actual[field] == nil || actual[field] == "" {
						t.Errorf("lost required field %s", field)
					}
				}
				var expected generatedBrief
				if err := structuredFromText(fixture, &expected); err != nil {
					t.Fatal(err)
				}
				if actual["summary"] != expected.Summary || actual["content"] != expected.Content || actual["severity"] != expected.Severity {
					t.Fatal("profile path altered substantive fixture fields")
				}
			})
		}
	}
}
