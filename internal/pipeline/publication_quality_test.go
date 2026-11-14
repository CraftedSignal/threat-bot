package pipeline

import (
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// This is the failure published on 2026-11-14: a registry description and a
// marketplace title passed grounding, despite providing no defender response.
const optimoleRegistryDescription = "The Optimole - Optimize Images | Convert WebP & AVIF | CDN & Lazy Load | Image Optimization plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the replace_urls_in_value function in all versions up to, and including, 4.2.19. Exploitation requires that the PEAR Archive_Tar library is present and loadable on the host and an administrator must perform an action using the plugin's Rename control."
const optimoleMarketplaceName = "Optimole – Optimize Images | Convert WebP & AVIF | CDN & Lazy Load | Image Optimization"

func TestPublicationRejectsRegistryDumpEvenWhenGrounded(t *testing.T) {
	doc := map[string]any{
		"title": "Optimole file deletion (CVE-2026-124969)", "summary": "Optimole permits file deletion with administrator interaction.",
		"content": optimoleRegistryDescription, "affected_products": []string{optimoleMarketplaceName},
		"cves": []string{"CVE-2026-124969"}, "qa_status": map[string]any{"verdict": "pass"},
	}
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	issues := strings.Join(ValidatePublicationConsistency(string(raw)), "; ")
	for _, want := range []string{"recommendation", "product"} {
		if !strings.Contains(issues, want) {
			t.Errorf("issues = %q, want %q", issues, want)
		}
	}
}

func TestPublicationRequiresSubstantiveContentAndResponse(t *testing.T) {
	for _, tc := range []struct{ name, content, want string }{
		{"empty body", "  ", "content"},
		{"summary copy", "A sourced vulnerability notice.", "repeats"},
		{"summary copy under heading", "## Overview\nA sourced vulnerability notice.", "repeats"},
		{"fenced body only", "```markdown\n## Recommendation\nInventory Widget.\n```", "content"},
		{"empty guidance", "## Overview\nWidget can delete files.\n\n## Recommendation\n", "recommendation"},
		{"punctuation guidance", "## Overview\nWidget can delete files.\n\n## Recommendation\n.", "recommendation"},
		{"formatted placeholder guidance", "## Overview\nWidget can delete files.\n\n## Recommendation\n**N/A**", "recommendation"},
		{"numbered placeholder guidance", "## Overview\nWidget can delete files.\n\n## Recommendation\n1. N/A", "recommendation"},
		{"invisible link guidance", "## Overview\nWidget can delete files.\n\n## Recommendation\n[advisory]: https://vendor.example/advisory", "recommendation"},
		{"code is not guidance", "## Overview\nWidget can delete files.\n\n```markdown\n## Recommendation\nInvestigate Widget.\n```", "recommendation"},
		{"short sourced notice", "## Overview\nWidget can delete files.\n\n## Recommendation\nInventory Widget installations and check the cited advisory for remediation; the source does not name a fixed version.", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := yaml.Marshal(map[string]any{"title": "Widget (CVE-2026-10001)", "summary": "A sourced vulnerability notice.", "content": tc.content, "affected_products": []string{"Widget"}})
			issues := strings.Join(ValidatePublicationConsistency(string(raw)), "; ")
			if tc.want == "" && issues != "" {
				t.Fatalf("short notice rejected: %s", issues)
			}
			if tc.want != "" && !strings.Contains(issues, tc.want) {
				t.Fatalf("issues = %q, want %q", issues, tc.want)
			}
		})
	}
}

func TestPublicationDoesNotCountEmptyHuntLeadsAsCoverage(t *testing.T) {
	raw := "title: Observed server abuse\ncontent: The source reports server abuse.\nttps:\n  - technique_id: T1190\naction_plan:\n  hunt_leads: [{}]\n"
	if issues := strings.Join(ValidatePublicationConsistency(raw), "; "); !strings.Contains(issues, "rule or hunt lead") {
		t.Fatalf("empty lead bypassed coverage check: %s", issues)
	}
}

func TestPublicationDoesNotCountInvalidRulesAsCoverage(t *testing.T) {
	raw := "title: Observed server abuse\ncontent: The source reports server abuse.\nttps:\n  - technique_id: T1190\nrules: [{}]\n"
	if issues := strings.Join(ValidatePublicationConsistency(raw), "; "); !strings.Contains(issues, "rule or hunt lead") {
		t.Fatalf("empty rule bypassed coverage check: %s", issues)
	}
}

func TestValidatorCanonicalizesMarketplaceProductWithoutLosingRange(t *testing.T) {
	raw := "id: brief-test\nslug: test\ntitle: Optimole advisory\nsummary: Confirmed issue.\nseverity: high\npublished_at: \"2026-11-14T06:23:40Z\"\naffected_products:\n  - '" + optimoleMarketplaceName + " (<= 4.2.19)'\n"
	cleaned, _, err := NewBriefValidator().Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(cleaned), &doc); err != nil {
		t.Fatal(err)
	}
	got := yamlStringList(doc["affected_products"])
	if len(got) != 1 || got[0] != "Optimole (<= 4.2.19)" {
		t.Fatalf("product = %q", got)
	}
}

func TestSourceInclusiveVersionRangeSurvivesWithoutNVDEnrichment(t *testing.T) {
	raw := "affected_products: [Optimole]\n"
	got := injectAffectedRanges(raw, scraper.RawItem{Source: "nvd", Content: optimoleRegistryDescription})
	if !strings.Contains(got, "Optimole (<= 4.2.19)") {
		t.Fatalf("source range missing: %s", got)
	}
	if strings.Contains(got, "4.2.20") {
		t.Fatal("invented a fixed version")
	}
}

func TestPublicationHonorsUnresolvedQABlockers(t *testing.T) {
	for _, qa := range []string{"verdict: do_not_publish", "verdict: pass\n  unsupported_claims: [Invented fixed release]", "verdict: pass\n  format_gaps: [Missing applicability]"} {
		raw := "title: Widget advisory\nsummary: Verified notice.\ncontent: The source describes a Widget security issue.\nqa_status:\n  " + qa + "\n"
		if issues := strings.Join(ValidatePublicationConsistency(raw), "; "); !strings.Contains(issues, "QA assessment") {
			t.Fatalf("QA veto bypassed: %s; issues %s", raw, issues)
		}
	}
}

func TestCleanProductListPreservesScopeOnLongNames(t *testing.T) {
	name := strings.Repeat("Long Product Name ", 12)
	got := CleanProductList([]string{name + "(>= 1.0, < 4.2.20)"})
	if len(got) != 1 || !strings.HasSuffix(got[0], "(>= 1.0, < 4.2.20)") {
		t.Fatalf("range lost: %q", got)
	}
	for _, name := range []string{"SQL Server - Reporting Services", "Visual Studio (Code)", "Widget (Model 42)", "Acme – Desktop Edition"} {
		got := CleanProductList([]string{name})
		if len(got) != 1 || got[0] != name {
			t.Fatalf("recognizable product name changed: %q -> %q", name, got)
		}
	}
}
