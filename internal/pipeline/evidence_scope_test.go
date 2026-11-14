package pipeline

import (
	"gopkg.in/yaml.v3"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestSourceScopeDoesNotLeakAcrossProductsOrBranches(t *testing.T) {
	for name, tc := range map[string]struct{ products, source, forbidden string }{
		"single Docker product with Moby range": {"  - Docker Engine\n", "Docker Engine uses Moby. Moby before 25.0.6 is affected.", "25.0.6"},
		"dependency in same clause":             {"  - Docker Engine\n", "Docker Engine uses Moby before 25.0.6.", "25.0.6"},
		"product follows unrelated bound":       {"  - Docker Engine\n", "Moby before 25.0.6 is bundled in Docker Engine.", "25.0.6"},
		"product name substring":                {"  - Moby\n", "MobyExtension before 25.0.6 is affected.", "25.0.6"},
		"nearby Hitachi product":                {"  - Hitachi Ops Center\n  - Hitachi Device Manager\n", "Hitachi Ops Center is discussed. Hitachi Device Manager before 8.8.8 is affected.", "Ops Center (< 8.8.8)"},
		"ambiguous multiple branches":           {"  - Moby\n", "Moby before 25.0.6 and 26.0.2 is affected.", "Moby (<"},
	} {
		t.Run(name, func(t *testing.T) {
			got := injectAffectedRanges("affected_products:\n"+tc.products, scraper.RawItem{Source: "nvd", Content: tc.source})
			if strings.Contains(got, tc.forbidden) {
				t.Fatalf("unsupported scope injected: %s", got)
			}
		})
	}
}

func TestSourceScopeMapsExplicitSeparateProducts(t *testing.T) {
	got := injectAffectedRanges("affected_products:\n  - Docker Engine\n  - Moby\n", scraper.RawItem{Source: "nvd", Content: "Docker Engine before 24.0.9 is affected. Moby before 26.0.2 is affected."})
	if !strings.Contains(got, "Docker Engine (< 24.0.9)") || !strings.Contains(got, "Moby (< 26.0.2)") || strings.Contains(got, "24.0.9, < 26.0.2") {
		t.Fatal(got)
	}
}

func TestEnrichmentCannotTrustRepairedBriefAsSourceOfScope(t *testing.T) {
	raw := "title: Moby vulnerability\naffected_products:\n  - Moby\ncontent: Moby before 99.99.99 is affected.\n"
	got := enrichCVEScope(raw, nil, []*CVEMeta{{Exists: true, Description: "Moby has a vulnerability; affected versions have not been established."}})
	if strings.Contains(got, "Moby (< 99.99.99)") {
		t.Fatalf("brief text laundered into authoritative scope: %s", got)
	}
}

func TestSeverityRecordsDeterministicBasis(t *testing.T) {
	got := normalizeDetectionSeverity("severity: critical\n", scraper.RawItem{Source: "nvd", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-1234", Metadata: map[string]string{"cvss": "7.1"}})
	if !strings.Contains(got, "kind: source_cvss") || !strings.Contains(got, "severity_basis:") {
		t.Fatal(got)
	}
}

func TestOptimoleCommaScopeDoesNotInventFixedRelease(t *testing.T) {
	source := "The Optimole plugin for WordPress is vulnerable in all versions up to, and including, 4.2.19."
	got := injectAffectedRanges("affected_products: [Optimole]\n", scraper.RawItem{Source: "nvd", Content: source})
	if !strings.Contains(got, "Optimole (<= 4.2.19)") {
		t.Fatal(got)
	}
	if hint := extractPatchVersionHint(source); hint.FixedVersion != "" {
		t.Fatalf("guessed fix: %#v", hint)
	}
}

func TestRepairRejectedScopeCannotBeReinjected(t *testing.T) {
	original := map[string]any{"affected_products": []string{"Moby (< 25.0.6)"}}
	revised := revisedBrief{generatedBrief: generatedBrief{AffectedProducts: []string{"Moby"}}}
	merged, err := mergeGroundingRepair(original, revised)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := yaml.Marshal(merged)
	got := injectAffectedRanges(string(encoded), scraper.RawItem{Source: "nvd", Content: "Moby before 25.0.6 is affected."})
	if strings.Contains(got, "Moby (<") {
		t.Fatal(got)
	}
}
