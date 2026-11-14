package pipeline

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const scopeBrief = `id: brief-1
title: Foo RCE
summary: Foo before 1.4.2 allows RCE.
severity: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1
  - https://vendor.example/advisory
cves:
  - id: CVE-2026-1
    cvss: 0
    epss: 0
    epss_percentile: 0
    kev_status: unknown
  - id: CVE-2026-2
    cvss: 9.8
    epss: 0
`

// The model's schema has no CVE score fields, so every cvss/epss/kev value is
// the pipeline's (a placeholder or enrichment) and is hidden whatever it is.
func TestGroundingViewStripsOnlyPipelineOwnedFields(t *testing.T) {
	view := groundingView(scopeBrief, "https://nvd.nist.gov/vuln/detail/CVE-2026-1")
	for _, gone := range []string{"nvd.nist.gov", "epss_percentile", "cvss", "epss", "kev_status"} {
		if strings.Contains(view, gone) {
			t.Errorf("view still contains %q:\n%s", gone, view)
		}
	}
	for _, kept := range []string{"severity: high", "vendor.example/advisory", "Foo before 1.4.2", "CVE-2026-2", "CVE-2026-1"} {
		if !strings.Contains(view, kept) {
			t.Errorf("view lost LLM-authored %q:\n%s", kept, view)
		}
	}
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(view), &parsed); err != nil {
		t.Fatalf("view is not valid YAML: %v", err)
	}
}

func TestGroundingViewLeavesUnparseableYAMLAlone(t *testing.T) {
	bad := "title: [unterminated"
	if got := groundingView(bad, "https://x.example"); got != bad {
		t.Errorf("got %q", got)
	}
}

func TestGroundingViewDropsEmptyReferencesKey(t *testing.T) {
	view := groundingView("title: t\nreferences:\n  - https://a.example/x\n", "https://a.example/x")
	if strings.Contains(view, "references") {
		t.Errorf("empty references should be dropped:\n%s", view)
	}
}
