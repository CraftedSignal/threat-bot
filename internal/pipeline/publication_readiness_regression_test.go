package pipeline

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPublicationRejectsOperationallyEmptyAdvice(t *testing.T) {
	for _, tc := range []struct{ name, content, want string }{
		{"inventory only", "## Overview\nA fictional widget requires an administrator response.\n\n## Recommendation\nVerify current usage of FixtureWidget.", "recommendation"},
		{"score only", "## Overview\nA fictional widget requires an administrator response.\n\n## Impact\nCVSS 8.8.\n\n## Recommendation\nUpgrade FixtureWidget to the vendor's fixed release.", "impact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := yaml.Marshal(map[string]any{
				"title": "FixtureWidget advisory (CVE-2099-11111)", "summary": "A fictional security notice.",
				"content": tc.content, "cves": []string{"CVE-2099-11111"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if issues := strings.Join(ValidatePublicationConsistency(string(raw)), "; "); !strings.Contains(issues, tc.want) {
				t.Fatalf("operationally empty brief accepted: issues=%q, want %q", issues, tc.want)
			}
		})
	}
}
