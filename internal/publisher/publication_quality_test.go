package publisher

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"gopkg.in/yaml.v3"
)

func TestPublicationQualityCannotBeBypassedByStoredBriefRender(t *testing.T) {
	b := BundleBrief{ID: "brief-fixture", Slug: "2099-01-fixturemedia", Title: "FixtureMedia (CVE-2099-11111)", Summary: "A fictional helper requires an administrator response.", Content: "FixtureMedia versions up to 4.2.19 require administrator review. This fictional source names no mitigation.", Severity: "high", PublishedAt: "2099-01-01T00:00:00Z", AffectedVendors: []string{"FixtureMedia"}, AffectedProducts: []string{"FixtureMedia"}, References: []string{"https://example.com/fixture-advisory"}}
	for _, route := range []string{"publish", "backfill"} {
		t.Run(route, func(t *testing.T) {
			var err error
			if route == "publish" {
				raw, _ := yaml.Marshal(b)
				p := &Publisher{logger: slog.Default()}
				err = p.Publish(string(raw))
				if len(p.pending) != 0 {
					t.Fatal("bad brief buffered")
				}
			} else {
				_, _, _, publish, renderErr := RenderPublicBriefMarkdown(b, nil)
				err = renderErr
				if publish {
					t.Error("bad stored brief marked publishable")
				}
			}
			if err == nil || !strings.Contains(err.Error(), "recommendation") {
				t.Fatalf("quality gate error = %v", err)
			}
		})
	}
}

func TestPublicationChecksDetectionCoverageAfterInvalidRulesAreRemoved(t *testing.T) {
	b := BundleBrief{ID: "brief-server", Slug: "2026-11-server", Title: "Server abuse", Summary: "The source reports server abuse.", Content: "An observed attack targets a server application.", Severity: "high", PublishedAt: "2026-11-14T06:23:40Z", References: []string{"https://vendor.example/advisory"}, TTPs: []BundleTTP{{TacticID: "TA0001", TacticName: "Initial Access", TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application", Evidence: "Observed server abuse"}}, Rules: []BundleRule{{Title: "Invalid rule"}}}
	raw, _ := yaml.Marshal(b)
	p := &Publisher{logger: slog.Default()}
	err := p.Publish(string(raw))
	if err == nil || !strings.Contains(err.Error(), "rule or hunt lead") {
		t.Fatalf("rule removal bypassed coverage gate: %v", err)
	}
	if len(p.pending) != 0 {
		t.Fatal("brief buffered after losing sole detector")
	}
}

func TestPublicProductProjectionPreservesCompoundRanges(t *testing.T) {
	for _, scope := range []string{">= 1.0, < 4.2.20", "< 7.3.1, < 7.2.2"} {
		products := []string{"Widget (" + scope + ")"}
		got := productVersionProjection(products)
		if len(got) != 1 || got[0].Product != "Widget" || got[0].Range != scope {
			t.Fatalf("lost source scope: %+v", got)
		}
		if names := canonicalProductProjection(products); len(names) != 1 || names[0] != "Widget" {
			t.Fatalf("range leaked into product taxonomy: %v", names)
		}
	}
}

func TestPublicProductProjectionPreservesLongNameRangeSyntax(t *testing.T) {
	name := strings.Repeat("Long Product Name ", 12)
	for _, tc := range []struct{ suffix, want string }{
		{"(n/a through 4.2.19)", "n/a through 4.2.19"},
		{"through 4.2.19", "through 4.2.19"},
		{"before 1:2.3.4", "before 1:2.3.4"},
	} {
		got := productVersionProjection([]string{name + tc.suffix})
		if len(got) != 1 || got[0].Range != tc.want {
			t.Fatalf("lost %q scope: %+v", tc.suffix, got)
		}
	}
}

func TestPublicationQualityPreservesSharedResponseSemantics(t *testing.T) {
	raw, err := os.ReadFile("../eval/testdata/brief_quality/valid-notice.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, content, wantIssue string
	}{
		{"response first", "## Recommendation\nUpgrade affected Widget installations to version 1.0.12.\n\n## Overview\nA fictional widget requires an administrator response.", ""},
		{"use patched release", "## Overview\nA fictional widget requires an administrator response.\n\n## Recommendation\nUse the patched Widget release 1.0.12 or later.", ""},
		{"noun patch", "## Overview\nA fictional widget requires an administrator response.\n\n## Recommendation\nVerify current usage of Widget. No patch is currently available.", "recommendation"},
		{"noun update", "## Overview\nA fictional widget requires an administrator response.\n\n## Recommendation\nVerify current usage of Widget. Security update information is not provided by the source.", "recommendation"},
		{"numeric score", "## Overview\nA fictional widget requires an administrator response.\n\n## Impact\n8.8\n\n## Recommendation\nUpgrade Widget to version 1.0.12.", "impact"},
		{"attributed score", "## Overview\nA fictional widget requires an administrator response.\n\n## Impact\nAccording to NVD, the CVSS v3.1 base score is 8.8 (HIGH).\n\n## Recommendation\nUpgrade Widget to version 1.0.12.", "impact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			doc["content"] = tc.content
			data, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			internal := pipeline.ValidatePublicationConsistency(string(data))
			p := &Publisher{logger: slog.Default()}
			final := p.ValidatePublication(string(data))
			if tc.wantIssue == "" {
				if len(internal) != 0 || final != nil {
					t.Fatalf("valid brief rejected: internal=%v, final=%v", internal, final)
				}
			} else if !strings.Contains(strings.Join(internal, "; "), tc.wantIssue) || final == nil || !strings.Contains(final.Error(), tc.wantIssue) {
				t.Fatalf("expected %s on both routes: internal=%v, final=%v", tc.wantIssue, internal, final)
			}
		})
	}
}
