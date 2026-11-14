package publisher

import (
	"log/slog"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPublicationQualityCannotBeBypassedByStoredBriefRender(t *testing.T) {
	b := BundleBrief{ID: "brief-optimole", Slug: "2026-11-optimole", Title: "Optimole (CVE-2026-124969)", Summary: "Optimole permits file deletion with administrator interaction.", Content: "Optimole versions up to, and including, 4.2.19 allow file deletion when PEAR Archive_Tar is loadable and an administrator uses Rename.", Severity: "high", PublishedAt: "2026-11-14T06:23:40Z", AffectedVendors: []string{"Optimole"}, AffectedProducts: []string{"Optimole"}, References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-124969"}}
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
