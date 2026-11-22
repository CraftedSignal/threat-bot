package pipeline

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// Affected entries of published CVE records the production grounding checker
// cited when it rejected briefs that lacked their ranges.
const (
	recordCmdGo      = `{"vendor":"Go toolchain","product":"cmd/go","packageName":"cmd/go","defaultStatus":"unaffected","versions":[{"version":"0","lessThan":"1.26.11","status":"affected","versionType":"semver"},{"version":"1.27.0-0","lessThan":"1.27.4","status":"affected","versionType":"semver"}]}`
	recordPrestaShop = `{"vendor":"PrestaShop","product":"PrestaShop","defaultStatus":"unaffected","versions":[{"version":"0","lessThan":"8.2.9","status":"affected","versionType":"semver"},{"version":"9.0.0","lessThan":"9.2.1","status":"affected","versionType":"semver"}]}`
	recordOfficeOS   = `{"vendor":"Microsoft","product":"Office Online Server","versions":[{"version":"16.0.0.0","lessThan":"16.0.10417.20236","versionType":"custom","status":"affected"}]}`
	recordM365URL    = `{"vendor":"Microsoft","product":"Microsoft 365 Apps for Enterprise","platforms":["32-bit Systems","x64-based Systems"],"versions":[{"version":"16.0.1","lessThan":"https://aka.ms/OfficeSecurityReleases","versionType":"custom","status":"affected"}]}`
	recordLoadMaster = `{"vendor":"Progress Software","product":"LoadMaster","defaultStatus":"affected","platforms":["Linux"],"versions":[{"lessThan":"7.2.48.10","status":"affected","version":"7.2.48.1","versionType":"semver"},{"lessThan":"7.2.54.8","status":"affected","version":"7.2.54.0","versionType":"semver"}]}`
	recordZammad     = `{"vendor":"Zammad GmbH","product":"Zammad","defaultStatus":"unaffected","platforms":["Linux","Docker"],"versions":[{"lessThan":"6.3.0","status":"unknown","version":"*","versionType":"semver"},{"lessThan":"6.5.4","status":"affected","version":"6.3.0","versionType":"semver"},{"lessThan":"7.1.3","status":"unknown","version":"7.0.0","versionType":"semver"}]}`
	recordELEX       = `{"vendor":"Elextensions","product":"ELEX WordPress HelpDesk","packageName":"elex-helpdesk-customer-support-ticket-system","defaultStatus":"unaffected","versions":[{"version":"0","versionType":"custom","status":"affected","lessThanOrEqual":"3.3.9","changes":[{"at":"3.4.0","status":"unaffected"}]}]}`
	recordNGINX      = `{"vendor":"F5","product":"NGINX Open Source","defaultStatus":"unknown","versions":[{"lessThan":"1.31.9","status":"affected","version":"1.31.0","versionType":"semver"},{"lessThan":"1.30.7","status":"affected","version":"1.30.0","versionType":"semver"},{"lessThan":"*","status":"affected","version":"1.19.7","versionType":"custom"}]}`
	recordFAZ        = `{"vendor":"Fortinet","product":"FortiAnalyzer","defaultStatus":"unaffected","versions":[{"versionType":"semver","version":"8.0.0","lessThanOrEqual":"8.0.1","status":"affected"},{"versionType":"semver","version":"7.6.0","lessThanOrEqual":"7.6.7","status":"affected"}]}`
	recordFAZCloud   = `{"vendor":"Fortinet","product":"FortiAnalyzer Cloud","defaultStatus":"unaffected","versions":[{"version":"8.0.1","status":"affected"},{"versionType":"semver","version":"7.6.0","lessThanOrEqual":"7.6.7","status":"affected"}]}`
)

func affectedFact(id, product, text string) cnaSourceFact {
	return cnaSourceFact{CVEID: id, Product: product, Kind: "affected", Text: text}
}

func renderedProducts(t *testing.T, briefYAML string) []string {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		t.Fatal(err)
	}
	return yamlStringList(doc["affected_products"])
}

func TestPrimaryRecordRangesRenderEveryStatedRange(t *testing.T) {
	for name, tc := range map[string]struct {
		product, record string
		want            []string
	}{
		"two release lines":    {"cmd/go", recordCmdGo, []string{"cmd/go (< 1.26.11)", "cmd/go (>= 1.27.0-0, < 1.27.4)"}},
		"branch per line":      {"PrestaShop", recordPrestaShop, []string{"PrestaShop (< 8.2.9)", "PrestaShop (>= 9.0.0, < 9.2.1)"}},
		"single bounded range": {"Office Online Server", recordOfficeOS, []string{"Office Online Server (>= 16.0.0.0, < 16.0.10417.20236)"}},
		"inclusive bounds":     {"FortiAnalyzer", recordFAZ, []string{"FortiAnalyzer (>= 8.0.0, <= 8.0.1)", "FortiAnalyzer (>= 7.6.0, <= 7.6.7)"}},
		// CVE-2026-123633 as F5 published it on 2026-11-18.
		"unbounded upper limit": {"NGINX Open Source", recordNGINX, []string{"NGINX Open Source (>= 1.31.0, < 1.31.9)", "NGINX Open Source (>= 1.30.0, < 1.30.7)", "NGINX Open Source (>= 1.19.7)"}},
	} {
		t.Run(name, func(t *testing.T) {
			brief := "affected_products:\n  - " + tc.product + "\n"
			facts := primaryRecordFacts{Included: []cnaSourceFact{affectedFact("CVE-2026-0001", tc.product, tc.record)}}
			once := injectAffectedRanges(brief, scraper.RawItem{Source: "nvd"}, facts)
			got := renderedProducts(t, once)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("affected_products = %q, want %q", got, tc.want)
			}
			for _, entry := range got {
				name, scope := SplitProductVersionScope(entry)
				if name != tc.product || scope == "" {
					t.Errorf("%q projects to product %q with scope %q", entry, name, scope)
				}
			}
			if twice := injectAffectedRanges(once, scraper.RawItem{Source: "nvd"}, facts); twice != once {
				t.Errorf("rendering is not idempotent:\n%s\n---\n%s", once, twice)
			}
		})
	}
}

func TestPrimaryCNAProductRangesTakePrecedenceOverNVDProjection(t *testing.T) {
	plus := `{"vendor":"F5","product":"NGINX Plus","defaultStatus":"unknown","versions":[{"lessThan":"37.3.0.1","status":"affected","version":"37.1.0","versionType":"custom"},{"lessThan":"37.0.8.1","status":"affected","version":"37.0.0","versionType":"custom"},{"lessThan":"*","status":"affected","version":"R33","versionType":"custom"}]}`
	openSource := `{"vendor":"F5","product":"NGINX Open Source","defaultStatus":"unknown","versions":[{"lessThan":"1.31.9","status":"affected","version":"1.31.0","versionType":"semver"},{"lessThan":"1.30.7","status":"affected","version":"1.30.0","versionType":"semver"},{"lessThan":"*","status":"affected","version":"0.5.33","versionType":"custom"}]}`
	brief := "affected_products:\n  - NGINX Plus\n  - NGINX Open Source\n"
	item := scraper.RawItem{Source: "nvd", Metadata: map[string]string{"affected_ranges": "f5 nginx open source: >= 0.5.33, < 1.30.7; >= 1.31.0, < 1.31.9\nf5 nginx plus: >= 37.0.0, < 37.0.8; >= 37.1.0, < 37.3.0"}}
	facts := primaryRecordFacts{Included: []cnaSourceFact{
		affectedFact("CVE-2026-113425", "NGINX Plus", plus),
		affectedFact("CVE-2026-113425", "NGINX Open Source", openSource),
	}}
	got := renderedProducts(t, injectAffectedRanges(brief, item, facts))
	want := []string{
		"NGINX Plus (>= 37.1.0, < 37.3.0.1)",
		"NGINX Plus (>= 37.0.0, < 37.0.8.1)",
		"NGINX Plus (>= R33)",
		"NGINX Open Source (>= 1.31.0, < 1.31.9)",
		"NGINX Open Source (>= 1.30.0, < 1.30.7)",
		"NGINX Open Source (>= 0.5.33)",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("affected_products = %q, want primary CNA scopes %q", got, want)
	}
}

func TestPrimaryRecordRangesLeaveInterpretationToReview(t *testing.T) {
	for name, tc := range map[string]struct{ product, record string }{
		"URL instead of a version bound":   {"Microsoft 365 Apps for Enterprise", recordM365URL},
		"affected by default":              {"LoadMaster", recordLoadMaster},
		"unknown status entries":           {"Zammad", recordZammad},
		"status changes inside a range":    {"ELEX WordPress HelpDesk", recordELEX},
		"commit range":                     {"Linux", `{"vendor":"Linux","product":"Linux","defaultStatus":"unaffected","versions":[{"version":"1da177e4c3f4","lessThan":"5e9d1f3a0b2c","status":"affected","versionType":"git"}]}`},
		"wildcard bound":                   {"Widget", `{"product":"Widget","versions":[{"version":"2.0","lessThan":"2.*","status":"affected"}]}`},
		"unaffected carve-out":             {"Widget", `{"product":"Widget","versions":[{"version":"0","lessThan":"3.0","status":"affected"},{"version":"2.5","status":"unaffected"}]}`},
		"open start without a bound":       {"Widget", `{"product":"Widget","versions":[{"version":"0","status":"affected"}]}`},
		"every version":                    {"Widget", `{"product":"Widget","versions":[{"version":"0","lessThan":"*","status":"affected"}]}`},
		"both upper bounds":                {"Widget", `{"product":"Widget","versions":[{"version":"1.0","lessThan":"2.0","lessThanOrEqual":"2.0","status":"affected"}]}`},
		"no versions":                      {"Widget", `{"product":"Widget","defaultStatus":"unaffected"}`},
		"record text that is not an entry": {"Widget", `not json`},
	} {
		t.Run(name, func(t *testing.T) {
			brief := "affected_products:\n  - " + tc.product + "\n"
			facts := primaryRecordFacts{Included: []cnaSourceFact{affectedFact("CVE-2026-0001", tc.product, tc.record)}}
			if got := renderedProducts(t, injectAffectedRanges(brief, scraper.RawItem{Source: "nvd"}, facts)); !slices.Equal(got, []string{tc.product}) {
				t.Fatalf("uninterpretable record rendered scope: %q", got)
			}
		})
	}
}

func TestPrimaryRecordRangesRequireExactProductIdentity(t *testing.T) {
	facts := primaryRecordFacts{Included: []cnaSourceFact{
		affectedFact("CVE-2026-126171", "FortiAnalyzer", recordFAZ),
		affectedFact("CVE-2026-126171", "FortiAnalyzer Cloud", recordFAZCloud),
	}}
	got := renderedProducts(t, injectAffectedRanges("affected_products:\n  - FortiAnalyzer Cloud\n  - FortiAnalyzer\n", scraper.RawItem{Source: "nvd"}, facts))
	want := []string{"FortiAnalyzer Cloud (= 8.0.1)", "FortiAnalyzer Cloud (>= 7.6.0, <= 7.6.7)", "FortiAnalyzer (>= 8.0.0, <= 8.0.1)", "FortiAnalyzer (>= 7.6.0, <= 7.6.7)"}
	if !slices.Equal(got, want) {
		t.Fatalf("affected_products = %q, want %q", got, want)
	}

	only := primaryRecordFacts{Included: []cnaSourceFact{affectedFact("CVE-2026-126171", "FortiAnalyzer Cloud", recordFAZCloud)}}
	if got := renderedProducts(t, injectAffectedRanges("affected_products:\n  - FortiAnalyzer\n", scraper.RawItem{Source: "nvd"}, only)); !slices.Equal(got, []string{"FortiAnalyzer"}) {
		t.Fatalf("a neighboring product's record scoped the brief product: %q", got)
	}

	qualified := primaryRecordFacts{Included: []cnaSourceFact{affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop)}}
	if got := renderedProducts(t, injectAffectedRanges("affected_products:\n  - PrestaShop PrestaShop\n", scraper.RawItem{Source: "nvd"}, qualified)); len(got) != 2 {
		t.Fatalf("vendor-qualified product name was not matched: %q", got)
	}
}

func TestPrimaryRecordRangesWithholdIncompleteOrConflictingRecords(t *testing.T) {
	brief := "affected_products:\n  - PrestaShop\n"
	other := `{"vendor":"PrestaShop","product":"PrestaShop","versions":[{"version":"0","lessThan":"8.2.8","status":"affected"}]}`
	for name, facts := range map[string]primaryRecordFacts{
		"records disagree": {Included: []cnaSourceFact{
			affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop),
			affectedFact("CVE-2026-129958", "PrestaShop", other),
		}},
		"an entry missed the evidence": {
			Included:   []cnaSourceFact{affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop)},
			Incomplete: []cnaSourceFact{affectedFact("CVE-2026-129958", "PrestaShop", other)},
		},
		"a record lost affected entries": {
			Included:  []cnaSourceFact{affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop)},
			Truncated: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := renderedProducts(t, injectAffectedRanges(brief, scraper.RawItem{Source: "nvd"}, facts)); !slices.Equal(got, []string{"PrestaShop"}) {
				t.Fatalf("partial or conflicting scope rendered: %q", got)
			}
		})
	}

	agree := primaryRecordFacts{Included: []cnaSourceFact{
		affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop),
		affectedFact("CVE-2026-129958", "PrestaShop", recordPrestaShop),
	}}
	if got := renderedProducts(t, injectAffectedRanges(brief, scraper.RawItem{Source: "nvd"}, agree)); len(got) != 2 {
		t.Fatalf("agreeing records were not rendered: %q", got)
	}
}

func TestPrimaryRecordRangesTakePrecedenceOverNVDProjectionAndProse(t *testing.T) {
	brief := "affected_products:\n  - PrestaShop\n"
	facts := primaryRecordFacts{Included: []cnaSourceFact{affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop)}}

	prose := scraper.RawItem{Source: "nvd", Content: "PrestaShop before 8.2.9 and 9.0.0 before 9.2.1 contains a path traversal vulnerability."}
	if got := renderedProducts(t, injectAffectedRanges(brief, prose, facts)); !slices.Equal(got, []string{"PrestaShop (< 8.2.9)", "PrestaShop (>= 9.0.0, < 9.2.1)"}) {
		t.Fatalf("record ranges did not map the release branches: %q", got)
	}

	agreeing := scraper.RawItem{Source: "nvd", Metadata: map[string]string{"affected_ranges": "prestashop prestashop: < 8.2.9; >= 9.0.0, < 9.2.1"}}
	if got := renderedProducts(t, injectAffectedRanges(brief, agreeing, facts)); len(got) != 2 {
		t.Fatalf("agreeing NVD and record ranges were not rendered: %q", got)
	}

	disagreeing := scraper.RawItem{Source: "nvd", Metadata: map[string]string{"affected_ranges": "prestashop prestashop: < 8.2.9"}}
	if got := renderedProducts(t, injectAffectedRanges(brief, disagreeing, facts)); !slices.Equal(got, []string{"PrestaShop (< 8.2.9)", "PrestaShop (>= 9.0.0, < 9.2.1)"}) {
		t.Fatalf("primary record did not take precedence over NVD's incomplete projection: %q", got)
	}
}

func TestNVDMetadataRendersEveryConfigurationRange(t *testing.T) {
	item := scraper.RawItem{Source: "nvd", Metadata: map[string]string{
		"affected_ranges": "linux linux kernel: >= 5.13, < 6.1.191; >= 6.2, < 6.6.160; >= 6.7, < 6.12",
	}}
	got := renderedProducts(t, injectAffectedRanges("affected_products:\n  - Linux Kernel\n", item, primaryRecordFacts{}))
	want := []string{"Linux Kernel (>= 5.13, < 6.1.191)", "Linux Kernel (>= 6.2, < 6.6.160)", "Linux Kernel (>= 6.7, < 6.12)"}
	if !slices.Equal(got, want) {
		t.Fatalf("affected_products = %q, want %q", got, want)
	}
}

func TestRenderedRangesRespectBriefScopeAndRepairRejection(t *testing.T) {
	facts := primaryRecordFacts{Included: []cnaSourceFact{affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop)}}

	scoped := "affected_products:\n  - PrestaShop (< 8.2.9)\n  - PrestaShop\n"
	if got := renderedProducts(t, injectAffectedRanges(scoped, scraper.RawItem{Source: "nvd"}, facts)); !slices.Equal(got, []string{"PrestaShop (< 8.2.9)", "PrestaShop"}) {
		t.Fatalf("brief-authored scope was rewritten: %q", got)
	}

	original := map[string]any{"affected_products": []string{"PrestaShop (< 8.2.9)", "PrestaShop (>= 9.0.0, < 9.2.1)"}}
	merged, err := mergeGroundingRepair(original, revisedBrief{generatedBrief: generatedBrief{AffectedProducts: []string{"PrestaShop"}}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := yaml.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	if got := renderedProducts(t, injectAffectedRanges(string(encoded), scraper.RawItem{Source: "nvd"}, facts)); !slices.Equal(got, []string{"PrestaShop"}) {
		t.Fatalf("scope removed by a grounding repair was reinjected: %q", got)
	}
}

func TestRangeEntriesOfOneProductRemainANarrowProductBrief(t *testing.T) {
	if !publicationNarrowProduct("PrestaShop path traversal (CVE-2026-129957)", []string{"PrestaShop (< 8.2.9)", "PrestaShop (>= 9.0.0, < 9.2.1)"}) {
		t.Fatal("range entries of one product counted as several products")
	}
	if publicationNarrowProduct("Fortinet advisory", []string{"FortiAnalyzer (= 8.0.1)", "FortiAnalyzer Cloud (= 8.0.1)"}) {
		t.Fatal("different products counted as one")
	}
}

func TestPrimaryFactsReportWhatReachedTheChecker(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2026-129957"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CachedAt: time.Now(), CNAChecked: true,
		CNAFacts: []cnaSourceFact{
			affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop),
			affectedFact("CVE-2026-129957", "Widget", `{"product":"Widget","versions":[{"version":"0","lessThan":"`+strings.Repeat("9", maxCNAEvidenceBytes)+`","status":"affected"}]}`),
			affectedFact("CVE-2026-129957", "Gadget", `{"product":"Gadget","notes":"see CVE-2026-11111"}`),
		}}
	p := &Pipeline{cveVerifier: v}
	evidence, facts := p.verifiedPrimaryFacts([]string{"CVE-2026-129957"})
	if len(facts.Included) != 1 || facts.Included[0].Product != "PrestaShop" || !strings.Contains(evidence, "8.2.9") {
		t.Fatalf("included facts = %+v", facts.Included)
	}
	if len(facts.Incomplete) != 2 || facts.Truncated {
		t.Fatalf("oversized and cross-record facts must be incomplete: %+v", facts)
	}

	v.cache["CVE-2026-129957"].CNAAffectedIncomplete = true
	if _, facts := p.verifiedPrimaryFacts([]string{"CVE-2026-129957"}); !facts.Truncated {
		t.Fatal("a record that lost affected entries was not reported")
	}
}

func TestVerifiedPrimaryEvidenceExplainsUnrenderableLinuxScope(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2026-99462"] = &CVEMeta{
		Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"},
		CachedAt: time.Now(), CNAChecked: true,
		CNAFacts: []cnaSourceFact{
			affectedFact("CVE-2026-99462", "Linux", `{"vendor":"Linux","product":"Linux","defaultStatus":"unaffected","versions":[{"version":"7460b470a131f985a70302a322617121efdd7caa","lessThan":"0fab93d241cfb6f3aae29530a9a214157bb64087","status":"affected","versionType":"git"}]}`),
			affectedFact("CVE-2026-99462", "Linux", `{"vendor":"Linux","product":"Linux","defaultStatus":"affected","versions":[{"version":"6.15","status":"affected"},{"version":"7.4-rc1","lessThanOrEqual":"*","status":"unaffected","versionType":"original_commit_for_fix"}]}`),
		},
	}
	p := &Pipeline{cveVerifier: v}
	evidence := p.verifiedPrimaryEvidence([]string{"CVE-2026-99462"})
	for _, want := range []string{"Applicability range limitation", "Apply each line only to a brief product that matches the product named on that line", "never transfer it to another product", "CVE-2026-99462", "Linux", "commit", "original_commit_for_fix", "cannot be mapped safely to release-version ranges"} {
		if !strings.Contains(evidence, want) {
			t.Errorf("verified evidence missing %q:\n%s", want, evidence)
		}
	}
	if strings.Contains(evidence, "7.4-rc1 is fixed") {
		t.Fatalf("evidence promoted an original_commit_for_fix marker to a released fix:\n%s", evidence)
	}
}

func TestVerifiedPrimaryEvidenceDoesNotFlagLiteralRangesAsUnresolved(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2026-0001"] = &CVEMeta{
		Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"},
		CachedAt: time.Now(), CNAChecked: true,
		CNAFacts: []cnaSourceFact{affectedFact("CVE-2026-0001", "PrestaShop", recordPrestaShop)},
	}
	p := &Pipeline{cveVerifier: v}
	evidence := p.verifiedPrimaryEvidence([]string{"CVE-2026-0001"})
	if strings.Contains(evidence, "Applicability range limitation") {
		t.Fatalf("literal, renderable ranges were marked unresolved:\n%s", evidence)
	}
}

func TestUnrenderablePrimaryScopeIsPublishedAsAnExplicitGap(t *testing.T) {
	facts := primaryRecordFacts{Included: []cnaSourceFact{
		affectedFact("CVE-2026-99462", "Linux", `{"vendor":"Linux","product":"Linux","defaultStatus":"affected","versions":[{"version":"7.4-rc1","lessThanOrEqual":"*","status":"unaffected","versionType":"original_commit_for_fix"}]}`),
	}}
	raw := injectAffectedRanges("affected_products:\n  - Linux Kernel\n", scraper.RawItem{Source: "nvd"}, facts)
	if strings.Contains(raw, "Linux Kernel (>=") || strings.Contains(raw, "7.4-rc1 is fixed") {
		t.Fatalf("unrenderable CNA marker became a release range or fix:\n%s", raw)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	assessment, ok := doc["source_assessment"].(map[string]any)
	if !ok {
		t.Fatalf("source_assessment gap was not added: %#v", doc["source_assessment"])
	}
	gaps := yamlStringList(assessment["gaps"])
	if len(gaps) != 1 || !strings.Contains(gaps[0], "CVE-2026-99462 / Linux") || !strings.Contains(gaps[0], "cannot be mapped safely") {
		t.Fatalf("source_assessment.gaps = %#v", gaps)
	}
	if twice := injectAffectedRanges(raw, scraper.RawItem{Source: "nvd"}, facts); twice != raw {
		t.Fatalf("adding primary scope gap is not idempotent:\n%s\n---\n%s", raw, twice)
	}
}

func TestUnrenderableUnrelatedCNAProductDoesNotAddAScopeGap(t *testing.T) {
	facts := primaryRecordFacts{Included: []cnaSourceFact{
		affectedFact("CVE-2026-99462", "Linux", `{"vendor":"Linux","product":"Linux","defaultStatus":"affected","versions":[{"version":"7.4-rc1","lessThanOrEqual":"*","status":"unaffected","versionType":"original_commit_for_fix"}]}`),
	}}
	raw := injectAffectedRanges("affected_products:\n  - Widget\n", scraper.RawItem{Source: "nvd"}, facts)
	if strings.Contains(raw, "Applicability range limitation") || strings.Contains(raw, "cannot be mapped safely") {
		t.Fatalf("unrelated product scope leaked into the brief:\n%s", raw)
	}
}

func TestUnrenderablePrimaryScopeGapCombinesAllRangeLimitations(t *testing.T) {
	primary := primaryRecordFacts{Included: []cnaSourceFact{
		affectedFact("CVE-2026-99462", "Linux", `{"vendor":"Linux","product":"Linux","defaultStatus":"unaffected","versions":[{"version":"7460b470a131f985a70302a322617121efdd7caa","lessThan":"0fab93d241cfb6f3aae29530a9a214157bb64087","status":"affected","versionType":"git"}]}`),
		affectedFact("CVE-2026-99462", "Linux", `{"vendor":"Linux","product":"Linux","defaultStatus":"affected","versions":[{"version":"7.4-rc1","lessThanOrEqual":"*","status":"unaffected","versionType":"original_commit_for_fix"}]}`),
	}}
	gaps := unresolvedPrimaryScopeGaps(primary, []string{"Linux Kernel"})
	if len(gaps) != 1 || !strings.Contains(gaps[0], "Git commit bounds") || !strings.Contains(gaps[0], "original_commit_for_fix markers") {
		t.Fatalf("scope gap lost one of the primary record limitations: %v", gaps)
	}
}

func TestCVERecordReportsTruncatedAffectedEntries(t *testing.T) {
	var record cnaSourceRecord
	if err := json.Unmarshal([]byte(`{"affected":[{"product":"A","versions":[{"version":"0","lessThan":"1.0","status":"affected"}]},{"product":"B","versions":[{"version":"0","lessThan":"`+strings.Repeat("1", maxCNAEvidenceBytes)+`","status":"affected"}]}]}`), &record); err != nil {
		t.Fatal(err)
	}
	facts, _ := record.sourceFacts("CVE-2026-0002")
	if !record.affectedFactsIncomplete("CVE-2026-0002", facts) {
		t.Fatal("dropped affected entry not detected")
	}
	var complete cnaSourceRecord
	if err := json.Unmarshal([]byte(`{"affected":[{"product":"A","versions":[{"version":"0","lessThan":"1.0","status":"affected"}]}]}`), &complete); err != nil {
		t.Fatal(err)
	}
	facts, _ = complete.sourceFacts("CVE-2026-0002")
	if complete.affectedFactsIncomplete("CVE-2026-0002", facts) {
		t.Fatal("complete record reported as truncated")
	}
}

// rangeCheckLLM records the brief section of the first grounding check.
type rangeCheckLLM struct {
	noopLLM
	firstCheck string
}

func (r *rangeCheckLLM) GenerateStructured(_ context.Context, prompt, system string, _ *llm.Schema, out any) error {
	if _, ok := out.(*groundingReport); ok && system == groundingSystem && r.firstCheck == "" {
		r.firstCheck = prompt
	}
	return nil
}

func TestGroundingCheckSeesRecordRangesBeforeAnyRepair(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client := &rangeCheckLLM{}
	p := New(Config{DB: db, LLMClient: client, Logger: quietLogger(), MaxGroundingAttempts: 1})
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2026-129957"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CachedAt: time.Now(), CNAChecked: true,
		CNAFacts: []cnaSourceFact{affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop)}}
	p.cveVerifier = v
	p.cveEnricher = NewCVEEnricher(v)
	item := scraper.RawItem{SourceID: "nvd:CVE-2026-129957", Source: "nvd", Title: "CVE-2026-129957 — PrestaShop path traversal", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-129957",
		Content: "PrestaShop before 8.2.9 and 9.0.0 before 9.2.1 contains a path traversal vulnerability in back-office theme import (CVE-2026-129957).", Enriched: true}
	brief, err := yaml.Marshal(map[string]any{
		"id": "brief-prestashop-traversal", "slug": "prestashop-traversal", "title": "PrestaShop path traversal (CVE-2026-129957)",
		"summary": "PrestaShop back-office import permits path traversal by authenticated employees.", "severity": "medium",
		"published_at": "2026-11-16T00:00:00Z", "content": "## Overview\nPrestaShop back-office theme import permits path traversal (CVE-2026-129957).\n\n## Recommendation\nApply the vendor update.",
		"affected_vendors": []string{"PrestaShop"}, "affected_products": []string{"PrestaShop"},
		"references": []string{item.URL}, "exploitation_evidence": map[string]string{"status": "unknown"},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := processingCandidate{Item: item, BriefYAML: string(brief), Score: 5, Confidence: 1, Extraction: &ExtractionResult{CVEs: []string{"CVE-2026-129957"}, AffectedProducts: []string{"PrestaShop"}}}
	if err := p.processCandidate(context.Background(), p.processingInputKey(item), state); err != nil {
		t.Fatal(err)
	}
	_, briefSection, found := strings.Cut(client.firstCheck, "## Generated Brief (YAML)")
	if !found {
		t.Fatal("grounding check did not run")
	}
	for _, entry := range []string{"PrestaShop (< 8.2.9)", "PrestaShop (>= 9.0.0, < 9.2.1)"} {
		if !strings.Contains(briefSection, entry) {
			t.Errorf("first grounding check judged a brief without %q:\n%s", entry, briefSection)
		}
	}
}
