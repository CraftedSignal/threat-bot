package pipeline

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// Affected entries of the published CVE-2025-24054 record (NTLM hash
// disclosure). Production briefs listed a few Windows releases and the checker
// rejected each one for omitting the Windows Server SKUs the record names.
var recordWindowsNTLM = []cnaSourceFact{
	affectedFact("CVE-2025-24054", "Windows 10 Version 1809", `{"vendor":"Microsoft","product":"Windows 10 Version 1809","platforms":["32-bit Systems","x64-based Systems"],"versions":[{"version":"10.0.17763.0","lessThan":"10.0.17763.7009","versionType":"custom","status":"affected"}]}`),
	affectedFact("CVE-2025-24054", "Windows 11 Version 24H2", `{"vendor":"Microsoft","product":"Windows 11 Version 24H2","platforms":["ARM64-based Systems","x64-based Systems"],"versions":[{"version":"10.0.26100.0","lessThan":"10.0.26100.3476","versionType":"custom","status":"affected"}]}`),
	affectedFact("CVE-2025-24054", "Windows Server 2008 R2 Service Pack 1", `{"vendor":"Microsoft","product":"Windows Server 2008 R2 Service Pack 1","platforms":["x64-based Systems"],"versions":[{"version":"6.1.7601.0","lessThan":"6.1.7601.27618","versionType":"custom","status":"affected"}]}`),
	affectedFact("CVE-2025-24054", "Windows Server 2012", `{"vendor":"Microsoft","product":"Windows Server 2012","platforms":["x64-based Systems"],"versions":[{"version":"6.2.9200.0","lessThan":"6.2.9200.25368","versionType":"custom","status":"affected"}]}`),
	affectedFact("CVE-2025-24054", "Windows Server 2012 R2", `{"vendor":"Microsoft","product":"Windows Server 2012 R2","platforms":["x64-based Systems"],"versions":[{"version":"6.3.9600.0","lessThan":"6.3.9600.22470","versionType":"custom","status":"affected"}]}`),
	affectedFact("CVE-2025-24054", "Windows Server 2025", `{"vendor":"Microsoft","product":"Windows Server 2025","platforms":["x64-based Systems"],"versions":[{"version":"10.0.26100.0","lessThan":"10.0.26100.3476","versionType":"custom","status":"affected"}]}`),
	affectedFact("CVE-2025-24054", "Windows Server 2025 (Server Core installation)", `{"vendor":"Microsoft","product":"Windows Server 2025 (Server Core installation)","platforms":["x64-based Systems"],"versions":[{"version":"10.0.26100.0","lessThan":"10.0.26100.3476","versionType":"custom","status":"affected"}]}`),
}

const ntlmBrief = "affected_products:\n  - Windows 10 Version 1809\n  - Windows Server 2012\n"

func TestRecordProductsAddMissingMicrosoftSKUs(t *testing.T) {
	facts := primaryRecordFacts{Included: recordWindowsNTLM}
	once := injectAffectedRanges(ntlmBrief, scraper.RawItem{Source: "nvd"}, facts)
	got := renderedProducts(t, once)
	want := []string{
		"Windows 10 Version 1809 (>= 10.0.17763.0, < 10.0.17763.7009)",
		"Windows Server 2012 (>= 6.2.9200.0, < 6.2.9200.25368)",
		"Windows 11 Version 24H2 (>= 10.0.26100.0, < 10.0.26100.3476)",
		"Windows Server 2008 R2 Service Pack 1 (>= 6.1.7601.0, < 6.1.7601.27618)",
		"Windows Server 2012 R2 (>= 6.3.9600.0, < 6.3.9600.22470)",
		"Windows Server 2025 (>= 10.0.26100.0, < 10.0.26100.3476)",
		"Windows Server 2025 (Server Core installation) (>= 10.0.26100.0, < 10.0.26100.3476)",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("affected_products = %q\nwant %q", got, want)
	}
	// The validator and the public projection both clean the list; every
	// added entry must survive unchanged and split into record name and range.
	if cleaned := CleanProductList(got); !slices.Equal(cleaned, got) {
		t.Fatalf("CleanProductList changed added entries: %q", cleaned)
	}
	for i, entry := range got {
		name, scope := SplitProductVersionScope(entry)
		if scope == "" || name != recordWindowsNTLM[slices.IndexFunc(recordWindowsNTLM, func(f cnaSourceFact) bool { return f.Product == name })].Product {
			t.Errorf("entry %d %q projects product %q scope %q", i, entry, name, scope)
		}
	}
	if twice := injectAffectedRanges(once, scraper.RawItem{Source: "nvd"}, facts); twice != once {
		t.Errorf("record product injection is not idempotent:\n%s\n---\n%s", once, twice)
	}
}

func TestRecordProductsDedupeAgainstBriefNames(t *testing.T) {
	for name, tc := range map[string]struct {
		products []string
		want     []string
	}{
		"a family name lists no SKU": {
			products: []string{"Windows"},
			want:     []string{"Windows", "Windows 10 Version 1809 (>= 10.0.17763.0, < 10.0.17763.7009)", "Windows 11 Version 24H2 (>= 10.0.26100.0, < 10.0.26100.3476)", "Windows Server 2008 R2 Service Pack 1 (>= 6.1.7601.0, < 6.1.7601.27618)", "Windows Server 2012 (>= 6.2.9200.0, < 6.2.9200.25368)", "Windows Server 2012 R2 (>= 6.3.9600.0, < 6.3.9600.22470)", "Windows Server 2025 (>= 10.0.26100.0, < 10.0.26100.3476)", "Windows Server 2025 (Server Core installation) (>= 10.0.26100.0, < 10.0.26100.3476)"},
		},
		"vendor-qualified and brief-scoped names are listed": {
			products: []string{"Microsoft Windows 10 Version 1809", "Windows 11 Version 24H2 (< 10.0.26100.3476)", "Windows Server 2008 R2 Service Pack 1", "Windows Server 2012", "Windows Server 2012 R2", "Windows Server 2025", "Windows Server 2025 (Server Core installation)"},
			want:     []string{"Microsoft Windows 10 Version 1809 (>= 10.0.17763.0, < 10.0.17763.7009)", "Windows 11 Version 24H2 (< 10.0.26100.3476)", "Windows Server 2008 R2 Service Pack 1 (>= 6.1.7601.0, < 6.1.7601.27618)", "Windows Server 2012 (>= 6.2.9200.0, < 6.2.9200.25368)", "Windows Server 2012 R2 (>= 6.3.9600.0, < 6.3.9600.22470)", "Windows Server 2025 (>= 10.0.26100.0, < 10.0.26100.3476)", "Windows Server 2025 (Server Core installation) (>= 10.0.26100.0, < 10.0.26100.3476)"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := yaml.Marshal(map[string]any{"affected_products": tc.products})
			got := renderedProducts(t, injectAffectedRanges(string(raw), scraper.RawItem{Source: "nvd"}, primaryRecordFacts{Included: recordWindowsNTLM}))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("affected_products = %q\nwant %q", got, tc.want)
			}
		})
	}
	tomcat := primaryRecordFacts{Included: []cnaSourceFact{affectedFact("CVE-2026-0101", "Apache Tomcat", `{"vendor":"Apache Software Foundation","product":"Apache Tomcat","defaultStatus":"unaffected","versions":[{"version":"11.0.0-M1","lessThan":"11.0.15","status":"affected","versionType":"semver"}]}`)}}
	if got := renderedProducts(t, injectAffectedRanges("affected_products: [Tomcat]\n", scraper.RawItem{Source: "nvd"}, tomcat)); !slices.Equal(got, []string{"Tomcat"}) {
		t.Fatalf("a product the brief names by its short form was added again: %q", got)
	}
}

func TestRecordProductsWithheldFromIncompleteOrTruncatedRecords(t *testing.T) {
	other := affectedFact("CVE-2025-24054", "Windows Server 2016", `{"vendor":"Microsoft","product":"Windows Server 2016","versions":[{"version":"10.0.14393.0","lessThan":"10.0.14393.7876","versionType":"custom","status":"affected"}]}`)
	for name, tc := range map[string]struct {
		facts primaryRecordFacts
		want  []string
	}{
		"record lost affected entries": {
			facts: primaryRecordFacts{Included: recordWindowsNTLM, Truncated: true},
			want:  []string{"Windows 10 Version 1809", "Windows Server 2012"},
		},
		"an entry of the record missed the evidence": {
			facts: primaryRecordFacts{Included: recordWindowsNTLM, Incomplete: []cnaSourceFact{other}},
			want:  []string{"Windows 10 Version 1809 (>= 10.0.17763.0, < 10.0.17763.7009)", "Windows Server 2012 (>= 6.2.9200.0, < 6.2.9200.25368)"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := renderedProducts(t, injectAffectedRanges(ntlmBrief, scraper.RawItem{Source: "nvd"}, tc.facts)); !slices.Equal(got, tc.want) {
				t.Fatalf("products added from a partial record: %q", got)
			}
		})
	}
	// An incomplete neighbor record does not withhold a complete one, but a
	// product it also names has unknown scope and is not added.
	thirtyBees := affectedFact("CVE-2026-129958", "thirty bees", `{"product":"thirty bees","versions":[{"version":"0","lessThan":"1.6.1","status":"affected"}]}`)
	complete := primaryRecordFacts{
		Included:   []cnaSourceFact{affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop)},
		Incomplete: []cnaSourceFact{thirtyBees},
	}
	got := renderedProducts(t, injectAffectedRanges("affected_products: [thirty bees]\n", scraper.RawItem{Source: "nvd"}, complete))
	if !slices.Equal(got, []string{"thirty bees", "PrestaShop (< 8.2.9)", "PrestaShop (>= 9.0.0, < 9.2.1)"}) {
		t.Fatalf("complete record withheld by a neighbor's gap: %q", got)
	}
	shared := primaryRecordFacts{
		Included:   []cnaSourceFact{affectedFact("CVE-2026-129957", "PrestaShop", recordPrestaShop)},
		Incomplete: []cnaSourceFact{affectedFact("CVE-2026-129958", "PrestaShop", `{"product":"PrestaShop","versions":[{"version":"0","lessThan":"8.2.8","status":"affected"}]}`)},
	}
	if got := renderedProducts(t, injectAffectedRanges("affected_products: [thirty bees]\n", scraper.RawItem{Source: "nvd"}, shared)); !slices.Equal(got, []string{"thirty bees"}) {
		t.Fatalf("product with an entry kept out of the evidence was added: %q", got)
	}
}

func TestRecordProductsLeaveUnrenderableEntriesToTheScopeGap(t *testing.T) {
	facts := primaryRecordFacts{Included: []cnaSourceFact{
		affectedFact("CVE-2026-99480", "Linux", `{"vendor":"Linux","product":"Linux","defaultStatus":"unaffected","versions":[{"version":"c6bbec068a9a","lessThan":"01806613d391","status":"affected","versionType":"git"}]}`),
		affectedFact("CVE-2026-116448", "PowerStore 500T", `{"vendor":"Dell","product":"PowerStore 500T","defaultStatus":"unaffected","versions":[{"status":"affected","version":"0","lessThan":"5.1.0.0-2798105 or later","versionType":"semver"}]}`),
		affectedFact("CVE-2026-120285", "BIG-IP", `{"vendor":"F5","product":"BIG-IP","defaultStatus":"unknown","versions":[{"changes":[{"at":"21.1.0.4","status":"unaffected"}],"lessThan":"*","status":"affected","version":"21.1.0","versionType":"custom"}]}`),
	}}
	got := renderedProducts(t, injectAffectedRanges("affected_products: [Widget]\n", scraper.RawItem{Source: "nvd"}, facts))
	if !slices.Equal(got, []string{"Widget"}) {
		t.Fatalf("entries that need interpretation became products: %q", got)
	}
}

// Red Hat records state a fixed rpm per stream as an exception to an affected
// default. affected_products cannot carry the package with that version (the
// product scope parser accepts no package qualifier), so these streams are not
// added and the brief product keeps the explicit applicability gap.
func TestRecordProductsKeepRedHatRPMStreamsOnTheScopeGap(t *testing.T) {
	facts := primaryRecordFacts{Included: []cnaSourceFact{
		affectedFact("CVE-2026-16118", "Red Hat Enterprise Linux 10", `{"vendor":"Red Hat","product":"Red Hat Enterprise Linux 10","packageName":"glib2","defaultStatus":"affected","versions":[{"version":"0:2.80.4-12.el10_2.22","lessThan":"*","versionType":"rpm","status":"unaffected"}]}`),
		affectedFact("CVE-2026-16118", "Red Hat Enterprise Linux 8", `{"vendor":"Red Hat","product":"Red Hat Enterprise Linux 8","packageName":"glib2","defaultStatus":"affected","versions":[{"version":"0:2.56.4-1.el8_10","lessThan":"*","versionType":"rpm","status":"unaffected"}]}`),
		affectedFact("CVE-2026-16118", "Red Hat Enterprise Linux 7", `{"vendor":"Red Hat","product":"Red Hat Enterprise Linux 7","packageName":"glib2","defaultStatus":"affected"}`),
	}}
	raw := injectAffectedRanges("affected_products:\n  - Red Hat Enterprise Linux 8\n", scraper.RawItem{Source: "nvd"}, facts)
	if got := renderedProducts(t, raw); !slices.Equal(got, []string{"Red Hat Enterprise Linux 8"}) {
		t.Fatalf("rpm streams were rendered or added: %q", got)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	assessment, _ := doc["source_assessment"].(map[string]any)
	gaps := yamlStringList(assessment["gaps"])
	if len(gaps) != 1 || !strings.HasPrefix(gaps[0], "CVE-2026-16118 / Red Hat Enterprise Linux 8: defaultStatus=affected with version exceptions") {
		t.Fatalf("source_assessment.gaps = %q", gaps)
	}
}

func TestRecordProductsNeverReaddRepairRejectedScope(t *testing.T) {
	facts := primaryRecordFacts{Included: recordWindowsNTLM}
	injected := renderedProducts(t, injectAffectedRanges(ntlmBrief, scraper.RawItem{Source: "nvd"}, facts))
	// The repair dropped an added SKU after the checker rejected it.
	kept := slices.DeleteFunc(slices.Clone(injected), func(p string) bool { return strings.HasPrefix(p, "Windows Server 2012 R2") })
	merged, err := mergeGroundingRepair(map[string]any{"affected_products": injected}, revisedBrief{generatedBrief: generatedBrief{AffectedProducts: kept}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := yaml.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	got := renderedProducts(t, injectAffectedRanges(string(encoded), scraper.RawItem{Source: "nvd"}, facts))
	if !slices.Equal(got, kept) {
		t.Fatalf("repair-rejected record product was re-added:\n got %q\nwant %q", got, kept)
	}
}

func TestRecordProductsCapAdditionsWithOneGap(t *testing.T) {
	var facts []cnaSourceFact
	for i := 1; i <= 40; i++ {
		product := fmt.Sprintf("PowerProtect DD%d", 3000+i*100)
		facts = append(facts, affectedFact("CVE-2026-86395", product, fmt.Sprintf(`{"vendor":"Dell","product":%q,"defaultStatus":"unaffected","versions":[{"version":"0","lessThan":"8.3.1.%d","status":"affected","versionType":"semver"}]}`, product, i)))
	}
	primary := primaryRecordFacts{Included: facts}
	brief := "affected_products:\n  - PowerProtect DD3100\n  - PowerProtect Data Manager\n"
	once := injectAffectedRanges(brief, scraper.RawItem{Source: "nvd"}, primary)
	got := renderedProducts(t, once)
	if len(got) != maxRecordProductEntries {
		t.Fatalf("got %d products, want the %d-entry cap: %q", len(got), maxRecordProductEntries, got)
	}
	if got[0] != "PowerProtect DD3100 (< 8.3.1.1)" || got[1] != "PowerProtect Data Manager" || got[2] != "PowerProtect DD3200 (< 8.3.1.2)" || got[24] != "PowerProtect DD5400 (< 8.3.1.24)" {
		t.Fatalf("record order was not kept: %q", got)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(once), &doc); err != nil {
		t.Fatal(err)
	}
	assessment, _ := doc["source_assessment"].(map[string]any)
	gaps := yamlStringList(assessment["gaps"])
	want := "16 more affected products are listed in the CVE record CVE-2026-86395 (https://cveawg.mitre.org/api/cve/CVE-2026-86395); affected_products is capped at 25 entries, so check the record for the complete product list."
	if !slices.Equal(gaps, []string{want}) {
		t.Fatalf("source_assessment.gaps = %q\nwant %q", gaps, want)
	}
	if twice := injectAffectedRanges(once, scraper.RawItem{Source: "nvd"}, primary); twice != once {
		t.Fatalf("capped injection is not idempotent:\n%s\n---\n%s", once, twice)
	}
	// A repair that removes added products restates the remaining count
	// instead of keeping a stale one beside it.
	shorter := injectAffectedRanges("affected_products: [PowerProtect DD3100]\nsource_assessment:\n  gaps:\n    - Vendor advisory is paywalled\n    - \""+want+"\"\n", scraper.RawItem{Source: "nvd"}, primaryRecordFacts{Included: facts[:30]})
	if err := yaml.Unmarshal([]byte(shorter), &doc); err != nil {
		t.Fatal(err)
	}
	assessment, _ = doc["source_assessment"].(map[string]any)
	gaps = yamlStringList(assessment["gaps"])
	if len(gaps) != 2 || gaps[0] != "Vendor advisory is paywalled" || !strings.HasPrefix(gaps[1], "5 more affected products") {
		t.Fatalf("overflow gap was not restated: %q", gaps)
	}
	if fits := injectAffectedRanges(shorter, scraper.RawItem{Source: "nvd"}, primaryRecordFacts{Included: facts[:3]}); strings.Contains(fits, "more affected product") {
		t.Fatalf("overflow gap kept after every record product fit:\n%s", fits)
	}
}

func TestGroundingCheckSeesRecordProductsBeforeAnyRepair(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client := &rangeCheckLLM{}
	p := New(Config{DB: db, LLMClient: client, Logger: quietLogger(), MaxGroundingAttempts: 1})
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2025-24054"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CachedAt: time.Now(), CNAChecked: true, CNAFacts: recordWindowsNTLM}
	// Named by the brief but not by the source: not a grounding primary CVE.
	v.cache["CVE-2025-33073"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CachedAt: time.Now(), CNAChecked: true,
		CNAFacts: []cnaSourceFact{affectedFact("CVE-2025-33073", "Windows Server 2022, 23H2 Edition", `{"vendor":"Microsoft","product":"Windows Server 2022, 23H2 Edition","versions":[{"version":"10.0.25398.0","lessThan":"10.0.25398.1665","versionType":"custom","status":"affected"}]}`)}}
	p.cveVerifier = v
	p.cveEnricher = NewCVEEnricher(v)
	item := scraper.RawItem{SourceID: "sploitus:LNK-NTLM-LEAK", Source: "sploitus", Title: "LNK weaponizer for CVE-2025-24054", URL: "https://example.com/lnk-weaponizer",
		Content: "A public Aggressor script creates .lnk and .library-ms files that leak NTLMv2-SSP hashes through CVE-2025-24054 when a user opens the folder.", Enriched: true}
	brief, err := yaml.Marshal(map[string]any{
		"id": "brief-lnk-ntlm-leak", "slug": "lnk-ntlm-leak", "title": "LNK weaponizer leaks NTLM hashes (CVE-2025-24054)",
		"summary": "A public script automates NTLM hash disclosure through CVE-2025-24054.", "severity": "medium",
		"published_at": "2026-11-22T00:00:00Z", "content": "## Overview\nThe script abuses CVE-2025-24054; compare CVE-2025-33073.\n\n## Recommendation\nApply the Windows security update.",
		"affected_vendors": []string{"Microsoft"}, "affected_products": []string{"Windows 10 Version 1809", "Windows Server 2012"},
		"references": []string{item.URL}, "exploitation_evidence": map[string]string{"status": "unknown"},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := processingCandidate{Item: item, BriefYAML: string(brief), Score: 5, Confidence: 1, Extraction: &ExtractionResult{CVEs: []string{"CVE-2025-24054"}, AffectedProducts: []string{"Windows"}}}
	if err := p.processCandidate(context.Background(), p.processingInputKey(item), state); err != nil {
		t.Fatal(err)
	}
	_, briefSection, found := strings.Cut(client.firstCheck, "## Generated Brief (YAML)")
	if !found {
		t.Fatal("grounding check did not run")
	}
	for _, entry := range []string{"Windows Server 2008 R2 Service Pack 1 (>= 6.1.7601.0, < 6.1.7601.27618)", "Windows Server 2012 R2 (>= 6.3.9600.0, < 6.3.9600.22470)", "Windows Server 2025 (Server Core installation) (>= 10.0.26100.0, < 10.0.26100.3476)"} {
		if !strings.Contains(briefSection, entry) {
			t.Errorf("first grounding check judged a brief without record product %q:\n%s", entry, briefSection)
		}
	}
	if strings.Contains(briefSection, "23H2 Edition") {
		t.Errorf("product of a CVE the source does not assert was added:\n%s", briefSection)
	}
}
