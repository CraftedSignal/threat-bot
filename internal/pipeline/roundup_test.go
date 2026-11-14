package pipeline

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

type roundupContentMockLLM struct{}

func (roundupContentMockLLM) Generate(context.Context, string, string) (string, error) {
	return "", nil
}

func (roundupContentMockLLM) GenerateJSON(_ context.Context, prompt, _ string, out any) error {
	resp, ok := out.(*roundupContentRelevanceResponse)
	if !ok {
		return nil
	}
	relevant := true
	resp.Relevant = &relevant
	resp.Reason = "selected products directly affected by the CVE"
	if strings.Contains(prompt, "Microsoft Teams") {
		resp.AffectedProducts = []string{"Microsoft Teams"}
		resp.AffectedOS = []string{"Windows"}
		return nil
	}
	if strings.Contains(prompt, "Windows") {
		resp.AffectedProducts = []string{"Windows"}
	}
	return nil
}

func msrcItem(id, cve string) (scraper.RawItem, *ExtractionResult) {
	return scraper.RawItem{
			SourceID: "msrc:" + id, Source: "msrc",
			Title:   cve + " Windows elevation of privilege",
			Content: "A vulnerability " + cve + " affects Windows.",
		},
		&ExtractionResult{CVEs: []string{cve}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Windows"}}
}

func TestRoundupConsolidation(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true // enable the gated feature

	// First Microsoft CVE → creates the monthly roundup.
	i1, e1 := msrcItem("1", "CVE-2026-1000")
	if !p.routeToRoundup(context.Background(), i1, e1) {
		t.Fatal("first patch-cycle CVE should create a roundup")
	}
	// Second Microsoft CVE, same cycle → folds into the same roundup.
	i2, e2 := msrcItem("2", "CVE-2026-1001")
	if !p.routeToRoundup(context.Background(), i2, e2) {
		t.Fatal("second CVE should fold into the roundup")
	}

	// Both CVEs must point at a single roundup draft for this cycle.
	key := vendorCycleKey("Microsoft", time.Now().UTC())
	entries, err := db.FindByVendorCycle(key)
	if err != nil {
		t.Fatalf("find cycle: %v", err)
	}
	ids := map[string]bool{}
	for _, e := range entries {
		ids[e.DraftID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("want exactly one roundup draft for the cycle, got %d (%v)", len(ids), ids)
	}
	var draftID string
	for id := range ids {
		draftID = id
	}
	d, err := db.GetDraft(draftID)
	if err != nil || d == nil {
		t.Fatalf("get roundup draft: %v", err)
	}
	yaml := d.BriefYAML
	if !strings.Contains(yaml, "CVE-2026-1000") || !strings.Contains(yaml, "CVE-2026-1001") {
		t.Fatalf("roundup should contain both CVEs, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "Security Updates") {
		t.Fatalf("roundup title expected, got:\n%s", yaml)
	}

	// A KEV CVE for the same vendor is carved out → NOT rolled up.
	p.kev = loadedKEVCatalog(t, "CVE-2026-9999")
	ik, ek := msrcItem("3", "CVE-2026-9999")
	if p.routeToRoundup(context.Background(), ik, ek) {
		t.Fatal("KEV CVE must be carved out of the roundup")
	}

	// A non-patch-cycle vendor must not be rolled up.
	inp := scraper.RawItem{SourceID: "ghsa:1", Source: "ghsa", Title: "cap-go flaw", Content: "an issue in cap-go"}
	enp := &ExtractionResult{CVEs: []string{"CVE-2026-2000"}, AffectedVendors: []string{"cap-go"}}
	if p.routeToRoundup(context.Background(), inp, enp) {
		t.Fatal("non-patch-cycle vendor must not be rolled up")
	}

	// Disabled by default: with the flag off, nothing is rolled up.
	p.roundupConsolidation = false
	i4, e4 := msrcItem("4", "CVE-2026-1002")
	if p.routeToRoundup(context.Background(), i4, e4) {
		t.Fatal("roundup must be inert when the flag is off")
	}
}

func TestRoundupConsolidation_RequiresCVE(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	// Detection-rule feeds, news articles, and threat-research blogs lack CVEs
	// and must NOT seed a vendor roundup, even when they mention a patch-cycle vendor.
	cases := []struct {
		name string
		item scraper.RawItem
		ex   *ExtractionResult
	}{
		{
			name: "elastic detection rule",
			item: scraper.RawItem{SourceID: "elastic:abc", Source: "elastic", Title: "GCP GKE secret access via unusual user agent"},
			ex:   &ExtractionResult{AffectedVendors: []string{"Google"}, AffectedProducts: []string{"Google Kubernetes Engine"}},
		},
		{
			name: "securityweek news article",
			item: scraper.RawItem{SourceID: "securityweek:1", Source: "securityweek", Title: "Gemini Agent-to-Agent Attack Exposed Secrets"},
			ex:   &ExtractionResult{AffectedVendors: []string{"Google"}},
		},
		{
			name: "unit42 threat research",
			item: scraper.RawItem{SourceID: "unit42:1", Source: "unit42", Title: "Passwordless Authentication Security Risks"},
			ex:   &ExtractionResult{AffectedVendors: []string{"Google"}, AffectedOS: []string{"Windows"}},
		},
		{
			name: "advisory source without CVE",
			item: scraper.RawItem{SourceID: "ghsa:nocve", Source: "ghsa", Title: "Microsoft hardening guidance"},
			ex:   &ExtractionResult{AffectedVendors: []string{"Microsoft"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if p.routeToRoundup(context.Background(), tc.item, tc.ex) {
				t.Fatalf("%s must not create a vendor roundup without a CVE", tc.name)
			}
		})
	}
}

func TestRoundupConsolidation_SingleVendorOnly(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	// A multi-vendor GHSA-style advisory must NOT be routed into the first
	// patch-cycle vendor's roundup, otherwise unrelated products leak in.
	multi := scraper.RawItem{
		SourceID: "ghsa:multi", Source: "ghsa",
		Title:   "Vulnerability affecting Angular and github.com",
		Content: "Cross-vendor advisory.",
	}
	multiEx := &ExtractionResult{
		CVEs:             []string{"CVE-2026-7000"},
		AffectedVendors:  []string{"Google", "GitHub"},
		AffectedProducts: []string{"Angular", "github.com"},
	}
	if p.routeToRoundup(context.Background(), multi, multiEx) {
		t.Fatal("multi-vendor advisory must not be routed into a single-vendor roundup")
	}

	// Single-vendor advisory from a vendor-authoritative source for a
	// patch-cycle vendor IS eligible.
	single := scraper.RawItem{
		SourceID: "google:angular", Source: "google-project-zero",
		Title:   "Angular XSS",
		Content: "Angular advisory.",
	}
	singleEx := &ExtractionResult{
		CVEs:             []string{"CVE-2026-7001"},
		AffectedVendors:  []string{"Google"},
		AffectedProducts: []string{"Angular"},
	}
	if !p.routeToRoundup(context.Background(), single, singleEx) {
		t.Fatal("single-vendor patch-cycle vendor source should create a roundup")
	}
}

func TestRoundupConsolidation_NonAuthoritativeSourcesRejected(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	// Seed a Microsoft roundup from an authoritative source.
	i1, e1 := msrcItem("1", "CVE-2026-1000")
	if !p.routeToRoundup(context.Background(), i1, e1) {
		t.Fatal("authoritative MSRC item should create a roundup")
	}

	cases := []struct {
		name string
		item scraper.RawItem
		ex   *ExtractionResult
	}{
		{
			name: "elastic detection rule mentioning Microsoft",
			item: scraper.RawItem{SourceID: "elastic:1", Source: "elastic", Title: "Azure AKS suspicious secret access", URL: "https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_azure_aks_secret_access_suspicious_user_agent.toml"},
			ex:   &ExtractionResult{CVEs: []string{"CVE-2026-1001"}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Azure Kubernetes Service"}},
		},
		{
			name: "bitdefender blog mentioning Microsoft products",
			item: scraper.RawItem{SourceID: "bitdefender:1", Source: "bitdefender", Title: "Fake Xeno Roblox/Discord executor also abuses Windows", URL: "https://www.bitdefender.com/en-us/blog/labs/fake-xeno-roblox-discord-executor"},
			ex:   &ExtractionResult{CVEs: []string{"CVE-2026-1002"}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Windows"}},
		},
		{
			name: "therecord news article mentioning SharePoint",
			item: scraper.RawItem{SourceID: "therecord:1", Source: "therecord", Title: "Swiss bit FOITT hacked possibly via SharePoint", URL: "https://therecord.media/swiss-bit-foitt-hacked-possibly-sharepoint-vulnerabilities"},
			ex:   &ExtractionResult{CVEs: []string{"CVE-2026-1003"}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"SharePoint Server"}},
		},
		{
			name: "sploitus exploit tracker",
			item: scraper.RawItem{SourceID: "sploitus:1", Source: "sploitus", Title: "Windows exploit PoC", URL: "https://sploitus.com/exploit?id=ABC"},
			ex:   &ExtractionResult{CVEs: []string{"CVE-2026-1004"}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Windows"}},
		},
		{
			name: "CERT-Bund advisory mentioning Microsoft",
			item: scraper.RawItem{SourceID: "bsi:1", Source: "bsi", Title: "WID-SEC-2026-1234 Microsoft", URL: "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1234"},
			ex:   &ExtractionResult{CVEs: []string{"CVE-2026-1005"}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Windows"}},
		},
		{
			name: "NVD Microsoft CVE is authoritative and folds in",
			item: scraper.RawItem{SourceID: "nvd:1", Source: "nvd", Title: "CVE-2026-1006 Windows EoP", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-1006"},
			ex:   &ExtractionResult{CVEs: []string{"CVE-2026-1006"}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Windows 11"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handled := p.routeToRoundup(context.Background(), tc.item, tc.ex)
			if tc.name == "NVD Microsoft CVE is authoritative and folds in" {
				if !handled {
					t.Fatal("NVD Microsoft CVE should fold into the roundup")
				}
				return
			}
			if handled {
				t.Fatalf("%s must not be folded into the Microsoft roundup", tc.name)
			}
		})
	}
}

func TestRoundupConsolidation_DropsNoisyProductsAndIOCs(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true
	p.llmClient = roundupContentMockLLM{}

	i1, e1 := msrcItem("1", "CVE-2026-1000")
	if !p.routeToRoundup(context.Background(), i1, e1) {
		t.Fatal("authoritative MSRC item should create a roundup")
	}

	noisy := scraper.RawItem{
		SourceID: "nvd:CVE-2026-1001",
		Source:   "nvd",
		Title:    "CVE-2026-1001 Microsoft Teams privilege escalation",
		URL:      "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
		Content:  "A Microsoft Teams vulnerability was published.",
	}
	noisyExtraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-1001"},
		AffectedVendors:  []string{"Microsoft"},
		AffectedProducts: []string{"Microsoft Teams", "Roblox", "Discord", "Android", "Elastic Stack", "GitHub", "curl"},
		AffectedOS:       []string{"Windows", "Android", "Alpine Linux"},
		IOCs: []ExtractedIOC{
			{Type: "url", Value: "https://solthere.net/api/v1/redeem"},
			{Type: "domain", Value: "storage.googleapis.com"},
		},
		Summary: "A Microsoft Teams vulnerability allows privilege escalation.",
	}
	if !p.routeToRoundup(context.Background(), noisy, noisyExtraction) {
		t.Fatal("authoritative NVD item should fold into the roundup")
	}

	key := vendorCycleKey("Microsoft", time.Now().UTC())
	entries, _ := db.FindByVendorCycle(key)
	if len(entries) == 0 {
		t.Fatal("expected roundup index entry")
	}
	d, err := db.GetDraft(entries[0].DraftID)
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}
	for _, bad := range []string{
		"Roblox",
		"Discord",
		"Elastic Stack",
		"GitHub",
		"curl",
		"Android",
		"Alpine Linux",
		"solthere.net",
		"storage.googleapis.com",
		"affected_products:",
		"iocs:",
		"ioc_counts:",
		"has_poc:",
		"poc_references:",
	} {
		if strings.Contains(d.BriefYAML, bad) {
			t.Fatalf("roundup retained noisy value %q:\n%s", bad, d.BriefYAML)
		}
	}
	for _, want := range []string{"CVE-2026-1001", "Microsoft Teams", "Windows"} {
		if !strings.Contains(d.BriefYAML, want) {
			t.Fatalf("roundup missing expected value %q:\n%s", want, d.BriefYAML)
		}
	}
}

func TestRoundupMergeBypassRejectsNonAuthoritativeMetadata(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	i1, e1 := msrcItem("1", "CVE-2026-1000")
	if !p.routeToRoundup(context.Background(), i1, e1) {
		t.Fatal("authoritative MSRC item should create a roundup")
	}

	item := scraper.RawItem{
		SourceID: "bitdefender:1",
		Source:   "bitdefender",
		Title:    "Fake Xeno Roblox/Discord executor PoC for CVE-2026-1000",
		URL:      "https://www.bitdefender.com/en-us/blog/labs/fake-xeno-roblox-discord-executor",
		Content:  "A public proof-of-concept mentions CVE-2026-1000 and uses https://solthere.net/api/v1/redeem.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-1000"},
		AffectedVendors:  []string{"Microsoft"},
		AffectedProducts: []string{"Roblox", "Discord", "Windows"},
		IOCs:             []ExtractedIOC{{Type: "url", Value: "https://solthere.net/api/v1/redeem"}},
	}
	if p.handlePostExtractionDedup(context.Background(), item, extraction, nil) {
		t.Fatal("non-authoritative update should not be consumed by the roundup merge path")
	}

	key := vendorCycleKey("Microsoft", time.Now().UTC())
	entries, _ := db.FindByVendorCycle(key)
	if len(entries) == 0 {
		t.Fatal("expected roundup index entry")
	}
	d, err := db.GetDraft(entries[0].DraftID)
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}
	for _, bad := range []string{"Roblox", "Discord", "solthere.net", "bitdefender.com", "has_poc:", "iocs:"} {
		if strings.Contains(d.BriefYAML, bad) {
			t.Fatalf("non-authoritative merge polluted roundup with %q:\n%s", bad, d.BriefYAML)
		}
	}
}

func TestRoundupContentEnrichment(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	first := scraper.RawItem{
		SourceID: "nvd:1", Source: "nvd",
		Title: "CVE-2026-1000 Windows EoP",
		URL:   "https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
	}
	firstEx := &ExtractionResult{
		CVEs:             []string{"CVE-2026-1000"},
		AffectedVendors:  []string{"Microsoft"},
		AffectedProducts: []string{"Windows 11 (<= 23H2)"},
		Summary:          "A privilege escalation vulnerability in Windows 11 allows local attackers to gain SYSTEM privileges.",
	}
	if !p.routeToRoundup(context.Background(), first, firstEx) {
		t.Fatal("first CVE should create a roundup")
	}

	key := vendorCycleKey("Microsoft", time.Now().UTC())
	entries, _ := db.FindByVendorCycle(key)
	if len(entries) == 0 {
		t.Fatal("expected roundup index entry")
	}
	draftID := entries[0].DraftID
	d, err := db.GetDraft(draftID)
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}

	// Initial CVE details should be written into the content body.
	for _, want := range []string{
		"## CVE-2026-1000",
		"A privilege escalation vulnerability in Windows 11",
		"Affected products:",
		"Windows 11 (<= 23H2)",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
		"## Overview",
		"This roundup covers 1 Microsoft security vulnerabilities",
		"## Summary",
		"| CVE | Product | Severity | CVSS | EPSS | KEV | Source |",
		"[CVE-2026-1000](#cve-2026-1000)",
		"|  |  |  | no |",
		"Windows 11",
		"product: Windows 11 (<= 23H2)",
		"[NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-1000) (authoritative)",
		"A privilege escalation vulnerability in Windows 11",
	} {
		if !strings.Contains(d.BriefYAML, want) {
			t.Fatalf("initial content missing %q:\n%s", want, d.BriefYAML)
		}
	}

	// The "What's new" timeline should record the original creation.
	if !strings.Contains(d.BriefYAML, "posted roundup") {
		t.Fatalf("initial posted event missing:\n%s", d.BriefYAML)
	}

	// Second CVE folds in and appends a new section, without duplicating the first.
	second := scraper.RawItem{
		SourceID: "nvd:2", Source: "nvd",
		Title:   "CVE-2026-1001 Windows RCE",
		Content: "Windows Server 2022 versions up to and including 23H2 have a remote code execution vulnerability.",
		URL:     "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
	}
	secondEx := &ExtractionResult{
		CVEs:             []string{"CVE-2026-1001"},
		AffectedVendors:  []string{"Microsoft"},
		AffectedProducts: []string{"Windows Server 2022 (<= 23H2)"},
		Summary:          "A remote code execution vulnerability in Windows Server 2022.",
	}
	if !p.routeToRoundup(context.Background(), second, secondEx) {
		t.Fatal("second CVE should fold into the roundup")
	}

	d, err = db.GetDraft(draftID)
	if err != nil {
		t.Fatalf("get draft after second merge: %v", err)
	}
	for _, want := range []string{
		"## CVE-2026-1000",
		"## CVE-2026-1001",
		"Windows Server 2022 (<= 23H2)",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
		"This roundup covers 2 Microsoft security vulnerabilities",
		"None are reported as actively exploited",
		"CVE-2026-1000",
		"CVE-2026-1001",
		"Windows 11",
		"Windows Server 2022",
		"product: Windows Server 2022 (<= 23H2)",
	} {
		if !strings.Contains(d.BriefYAML, want) {
			t.Fatalf("content after second merge missing %q:\n%s", want, d.BriefYAML)
		}
	}

	// Re-merging the same CVE must not duplicate its section.
	sectionCount := strings.Count(d.BriefYAML, "## CVE-2026-1001")
	if sectionCount != 1 {
		t.Fatalf("CVE-2026-1001 section duplicated %d times", sectionCount)
	}
}

func TestRebuildRoundupContent(t *testing.T) {
	fm := map[string]any{
		"affected_vendors": []any{"Microsoft"},
		"cves": []any{
			map[string]any{"id": "CVE-2026-1000", "cvss": 8.8, "epss": 0.1234},
			map[string]any{"id": "CVE-2026-1001", "cvss": 7.5, "epss": "0.0005", "kev": true},
			map[string]any{"id": "CVE-2026-1002", "cvss": 9.1},
		},
	}
	content := "## CVE-2026-1000\n\nA privilege escalation vulnerability in Windows 11.\n\nAffected products:\n- Windows 11 (<= 23H2)\n\nSource: https://nvd.nist.gov/vuln/detail/CVE-2026-1000\n\n## CVE-2026-1001\n\nA remote code execution vulnerability in Windows Server 2022.\n\nAffected products:\n- Windows Server 2022 (<= 23H2)\n\nSource: https://nvd.nist.gov/vuln/detail/CVE-2026-1001\n\n## CVE-2026-1002\n\nA related remote code execution vulnerability in Windows Server 2022.\n\nAffected products:\n- Windows Server 2022 (<= 23H2)\n\nSource: https://nvd.nist.gov/vuln/detail/CVE-2026-1002\n\n## Recommendation\n\nApply the vendor updates.\n"

	out := rebuildRoundupContent(fm, content)
	for _, want := range []string{
		"## Overview",
		"This roundup covers 3 Microsoft security vulnerabilities",
		"CVSS base scores range from 7.5 to 9.1",
		"1 is listed in the CISA Known Exploited Vulnerabilities catalog",
		"The issues affect Windows 11, Windows Server 2022",
		"## Summary",
		"| CVE | Product | Severity | CVSS | EPSS | KEV | Source |",
		"| [CVE-2026-1000](#cve-2026-1000) | Windows 11 (<= 23H2) | High | 8.8 | 12.34% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-1000) (authoritative) |",
		"| [CVE-2026-1001](#cve-2026-1001) | Windows Server 2022 (<= 23H2) | High | 7.5 | 0.05% | yes | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-1001) (authoritative) |",
		"| [CVE-2026-1002](#cve-2026-1002) | Windows Server 2022 (<= 23H2) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-1002) (authoritative) |",
		"## CVE-2026-1000",
		"## CVE-2026-1001",
		"## By product",
		"- **Windows Server 2022**: [CVE-2026-1001](#cve-2026-1001), [CVE-2026-1002](#cve-2026-1002)",
		"## Recommendation",
		"Apply the vendor updates.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rebuilt content missing %q:\n%s", want, out)
		}
	}
}

func TestRebuildRoundupContent_UsesFrontmatterCVEProduct(t *testing.T) {
	fm := map[string]any{
		"affected_vendors": []any{"Microsoft"},
		"cves": []any{
			map[string]any{"id": "CVE-2026-1000", "product": "Microsoft Teams", "cvss": 8.8},
		},
	}
	content := "## CVE-2026-1000\n\nA privilege escalation vulnerability.\n\nSource: https://nvd.nist.gov/vuln/detail/CVE-2026-1000\n"

	out := rebuildRoundupContent(fm, content)
	want := "| [CVE-2026-1000](#cve-2026-1000) | Microsoft Teams | High | 8.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-1000) (authoritative) |"
	if !strings.Contains(out, want) {
		t.Fatalf("rebuilt content missing frontmatter product row %q:\n%s", want, out)
	}
}

func nvdRoundupItem(cve string) (scraper.RawItem, *ExtractionResult) {
	return scraper.RawItem{
			SourceID: "nvd:" + cve, Source: "nvd",
			Title:   cve + " — vulnerability",
			Content: "A vulnerability in WindowState.java allows privilege escalation.",
			URL:     "https://nvd.nist.gov/vuln/detail/" + cve,
		},
		&ExtractionResult{CVEs: []string{cve}, AffectedVendors: []string{"Microsoft"}}
}

func TestRoundupConsolidation_ChecksNVDVendorData(t *testing.T) {
	cases := []struct {
		name string
		cve  string
		meta *CVEMeta
		want bool
	}{
		{
			name: "android CPE and CNA is not folded into Microsoft roundup",
			cve:  "CVE-2026-58934",
			meta: &CVEMeta{Exists: true, SourceIdentifier: "security@android.com",
				CPEs: []string{"cpe:2.3:o:google:android:*:*:*:*:*:*:*:*"}, Description: "In WindowState.java, a flaw."},
			want: false,
		},
		{
			name: "android-only CNA without CPEs is not folded",
			cve:  "CVE-2026-58935",
			meta: &CVEMeta{Exists: true, SourceIdentifier: "security@android.com"},
			want: false,
		},
		{
			name: "Microsoft CNA with zero CPEs is folded",
			cve:  "CVE-2026-109469",
			meta: &CVEMeta{Exists: true, SourceIdentifier: "secure@microsoft.com"},
			want: true,
		},
		{
			name: "Microsoft CPE is folded",
			cve:  "CVE-2026-109470",
			meta: &CVEMeta{Exists: true, SourceIdentifier: "cve@mitre.org",
				CPEs: []string{"cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "no NVD data cached keeps existing behaviour",
			cve:  "CVE-2026-109471",
			meta: nil,
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			p := newDedupTestPipeline(t, db)
			p.roundupConsolidation = true
			if tc.meta != nil {
				tc.meta.CachedAt = time.Now()
				p.cveVerifier.cache[tc.cve] = tc.meta
			}
			item, ext := nvdRoundupItem(tc.cve)
			if got := p.routeToRoundup(context.Background(), item, ext); got != tc.want {
				t.Fatalf("routeToRoundup = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRoundupConsolidation_UsesNVDItemMetadata(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true
	item, ext := nvdRoundupItem("CVE-2026-58934")
	item.Metadata = map[string]string{
		"cve":               "CVE-2026-58934",
		"source_identifier": "security@android.com",
		"cpes":              "cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
	}
	if p.routeToRoundup(context.Background(), item, ext) {
		t.Fatal("NVD item carrying Android vendor data must not fold into the Microsoft roundup")
	}
}

// A fold whose only scope-matching CVE is new must not drop the CVEs the
// roundup already lists: the publisher's append-only guard rejects a
// structured CVE set that shares nothing with the published one.
func TestRoundupFoldKeepsAlreadyListedCVEs(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	const a, b, c = "CVE-2026-58934", "CVE-2026-109469", "CVE-2026-60001"
	// A is an Android CVE, B has no CPEs yet, C is a Windows CVE.
	p.cveVerifier.cache[a] = &CVEMeta{Exists: true, CachedAt: time.Now(), CVSS: 7.8, Description: "Android framework flaw.",
		CPEs: []string{"cpe:2.3:o:google:android:14.0:*:*:*:*:*:*:*"}}
	p.cveVerifier.cache[b] = &CVEMeta{Exists: true, CachedAt: time.Now(), CVSS: 7.5, Description: "A flaw."}
	p.cveVerifier.cache[c] = &CVEMeta{Exists: true, CachedAt: time.Now(), CVSS: 8.8, Description: "Windows flaw.",
		CPEs: []string{"cpe:2.3:o:microsoft:windows_11_24h2:-:*:*:*:*:*:*:*"}}

	var snaps []string
	for i, cve := range []string{a, b, c} {
		item, ex := msrcItem(string(rune('a'+i)), cve)
		if !p.routeToRoundup(context.Background(), item, ex) {
			t.Fatalf("fold %s: expected roundup routing", cve)
		}
		entries, err := db.FindByVendorCycle(vendorCycleKey("Microsoft", time.Now().UTC()))
		if err != nil || len(entries) == 0 {
			t.Fatalf("find cycle: %v", err)
		}
		d, err := db.GetDraft(entries[0].DraftID)
		if err != nil || d == nil {
			t.Fatalf("get draft: %v", err)
		}
		snaps = append(snaps, d.BriefYAML)
	}

	got := map[string]bool{}
	for _, cve := range structuredCVEsFromBrief(snaps[2]) {
		got[cve.ID] = true
	}
	for _, want := range []string{a, b, c} {
		if !got[want] {
			t.Errorf("after folding %s, structured cves lost %s: %v", c, want, got)
		}
	}
}

// A roundup with no references fails the publisher's attribution check and is
// held for review. The item that triggers it is the first source.
func TestRoundupSeedsTriggeringItemURLAsFirstReference(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	item, extraction := msrcItem("ref", "CVE-2026-2000")
	item.URL = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-2000"
	if !p.routeToRoundup(context.Background(), item, extraction) {
		t.Fatal("roundup was not created")
	}
	entries, err := db.FindByVendorCycle(vendorCycleKey("Microsoft", time.Now().UTC()))
	if err != nil || len(entries) == 0 {
		t.Fatalf("find cycle: %v %d", err, len(entries))
	}
	d, err := db.GetDraft(entries[0].DraftID)
	if err != nil || d == nil {
		t.Fatalf("get draft: %v", err)
	}
	var doc struct {
		References []string `yaml:"references"`
	}
	if err := yaml.Unmarshal([]byte(d.BriefYAML), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.References) == 0 || doc.References[0] != item.URL {
		t.Fatalf("references = %v, want %s first", doc.References, item.URL)
	}
}

func bigWindowsRoundup(n int, legacy bool) (map[string]any, string) {
	var cves []any
	var b strings.Builder
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("CVE-2026-%04d", 1000+i)
		cves = append(cves, map[string]any{"id": id, "cvss": 7.5})
		fmt.Fprintf(&b, "## %s\n\nA flaw in Windows.\n\n", id)
		if legacy {
			b.WriteString("Related in this roundup: [CVE-2026-1000](#cve-2026-1000), [CVE-2026-1001](#cve-2026-1001).\n\n")
		}
		b.WriteString("Affected products:\n- Windows (<= 23H2)\n\n")
		fmt.Fprintf(&b, "Source: https://nvd.nist.gov/vuln/detail/%s\n\n", id)
	}
	return map[string]any{"affected_vendors": []any{"Microsoft"}, "cves": cves}, b.String()
}

func TestRebuildRoundupContent_ProductIndexIsLinear(t *testing.T) {
	const n = 200
	fm, content := bigWindowsRoundup(n, false)
	out := rebuildRoundupContent(fm, content)

	if strings.Contains(out, "Related in this roundup:") {
		t.Fatal("per-section related lines must not be emitted")
	}
	if !strings.Contains(out, "## By product") {
		t.Fatal("missing By product index")
	}
	// Each CVE is linked exactly once from the index (plus once from the
	// summary table), never k-1 times from every section.
	for _, id := range []string{"CVE-2026-1000", "CVE-2026-1199"} {
		if got := strings.Count(out, "["+id+"](#"); got != 2 {
			t.Fatalf("%s linked %d times, want 2 (table + index)", id, got)
		}
	}
	if total := strings.Count(out, "](#cve-"); total != 2*n {
		t.Fatalf("total CVE anchors = %d, want %d", total, 2*n)
	}
}

func TestRebuildRoundupContent_StripsLegacyRelatedLines(t *testing.T) {
	fm, content := bigWindowsRoundup(3, true)
	out := rebuildRoundupContent(fm, content)
	if strings.Contains(out, "Related in this roundup:") {
		t.Fatalf("legacy related lines survived rebuild:\n%s", out)
	}
	// Idempotent: rebuilding the output again is stable.
	if again := rebuildRoundupContent(fm, out); again != out {
		t.Fatal("rebuildRoundupContent is not idempotent")
	} // The legacy rebuild equals the rebuild of the same content without the
	// legacy lines.
	cleanFM, cleanContent := bigWindowsRoundup(3, false)
	if clean := rebuildRoundupContent(cleanFM, cleanContent); out != clean {
		t.Fatalf("legacy rebuild differs from non-legacy rebuild:\n--- legacy\n%s\n--- clean\n%s", out, clean)
	}
}
