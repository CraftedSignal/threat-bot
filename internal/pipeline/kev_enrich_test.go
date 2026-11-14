package pipeline

import (
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// CVE-2026-84869 (ConnectWise ScreenConnect) is in the live CISA KEV catalog
// (added 2026-09-11) but was published with kev: false, because the set the
// enricher read was created empty and never filled.
const screenConnectKEVBrief = `id: brief-2026-09-07-screenconnect-worm
title: Worm-like Campaign Leveraging Modified ScreenConnect Clients (CVE-2026-84869)
summary: Attackers abuse CVE-2026-84869 in ConnectWise ScreenConnect.
severity: high
published_at: "2026-09-07T11:55:13Z"
affected_vendors:
  - ConnectWise
affected_products:
  - ScreenConnect
cves:
  - id: CVE-2026-84869
    kev: false
    kev_status: unknown
`

func loadedKEVCatalog(t *testing.T, ids ...string) *scraper.KEVCatalog {
	t.Helper()
	catalog := scraper.NewKEVCatalog()
	if err := catalog.Replace(ids); err != nil {
		t.Fatalf("loading KEV catalog: %v", err)
	}
	return catalog
}

func screenConnectVerifier(kev *scraper.KEVCatalog) *CVEVerifier {
	verifier := NewCVEVerifier(nil, kev)
	verifier.cache["CVE-2026-84869"] = &CVEMeta{
		Exists:      true,
		CVSS:        9.9,
		CPEs:        []string{"cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*"},
		Description: "ConnectWise ScreenConnect contains an improper privilege management vulnerability.",
		CachedAt:    time.Now(),
	}
	return verifier
}

type enrichedKEV struct {
	CVEs                 []BundleCVE           `yaml:"cves"`
	Exploited            bool                  `yaml:"exploited"`
	ExploitationEvidence *ExploitationEvidence `yaml:"exploitation_evidence"`
}

func enrichKEV(t *testing.T, verifier *CVEVerifier) enrichedKEV {
	t.Helper()
	out, cves := NewCVEEnricher(verifier).Enrich(screenConnectKEVBrief, nil)
	var parsed enrichedKEV
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("enriched brief is not YAML: %v\n%s", err, out)
	}
	if len(cves) != 1 || len(parsed.CVEs) != 1 || parsed.CVEs[0].ID != "CVE-2026-84869" {
		t.Fatalf("enriched CVEs = %#v (returned %#v)\n%s", parsed.CVEs, cves, out)
	}
	return parsed
}

func TestCVEEnricherMarksKEVListedCVE(t *testing.T) {
	got := enrichKEV(t, screenConnectVerifier(loadedKEVCatalog(t, "CVE-2026-84869")))
	if cve := got.CVEs[0]; !cve.KEV || cve.KEVStatus != "true" {
		t.Fatalf("CVE-2026-84869 kev = %v, kev_status = %q; want true, \"true\"", cve.KEV, cve.KEVStatus)
	}
	if !got.Exploited || got.ExploitationEvidence == nil || got.ExploitationEvidence.Status != "confirmed_active" {
		t.Fatalf("KEV listing did not set attributed exploitation: exploited=%v evidence=%#v", got.Exploited, got.ExploitationEvidence)
	}
}

func TestCVEEnricherKEVStatusFalseOnlyWhenCatalogLoaded(t *testing.T) {
	notListed := enrichKEV(t, screenConnectVerifier(loadedKEVCatalog(t, "CVE-2021-44228")))
	if cve := notListed.CVEs[0]; cve.KEV || cve.KEVStatus != "false" {
		t.Errorf("loaded catalog without the CVE: kev = %v, kev_status = %q; want false, \"false\"", cve.KEV, cve.KEVStatus)
	}

	for name, catalog := range map[string]*scraper.KEVCatalog{"not loaded": scraper.NewKEVCatalog(), "nil": nil} {
		unknown := enrichKEV(t, screenConnectVerifier(catalog))
		if cve := unknown.CVEs[0]; cve.KEV || cve.KEVStatus != "unknown" {
			t.Errorf("%s catalog: kev = %v, kev_status = %q; want false, \"unknown\"", name, cve.KEV, cve.KEVStatus)
		}
	}
}

// NVD metadata is cached for a day; KEV membership must come from the catalog
// as it is now, so a CVE CISA lists after its NVD record was cached is marked.
func TestCVEEnricherReadsCurrentKEVCatalog(t *testing.T) {
	catalog := loadedKEVCatalog(t, "CVE-2021-44228")
	verifier := screenConnectVerifier(catalog)
	if before := enrichKEV(t, verifier); before.CVEs[0].KEV {
		t.Fatal("CVE marked KEV before CISA listed it")
	}

	if err := catalog.Replace([]string{"CVE-2021-44228", "CVE-2026-84869"}); err != nil {
		t.Fatal(err)
	}
	if after := enrichKEV(t, verifier); !after.CVEs[0].KEV || after.CVEs[0].KEVStatus != "true" {
		t.Fatalf("after the KEV refresh: kev = %v, kev_status = %q; want true", after.CVEs[0].KEV, after.CVEs[0].KEVStatus)
	}
}

// The verifier fetches NVD records; KEV membership is read from the catalog
// the KEV source fills, not from a set captured at startup.
func TestCVEVerifierKEVLookup(t *testing.T) {
	verifier := NewCVEVerifier(nil, loadedKEVCatalog(t, "CVE-2026-84869"))
	if listed, known := verifier.KEV("cve-2026-84869"); !listed || !known {
		t.Fatalf("KEV(CVE-2026-84869) = (%v, %v), want listed", listed, known)
	}
	if listed, known := NewCVEVerifier(nil, nil).KEV("CVE-2026-84869"); listed || known {
		t.Fatalf("KEV without a catalog = (%v, %v), want unknown", listed, known)
	}
}

func TestRoundupCarvesOutKEVListedCVEFromCatalog(t *testing.T) {
	p := &Pipeline{kev: loadedKEVCatalog(t, "CVE-2026-84869")}
	item := scraper.RawItem{Title: "ConnectWise security update", Content: "Fixes CVE-2026-84869."}
	if !p.isCarvedOutFromRoundup(item, &ExtractionResult{CVEs: []string{"cve-2026-84869"}}) {
		t.Fatal("KEV-listed CVE was not carved out of the roundup")
	}
	if p.isCarvedOutFromRoundup(item, &ExtractionResult{CVEs: []string{"CVE-2026-0001"}}) {
		t.Fatal("CVE outside KEV was carved out")
	}
	unloaded := &Pipeline{kev: scraper.NewKEVCatalog()}
	if unloaded.isCarvedOutFromRoundup(item, &ExtractionResult{CVEs: []string{"CVE-2026-84869"}}) {
		t.Fatal("unloaded catalog carved a CVE out")
	}
}

// KEV membership does not depend on NVD: Verify checks only five CVEs per
// brief and NVD often rate-limits, so a listed CVE without an NVD record must
// still be marked.
func TestCVEEnricherMarksKEVListedCVEWithoutNVDRecord(t *testing.T) {
	verifier := NewCVEVerifier(nil, loadedKEVCatalog(t, "CVE-2026-84869"))
	out, cves := NewCVEEnricher(verifier).Enrich(screenConnectKEVBrief, nil)
	var parsed enrichedKEV
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.CVEs) != 1 || !parsed.CVEs[0].KEV || parsed.CVEs[0].KEVStatus != "true" {
		t.Fatalf("unverified KEV CVE = %#v, want kev true\n%s", parsed.CVEs, out)
	}
	if len(cves) != 1 || !cves[0].KEV {
		t.Fatalf("returned CVEs %#v do not carry KEV for priority", cves)
	}
}

// A KEV outage at startup must not erase a listing an earlier enrichment
// recorded on a brief being updated.
func TestCVEEnricherKeepsPriorKEVWhileCatalogUnknown(t *testing.T) {
	brief := strings.Replace(screenConnectKEVBrief, "    kev: false\n    kev_status: unknown\n", "    kev: true\n    kev_status: \"true\"\n", 1)
	out, _ := NewCVEEnricher(screenConnectVerifier(scraper.NewKEVCatalog())).Enrich(brief, nil)
	var parsed enrichedKEV
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.CVEs) != 1 || !parsed.CVEs[0].KEV || parsed.CVEs[0].KEVStatus != "true" {
		t.Fatalf("prior KEV listing lost while the catalog is unknown: %#v\n%s", parsed.CVEs, out)
	}
}
