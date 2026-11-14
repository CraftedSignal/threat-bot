package publisher

import (
	"slices"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestEPSSRefresh_DetectsChanges(t *testing.T) {
	old := BundleCVE{ID: "CVE-2026-1234", EPSS: 0.50, EPSSPercentile: 0.80, CVSS: 9.8, KEV: false}
	newEPSS := float64(0.87)
	newPct := float64(0.99)
	changed, updated := applyEPSSUpdate(old, newEPSS, newPct, kevNotListed, 0.01)
	if !changed {
		t.Error("expected change detected")
	}
	if updated.EPSS != 0.87 || updated.EPSSPercentile != 0.99 {
		t.Errorf("unexpected updated values: %+v", updated)
	}
}

func TestEPSSRefresh_BelowThreshold(t *testing.T) {
	old := BundleCVE{ID: "CVE-2026-1234", EPSS: 0.500, EPSSPercentile: 0.80, CVSS: 9.8}
	changed, _ := applyEPSSUpdate(old, 0.505, 0.81, kevNotListed, 0.01)
	if changed {
		t.Error("change below threshold should be ignored")
	}
}

func TestEPSSRefresh_KEVFlip(t *testing.T) {
	old := BundleCVE{ID: "CVE-2026-1234", EPSS: 0.50, KEV: false}
	changed, updated := applyEPSSUpdate(old, 0.50, 0.80, kevListed, 0.01)
	if !changed {
		t.Error("KEV flip should be detected as change")
	}
	if !updated.KEV {
		t.Error("expected KEV=true")
	}
	if updated.KEVStatus != "true" {
		t.Fatalf("expected known true KEV status, got %q", updated.KEVStatus)
	}
}

// Until the KEV catalog loads, membership is unknown: the refresh must leave a
// CVE's KEV fields as they are instead of writing kev_status "false".
func TestEPSSRefreshLeavesKEVAloneWhileCatalogUnknown(t *testing.T) {
	for _, old := range []BundleCVE{
		{ID: "CVE-2026-84869", EPSS: 0.50, KEV: true, KEVStatus: "true"},
		{ID: "CVE-2026-1234", EPSS: 0.50, KEVStatus: "unknown"},
	} {
		changed, updated := applyEPSSUpdate(old, 0.50, 0.80, kevUnknown, 0.01)
		if changed {
			t.Errorf("%s: unknown KEV status counted as a change", old.ID)
		}
		if updated.KEV != old.KEV || updated.KEVStatus != old.KEVStatus {
			t.Errorf("%s: KEV = %v/%q, want unchanged %v/%q", old.ID, updated.KEV, updated.KEVStatus, old.KEV, old.KEVStatus)
		}
	}
}

func TestRefreshSegmentEPSSReadsKEVCatalog(t *testing.T) {
	cache := epssCacheServing(t, "#model_version:v2025.03.14\ncve,epss,percentile\nCVE-2026-84869,0.004,0.6\nCVE-2026-0002,0.2,0.5\n")
	if err := cache.Refresh(); err != nil {
		t.Fatal(err)
	}
	segment := func() *SegmentContent {
		return &SegmentContent{Briefs: []BundleBrief{{ID: "a", CVEs: []BundleCVE{
			{ID: "CVE-2026-84869", EPSS: 0.004, KEVStatus: "false"},
			{ID: "CVE-2026-0002", EPSS: 0.2, KEVStatus: "unknown"},
		}}}}
	}

	catalog := scraper.NewKEVCatalog()
	unknown := segment()
	if refreshSegmentEPSS(unknown, cache, catalog, 0.01, &Changelog{}) {
		t.Fatalf("unloaded catalog changed the segment: %#v", unknown.Briefs[0].CVEs)
	}

	if err := catalog.Replace([]string{"CVE-2026-84869"}); err != nil {
		t.Fatal(err)
	}
	loaded := segment()
	if !refreshSegmentEPSS(loaded, cache, catalog, 0.01, &Changelog{}) {
		t.Fatal("KEV listing did not change the segment")
	}
	got := loaded.Briefs[0]
	if cve := got.CVEs[0]; !cve.KEV || cve.KEVStatus != "true" {
		t.Errorf("CVE-2026-84869 = %v/%q, want KEV true", cve.KEV, cve.KEVStatus)
	}
	if cve := got.CVEs[1]; cve.KEV || cve.KEVStatus != "false" {
		t.Errorf("CVE-2026-0002 = %v/%q, want known false", cve.KEV, cve.KEVStatus)
	}
	if !slices.Contains(got.PrioritySignals, "kev") {
		t.Errorf("priority signals %v lack kev", got.PrioritySignals)
	}
}
