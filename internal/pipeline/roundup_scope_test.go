package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Fresh Microsoft CVEs have no CPEs and descriptions that never say
// "Microsoft". Once one CVE matches the vendor scope by description, the scope
// filter must not strip the others from the roundup's structured cves while
// their body sections are still added.
func TestRoundupFoldKeepsNewCVEsWithoutScopeSignals(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	const a, b = "CVE-2026-109454", "CVE-2026-119834"
	p.cveVerifier.cache[a] = &CVEMeta{Exists: true, CachedAt: time.Now(), SourceIdentifier: "secure@microsoft.com",
		Description: "Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allows an authorized attacker to perform spoofing over a network."}
	p.cveVerifier.cache[b] = &CVEMeta{Exists: true, CachedAt: time.Now(), SourceIdentifier: "secure@microsoft.com",
		Description: "Heap-based buffer overflow in Windows Subsystem for Linux allows an authorized attacker to elevate privileges locally."}

	for _, id := range []string{a, b} {
		item, ext := nvdRoundupItem(id)
		if !p.routeToRoundup(context.Background(), item, ext) {
			t.Fatalf("%s should fold into the roundup", id)
		}
	}

	entries, err := db.FindByVendorCycle(vendorCycleKey("Microsoft", time.Now().UTC()))
	if err != nil || len(entries) == 0 {
		t.Fatalf("find cycle: %v (%d entries)", err, len(entries))
	}
	d, err := db.GetDraft(entries[0].DraftID)
	if err != nil || d == nil {
		t.Fatalf("get draft: %v", err)
	}
	got := cveIDSet(structuredBundleCVEs(t, d.BriefYAML))
	for _, id := range []string{a, b} {
		if !got[id] {
			t.Errorf("structured cves missing %s: %v", id, got)
		}
	}
}

func structuredBundleCVEs(t *testing.T, briefYAML string) []BundleCVE {
	t.Helper()
	return structuredCVEsFromBrief(briefYAML)
}

// Exempting the scope filter must not make the enricher pick up every CVE ID
// mentioned anywhere in the roundup (body text, related links): only the CVEs
// the front matter lists are structured.
func TestRoundupFoldDoesNotStructureMentionedCVEs(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := newDedupTestPipeline(t, db)
	p.roundupConsolidation = true

	const a, b, other = "CVE-2026-109454", "CVE-2026-119834", "CVE-2026-55555"
	p.cveVerifier.cache[a] = &CVEMeta{Exists: true, CachedAt: time.Now(), SourceIdentifier: "secure@microsoft.com",
		Description: "Cross-site scripting in Microsoft Office SharePoint allows spoofing."}
	p.cveVerifier.cache[b] = &CVEMeta{Exists: true, CachedAt: time.Now(), SourceIdentifier: "secure@microsoft.com",
		Description: "Heap-based buffer overflow in Windows Subsystem for Linux allows elevation of privilege."}
	p.cveVerifier.cache[other] = &CVEMeta{Exists: true, CachedAt: time.Now(), SourceIdentifier: "security@android.com",
		CPEs: []string{"cpe:2.3:o:google:android:*:*:*:*:*:*:*:*"}, Description: "Flaw in Android."}

	for _, id := range []string{a, b} {
		item, ext := nvdRoundupItem(id)
		item.Content = "A vulnerability allows privilege escalation, related " + other + "."
		ext.Summary = "See related " + other + " for details."
		if !p.routeToRoundup(context.Background(), item, ext) {
			t.Fatalf("%s should fold into the roundup", id)
		}
	}

	entries, err := db.FindByVendorCycle(vendorCycleKey("Microsoft", time.Now().UTC()))
	if err != nil || len(entries) == 0 {
		t.Fatalf("find cycle: %v (%d entries)", err, len(entries))
	}
	d, err := db.GetDraft(entries[0].DraftID)
	if err != nil || d == nil {
		t.Fatalf("get draft: %v", err)
	}
	if !strings.Contains(d.BriefYAML, other) {
		t.Skipf("%s is not mentioned in the roundup; test would be vacuous", other)
	}
	got := cveIDSet(structuredCVEsFromBrief(d.BriefYAML))
	if got[other] {
		t.Errorf("mentioned CVE %s leaked into structured cves: %v", other, got)
	}
	for _, id := range []string{a, b} {
		if !got[id] {
			t.Errorf("structured cves missing %s: %v", id, got)
		}
	}
}
