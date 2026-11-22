package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestRoundupFoldScopesExtractedCVEsToSourceEvidence(t *testing.T) {
	const target, unrelated, prefix = "CVE-2026-111306", "CVE-2026-118707", "CVE-2026-11130"
	const first, second, historical = "CVE-2026-111301", "CVE-2026-111302", "CVE-2024-4577"
	tests := []struct {
		name       string
		item       scraper.RawItem
		extraction *ExtractionResult
		want       []string
		unwant     []string
	}{
		{
			name: "NVD record keeps only its own CVE",
			item: scraper.RawItem{
				SourceID: "nvd:" + target,
				Source:   "nvd",
				Title:    target + " — Microsoft Office Word heap-based buffer overflow",
				Content:  "A heap-based buffer overflow in Microsoft Office Word allows code execution. The advisory also references " + unrelated + ".",
				URL:      "https://nvd.nist.gov/vuln/detail/" + target,
			},
			extraction: &ExtractionResult{CVEs: []string{target, unrelated, prefix}, AffectedVendors: []string{"Microsoft"}},
			want:       []string{target},
			unwant:     []string{unrelated, prefix},
		},
		{
			name: "vendor roundup keeps every CVE named by its source",
			item: scraper.RawItem{
				SourceID:            "msrc:november-2026",
				Source:              "msrc",
				Title:               "Microsoft security updates — November 2026",
				Content:             "Microsoft's November security updates address " + first + " and " + second + ". For comparison, the older " + historical + " was a different issue.",
				URL:                 "https://msrc.microsoft.com/update-guide/releaseNote/november-2026",
				BodyCVEsAreSubjects: true,
			},
			extraction: &ExtractionResult{CVEs: []string{first, second, historical}, AffectedVendors: []string{"Microsoft"}},
			want:       []string{first, second},
			unwant:     []string{historical},
		},
		{
			name: "previously exploitable wording is not a historical CVE",
			item: scraper.RawItem{
				SourceID:            "msrc:previously-exploitable",
				Source:              "msrc",
				Title:               "Microsoft security update",
				Content:             "The update fixes CVE-2026-111303, which previously allowed privilege escalation.",
				URL:                 "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111303",
				BodyCVEsAreSubjects: true,
			},
			extraction: &ExtractionResult{CVEs: []string{"CVE-2026-111303"}, AffectedVendors: []string{"Microsoft"}},
			want:       []string{"CVE-2026-111303"},
		},
		{
			name: "fixing a previously disclosed CVE remains a current subject",
			item: scraper.RawItem{
				SourceID:            "msrc:previously-disclosed",
				Source:              "msrc",
				Title:               "Microsoft security update",
				Content:             "This update fixes the previously disclosed CVE-2026-111305.",
				URL:                 "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111305",
				BodyCVEsAreSubjects: true,
			},
			extraction: &ExtractionResult{CVEs: []string{"CVE-2026-111305"}, AffectedVendors: []string{"Microsoft"}},
			want:       []string{"CVE-2026-111305"},
		},
		{
			name: "unicode before a body CVE does not panic or lose it",
			item: scraper.RawItem{
				SourceID:            "msrc:unicode",
				Source:              "msrc",
				Title:               "Microsoft security update",
				Content:             "İ fixes CVE-2026-111304.",
				URL:                 "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111304",
				BodyCVEsAreSubjects: true,
			},
			extraction: &ExtractionResult{CVEs: []string{"CVE-2026-111304"}, AffectedVendors: []string{"Microsoft"}},
			want:       []string{"CVE-2026-111304"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			p := newDedupTestPipeline(t, db)
			p.roundupConsolidation = true
			if !p.routeToRoundup(context.Background(), tt.item, tt.extraction) {
				t.Fatal("source was not routed to the vendor roundup")
			}
			entries, err := db.FindByVendorCycle(vendorCycleKey("Microsoft", time.Now().UTC()))
			if err != nil || len(entries) == 0 {
				t.Fatalf("find roundup: %v (%d entries)", err, len(entries))
			}
			draft, err := db.GetDraft(entries[0].DraftID)
			if err != nil || draft == nil {
				t.Fatalf("get roundup: %v", err)
			}
			ids := cveIDSet(structuredCVEsFromBrief(draft.BriefYAML))
			for _, id := range tt.want {
				if !ids[id] {
					t.Errorf("source-supported CVE %s missing from roundup: %v", id, ids)
				}
			}
			for _, id := range tt.unwant {
				if ids[id] || strings.Contains(draft.BriefYAML, "## "+id+"\n") {
					t.Errorf("unsubstantiated CVE %s leaked into roundup frontmatter or content", id)
				}
			}
		})
	}
}

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
