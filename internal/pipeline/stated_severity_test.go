package pipeline

import (
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func statedSeverityPipeline(scores map[string]float64) *Pipeline {
	v := NewCVEVerifier(nil, nil)
	for id, score := range scores {
		v.cacheMeta(id, &CVEMeta{Exists: true, CVSS: score, Verification: CVEVerification{Status: "verified", Source: "nvd"}})
	}
	return &Pipeline{cveVerifier: v}
}

func severityAndBasis(t *testing.T, briefYAML string) (string, SeverityBasis) {
	t.Helper()
	doc := parseBriefFrontmatter(briefYAML)
	if doc == nil {
		t.Fatalf("unparseable brief:\n%s", briefYAML)
	}
	severity, _ := doc["severity"].(string)
	var basis SeverityBasis
	if raw, ok := doc["severity_basis"].(map[string]any); ok {
		basis.Kind = SeverityBasisKind(stringFromAny(raw["kind"]))
		basis.Value = stringFromAny(raw["value"])
		basis.Rule = stringFromAny(raw["rule"])
		basis.Source = stringFromAny(raw["source"])
	}
	return severity, basis
}

// The CERT-Bund rating in a BSI advisory title is the source's own rating.
// The checker rejected model labels that disagreed with it ("the source
// explicitly states 'hoch' (high), whereas the brief characterizes it as
// 'medium'"), and no repair reconciled them.
func TestBSIAdvisoryTakesCertBundTitleRating(t *testing.T) {
	cases := []struct{ title, model, want string }{
		{"[UPDATE] [hoch] util-linux: Schwachstelle ermöglicht Umgehen von Sicherheitsvorkehrungen", "medium", "high"},
		{"[NEU] [UNGEPATCHT] [mittel] Flowise: Schwachstelle ermöglicht Umgehen von Sicherheitsvorkehrungen", "critical", "medium"},
		{"[NEU] [kritisch] IGEL UMS: Schwachstelle ermöglicht Erlangen von Administratorrechten", "high", "critical"},
		{"[UPDATE] [niedrig] Linux Kernel: Schwachstelle ermöglicht Denial of Service", "medium", "low"},
	}
	p := statedSeverityPipeline(nil)
	for _, c := range cases {
		item := scraper.RawItem{Source: "bsi", Title: c.title, URL: "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0001"}
		got, basis := severityAndBasis(t, p.normalizeSeverity("title: x\nseverity: "+c.model+"\n", item))
		if got != c.want || basis.Kind != SeveritySourceRating || basis.Rule != "cert-bund-rating/v1" || basis.Value != c.want {
			t.Errorf("%q: severity=%q basis=%+v, want %q from the CERT-Bund rating", c.title, got, basis, c.want)
		}
	}
	// A title without a rating leaves the model label, recorded as inference.
	got, basis := severityAndBasis(t, p.normalizeSeverity("title: x\nseverity: medium\n", scraper.RawItem{Source: "bsi", Title: "[NEU] Produkt: Schwachstelle"}))
	if got != "medium" || basis.Kind != SeverityModelInference {
		t.Errorf("unrated BSI title: severity=%q basis=%+v, want the model label as inference", got, basis)
	}
}

// Exploit trackers and oss-security state no rating of their own, so the
// checker compares the label with the primary CVE record's score ("the source
// specifies HIGH (CVSS 8.8), not CRITICAL").
func TestExploitTrackerBriefTakesPrimaryCVSSBand(t *testing.T) {
	item := scraper.RawItem{Source: "sploitus", Title: "Exploit for CVE-2026-50001", Content: "PoC for CVE-2026-50001 in Example Server."}
	brief := "title: 'Example Server: auth bypass (CVE-2026-50001)'\nseverity: critical\ncves:\n  - CVE-2026-50001\n"
	got, basis := severityAndBasis(t, statedSeverityPipeline(map[string]float64{"CVE-2026-50001": 8.8}).normalizeSeverity(brief, item))
	if got != "high" || basis.Kind != SeveritySourceCVSS || basis.Rule != "primary-cve-cvss-band/v1" || basis.Source != "nvd" {
		t.Fatalf("severity=%q basis=%+v, want high from the record's CVSS band", got, basis)
	}

	oss := scraper.RawItem{Source: "oss-security", Title: "CVE-2026-50001: Example Server", Content: "CVE-2026-50001 allows ..."}
	if got, _ := severityAndBasis(t, statedSeverityPipeline(map[string]float64{"CVE-2026-50001": 5.3}).normalizeSeverity(brief, oss)); got != "medium" {
		t.Fatalf("oss-security severity=%q, want medium for CVSS 5.3", got)
	}
}

func TestPrimaryCVSSBandStaysWithModelWhenItCannotBeStated(t *testing.T) {
	two := scraper.RawItem{Source: "sploitus", Title: "Exploits for CVE-2026-50001 and CVE-2026-50002", Content: "CVE-2026-50001 CVE-2026-50002"}
	twoBrief := "title: x\nseverity: critical\ncves:\n  - CVE-2026-50001\n  - CVE-2026-50002\n"
	exploited := "title: x\nseverity: critical\ncves:\n  - CVE-2026-50001\nexploitation_evidence:\n  status: confirmed_active\n  source_url: https://example.com/report\n"
	one := scraper.RawItem{Source: "sploitus", Title: "Exploit for CVE-2026-50001", Content: "CVE-2026-50001"}
	oneBrief := "title: x\nseverity: critical\ncves:\n  - CVE-2026-50001\n"
	cases := []struct {
		name   string
		p      *Pipeline
		item   scraper.RawItem
		brief  string
		reason string
	}{
		{"disagreeing records", statedSeverityPipeline(map[string]float64{"CVE-2026-50001": 9.8, "CVE-2026-50002": 6.1}), two, twoBrief, "records disagree on the band"},
		{"unscored record", statedSeverityPipeline(map[string]float64{"CVE-2026-50001": 9.8, "CVE-2026-50002": 0}), two, twoBrief, "one record has no score"},
		{"confirmed exploitation", statedSeverityPipeline(map[string]float64{"CVE-2026-50001": 7.5}), one, exploited, "urgency of exploited CVEs is operational"},
		{"vendor-rated source", statedSeverityPipeline(map[string]float64{"CVE-2026-50001": 6.5}), scraper.RawItem{Source: "msrc", Title: "CVE-2026-50001", Content: "CVE-2026-50001"}, oneBrief, "vendors rate on their own scale"},
		{"no verifier", &Pipeline{}, one, oneBrief, "no records loaded"},
	}
	for _, c := range cases {
		if got, basis := severityAndBasis(t, c.p.normalizeSeverity(c.brief, c.item)); got != "critical" || basis.Kind == SeveritySourceCVSS {
			t.Errorf("%s: severity=%q basis=%+v, want the model label kept (%s)", c.name, got, basis, c.reason)
		}
	}
}

// Advisory data, detector caps and the pipeline's rumour label keep their
// existing precedence over any CVE record score.
func TestStatedSeverityKeepsExistingPrecedence(t *testing.T) {
	p := statedSeverityPipeline(map[string]float64{"CVE-2026-50001": 9.8})
	nvd := scraper.RawItem{Source: "nvd", Title: "CVE-2026-50001", Content: "CVE-2026-50001", Metadata: map[string]string{"cvss": "5.0"}}
	if got, _ := severityAndBasis(t, p.normalizeSeverity("title: x\nseverity: critical\ncves:\n  - CVE-2026-50001\n", nvd)); got != "medium" {
		t.Errorf("nvd severity=%q, want medium from the item's own advisory data", got)
	}
	rumour := scraper.RawItem{Source: "sploitus", Title: "CVE-2026-50001", Content: "CVE-2026-50001"}
	if got, _ := severityAndBasis(t, p.normalizeSeverity("title: x\nseverity: rumour\ncves:\n  - CVE-2026-50001\n", rumour)); got != "rumour" {
		t.Errorf("rumour severity=%q, want rumour kept", got)
	}
}

// A grounding repair rewrites severity with the rest of the brief; the
// post-repair normalization restores the stated rating.
func TestStatedSeverityOverridesRepairedLabel(t *testing.T) {
	p := statedSeverityPipeline(map[string]float64{"CVE-2026-50001": 7.2})
	item := scraper.RawItem{Source: "sploitus", Title: "Exploit for CVE-2026-50001", Content: "CVE-2026-50001"}
	first := p.normalizeSeverity("title: x\nseverity: medium\ncves:\n  - CVE-2026-50001\n", item)
	repaired := setBriefSeverity(first, "critical")
	if got, basis := severityAndBasis(t, p.normalizeSeverity(repaired, item)); got != "high" || basis.Value != "high" {
		t.Fatalf("after repair severity=%q basis=%+v, want the stated band high", got, basis)
	}
}
