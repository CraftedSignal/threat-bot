package pipeline

import (
	"regexp"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// certBundRating is the risk marker CERT-Bund puts in every WID advisory title
// ("[UPDATE] [hoch] util-linux: ..."), next to markers such as [NEU] and
// [UNGEPATCHT]. It is the source's own rating of the advisory.
var certBundRating = regexp.MustCompile(`(?i)\[(niedrig|mittel|hoch|kritisch)\]`)

var certBundSeverity = map[string]string{"niedrig": "low", "mittel": "medium", "hoch": "high", "kritisch": "critical"}

// certBundTitleSeverity returns the severity a BSI advisory states in its
// title, or "" for any other source or a title without a rating.
func certBundTitleSeverity(item scraper.RawItem) string {
	if item.Source != "bsi" {
		return ""
	}
	if m := certBundRating.FindStringSubmatch(item.Title); m != nil {
		return certBundSeverity[strings.ToLower(m[1])]
	}
	return ""
}

// cvssBand is the qualitative rating of a CVSS base score: 9.0 and above
// critical, 7.0-8.9 high, 4.0-6.9 medium, below that low. A score outside
// (0, 10] has no band.
func cvssBand(score float64) string {
	switch {
	case score <= 0 || score > 10:
		return ""
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	}
	return "low"
}

// cvssBandSource reports whether a source's severity is taken from the CVSS
// band of the CVE records it reports. Exploit trackers and mailing-list
// disclosures state no rating of their own, so the grounding checker compares
// a model-picked label with the record's score. Vendor advisories (MSRC
// "Important", PSIRT "High", ...) rate on their own scale, and KEV items are
// exploited, where urgency is an operational judgement rather than the base
// score, so those keep their current handling.
func cvssBandSource(source string) bool {
	return isExploitTracker(source) || source == "oss-security"
}

// normalizeSeverity sets the severity a source states for itself, once CVE
// verification has loaded the brief's primary records. In order:
//   - nvd/ghsa advisory data and detection-rule caps keep their existing
//     handling in normalizeDetectionSeverity, as does the pipeline's "rumour";
//   - a BSI advisory takes its CERT-Bund title rating;
//   - an exploit-tracker or oss-security brief without confirmed exploitation
//     takes the CVSS band all of its primary CVE records agree on.
//
// The model's label stands only where the source states no rating. The
// checker compares severity with exactly these stated ratings, and the repair
// step could not reconcile them (1 of 34 severity findings repaired), so the
// mismatch cost a full repair cycle before quarantine. Running again after a
// repair keeps the repaired brief from reintroducing a model label.
func (p *Pipeline) normalizeSeverity(briefYAML string, item scraper.RawItem) string {
	current, _ := parseBriefFrontmatter(briefYAML)["severity"].(string)
	if structuredAdvisorySeverity(item) != "" || detectionSeverityCap(item) != "" || strings.EqualFold(strings.TrimSpace(current), "rumour") {
		return normalizeDetectionSeverity(briefYAML, item)
	}
	if rating := certBundTitleSeverity(item); rating != "" {
		return setSeverityBasis(setBriefSeverity(briefYAML, rating), SeverityBasis{Kind: SeveritySourceRating, Source: item.Source, SourceURL: item.URL, Rule: "cert-bund-rating/v1"})
	}
	if cvssBandSource(item.Source) && !confirmedExploitationEvidence(briefYAML) {
		if band, id, recordSource := p.primaryCVSSBand(item, briefYAML); band != "" {
			return setSeverityBasis(setBriefSeverity(briefYAML, band), SeverityBasis{Kind: SeveritySourceCVSS, Source: recordSource, SourceURL: "https://nvd.nist.gov/vuln/detail/" + id, Rule: "primary-cve-cvss-band/v1"})
		}
	}
	return normalizeDetectionSeverity(briefYAML, item)
}

// primaryCVSSBand returns the CVSS band shared by every primary CVE record of
// the brief (the targets the source itself asserts), with the first record's
// ID and verification source. Any record that is unverified, lacks a score or
// falls in another band yields "": a disagreement needs editorial judgement.
func (p *Pipeline) primaryCVSSBand(item scraper.RawItem, briefYAML string) (band, id, recordSource string) {
	if p.cveVerifier == nil {
		return "", "", ""
	}
	for _, cve := range groundingPrimaryCVEs(item, briefYAML) {
		meta := p.cveVerifier.GetMeta(cve)
		if meta == nil || !meta.Exists || meta.Verification.Status != "verified" {
			return "", "", ""
		}
		b := cvssBand(meta.CVSS)
		if b == "" || (band != "" && b != band) {
			return "", "", ""
		}
		if band == "" {
			band, id, recordSource = b, cve, meta.Verification.Source
		}
	}
	return band, id, recordSource
}
