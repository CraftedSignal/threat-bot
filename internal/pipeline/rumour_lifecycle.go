package pipeline

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"

	"golang.org/x/net/publicsuffix"
)

func mergeRumourLifecycle(frontmatter map[string]any, extraction *ExtractionResult) bool {
	if extraction == nil || extraction.ClaimAssessment == nil {
		return false
	}
	if !rumourLifecycleActive(frontmatter) {
		return false
	}
	raw, _ := frontmatter["claim_state"].(string)
	current := ClaimState(strings.ToLower(strings.TrimSpace(raw)))
	assessment := *extraction.ClaimAssessment
	var existing []ClaimEvidence
	if raw, ok := frontmatter["evidence"]; ok {
		if data, err := yaml.Marshal(raw); err == nil {
			_ = yaml.Unmarshal(data, &existing)
		}
	}
	assessment.Evidence = mergeClaimEvidence(existing, assessment.Evidence)
	if raw, ok := frontmatter["gaps"].([]any); ok {
		for _, gap := range raw {
			assessment.Gaps = appendUniqueString(assessment.Gaps, fmt.Sprint(gap))
		}
	}
	next := NextClaimState(current, assessment)
	changed := next != current || !reflect.DeepEqual(assessment.Evidence, existing)
	if !changed {
		return false
	}
	frontmatter["claim_state"] = string(next)
	frontmatter["evidence"] = assessment.Evidence
	frontmatter["gaps"] = assessment.Gaps
	switch next {
	case ClaimVerified:
		frontmatter["type"] = "advisory"
		if strings.EqualFold(fmt.Sprint(frontmatter["severity"]), "rumour") {
			frontmatter["severity"] = "medium"
		}
		frontmatter["unverified_notice"] = ""
	case ClaimDisputed, ClaimRetracted:
		frontmatter["type"] = "rumour"
		frontmatter["severity"] = "rumour"
		frontmatter["unverified_notice"] = "This report is " + string(next) + " and retained for historical context; do not follow its original recommendations."
	}
	return true
}

func mergeClaimEvidence(groups ...[]ClaimEvidence) []ClaimEvidence {
	seen := map[string]int{}
	var out []ClaimEvidence
	for _, group := range groups {
		for _, e := range group {
			key := strings.ToLower(strings.TrimSpace(e.Type) + "|" + strings.TrimSpace(e.SourceURL) + "|" + strings.TrimSpace(e.Detail))
			if key == "||" {
				continue
			}
			if index, ok := seen[key]; ok {
				if attestedClaimEvidence(e) && !attestedClaimEvidence(out[index]) {
					out[index] = e
				}
				continue
			}
			seen[key] = len(out)
			out = append(out, e)
		}
	}
	return out
}

type ClaimState string

// ClaimEvidenceProvenance is pipeline-attested, never a model JSON field.
// The digest binds it to the precise attributed evidence across persistence.
type ClaimEvidenceProvenance struct {
	SourceURL      string `yaml:"source_url"`
	SourceID       string `yaml:"source_id"`
	Source         string `yaml:"source"`
	EvidenceHash   string `yaml:"evidence_hash"`
	TrustedPrimary bool   `yaml:"trusted_primary"`
	Independent    bool   `yaml:"independent"`
}

func claimEvidenceHash(e ClaimEvidence) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(e.Type+"\n"+strings.TrimSpace(e.SourceURL)+"\n"+strings.TrimSpace(e.Detail))))
}

func attestedClaimEvidence(e ClaimEvidence) bool {
	p := e.Provenance
	return p != nil && p.SourceURL == e.SourceURL && p.EvidenceHash == claimEvidenceHash(e) && claimEvidenceLineage(e) != ""
}

func trustedClaimPrimary(item scraper.RawItem, vendors []string) bool {
	u, err := url.Parse(item.URL)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if item.Source == "nvd" && host == "nvd.nist.gov" {
		return true
	}
	if item.Source == "cisa-kev" && hasDomainSuffix(host, "cisa.gov") {
		return true
	}
	if item.Source == "ghsa" && host == "github.com" && strings.HasPrefix(u.Path, "/advisories/") {
		return true
	}
	for _, vendor := range vendors {
		if hostnameMatchesVendor(item.URL, vendor) {
			return true
		}
	}
	return false
}

const (
	ClaimReported  ClaimState = "reported"
	ClaimDisputed  ClaimState = "disputed"
	ClaimRetracted ClaimState = "retracted"
	ClaimVerified  ClaimState = "verified"
)

// KnownClaimState reports whether state is a rumour lifecycle state.
func KnownClaimState(state string) bool {
	switch ClaimState(strings.ToLower(strings.TrimSpace(state))) {
	case ClaimReported, ClaimDisputed, ClaimRetracted, ClaimVerified:
		return true
	}
	return false
}

// rumourLifecycleActive reports whether a brief started a rumour lifecycle.
// Only those carry a known claim_state. fmt.Sprint of a missing value is
// "<nil>", which once passed the lifecycle guard and stamped claim_state
// "<nil>" plus claim evidence on ordinary advisories.
func rumourLifecycleActive(frontmatter map[string]any) bool {
	raw, _ := frontmatter["claim_state"].(string)
	return KnownClaimState(raw)
}

func IndependentEvidenceLineages(evidence []ClaimEvidence) int {
	seen := map[string]bool{}
	for _, e := range evidence {
		if e.Type != "artifact" && e.Type != "first_party_observation" && e.Type != "authoritative_primary" {
			continue
		}
		if lineage := claimEvidenceLineage(e); lineage != "" {
			seen[lineage] = true
		}
	}
	return len(seen)
}

// claimEvidenceLineage requires an attributed statement and groups it by
// publisher domain. The evidence schema has no independently verified author
// or citation lineage, so separate paths, subdomains, and posts cannot establish
// independence. This deliberately counts shared-platform reports conservatively.
func claimEvidenceLineage(e ClaimEvidence) string {
	detail := strings.TrimSpace(e.Detail)
	if detail == "" || isPlaceholder(detail) {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(e.SourceURL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || net.ParseIP(host) != nil || strings.HasSuffix(host, ".local") {
		return ""
	}
	lineage, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	if lineage == "twitter.com" {
		lineage = "x.com"
	}
	return lineage
}

func NextClaimState(current ClaimState, a ClaimAssessment) ClaimState {
	status := strings.ToLower(strings.TrimSpace(a.Status))
	for _, e := range a.Evidence {
		if !attestedClaimEvidence(e) {
			continue
		}
		detail := strings.ToLower(e.Detail)
		switch status {
		case "retracted", "withdrawn":
			if e.Provenance.TrustedPrimary && (strings.Contains(detail, "retract") || strings.Contains(detail, "withdraw")) {
				return ClaimRetracted
			}
		case "disputed", "contradicted":
			if strings.Contains(detail, "disput") || strings.Contains(detail, "contradict") {
				return ClaimDisputed
			}
		}
	}
	authoritative := false
	artifacts := []ClaimEvidence{}
	for _, e := range a.Evidence {
		if e.Type == "authoritative_primary" && attestedClaimEvidence(e) && e.Provenance.TrustedPrimary {
			authoritative = true
		}
		if e.Type == "artifact" && attestedClaimEvidence(e) && e.Provenance.Independent {
			artifacts = append(artifacts, e)
		}
	}
	if authoritative || IndependentEvidenceLineages(artifacts) >= 2 {
		return ClaimVerified
	}
	if current == "" {
		return ClaimReported
	}
	return current
}
