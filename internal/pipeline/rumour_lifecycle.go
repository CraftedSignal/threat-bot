package pipeline

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func mergeRumourLifecycle(frontmatter map[string]any, extraction *ExtractionResult) bool {
	if extraction == nil || extraction.ClaimAssessment == nil {
		return false
	}
	current := ClaimState(strings.ToLower(strings.TrimSpace(fmt.Sprint(frontmatter["claim_state"]))))
	if current == "" {
		return false
	}
	assessment := *extraction.ClaimAssessment
	var existing []ClaimEvidence
	if raw, ok := frontmatter["evidence"]; ok {
		if data, err := json.Marshal(raw); err == nil {
			_ = json.Unmarshal(data, &existing)
		}
	}
	assessment.Evidence = mergeClaimEvidence(existing, assessment.Evidence)
	if raw, ok := frontmatter["gaps"].([]any); ok {
		for _, gap := range raw {
			assessment.Gaps = appendUniqueString(assessment.Gaps, fmt.Sprint(gap))
		}
	}
	next := NextClaimState(current, assessment)
	changed := next != current || len(assessment.Evidence) != len(existing)
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
	seen := map[string]bool{}
	var out []ClaimEvidence
	for _, group := range groups {
		for _, e := range group {
			key := strings.ToLower(strings.TrimSpace(e.Type) + "|" + strings.TrimSpace(e.SourceURL) + "|" + strings.TrimSpace(e.Detail))
			if key == "||" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, e)
		}
	}
	return out
}

type ClaimState string

const (
	ClaimReported  ClaimState = "reported"
	ClaimDisputed  ClaimState = "disputed"
	ClaimRetracted ClaimState = "retracted"
	ClaimVerified  ClaimState = "verified"
)

func IndependentEvidenceLineages(evidence []ClaimEvidence) int {
	seen := map[string]bool{}
	for _, e := range evidence {
		if e.Type != "artifact" && e.Type != "first_party_observation" && e.Type != "authoritative_primary" {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(e.SourceURL))
		if err != nil || u.Hostname() == "" {
			continue
		}
		u.Fragment = ""
		key := strings.ToLower(u.Hostname() + u.Path)
		seen[key] = true
	}
	return len(seen)
}
func NextClaimState(current ClaimState, a ClaimAssessment) ClaimState {
	switch strings.ToLower(strings.TrimSpace(a.Status)) {
	case "retracted", "withdrawn":
		return ClaimRetracted
	case "disputed", "contradicted":
		return ClaimDisputed
	}
	authoritative := false
	artifacts := []ClaimEvidence{}
	for _, e := range a.Evidence {
		if e.Type == "authoritative_primary" {
			authoritative = true
		}
		if e.Type == "artifact" && strings.TrimSpace(e.Detail) != "" {
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
