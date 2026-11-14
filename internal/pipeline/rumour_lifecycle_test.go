package pipeline

import "testing"

func TestIndependentEvidenceLineages(t *testing.T) {
	one := []ClaimEvidence{{Type: "artifact", Detail: "reproduction", SourceURL: "https://lab.example/poc"}, {Type: "corroboration", Detail: "cites same", SourceURL: "https://lab.example/poc#result"}}
	if got := IndependentEvidenceLineages(one); got != 1 {
		t.Fatalf("lineages=%d", got)
	}
	two := append(one, ClaimEvidence{Type: "artifact", Detail: "independent reproduction", SourceURL: "https://other.example/repro"})
	if got := IndependentEvidenceLineages(two); got != 2 {
		t.Fatalf("lineages=%d", got)
	}
}

func TestRumourLifecycleTransitions(t *testing.T) {
	base := ClaimAssessment{Likelihood: "likely", Evidence: []ClaimEvidence{{Type: "first_party_observation", Detail: "report", SourceURL: "https://a.example/post"}}}
	if got := NextClaimState(ClaimReported, base); got != ClaimReported {
		t.Fatalf("agreement promoted to %s", got)
	}
	verified := base
	verified.Evidence = []ClaimEvidence{{Type: "authoritative_primary", Detail: "vendor confirms", SourceURL: "https://vendor.example/advisory"}}
	if got := NextClaimState(ClaimReported, verified); got != ClaimVerified {
		t.Fatalf("vendor => %s", got)
	}
	disputed := base
	disputed.Status = "disputed"
	if got := NextClaimState(ClaimReported, disputed); got != ClaimDisputed {
		t.Fatalf("contradiction => %s", got)
	}
	retracted := base
	retracted.Status = "retracted"
	if got := NextClaimState(ClaimVerified, retracted); got != ClaimRetracted {
		t.Fatalf("withdrawal => %s", got)
	}
}
