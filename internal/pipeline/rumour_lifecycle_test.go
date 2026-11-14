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
	verified.Evidence = attestEvidenceForTest(verified.Evidence, true, false)
	if got := NextClaimState(ClaimReported, verified); got != ClaimVerified {
		t.Fatalf("vendor => %s", got)
	}
	disputed := base
	disputed.Status = "disputed"
	disputed.Evidence = attestEvidenceForTest([]ClaimEvidence{{Type: "first_party_observation", Detail: "We dispute this specific reported claim.", SourceURL: "https://a.example/post"}}, false, false)
	if got := NextClaimState(ClaimReported, disputed); got != ClaimDisputed {
		t.Fatalf("contradiction => %s", got)
	}
	retracted := base
	retracted.Status = "retracted"
	retracted.Evidence = attestEvidenceForTest([]ClaimEvidence{{Type: "authoritative_primary", Detail: "We retract our previous reported claim.", SourceURL: "https://a.example/post"}}, true, false)
	if got := NextClaimState(ClaimVerified, retracted); got != ClaimRetracted {
		t.Fatalf("withdrawal => %s", got)
	}
}

func TestRumourLifecycleRequiresAttributedPrimaryEvidence(t *testing.T) {
	for name, evidence := range map[string]ClaimEvidence{
		"empty evidence":      {Type: "authoritative_primary"},
		"missing source":      {Type: "authoritative_primary", Detail: "Vendor confirms the reported issue"},
		"missing detail":      {Type: "authoritative_primary", SourceURL: "https://vendor.example/advisory"},
		"placeholder detail":  {Type: "authoritative_primary", Detail: "unknown", SourceURL: "https://vendor.example/advisory"},
		"non-http source":     {Type: "authoritative_primary", Detail: "Vendor confirms the reported issue", SourceURL: "ftp://vendor.example/advisory"},
		"credentialed source": {Type: "authoritative_primary", Detail: "Vendor confirms the reported issue", SourceURL: "https://vendor.example@other.example/advisory"},
		"local source":        {Type: "authoritative_primary", Detail: "Vendor confirms the reported issue", SourceURL: "http://localhost/advisory"},
	} {
		t.Run(name, func(t *testing.T) {
			assessment := ClaimAssessment{Evidence: []ClaimEvidence{evidence}}
			if got := NextClaimState(ClaimReported, assessment); got != ClaimReported {
				t.Fatalf("unattributed evidence promoted claim to %s", got)
			}
		})
	}
}

func TestRumourLifecycleDoesNotCountRepeatedSourceAsIndependent(t *testing.T) {
	for name, urls := range map[string][]string{
		"same author paths":            {"https://lab.example/researcher/first", "https://lab.example/researcher/second"},
		"same publisher subdomains":    {"https://research.lab.example/first", "https://blog.lab.example/second"},
		"same publisher query strings": {"https://lab.example/post?id=1", "https://lab.example/post?id=2"},
		"social host aliases":          {"https://x.com/researcher/status/1", "https://twitter.com/researcher/status/2"},
	} {
		t.Run(name, func(t *testing.T) {
			assessment := ClaimAssessment{Evidence: []ClaimEvidence{
				{Type: "artifact", Detail: "Researcher supplies a crash reproducer", SourceURL: urls[0]},
				{Type: "artifact", Detail: "Researcher posts the same reproducer again", SourceURL: urls[1]},
			}}
			if got := IndependentEvidenceLineages(assessment.Evidence); got != 1 {
				t.Fatalf("one source counted as %d lineages", got)
			}
			if got := NextClaimState(ClaimReported, assessment); got != ClaimReported {
				t.Fatalf("one source promoted claim to %s", got)
			}
		})
	}
}

func TestRumourLifecyclePromotesIndependentAttributedArtifacts(t *testing.T) {
	assessment := ClaimAssessment{Evidence: []ClaimEvidence{
		{Type: "artifact", Detail: "First lab supplies a reproducer", SourceURL: "https://first.example/reproduction"},
		{Type: "artifact", Detail: "Second lab supplies its independent reproduction", SourceURL: "https://second.example/research"},
	}}
	assessment.Evidence = attestEvidenceForTest(assessment.Evidence, false, true)
	if got := NextClaimState(ClaimReported, assessment); got != ClaimVerified {
		t.Fatalf("independent evidence did not promote claim: %s", got)
	}
}

func TestMergeRumourLifecycleKeepsNoticeForUnattributedConfirmation(t *testing.T) {
	brief := map[string]any{
		"claim_state": "reported", "type": "rumour", "severity": "rumour",
		"unverified_notice": "Unverified; recommendations are provisional.",
	}
	mergeRumourLifecycle(brief, &ExtractionResult{ClaimAssessment: &ClaimAssessment{
		Evidence: []ClaimEvidence{{Type: "authoritative_primary"}},
	}})
	if brief["claim_state"] != "reported" || brief["type"] != "rumour" || brief["severity"] != "rumour" || brief["unverified_notice"] == "" {
		t.Fatalf("unattributed confirmation removed rumour safeguards: %#v", brief)
	}
}

func TestMergeRumourLifecyclePreservesExistingEvidenceForPromotion(t *testing.T) {
	brief := map[string]any{
		"claim_state": "reported", "type": "rumour", "severity": "rumour",
		"unverified_notice": "Unverified; recommendations are provisional.",
		"evidence":          attestEvidenceForTest([]ClaimEvidence{{Type: "artifact", Detail: "First lab supplies a reproducer", SourceURL: "https://first.example/reproduction"}}, false, true),
	}
	changed := mergeRumourLifecycle(brief, &ExtractionResult{ClaimAssessment: &ClaimAssessment{
		Evidence: attestEvidenceForTest([]ClaimEvidence{{Type: "artifact", Detail: "Second lab independently reproduces the issue", SourceURL: "https://second.example/research"}}, false, true),
	}})
	if !changed || brief["claim_state"] != "verified" || brief["type"] != "advisory" || brief["severity"] != "medium" || brief["unverified_notice"] != "" {
		t.Fatalf("independent source update did not promote existing evidence: %#v", brief)
	}
}

func attestEvidenceForTest(in []ClaimEvidence, primary, independent bool) []ClaimEvidence {
	out := append([]ClaimEvidence(nil), in...)
	for i := range out {
		out[i].Provenance = &ClaimEvidenceProvenance{SourceURL: out[i].SourceURL, EvidenceHash: claimEvidenceHash(out[i]), TrustedPrimary: primary, Independent: independent}
	}
	return out
}

func TestRumourDoesNotPromoteModelAuthorityLabelOrUnattestedDomains(t *testing.T) {
	for _, evidence := range [][]ClaimEvidence{
		{{Type: "authoritative_primary", Detail: "The vendor confirms this vulnerability.", SourceURL: "https://arbitrary.example/report"}},
		{{Type: "artifact", Detail: "Independently confirmed the issue", SourceURL: "https://first.example/report"}, {Type: "artifact", Detail: "Independently confirmed the issue", SourceURL: "https://second.example/report"}},
	} {
		if got := NextClaimState(ClaimReported, ClaimAssessment{Evidence: evidence}); got != ClaimReported {
			t.Fatal(got)
		}
	}
}
