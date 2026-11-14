package pipeline

import (
	"strings"
	"testing"
)

func TestEnrichBriefWithExploitationEvidence(t *testing.T) {
	in := `id: brief-1
published_at: "2026-10-19T08:00:00Z"
exploitation_evidence:
  status: unknown
`
	got := EnrichBriefWithExploitationEvidence(in, "https://vendor.test/advisory", "2026-10-19T09:00:00Z", "high")
	for _, want := range []string{"status: confirmed_active", "source_url: https://vendor.test/advisory", `observed_at: "2026-10-19T09:00:00Z"`, "confidence: high"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestComputePriority_Critical(t *testing.T) {
	signals := PriorityInput{
		CVEs:               []BundleCVE{{EPSS: 0.87, CVSS: 9.8, KEV: true}},
		ActiveExploitation: false,
		SourceConfidence:   0.95,
		Corroborated:       false,
		WatchlistMatch:     false,
		HasRules:           false,
		HasIOCs:            false,
	}
	result := ComputePriority(signals)
	// KEV(4) + EPSS>=0.7(4) + CVSS>=9.0(3) + confidence boost(1) = 12
	if result.Tier != "critical" {
		t.Errorf("expected critical, got %s (score=%d)", result.Tier, result.Score)
	}
	if result.Score != 12 {
		t.Errorf("expected score 12, got %d", result.Score)
	}
}

func TestComputePriority_High(t *testing.T) {
	signals := PriorityInput{
		SourceConfidence: 0.90,
		Corroborated:     true,
		WatchlistMatch:   true,
	}
	result := ComputePriority(signals)
	// corroboration(2) + watchlist(2) + confidence boost(1) = 5
	if result.Tier != "high" {
		t.Errorf("expected high, got %s (score=%d)", result.Tier, result.Score)
	}
}

func TestComputePriority_Low(t *testing.T) {
	signals := PriorityInput{
		SourceConfidence: 0.30,
		CVEs:             []BundleCVE{{EPSS: 0.1, CVSS: 4.0}},
	}
	result := ComputePriority(signals)
	if result.Tier != "low" {
		t.Errorf("expected low, got %s (score=%d)", result.Tier, result.Score)
	}
}

func TestComputePriority_Medium(t *testing.T) {
	signals := PriorityInput{
		SourceConfidence: 0.75,
		HasRules:         true,
	}
	result := ComputePriority(signals)
	// has_rules(1) + confidence boost(1) = 2
	if result.Tier != "medium" {
		t.Errorf("expected medium, got %s (score=%d)", result.Tier, result.Score)
	}
}

func TestComputePriority_SourceConfidenceAloneDoesNotPromote(t *testing.T) {
	result := ComputePriority(PriorityInput{SourceConfidence: 0.95})

	if result.Tier != "low" {
		t.Errorf("expected trusted source alone to stay low, got %s (score=%d)", result.Tier, result.Score)
	}
	if result.Score != 0 {
		t.Errorf("expected score 0, got %d", result.Score)
	}
}

func TestComputePriority_LowCVSSFromTrustedSourceStaysLow(t *testing.T) {
	result := ComputePriority(PriorityInput{
		CVEs:             []BundleCVE{{ID: "CVE-2026-1", CVSS: 4.3}},
		SourceConfidence: 0.95,
	})

	if result.Tier != "low" {
		t.Errorf("expected low CVSS advisory to stay low, got %s (score=%d, signals=%v)", result.Tier, result.Score, result.Signals)
	}
}

func TestComputePriority_AvailabilityOnlyVectorStaysLow(t *testing.T) {
	result := ComputePriority(PriorityInput{
		CVEs: []BundleCVE{{
			ID:         "CVE-2026-2",
			CVSS:       7.5,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		}},
		SourceConfidence: 0.95,
	})

	if result.Tier != "low" {
		t.Errorf("expected availability-only issue to stay low, got %s (score=%d, signals=%v)", result.Tier, result.Score, result.Signals)
	}
}

func TestComputePriority_KEVRaisesAvailabilityOnlyVector(t *testing.T) {
	result := ComputePriority(PriorityInput{
		CVEs: []BundleCVE{{
			ID:         "CVE-2026-3",
			CVSS:       7.5,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			KEV:        true,
		}},
		SourceConfidence: 0.95,
	})

	if result.Tier == "low" {
		t.Errorf("expected KEV availability issue to rise above low, got %s (score=%d, signals=%v)", result.Tier, result.Score, result.Signals)
	}
}

func TestComputePriority_EPSSMutuallyExclusive(t *testing.T) {
	signals := PriorityInput{
		CVEs: []BundleCVE{{EPSS: 0.85, CVSS: 5.0}},
	}
	result := ComputePriority(signals)
	// EPSS>=0.7 gives +4, NOT +4 and +2
	if result.Score != 4 {
		t.Errorf("expected score 4 (EPSS mutually exclusive), got %d", result.Score)
	}
}

func TestComputePriority_Signals(t *testing.T) {
	signals := PriorityInput{
		CVEs:           []BundleCVE{{EPSS: 0.87, CVSS: 9.8, KEV: true}},
		WatchlistMatch: true,
	}
	result := ComputePriority(signals)
	expected := map[string]bool{"kev": true, "epss_high": true, "cvss_critical": true, "watchlist_match": true}
	for _, s := range result.Signals {
		if !expected[s] {
			t.Errorf("unexpected signal: %s", s)
		}
		delete(expected, s)
	}
	for s := range expected {
		t.Errorf("missing signal: %s", s)
	}
}

func TestEnrichBriefWithSourceAssessment(t *testing.T) {
	raw := `id: brief-x
title: Test
summary: Summary
severity: high
published_at: "2026-08-02T00:00:00Z"
`

	got := EnrichBriefWithSourceAssessment(raw, SourceAssessmentInput{
		Source:             "reddit-netsec",
		SourceConfidence:   0.30,
		Corroborated:       false,
		ActiveExploitation: false,
	})

	if !strings.Contains(got, "source_assessment:") {
		t.Fatalf("expected source_assessment in YAML, got:\n%s", got)
	}
	if !strings.Contains(got, "rating: E6") {
		t.Fatalf("expected low-confidence E6 rating, got:\n%s", got)
	}
	if !strings.Contains(got, "type: single_source") || !strings.Contains(got, "type: anonymous") {
		t.Fatalf("expected provenance flags, got:\n%s", got)
	}
}

func TestIsRumour(t *testing.T) {
	cases := []struct {
		name string
		in   RumourInput
		want bool
	}{
		{
			name: "low-conf-no-cve-no-corroboration-no-exploit",
			in:   RumourInput{SourceConfidence: 0.30},
			want: true,
		},
		{
			name: "low-conf-but-has-cve",
			in:   RumourInput{SourceConfidence: 0.25, CVEs: []BundleCVE{{ID: "CVE-2026-1"}}},
			want: false,
		},
		{
			name: "low-conf-but-corroborated",
			in:   RumourInput{SourceConfidence: 0.25, Corroborated: true},
			want: false,
		},
		{
			name: "low-conf-but-active-exploitation",
			in:   RumourInput{SourceConfidence: 0.25, ActiveExploitation: true},
			want: false,
		},
		{
			name: "low-conf-but-watchlist-match",
			in:   RumourInput{SourceConfidence: 0.25, WatchlistMatch: true},
			want: false,
		},
		{
			name: "sigma-rule-never-rumour",
			in:   RumourInput{SourceConfidence: 0.10, HasSigmaRule: true},
			want: false,
		},
		{
			name: "high-conf-source-not-rumour",
			in:   RumourInput{SourceConfidence: 0.90},
			want: false,
		},
		{
			name: "boundary-just-below-threshold",
			in:   RumourInput{SourceConfidence: 0.49},
			want: true,
		},
		{
			name: "boundary-at-threshold-not-rumour",
			in:   RumourInput{SourceConfidence: 0.50},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRumour(tc.in); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
