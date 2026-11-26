package pipeline

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// Assembly, grounding and repair must judge a release bound the same way. When
// they disagreed, the checker rejected "upgrade to X" and then demanded it.
func TestReleaseBoundRemediationRuleIsSharedByEveryStage(t *testing.T) {
	for name, prompt := range map[string]string{
		"assembly":         briefSystemPrompt,
		"compact assembly": compactAdvisorySystemPrompt,
		"grounding":        groundingSystem,
		"claim grounding":  groundingClaimsSystem,
		"repair":           groundingRepairSystemPrompt,
	} {
		if !strings.Contains(prompt, releaseBoundRemediationRule) {
			t.Errorf("%s prompt does not carry the shared release-bound remediation rule", name)
		}
	}
	if strings.Contains(structuredAdvisoryInstruction, "An affected upper bound alone does not establish a fixed release") {
		t.Error("structured advisory instruction still contradicts the release-bound rule")
	}
}

func TestExclusiveReleaseBoundsDeriveFixedReleases(t *testing.T) {
	for name, tc := range map[string]struct {
		entry string
		want  []releaseBoundFix
	}{
		"open before": {`{"product":"FFmpeg","versions":[{"version":"0","lessThan":"9.1","status":"affected","versionType":"semver"}]}`,
			[]releaseBoundFix{{Fixed: "9.1", Range: "< 9.1"}}},
		"one fix per branch": {`{"product":"Widget","versions":[{"version":"1.0","lessThan":"1.2.3","status":"affected"},{"version":"2.0","lessThan":"2.1.4","status":"affected"}]}`,
			[]releaseBoundFix{{Fixed: "1.2.3", Range: ">= 1.0, < 1.2.3"}, {Fixed: "2.1.4", Range: ">= 2.0, < 2.1.4"}}},
		"inclusive bound": {`{"product":"Widget","versions":[{"version":"0","lessThanOrEqual":"2.3","status":"affected"}]}`, nil},
		"inclusive branch is not a fix": {`{"product":"Widget","versions":[{"version":"1.0","lessThan":"1.2.3","status":"affected"},{"version":"2.0","lessThanOrEqual":"2.4","status":"affected"}]}`,
			[]releaseBoundFix{{Fixed: "1.2.3", Range: ">= 1.0, < 1.2.3"}}},
		"unbounded":        {`{"product":"Widget","versions":[{"version":"2.0","lessThan":"*","status":"affected"}]}`, nil},
		"commit bounds":    {`{"product":"Linux","versions":[{"version":"7460b470a131","lessThan":"0fab93d241cf","status":"affected","versionType":"git"}]}`, nil},
		"default affected": {`{"product":"Linux","defaultStatus":"affected","versions":[{"version":"6.15","lessThan":"6.16","status":"affected"}]}`, nil},
	} {
		var entry cnaAffectedEntry
		if err := json.Unmarshal([]byte(tc.entry), &entry); err != nil {
			t.Fatal(err)
		}
		if got := entry.exclusiveReleaseBounds(); !slices.Equal(got, tc.want) {
			t.Errorf("%s: fixes=%+v want %+v", name, got, tc.want)
		}
	}
}

func releaseBoundRecord(versions string) cnaSourceRecord {
	var record cnaSourceRecord
	if err := json.Unmarshal([]byte(`{"descriptions":[{"lang":"en","value":"FFmpeg before 9.1 has a heap overflow."}],"affected":[{"vendor":"FFmpeg","product":"FFmpeg","versions":`+versions+`}]}`), &record); err != nil {
		panic(err)
	}
	return record
}

// The evidence both stages read states the derived fix, and its coverage note
// no longer calls remediation absent. Inclusive bounds keep the gap.
func TestPrimaryEvidenceStatesReleaseBoundRemediation(t *testing.T) {
	const id = "CVE-2099-4242"
	facts, gap := releaseBoundRecord(`[{"version":"0","lessThan":"9.1","status":"affected","versionType":"semver"}]`).sourceFacts(id)
	if strings.Contains(gap, "usable remediation is not present") || !strings.Contains(gap, "release-bound remediation") {
		t.Fatalf("coverage contradicts the derived fix: %q", gap)
	}
	v := NewCVEVerifier(nil, nil)
	v.cache[id] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CachedAt: time.Now(), CNAChecked: true, CNAFacts: facts, CNAGap: gap}
	evidence := (&Pipeline{cveVerifier: v}).verifiedPrimaryEvidence([]string{id})
	derived := "- " + id + " / FFmpeg: fixed release 9.1 (affected < 9.1)"
	if !strings.Contains(evidence, "Release-bound remediation") || !strings.Contains(evidence, derived) {
		t.Fatalf("evidence lacks the derived fixed release:\n%s", evidence)
	}
	// Generated guidance never becomes positive evidence for a finding.
	brief := "affected_products: [FFmpeg]\ncves: [" + id + "]\ncontent: FFmpeg is vulnerable.\n"
	issue := groundingIssue{Kind: groundingKindMaterialOmission, Subject: id, Field: "recommendation", SourceQuote: strings.TrimPrefix(derived, "- "), Reason: "Missing fixed release."}
	if err := validateMaterialOmission(issue, evidence+"\nOriginal source:\nFFmpeg advisory.", brief); err == nil {
		t.Fatal("machine-derived guidance was accepted as a verbatim source quote")
	}

	_, inclusiveGap := releaseBoundRecord(`[{"version":"0","lessThanOrEqual":"9.0","status":"affected"}]`).sourceFacts(id)
	if !strings.Contains(inclusiveGap, "usable remediation is not present") {
		t.Fatalf("an inclusive bound derived a fix: %q", inclusiveGap)
	}
}
