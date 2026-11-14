package publicfeed

import (
	"strings"
	"testing"
)

func TestContentQualityRequiresOperationalResponse(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		plan           map[string]any
		reject         bool
	}{
		{name: "fictional inventory only", response: "Verify current usage of the FixtureWidget plugin.", reject: true},
		{name: "formatting cannot supply guidance", response: "**Verify** current usage of Widget.\n- .", reject: true},
		{name: "punctuation cannot supply an action target", response: "Inventory Widget. Apply the .", reject: true},
		{name: "placeholder cannot supply an action target", response: "Inventory Widget. Update N/A.", reject: true},
		{name: "updating inventory is still inventory only", response: "Update the asset inventory for this plugin.", reject: true},
		{name: "updating plugin inventory is still inventory only", response: "Update the Widget software inventory.", reject: true},
		{name: "patch availability is not an action", response: "Verify current usage of Widget. No patch is currently available.", reject: true},
		{name: "security update information is not an action", response: "Verify current usage of Widget. Security update information is not provided by the source.", reject: true},
		{name: "inventory evidence does not supply a response", plan: map[string]any{"immediate_actions": []any{map[string]any{"action": "Inventory Widget installations.", "evidence": "Widget installations are affected."}}}, reject: true},
		{name: "honest short source", response: "Inventory Widget installations and check the cited advisory for remediation; the source does not name a fixed version."},
		{name: "known fix", response: "Upgrade affected Widget installations to version 1.0.12 or later."},
		{name: "use patched release", response: "Use the patched Widget release 1.0.12 or later."},
		{name: "qualified action", response: "Administrators should update affected Widget installations to version 1.0.12."},
		{name: "unknown fix with containment", response: "If an update is unavailable, disable the affected Widget plugin while confirming remediation with the vendor."},
		{name: "action plan fix", plan: map[string]any{"immediate_actions": []any{map[string]any{"action": "Apply the Widget security update.", "evidence": "The vendor published a security update for Widget."}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "## Overview\nWidget permits object injection.\n\n## Recommendation\n" + tc.response
			issues := ContentQualityIssues(ContentQualityInput{Content: body, Summary: "A security notice.", HasCVE: true, ActionPlan: tc.plan})
			got := strings.Join(issues, "; ")
			if tc.reject && !strings.Contains(got, "recommendation") {
				t.Fatalf("inventory-only response accepted: %s", got)
			}
			if !tc.reject && len(issues) > 0 {
				t.Fatalf("groundable short response rejected: %s", got)
			}
		})
	}
}

func TestContentQualityDoesNotTreatScoreAsImpact(t *testing.T) {
	for _, impact := range []string{"8.8", "According to NVD, the CVSS v3.1 base score is 8.8 (HIGH).", "The vulnerability has been assigned a CVSS v3.1 base score of 8.8.", "**CVSS**: 8.8 (HIGH).", "- CVSS v3.1: **8.8**\n- Severity: High", "CVSS v3.1 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"} {
		body := "## Overview\nWidget permits object injection.\n\n## Impact\n" + impact + "\n\n## Recommendation\nUpgrade Widget to version 1.0.12."
		if got := strings.Join(ContentQualityIssues(ContentQualityInput{Content: body, HasCVE: true}), "; "); !strings.Contains(got, "impact") {
			t.Fatalf("score-only impact accepted: %s", got)
		}
	}
	for _, impact := range []string{"The source does not describe the impact beyond object injection.", "The flaw can delete application files, disrupting service. CVSS 8.8."} {
		body := "## Overview\nWidget permits object injection.\n\n## Impact\n" + impact + "\n\n## Recommendation\nConsult the cited advisory for remediation."
		if got := ContentQualityIssues(ContentQualityInput{Content: body, HasCVE: true}); len(got) > 0 {
			t.Fatalf("honest impact rejected: %v", got)
		}
	}
}

func TestContentQualityRejectsLegacyPlaceholders(t *testing.T) {
	for _, value := range []string{"na", "unspecified"} {
		t.Run(value, func(t *testing.T) {
			if MeaningfulText(value) || HasTelemetry([]string{value}) {
				t.Fatal("placeholder counted as substantive text or telemetry")
			}
			if issues := ContentQualityIssues(ContentQualityInput{Content: value}); len(issues) == 0 {
				t.Fatal("placeholder-only body accepted")
			}
			plan := map[string]any{"hunt_leads": []any{map[string]any{"lead": value, "evidence": value, "data_needed": []any{value}}}}
			issues := ContentQualityIssues(ContentQualityInput{Content: "Widget permits object injection.", HasCVE: true, ActionPlan: plan})
			if !strings.Contains(strings.Join(issues, "; "), "recommendation") {
				t.Fatal("placeholder hunt lead supplied missing response")
			}
		})
	}
}

func TestPublicBriefUsesSharedContentQualityContract(t *testing.T) {
	body := "## Overview\nWidget permits object injection.\n\n## Impact\nCVSS 8.8.\n\n## Recommendation\nVerify current usage of Widget.\n"
	parts := strings.SplitN(validBrief, "---\n\n", 2)
	if len(parts) != 2 {
		t.Fatal("invalid test fixture")
	}
	issues := CheckBrief("fixture-widget.md", []byte(parts[0]+"---\n\n"+body))
	var messages []string
	for _, issue := range issues {
		messages = append(messages, issue.Message)
	}
	got := strings.Join(messages, "; ")
	if !strings.Contains(got, "impact") || !strings.Contains(got, "recommendation") {
		t.Fatalf("public final gate missed sparse content: %s", got)
	}
}
