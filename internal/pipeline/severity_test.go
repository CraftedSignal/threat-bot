package pipeline

import (
	"strings"
	"testing"
)

func TestNormalizeOperationalSeverity_LowCVSS(t *testing.T) {
	in := `title: Mistune TOC Collision
summary: Low-impact anchor collision issue.
severity: medium
content: "CVE-2026-1234 has CVSS 4.3 and no exploitation."
`

	out, notes := NormalizeOperationalSeverity(in, SeverityContext{
		CVEs: []BundleCVE{{ID: "CVE-2026-1234", CVSS: 4.3}},
	})

	if !strings.Contains(out, "severity: low") {
		t.Fatalf("expected severity low, got:\n%s", out)
	}
	if len(notes) == 0 {
		t.Fatal("expected normalization note")
	}
}

func TestNormalizeOperationalSeverity_AvailabilityOnlyVector(t *testing.T) {
	in := `title: YAML CPU Consumption
summary: Quadratic CPU denial of service.
severity: medium
content: "CVE-2026-1234 causes CPU exhaustion."
`

	out, _ := NormalizeOperationalSeverity(in, SeverityContext{
		CVEs: []BundleCVE{{
			ID:         "CVE-2026-1234",
			CVSS:       7.5,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		}},
	})

	if !strings.Contains(out, "severity: low") {
		t.Fatalf("expected availability-only CVE to normalize low, got:\n%s", out)
	}
}

func TestNormalizeOperationalSeverity_UrgencyBoostSkipsCap(t *testing.T) {
	in := `title: YAML CPU Consumption
summary: Quadratic CPU denial of service.
severity: medium
content: "CVE-2026-1234 causes CPU exhaustion."
`

	out, notes := NormalizeOperationalSeverity(in, SeverityContext{
		ActiveExploitation: true,
		CVEs: []BundleCVE{{
			ID:         "CVE-2026-1234",
			CVSS:       7.5,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		}},
	})

	if !strings.Contains(out, "severity: medium") {
		t.Fatalf("expected active exploitation to preserve severity, got:\n%s", out)
	}
	if len(notes) != 0 {
		t.Fatalf("expected no normalization note, got %v", notes)
	}
}

func TestNormalizeOperationalSeverity_AuthRequiredLowMediumImpact(t *testing.T) {
	in := `title: Authenticated Settings Bug
summary: Authenticated users can trigger limited impact.
severity: medium
content: "CVE-2026-1234 requires privileges and has limited impact."
`

	out, _ := NormalizeOperationalSeverity(in, SeverityContext{
		CVEs: []BundleCVE{{
			ID:         "CVE-2026-1234",
			CVSS:       6.3,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
		}},
	})

	if !strings.Contains(out, "severity: low") {
		t.Fatalf("expected authenticated low/medium CVSS issue to normalize low, got:\n%s", out)
	}
}
