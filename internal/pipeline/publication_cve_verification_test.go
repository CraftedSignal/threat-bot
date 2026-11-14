package pipeline

import (
	"strings"
	"testing"
)

func TestPublicationHoldsRejectedAndReservedCVEIdentities(t *testing.T) {
	for _, status := range []string{"rejected", "reserved", "unavailable", "not_found", "verified"} {
		raw := "title: CVE-2026-12345\ncves: [CVE-2026-12345]\ncve_verification:\n  CVE-2026-12345:\n    status: " + status + "\n    source: cve_program\n"
		issues := ValidatePublicationConsistency(raw)
		blocked := false
		for _, issue := range issues {
			if strings.Contains(issue, "CVE identity") {
				blocked = true
			}
		}
		if want := status == "rejected" || status == "reserved"; blocked != want {
			t.Fatalf("%s blocked=%v: %v", status, blocked, issues)
		}
	}
}
