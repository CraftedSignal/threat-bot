package pipeline

import "testing"

func TestClaimKeyStableAndClaimSpecific(t *testing.T) {
	a := &ExtractionResult{CVEs: []string{"cve-2026-111497"}, AffectedProducts: []string{"Node.js"}, VulnClass: "oob", ClaimAssessment: &ClaimAssessment{Claim: "Brotli decoder leaks heap bytes"}}
	b := &ExtractionResult{CVEs: []string{"CVE-2026-111497"}, AffectedProducts: []string{" node.js "}, VulnClass: "OOB", ClaimAssessment: &ClaimAssessment{Claim: "Brotli decoder leaks heap bytes!"}}
	if ClaimKey(a) == "" || ClaimKey(a) != ClaimKey(b) {
		t.Fatalf("unstable: %q %q", ClaimKey(a), ClaimKey(b))
	}
	c := *a
	c.ClaimAssessment = &ClaimAssessment{Claim: "Brotli decoder permits remote code execution"}
	if ClaimKey(a) == ClaimKey(&c) {
		t.Fatal("different mechanism/impact merged")
	}
	d := *a
	d.CVEs = []string{"CVE-2026-999999"}
	if ClaimKey(a) == ClaimKey(&d) {
		t.Fatal("different CVEs merged through product overlap")
	}
}

func TestClaimKeyRequiresClaimIdentity(t *testing.T) {
	if got := ClaimKey(&ExtractionResult{AffectedProducts: []string{"Node.js"}}); got != "" {
		t.Fatalf("product-only key=%q", got)
	}
}
