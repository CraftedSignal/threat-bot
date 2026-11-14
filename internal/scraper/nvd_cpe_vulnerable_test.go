package scraper

import (
	"encoding/json"
	"slices"
	"testing"
)

// A CVE in a third-party app lists the platform it runs on as a
// vulnerable:false CPE. Only vulnerable:true matches name affected software.
func TestExtractCPEsKeepsOnlyVulnerableMatches(t *testing.T) {
	const raw = `{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"},
		{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
		{"criteria":"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}
	]}]}]}`
	var cve nvdCVE
	if err := json.Unmarshal([]byte(raw), &cve); err != nil {
		t.Fatal(err)
	}
	got := (&NVD{}).extractCPEs(cve)
	want := []string{"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}
	if !slices.Equal(got, want) {
		t.Fatalf("cpes = %v, want %v", got, want)
	}
}

// Each version bound NVD attaches to a cpeMatch becomes a human-readable range
// per product, so code can render the affected versions without the LLM.
func TestNVDAffectedRangesParsesEachBound(t *testing.T) {
	const raw = `{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0","versionEndExcluding":"1.4.2"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionStartExcluding":"2.0","versionEndIncluding":"2.3"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionEndExcluding":"1.4.2"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:other:gadget:*:*:*:*:*:*:*:*","versionEndIncluding":"9.1"},
		{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*","versionEndExcluding":"11"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:plain:thing:1.0:*:*:*:*:*:*:*"}
	]}]}]}`
	var cve nvdCVE
	if err := json.Unmarshal([]byte(raw), &cve); err != nil {
		t.Fatal(err)
	}
	if m := cve.Configurations[0].Nodes[0].CPEMatch[0]; m.VersionStartIncluding != "1.0" || m.VersionEndExcluding != "1.4.2" {
		t.Fatalf("bounds not parsed: %+v", m)
	}
	got := nvdAffectedRanges(cve)
	want := "acme widget: >= 1.0, < 1.4.2; > 2.0, <= 2.3; < 1.4.2\nother gadget: <= 9.1"
	if got != want {
		t.Fatalf("ranges = %q, want %q", got, want)
	}
	md := nvdItemMetadata(cve, "9.8", nil)
	if md["affected_ranges"] != want {
		t.Fatalf("metadata affected_ranges = %q", md["affected_ranges"])
	}
}
