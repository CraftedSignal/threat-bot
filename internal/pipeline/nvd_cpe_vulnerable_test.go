package pipeline

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestCPEsFromNVDDropsNonVulnerablePlatformCPEs(t *testing.T) {
	const raw = `{"vulnerabilities":[{"cve":{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"},
		{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}
	]}]}]}}]}`
	var resp nvdDetailResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	got := cpesFromNVD(&resp)
	if !slices.Equal(got, []string{"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}) {
		t.Fatalf("cpes = %v", got)
	}
}

func TestCPEsFromNVDPreservesReleaseCandidateScope(t *testing.T) {
	const raw = `{"vulnerabilities":[{"cve":{"configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:o:linux:linux_kernel:7.2:rc2:*:*:*:*:*:*"},
		{"vulnerable":true,"criteria":"cpe:2.3:o:linux:linux_kernel:7.2:rc1:*:*:*:*:*:*"}
	]}]}]}}]}`
	var resp nvdDetailResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cpe:2.3:o:linux:linux_kernel:7.2:rc1:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:7.2:rc2:*:*:*:*:*:*",
	}
	if got := cpesFromNVD(&resp); !slices.Equal(got, want) {
		t.Fatalf("NVD applicability changed: got %q want %q", got, want)
	}
}
