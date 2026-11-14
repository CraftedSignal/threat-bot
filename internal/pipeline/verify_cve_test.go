package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCVEVerifier_ValidCVE(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	// Since checkCVE hardcodes the NVD URL, we test the full Verify by overriding the transport.
	v.client = &http.Client{
		Transport: &mockNVDTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				json.NewEncoder(rec).Encode(nvdDetailResponse{
					Vulnerabilities: []nvdVulnerability{{
						CVE: nvdCVEDetail{
							ID: req.URL.Query().Get("cveId"),
							Metrics: nvdMetrics{
								CvssV31: []nvdCVSSV31{{CVSSData: nvdCVSSData{BaseScore: 7.5}}},
							},
						},
					}},
				})
				return rec.Result(), nil
			},
		},
	}

	yaml := `
id: "brief-test"
slug: "test"
title: "Test CVE-2024-1234"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test about CVE-2024-1234"
tags: []
references: []
iocs:
  - type: "cve"
    value: "CVE-2024-1234"
    context: "vulnerability"
`
	result, notes := v.Verify(context.Background(), yaml)

	// CVE exists, so no removal notes expected.
	for _, n := range notes {
		if strings.Contains(n, "not found") {
			t.Errorf("unexpected 'not found' note: %s", n)
		}
	}
	if !strings.Contains(result, "CVE-2024-1234") {
		t.Error("expected valid CVE to remain in output")
	}
}

func TestCVEVerifier_InvalidCVE(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.client = &http.Client{
		Transport: &mockNVDTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				if req.URL.Host == "cveawg.mitre.org" {
					rec.WriteHeader(http.StatusNotFound)
				} else {
					json.NewEncoder(rec).Encode(nvdDetailResponse{Vulnerabilities: nil})
				}
				return rec.Result(), nil
			},
		},
	}

	yaml := `
id: "brief-test"
slug: "test"
title: "Test CVE-2024-99999"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test about CVE-2024-99999"
tags: []
references: []
iocs:
  - type: "cve"
    value: "CVE-2024-99999"
    context: "hallucinated"
`
	_, notes := v.Verify(context.Background(), yaml)

	found := false
	for _, n := range notes {
		if strings.Contains(n, "verification not_found") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'not found in NVD' note, got: %v", notes)
	}
}

func TestCVEVerifier_NVDUnreachable(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.client = &http.Client{
		Transport: &mockNVDTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				rec.WriteHeader(http.StatusInternalServerError)
				return rec.Result(), nil
			},
		},
	}

	yaml := `
id: "brief-test"
slug: "test"
title: "Test CVE-2024-5678"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
`
	result, notes := v.Verify(context.Background(), yaml)

	// Should skip gracefully — no notes about NVD failure blocking.
	for _, n := range notes {
		if strings.Contains(n, "not found") {
			t.Errorf("should not report CVE as invalid when NVD is unreachable: %s", n)
		}
	}
	if !strings.Contains(result, "status: unavailable") {
		t.Error("verification outage must be explicit")
	}
}

func TestCVEVerifier_NoCVEs(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "no CVEs here"
tags: []
references: []
`
	result, notes := v.Verify(context.Background(), yaml)
	if len(notes) > 0 {
		t.Errorf("expected no notes, got: %v", notes)
	}
	if result != yaml {
		t.Error("YAML should be unchanged when no CVEs present")
	}
}

func TestCVEVerifier_Cache(t *testing.T) {
	callCount := 0
	cnaCalls := 0
	v := NewCVEVerifier(nil, nil)
	v.client = &http.Client{
		Transport: &mockNVDTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "cveawg.mitre.org" {
					cnaCalls++
					rec := httptest.NewRecorder()
					rec.WriteHeader(http.StatusServiceUnavailable)
					return rec.Result(), nil
				}
				callCount++
				rec := httptest.NewRecorder()
				json.NewEncoder(rec).Encode(nvdDetailResponse{
					Vulnerabilities: []nvdVulnerability{{CVE: nvdCVEDetail{ID: req.URL.Query().Get("cveId")}}},
				})
				return rec.Result(), nil
			},
		},
	}

	yaml := `
id: "brief-test"
slug: "test"
title: "Test CVE-2024-1111 and CVE-2024-1111"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "CVE-2024-1111 mentioned twice"
tags: []
references: []
`
	v.Verify(context.Background(), yaml)
	if callCount != 1 {
		t.Errorf("expected 1 NVD API call (deduped), got %d", callCount)
	}

	// Second call should use cache.
	v.Verify(context.Background(), yaml)
	if callCount != 1 {
		t.Errorf("expected still 1 NVD API call (cached), got %d", callCount)
	}
	if cnaCalls != 1 {
		t.Errorf("optional CNA lookup was not cached: got %d calls", cnaCalls)
	}
}

func TestCVEMetaFromNVD(t *testing.T) {
	resp := &nvdDetailResponse{
		Vulnerabilities: []nvdVulnerability{{
			CVE: nvdCVEDetail{
				Metrics: nvdMetrics{
					CvssV31: []nvdCVSSV31{{
						CVSSData: nvdCVSSData{
							BaseScore:    9.8,
							VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						},
					}},
				},
			},
		}},
	}
	meta := cvssFromNVD(resp)
	if meta != 9.8 {
		t.Errorf("expected CVSS 9.8, got %f", meta)
	}
	score, vector := cvssScoreVectorFromNVD(resp)
	if score != 9.8 || vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("expected score/vector from NVD, got %f %q", score, vector)
	}
}

// CVE-2026-48362 lists 23 ColdFusion 2023 builds ahead of 12 ColdFusion 2025
// builds. Capping before collapsing kept 20 identical-looking 2023 entries and
// dropped ColdFusion 2025 entirely.
func TestCPEsFromNVD_CollapsesBuildsBeforeCap(t *testing.T) {
	var matches []nvdCpeMatch
	add := func(version string, updates int) {
		matches = append(matches, nvdCpeMatch{Vulnerable: true, Criteria: "cpe:2.3:a:adobe:coldfusion:" + version + ":-:*:*:*:*:*:*"})
		for i := 1; i <= updates; i++ {
			matches = append(matches, nvdCpeMatch{Vulnerable: true, Criteria: fmt.Sprintf("cpe:2.3:a:adobe:coldfusion:%s:update%d:*:*:*:*:*:*", version, i)})
		}
	}
	add("2023", 22)
	add("2025", 11)
	resp := &nvdDetailResponse{
		Vulnerabilities: []nvdVulnerability{{
			CVE: nvdCVEDetail{Configurations: []nvdConfig{{Nodes: []nvdConfigNode{{CpeMatch: matches}}}}},
		}},
	}

	got := cpesFromNVD(resp)
	want := []string{
		"cpe:2.3:a:adobe:coldfusion:2023:*:*:*:*:*:*:*",
		"cpe:2.3:a:adobe:coldfusion:2025:*:*:*:*:*:*:*",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("cpesFromNVD:\n got: %q\nwant: %q", got, want)
	}
}

func TestCVEMetaFromNVD_NoMetrics(t *testing.T) {
	resp := &nvdDetailResponse{
		Vulnerabilities: []nvdVulnerability{{CVE: nvdCVEDetail{}}},
	}
	meta := cvssFromNVD(resp)
	if meta != 0 {
		t.Errorf("expected CVSS 0, got %f", meta)
	}
}

func TestCVEMetaFromNVD_V30Fallback(t *testing.T) {
	resp := &nvdDetailResponse{
		Vulnerabilities: []nvdVulnerability{{
			CVE: nvdCVEDetail{
				Metrics: nvdMetrics{
					CvssV30: []nvdCVSSV31{{
						CVSSData: nvdCVSSData{BaseScore: 7.2},
					}},
				},
			},
		}},
	}
	score := cvssFromNVD(resp)
	if score != 7.2 {
		t.Errorf("expected CVSS 7.2 from v3.0 fallback, got %f", score)
	}
}

func TestCVEMetaFromNVD_NilResponse(t *testing.T) {
	score := cvssFromNVD(nil)
	if score != 0 {
		t.Errorf("expected CVSS 0 for nil response, got %f", score)
	}
}

func TestDescriptionFromNVDPrefersEnglish(t *testing.T) {
	resp := &nvdDetailResponse{
		Vulnerabilities: []nvdVulnerability{{
			CVE: nvdCVEDetail{
				Descriptions: []nvdDescription{
					{Lang: "fr", Value: "description francaise"},
					{Lang: "en", Value: "English vulnerability description"},
				},
			},
		}},
	}
	if got := descriptionFromNVD(resp); got != "English vulnerability description" {
		t.Fatalf("description = %q", got)
	}
}

func TestCVEVerifier_GetMeta(t *testing.T) {
	v := NewCVEVerifier(nil, loadedKEVCatalog(t, "CVE-2024-5555"))
	v.client = &http.Client{
		Transport: &mockNVDTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				json.NewEncoder(rec).Encode(nvdDetailResponse{
					Vulnerabilities: []nvdVulnerability{{
						CVE: nvdCVEDetail{
							ID: req.URL.Query().Get("cveId"),
							Metrics: nvdMetrics{
								CvssV31: []nvdCVSSV31{{CVSSData: nvdCVSSData{BaseScore: 8.1}}},
							},
						},
					}},
				})
				return rec.Result(), nil
			},
		},
	}

	briefStr := `
id: "brief-test"
slug: "test"
title: "Test CVE-2024-5555"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "CVE-2024-5555 detail"
tags: []
references: []
`
	v.Verify(context.Background(), briefStr)

	meta := v.GetMeta("CVE-2024-5555")
	if meta == nil {
		t.Fatal("expected cached meta, got nil")
	}
	if !meta.Exists {
		t.Error("expected Exists=true")
	}
	if meta.CVSS != 8.1 {
		t.Errorf("expected CVSS 8.1, got %f", meta.CVSS)
	}
	if listed, known := v.KEV("CVE-2024-5555"); !listed || !known {
		t.Error("expected KEV=true for CVE-2024-5555")
	}
}

// mockNVDTransport implements http.RoundTripper for testing.
type mockNVDTransport struct {
	handler func(req *http.Request) (*http.Response, error)
}

func (m *mockNVDTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.handler(req)
}

// An NVD record past the read cap is treated like any NVD failure: the CVE is
// left unverified, not reported as hallucinated.
func TestCVEVerifier_OversizedRecordSkipsVerification(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.client = &http.Client{
		Transport: &mockNVDTransport{
			handler: func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				rec.WriteString(`{"vulnerabilities":[{"cve":{"descriptions":[{"lang":"en","value":"`)
				rec.WriteString(strings.Repeat("x", maxNVDRecordBytes))
				rec.WriteString(`"}]}}]}`)
				return rec.Result(), nil
			},
		},
	}

	brief := "id: brief-big\ntitle: Test CVE-2017-5753\nsummary: Spectre\n"
	_, notes := v.Verify(context.Background(), brief)
	for _, n := range notes {
		if !strings.Contains(n, "verification unavailable") {
			t.Errorf("oversized NVD record flagged the CVE: %q", n)
		}
	}
	if meta := v.GetMeta("CVE-2017-5753"); meta == nil || meta.Exists || meta.Verification.Status != "unavailable" {
		t.Error("oversized response must be recorded unavailable")
	}
}
