package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func syntheticCompletenessCNA(t *testing.T) []byte {
	t.Helper()
	return []byte(`{"cveMetadata":{"cveId":"CVE-2099-4001","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Example Harbor permits a configuration change with low privileges and no user interaction."}],"affected":[{"vendor":"ExampleCo","product":"Example Harbor","packageName":"example-harbor","versions":[{"version":"0","lessThanOrEqual":"2.3","status":"affected","versionType":"custom"}]}],"solutions":[{"lang":"en","value":"Update Example Harbor to at least 2.4."}],"metrics":[{"cvssV3_1":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N","baseScore":5.4}}]}}}`)
}

func TestCVEVerifierRetainsPrimaryCompletenessFacts(t *testing.T) {
	for _, mode := range []string{"NVD success", "NVD cached success", "CVE Program fallback"} {
		t.Run(mode, func(t *testing.T) {
			v := NewCVEVerifier(nil, nil)
			var nvdCalls, cnaCalls int
			if mode == "NVD cached success" {
				v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, Description: "Example Harbor permits object injection.", CachedAt: time.Now()}
			}
			primary := syntheticCompletenessCNA(t)
			v.client = &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				if req.URL.Host == "cveawg.mitre.org" {
					cnaCalls++
					_, _ = rec.Write(primary)
				} else {
					nvdCalls++
					if mode == "CVE Program fallback" {
						rec.WriteHeader(http.StatusServiceUnavailable)
					} else {
						_ = json.NewEncoder(rec).Encode(nvdDetailResponse{Vulnerabilities: []nvdVulnerability{{CVE: nvdCVEDetail{ID: "CVE-2099-4001", Descriptions: []nvdDescription{{Lang: "en", Value: "Example Harbor permits object injection."}}}}}})
					}
				}
				return rec.Result(), nil
			}}}
			for range 2 {
				if exists, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err != nil || !exists {
					t.Fatalf("verification lost: exists=%v, err=%v", exists, err)
				}
			}
			meta := v.GetMeta("CVE-2099-4001")
			raw, _ := json.Marshal(meta)
			for _, fact := range []string{"2.3", "2.4", "PR:L", "ExampleCo", "example-harbor"} {
				if !strings.Contains(string(raw), fact) {
					t.Errorf("verified primary fact %q discarded: %s", fact, raw)
				}
			}
			wantNVD := 1
			if mode == "NVD cached success" {
				wantNVD = 0
			}
			if cnaCalls != 1 || nvdCalls != wantNVD {
				t.Fatalf("not bounded and cached: NVD=%d CNA=%d", nvdCalls, cnaCalls)
			}
		})
	}
}

func TestCVEVerifierOptionalCNAGapPreservesNVDVerification(t *testing.T) {
	for _, mode := range []string{"unavailable", "identity mismatch"} {
		t.Run(mode, func(t *testing.T) {
			v := NewCVEVerifier(nil, nil)
			// A timestamp containing "2.4" must not be mistaken for a fixed-version claim.
			cachedAt := time.Now().Add(-time.Hour).Truncate(time.Minute).Add(2*time.Second + 400*time.Millisecond)
			v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, Description: "Example Harbor permits object injection.", CachedAt: cachedAt}
			primary := strings.ReplaceAll(string(syntheticCompletenessCNA(t)), "CVE-2099-4001", "CVE-2099-4002")
			calls := 0
			v.client = &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Host != "cveawg.mitre.org" {
					t.Fatalf("cached verification refetched NVD: %s", req.URL)
				}
				deadline, ok := req.Context().Deadline()
				if !ok || time.Until(deadline) > 4*time.Second {
					t.Error("optional request lacks short timeout")
				}
				rec := httptest.NewRecorder()
				if mode == "unavailable" {
					rec.WriteHeader(http.StatusServiceUnavailable)
				} else {
					_, _ = io.WriteString(rec, primary)
				}
				return rec.Result(), nil
			}}}
			for range 2 {
				if exists, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err != nil || !exists {
					t.Fatalf("optional failure erased NVD verification: exists=%v, err=%v", exists, err)
				}
			}
			meta := v.GetMeta("CVE-2099-4001")
			raw, _ := json.Marshal(meta)
			if !meta.Exists || meta.Verification.Status != "verified" || meta.Verification.Source != "nvd" || meta.Description != "Example Harbor permits object injection." {
				t.Fatalf("optional failure changed NVD verification: %s", raw)
			}
			if !meta.CNAChecked || len(meta.CNAFacts) != 0 {
				t.Fatalf("optional failure retained unverified CNA facts or lost lookup status: %s", raw)
			}
			gap := strings.ToLower(meta.CNAGap)
			if !strings.Contains(gap, "unknown") || !strings.Contains(gap, "unavailable") || strings.Contains(gap, "2.4") || strings.Contains(gap, "no fixed") {
				t.Fatalf("missing or misleading evidence-gap status: %s", raw)
			}
			if calls != 1 {
				t.Fatalf("optional request count = %d, want 1", calls)
			}
		})
	}
}

func TestCVEVerifierCachedCNASupplementSingleflight(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, CachedAt: time.Now()}
	primary := syntheticCompletenessCNA(t)
	var calls atomic.Int32
	v.client = &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		rec := httptest.NewRecorder()
		_, _ = rec.Write(primary)
		return rec.Result(), nil
	}}}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if exists, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err != nil || !exists {
				t.Errorf("verification lost: exists=%v err=%v", exists, err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent optional primary requests = %d, want 1", calls.Load())
	}
}

func TestCVEVerifierCNASupplementSurvivesConcurrentCacheEviction(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, CachedAt: time.Now()}
	primary := syntheticCompletenessCNA(t)
	v.client = &http.Client{Transport: &mockNVDTransport{handler: func(*http.Request) (*http.Response, error) {
		v.mu.Lock()
		delete(v.cache, "CVE-2099-4001")
		v.mu.Unlock()
		rec := httptest.NewRecorder()
		_, _ = rec.Write(primary)
		return rec.Result(), nil
	}}}
	if exists, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err == nil && !exists {
		t.Fatal("cache eviction turned a verified identity into a negative result")
	}
}

func TestCNASupplementSurvivesOverlappingNVDResponses(t *testing.T) {
	for _, order := range []string{"NVD before CNA", "NVD after CNA"} {
		t.Run(order, func(t *testing.T) {
			v := NewCVEVerifier(nil, nil)
			freshNVD := func() *CVEMeta {
				return &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, CachedAt: time.Now()}
			}
			v.cacheMeta("CVE-2099-4001", freshNVD())
			calls := 0
			v.client = &http.Client{Transport: &mockNVDTransport{handler: func(*http.Request) (*http.Response, error) {
				calls++
				if order == "NVD before CNA" {
					v.cacheMeta("CVE-2099-4001", freshNVD())
				}
				rec := httptest.NewRecorder()
				_, _ = rec.Write(syntheticCompletenessCNA(t))
				return rec.Result(), nil
			}}}
			if _, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err != nil {
				t.Fatal(err)
			}
			if order == "NVD after CNA" {
				v.cacheMeta("CVE-2099-4001", freshNVD())
			}
			if _, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || len(v.GetMeta("CVE-2099-4001").CNAFacts) == 0 {
				t.Fatalf("overlapping NVD response discarded cached primary evidence: CNA calls=%d", calls)
			}
		})
	}
}
