package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCVEVerifierChecksEveryIDDeterministically(t *testing.T) {
	var calls []string
	v := NewCVEVerifier(nil, nil)
	v.client = &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "cveawg.mitre.org" {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusServiceUnavailable)
			return rec.Result(), nil
		}
		id := req.URL.Query().Get("cveId")
		calls = append(calls, id)
		rec := httptest.NewRecorder()
		fmt.Fprintf(rec, `{"vulnerabilities":[{"cve":{"id":%q}}]}`, id)
		return rec.Result(), nil
	}}}
	got, _ := v.Verify(context.Background(), "title: CVE-2026-1007 CVE-2026-1002 CVE-2026-1006 CVE-2026-1001 CVE-2026-1005 CVE-2026-1004 CVE-2026-1003\ncustom_metadata: retained\n")
	if len(calls) != 7 || !strings.HasSuffix(calls[0], "1001") || !strings.HasSuffix(calls[6], "1007") {
		t.Fatalf("verification skipped/randomized IDs: %v", calls)
	}
	if !strings.Contains(got, "status: verified") || !strings.Contains(got, "custom_metadata: retained") {
		t.Fatal(got)
	}
}

func TestCVEVerifierFreshAuthorityFallbackAndUnavailable(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprint(unavailable), func(t *testing.T) {
			v := NewCVEVerifier(nil, nil)
			v.client = &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				if unavailable {
					rec.WriteHeader(503)
				} else if req.URL.Host == "cveawg.mitre.org" {
					rec.WriteString(`{"cveMetadata":{"cveId":"CVE-2026-12345","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"A fresh disclosure."}]}}}`)
				} else {
					rec.WriteString(`{"vulnerabilities":[]}`)
				}
				return rec.Result(), nil
			}}}
			got, _ := v.Verify(context.Background(), "title: CVE-2026-12345\n")
			want := "status: verified"
			if unavailable {
				want = "status: unavailable"
			}
			if !strings.Contains(got, want) {
				t.Fatal(got)
			}
			if !unavailable && !strings.Contains(got, "source: cve_program") {
				t.Fatal(got)
			}
		})
	}
}

func TestCVEVerifierDoesNotVerifyRejectedOrMismatchedRecord(t *testing.T) {
	for _, record := range []string{`{"id":"CVE-2026-12345","vulnStatus":"Rejected"}`, `{"id":"CVE-2026-54321"}`} {
		v := NewCVEVerifier(nil, nil)
		v.client = &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			if req.URL.Host == "cveawg.mitre.org" {
				rec.WriteHeader(503)
			} else {
				fmt.Fprintf(rec, `{"vulnerabilities":[{"cve":%s}]}`, record)
			}
			return rec.Result(), nil
		}}}
		got, _ := v.Verify(context.Background(), "title: CVE-2026-12345\n")
		want := "unavailable"
		if strings.Contains(record, "Rejected") {
			want = "rejected"
		}
		if !strings.Contains(got, "status: "+want) {
			t.Fatal(got)
		}
	}
}
