package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestCNAOptionalOutageRedactsTransportDetailsFromEvidence(t *testing.T) {
	const diagnostic = "synthetic-private-transport-detail"
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, CachedAt: time.Now()}
	v.client = &http.Client{Transport: &mockNVDTransport{handler: func(*http.Request) (*http.Response, error) {
		return nil, errors.New(diagnostic)
	}}}
	if exists, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err != nil || !exists {
		t.Fatalf("optional outage changed verified identity: exists=%v err=%v", exists, err)
	}
	meta := v.GetMeta("CVE-2099-4001")
	source := (&Pipeline{cveVerifier: v}).groundingEvidence(scraper.RawItem{Title: "Example Harbor CVE-2099-4001", Content: syntheticCompletenessSource}, syntheticIncompleteBrief)
	if strings.Contains(meta.CNAGap, diagnostic) || strings.Contains(source, diagnostic) {
		t.Fatal("raw transport diagnostics escaped into cached evidence or the model source")
	}
	if !strings.Contains(source, "unknown") || !strings.Contains(source, "unavailable") {
		t.Fatal("redaction lost the explicit evidence coverage gap")
	}
}

func TestCNASupplementCancellationPreservesRetryableEvidence(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, CachedAt: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	v.client = &http.Client{Transport: &mockNVDTransport{handler: func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			cancel()
			return nil, context.Canceled
		}
		rec := httptest.NewRecorder()
		_, _ = rec.Write(syntheticCompletenessCNA(t))
		return rec.Result(), nil
	}}}
	if _, err := v.checkCVE(ctx, "CVE-2099-4001"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if meta := v.GetMeta("CVE-2099-4001"); !meta.Exists || meta.CNAChecked {
		t.Fatal("canceled optional lookup changed identity or prevented retry")
	}
	if exists, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err != nil || !exists {
		t.Fatalf("later evidence lookup could not retry: %v", err)
	}
	if calls != 2 || len(v.GetMeta("CVE-2099-4001").CNAFacts) == 0 {
		t.Fatal("retry did not retain primary evidence exactly once")
	}
}

func TestCNAPrimaryIdentityContradictionOverridesNVDListing(t *testing.T) {
	for _, state := range []string{"REJECTED", "RESERVED"} {
		t.Run(state, func(t *testing.T) {
			v := NewCVEVerifier(nil, nil)
			v.cache["CVE-2099-4001"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "nvd"}, CachedAt: time.Now()}
			v.client = &http.Client{Transport: &mockNVDTransport{handler: func(*http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				_, _ = rec.Write([]byte(strings.Replace(string(syntheticCompletenessCNA(t)), `"state":"PUBLISHED"`, `"state":"`+state+`"`, 1)))
				return rec.Result(), nil
			}}}
			if exists, err := v.checkCVE(context.Background(), "CVE-2099-4001"); err != nil || exists {
				t.Fatalf("primary identity contradiction ignored: exists=%v err=%v", exists, err)
			}
			meta := v.GetMeta("CVE-2099-4001")
			if meta.Verification.Status != strings.ToLower(state) || meta.Verification.Source != "nvd+cve_program" || len(meta.CNAFacts) != 0 {
				t.Fatal("contradictory record retained source facts or wrong identity status")
			}
		})
	}
}
