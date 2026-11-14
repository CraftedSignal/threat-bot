package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// Grounding runs before CVE enrichment, so the brief the checker sees holds the
// validator's placeholders (kev: false, kev_status: unknown, an unknown
// exploitation state) and, on later checks, enrichment values. None of these
// are claims the model made; the checker must not judge them.
const enrichmentPlaceholderBrief = `id: brief-2026-09-07-screenconnect-worm
title: ScreenConnect CVE-2026-84869 abused by a worm
summary: Attackers abuse CVE-2026-84869 in ConnectWise ScreenConnect.
severity: high
content: |
  ## Overview
  CVE-2026-84869 lets attackers transfer and execute files.
has_poc: true
poc_references:
  - https://www.exploit-db.com/exploits/99999
exploited: true
cves:
  - id: CVE-2026-84869
    product: ScreenConnect
    cvss: 9.9
    cvss_vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
    epss: 0.00382
    epss_percentile: 0.6
    kev: false
    kev_status: unknown
  - id: CVE-2026-0002
    kev: true
    kev_status: "true"
`

func TestGroundingViewHidesEnrichmentOwnedFields(t *testing.T) {
	view := groundingView(enrichmentPlaceholderBrief+"exploitation_evidence:\n  status: unknown\n", "")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(view), &doc); err != nil {
		t.Fatalf("view is not YAML: %v\n%s", err, view)
	}
	for _, key := range []string{"has_poc", "poc_references", "exploited", "exploitation_evidence"} {
		if _, ok := doc[key]; ok {
			t.Errorf("view still has pipeline-owned %q:\n%s", key, view)
		}
	}
	for _, gone := range []string{"kev", "cvss", "epss"} {
		if strings.Contains(view, gone) {
			t.Errorf("view still contains enrichment field %q:\n%s", gone, view)
		}
	}
	for _, kept := range []string{"CVE-2026-84869", "CVE-2026-0002", "product: ScreenConnect", "transfer and execute files", "severity: high"} {
		if !strings.Contains(view, kept) {
			t.Errorf("view lost model-written %q:\n%s", kept, view)
		}
	}
}

// An exploitation state the model asserted is a claim the checker must see;
// only the claim-free unknown state is hidden.
func TestGroundingViewKeepsAssertedExploitationState(t *testing.T) {
	for _, status := range []string{"confirmed_active", "not_observed"} {
		brief := enrichmentPlaceholderBrief + "exploitation_evidence:\n  status: " + status + "\n  source_url: https://vendor.example/advisory\n"
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(groundingView(brief, "")), &doc); err != nil {
			t.Fatal(err)
		}
		evidence, _ := doc["exploitation_evidence"].(map[string]any)
		if evidence["status"] != status {
			t.Errorf("view lost the asserted %s state: %#v", status, doc["exploitation_evidence"])
		}
	}
}

// failingTransport fails the test on any HTTP request: the pipeline tests below
// must answer CVE lookups from the verifier cache, never from NVD.
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected network request: %s", req.URL)
	return nil, errors.New("network disabled in test")
}

// End to end: the checker never sees KEV/CVSS/EPSS, and enrichment still
// writes the authoritative values afterwards.
func TestPipelineGroundsBeforeEnrichmentWithoutPlaceholders(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	brief := strings.Replace(validWindowsPathBriefYAML, "summary: Detects a Windows binary path.\n",
		"summary: Detects ScreenConnect abuse via CVE-2026-84869.\naffected_vendors:\n  - ConnectWise\naffected_products:\n  - ScreenConnect\n", 1)
	var checked []string
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return brief, nil },
		generateJSON: func(_ context.Context, prompt, system string, out any) error {
			if system != groundingSystem {
				return fmt.Errorf("unexpected JSON system: %s", system)
			}
			checked = append(checked, prompt)
			out.(*GroundingResult).Grounded = true
			return nil
		},
	}
	pipe := New(Config{
		DB: db, LLMClient: client, QualityThreshold: 3,
		KEV:    loadedKEVCatalog(t, "CVE-2026-84869"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	pipe.cveVerifier.client = &http.Client{Transport: failingTransport{t}}
	pipe.cveVerifier.cache["CVE-2026-84869"] = &CVEMeta{
		Exists: true, CVSS: 9.9, CachedAt: time.Now(),
		CPEs:        []string{"cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*"},
		Description: "ConnectWise ScreenConnect contains an improper privilege management vulnerability.",
	}
	item := scraper.RawItem{SourceID: "cisa-kev:CVE-2026-84869", Source: "cisa-kev", URL: "https://www.cve.org/CVERecord?id=CVE-2026-84869",
		Title:     "CVE-2026-84869 - ConnectWise ScreenConnect",
		Content:   strings.Repeat("CVE-2026-84869 in ConnectWise ScreenConnect allows unauthorized file transfer and execution. ", 10),
		SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if len(checked) == 0 {
		t.Fatal("grounding never ran")
	}
	for _, prompt := range checked {
		view := prompt[strings.Index(prompt, "## Generated Brief"):]
		for _, gone := range []string{"kev", "cvss", "epss", "exploitation_evidence"} {
			if strings.Contains(view, gone) {
				t.Errorf("checker saw enrichment-owned %q:\n%s", gone, view)
			}
		}
		if !strings.Contains(view, "CVE-2026-84869") {
			t.Errorf("checker lost the CVE the model wrote:\n%s", view)
		}
	}

	drafts := 0
	for draft, err := range db.DraftsWithStatus(storage.StatusPending) {
		if err != nil {
			t.Fatal(err)
		}
		drafts++
		var saved enrichedKEV
		if err := yaml.Unmarshal([]byte(draft.BriefYAML), &saved); err != nil {
			t.Fatal(err)
		}
		if len(saved.CVEs) != 1 || !saved.CVEs[0].KEV || saved.CVEs[0].KEVStatus != "true" {
			t.Errorf("saved CVEs %#v, want CVE-2026-84869 marked KEV\n%s", saved.CVEs, draft.BriefYAML)
		}
		if saved.ExploitationEvidence == nil || saved.ExploitationEvidence.Status != "confirmed_active" {
			t.Errorf("KEV listing did not set exploitation evidence: %#v", saved.ExploitationEvidence)
		}
	}
	if drafts != 1 {
		t.Fatalf("drafts = %d, want 1", drafts)
	}
}
