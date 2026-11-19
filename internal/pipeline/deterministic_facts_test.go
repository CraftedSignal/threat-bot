package pipeline

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

const synologyDescription = "Improper neutralization of special elements in Synology DiskStation Manager (DSM) allows remote attackers to execute arbitrary commands via unspecified vectors. Affected: DSM before 7.3.2-86009-5 and 7.4.1-90080-1."

func TestExtractPatchVersionHintReturnsAllBeforeVersions(t *testing.T) {
	cases := map[string][]string{
		"DSM before 7.3.2-86009-5 and 7.4.1-90080-1.":                {"7.3.2-86009-5", "7.4.1-90080-1"},
		"Fixed in releases before 1.2.3, 1.3.4 and 2.0.1 of the app": {"1.2.3", "1.3.4", "2.0.1"},
		"prior to version 4.5.6 only":                                {"4.5.6"},
	}
	for text, want := range cases {
		got := extractPatchVersionHint(text)
		if !slices.Equal(got.BeforeVersions, want) {
			t.Errorf("%q: BeforeVersions = %v, want %v", text, got.BeforeVersions, want)
		}
		if got.FixedVersion != "" || got.VulnerableRange == "" {
			t.Errorf("%q: a boundary must not assert a fixed release: %+v", text, got)
		}
	}
}

func synologyItem() scraper.RawItem {
	return scraper.RawItem{
		SourceID: "nvd:CVE-2026-0001", Source: "nvd", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
		Title:    "CVE-2026-0001 — Synology DSM command injection",
		Content:  synologyDescription + "\n\nCVSS v3.1 Base Score: 8.8",
		Metadata: map[string]string{"cve": "CVE-2026-0001", "cvss": "8.8"},
	}
}

const synologyBrief = `affected_vendors:
  - Synology
affected_products:
  - DiskStation Manager
`

func TestInjectAffectedRangesHoldsAmbiguousBranches(t *testing.T) {
	item := synologyItem()
	once := injectAffectedRanges(synologyBrief, item, primaryRecordFacts{})
	for _, v := range []string{"7.3.2-86009-5", "7.4.1-90080-1"} {
		if strings.Contains(once, v) {
			t.Errorf("ambiguous branch %s injected:\n%s", v, once)
		}
	}
	if twice := injectAffectedRanges(once, item, primaryRecordFacts{}); twice != once {
		t.Errorf("injection is not idempotent:\n%s\n---\n%s", once, twice)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(once), &doc); err != nil {
		t.Fatal(err)
	}
	if got := yamlStringList(doc["affected_products"]); len(got) != 1 {
		t.Errorf("products duplicated: %v", got)
	}
}

func TestInjectAffectedRangesUsesNVDMetadataRanges(t *testing.T) {
	item := scraper.RawItem{Source: "nvd", Content: "no versions in prose", Metadata: map[string]string{
		"affected_ranges": "diskstation manager: >= 7.3.0, < 7.3.2\nother gadget: <= 9.1",
	}}
	got := injectAffectedRanges(synologyBrief, item, primaryRecordFacts{})
	if !strings.Contains(got, "DiskStation Manager (>= 7.3.0, < 7.3.2)") {
		t.Errorf("metadata range not merged:\n%s", got)
	}
	if strings.Contains(got, "<= 9.1") {
		t.Errorf("range for an unrelated product leaked:\n%s", got)
	}
}

func TestPipelineKeepsAmbiguousNVDVersionsInSourceOnly(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	var prompt string
	brief := "affected_vendors:\n  - Synology\naffected_products:\n  - DiskStation Manager\n" + validWindowsPathBriefYAML
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return brief, nil },
		generateJSON: func(_ context.Context, p, system string, out any) error {
			if q, ok := out.(*QualityScore); ok {
				*q = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
			}
			if system == groundingSystem && prompt == "" {
				prompt = p
			}
			return nil
		},
	}
	var logs bytes.Buffer
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	item := synologyItem()
	item.SigmaRule = &scraper.SigmaRule{Title: "Rule"}
	item.Content += "\n" + strings.Repeat("Confirmed vendor notice. ", 30)
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "DiskStation Manager (<") {
		t.Fatalf("ambiguous branches synthesized in prompt: %s", prompt)
	}
	found := false
	for draft, err := range db.DraftsWithStatus(storage.StatusPending) {
		if err != nil {
			t.Fatal(err)
		}
		found = true
		if strings.Contains(draft.BriefYAML, "DiskStation Manager (<") {
			t.Errorf("saved brief invented a branch intersection:\n%s", draft.BriefYAML)
		}
	}
	if !found {
		t.Error("no draft saved")
	}
}
