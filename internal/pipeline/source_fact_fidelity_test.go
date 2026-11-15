package pipeline

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

func TestValidationPreservesCPEReleaseCandidatesAcrossCycles(t *testing.T) {
	want := []string{
		"cpe:2.3:o:linux:linux_kernel:7.2:rc1:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:7.2:rc2:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:7.2:rc3:*:*:*:*:*:*",
	}
	current := validWindowsPathBriefYAML + "\ncpes:\n  - " + strings.Join(want, "\n  - ") + "\n"
	for cycle := range 3 {
		cleaned, _, err := NewBriefValidator().Validate(current)
		if err != nil {
			t.Fatal(err)
		}
		var checked struct {
			CPEs []string `yaml:"cpes"`
		}
		if err := yaml.Unmarshal([]byte(groundingView(cleaned, "")), &checked); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(checked.CPEs, want) {
			t.Fatalf("validation cycle %d changed checked applicability: %q", cycle, checked.CPEs)
		}
		current = cleaned
	}
}

// A correct model response must not enter the durable repair loop because
// validation broadens its release-candidate CPEs before independent grounding.
func TestExactSourceCPEsDoNotBuyFutileGroundingRepairs(t *testing.T) {
	const rc1 = "cpe:2.3:o:linux:linux_kernel:7.2:rc1:*:*:*:*:*:*"
	const rc2 = "cpe:2.3:o:linux:linux_kernel:7.2:rc2:*:*:*:*:*:*"
	const general = "cpe:2.3:o:linux:linux_kernel:7.2:*:*:*:*:*:*:*"
	exact := validWindowsPathBriefYAML + "\ncpes:\n  - " + rc1 + "\n  - " + rc2 + "\n"
	assemblies, repairs, checks := 0, 0, 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, _ string, _ *llm.Schema, out any) error {
		switch v := out.(type) {
		case *generatedBrief:
			assemblies++
			return structuredFromText(exact, out)
		case *revisedBrief:
			repairs++
			return structuredFromText(exact, out)
		case *groundingReport:
			checks++
			_, brief, ok := strings.Cut(prompt, "## Generated Brief (YAML)")
			if !ok {
				t.Fatal("independent checker did not receive the brief")
			}
			if strings.Contains(brief, general) {
				v.Issues = []groundingIssue{{Kind: groundingKindUnsupported, Field: "cpes", BriefQuote: general, Reason: "The source lists rc1 and rc2, not the general release."}}
			} else if !strings.Contains(brief, rc1) || !strings.Contains(brief, rc2) {
				t.Fatal("independent checker lost exact source CPEs")
			}
			return nil
		default:
			t.Fatalf("unexpected provider boundary %T", out)
		}
		return nil
	}}
	db := mustOpenTestDB(t)
	defer db.Close()
	cfg := Config{DB: db, LLMClient: client, MaxGroundingAttempts: 3, RetryBackoff: -1, Logger: quietLogger()}
	item := scraper.RawItem{SourceID: "cpe:release-candidates", Source: "cisa-kev", Title: "Vendor security advisory", Content: strings.Repeat("Vendor confirms affected Linux release candidates. ", 10) + rc1 + " " + rc2, SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
	for range 4 {
		if err := New(cfg).processItem(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	if assemblies != 1 || repairs != 0 || checks != 1 {
		t.Fatalf("correct source response bought futile work: assembly=%d repair=%d check=%d", assemblies, repairs, checks)
	}
	if _, held, err := db.PipelineQuarantineReason(item.SourceID); err != nil || held {
		t.Fatalf("correct source response quarantined: held=%v err=%v", held, err)
	}
}

func TestRetainedWildcardCandidateRecoversWithoutReassembly(t *testing.T) {
	const rc1 = "cpe:2.3:o:linux:linux_kernel:7.2:rc1:*:*:*:*:*:*"
	const rc2 = "cpe:2.3:o:linux:linux_kernel:7.2:rc2:*:*:*:*:*:*"
	const general = "cpe:2.3:o:linux:linux_kernel:7.2:*:*:*:*:*:*:*"
	exact := validWindowsPathBriefYAML + "\ncpes:\n  - " + rc1 + "\n  - " + rc2 + "\n"
	repairs, checks := 0, 0
	client := referenceTestLLM{respond: func(_ context.Context, prompt, _ string, _ *llm.Schema, out any) error {
		switch v := out.(type) {
		case *revisedBrief:
			repairs++
			return structuredFromText(exact, out)
		case *groundingReport:
			checks++
			_, brief, ok := strings.Cut(prompt, "## Generated Brief (YAML)")
			if !ok {
				t.Fatal("independent checker did not receive the repaired brief")
			}
			if strings.Contains(brief, general) {
				v.Issues = []groundingIssue{{Kind: groundingKindUnsupported, Field: "cpes", BriefQuote: general, Reason: "The source supports release candidates only."}}
			} else if !strings.Contains(brief, rc1) || !strings.Contains(brief, rc2) {
				t.Fatal("independent checker lost repaired source scope")
			}
			return nil
		default:
			t.Fatalf("saved paid candidate was rebuilt: %T", out)
		}
		return nil
	}}
	db := mustOpenTestDB(t)
	defer db.Close()
	cfg := Config{DB: db, LLMClient: client, MaxGroundingAttempts: 3, RetryBackoff: -1, Logger: quietLogger()}
	p := New(cfg)
	item := scraper.RawItem{SourceID: "cpe:retained", Source: "cisa-kev", Title: "Vendor security advisory", Content: strings.Repeat("Vendor confirms affected Linux release candidates. ", 10) + rc1 + " " + rc2}
	item.Revision = item.ContentRevision()
	state := processingCandidate{Item: item, Extraction: &ExtractionResult{}, BriefYAML: validWindowsPathBriefYAML + "\ncpes: [" + general + "]\n", Issues: []string{"cpes: source supports rc1 and rc2, not the general release"}}
	if err := p.saveCandidate(p.processingInputKey(item), state, time.Time{}); err != nil {
		t.Fatal(err)
	}
	// The old budget and saved YAML survive deployment/restart unchanged.
	for range 2 {
		if _, err := db.RecordGroundingAttempt(item.SourceID); err != nil {
			t.Fatal(err)
		}
	}
	if err := New(cfg).processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if repairs != 1 || checks != 1 {
		t.Fatalf("saved candidate recovery calls: repair=%d check=%d", repairs, checks)
	}
	if _, held, err := db.PipelineQuarantineReason(item.SourceID); err != nil || held {
		t.Fatalf("saved candidate could not recover: held=%v err=%v", held, err)
	}
	if cp, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || cp != nil {
		t.Fatalf("completed candidate retained: %+v err=%v", cp, err)
	}
}

func TestAssemblyIncludesNVDProductRangesWithPrimaryEvidenceOrGap(t *testing.T) {
	const ranges = "linux linux kernel: >= 4.18, < 5.10.261; >= 5.11, < 5.15.212; >= 5.16, < 6.1.178\nacme other_product: >= 2.0, < 2.4"
	for _, unavailable := range []bool{false, true} {
		name := "primary present"
		if unavailable {
			name = "primary unavailable"
		}
		t.Run(name, func(t *testing.T) {
			verifier := NewCVEVerifier(nil, nil)
			meta := verifiedAssemblyMeta("CVE-2099-4001", "Linux kernel", "Linux kernel has a use-after-free condition.")
			if unavailable {
				meta.CNAFacts, meta.CNAUnavailable, meta.CNAGap = nil, true, "unknown: optional CNA request unavailable"
			}
			verifier.cache["CVE-2099-4001"] = meta
			p, prompts := evidenceAssemblyPipeline(t, verifier)
			item := scraper.RawItem{Source: "nvd", Title: "Linux kernel CVE-2099-4001", Content: "Linux kernel has a use-after-free condition.", Metadata: map[string]string{"affected_ranges": ranges}}
			if _, err := p.assembleWithVerifiedEvidence(context.Background(), item, nil, nil); err != nil {
				t.Fatal(err)
			}
			if len(*prompts) != 1 || strings.Count((*prompts)[0], ranges) != 1 {
				t.Fatalf("assembly did not receive all exact product/branch ranges once: %q", *prompts)
			}
		})
	}
}

func TestGroundingSourceIncludesTrustedRangesOnce(t *testing.T) {
	const ranges = "linux linux kernel: >= 4.18, < 5.10.261; >= 5.11, < 5.15.212"
	for _, source := range []string{"nvd", "ghsa", "cisa-kev", "rss"} {
		t.Run(source, func(t *testing.T) {
			item := scraper.RawItem{Source: source, Content: "Advisory source.", Metadata: map[string]string{"affected_ranges": ranges}}
			want := 1
			if source == "rss" {
				want = 0
			}
			if got := strings.Count(groundingSource(item), ranges); got != want {
				t.Fatalf("trusted range occurrences=%d, want %d", got, want)
			}
		})
	}
}
