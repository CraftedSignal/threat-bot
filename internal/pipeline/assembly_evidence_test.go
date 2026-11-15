package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

type assemblyEvidenceLLM struct {
	noopLLM
	t                  *testing.T
	assemblies, checks int
}

func (c *assemblyEvidenceLLM) GenerateJSON(_ context.Context, _, _ string, out any) error {
	switch v := out.(type) {
	case *QualityScore:
		*v = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
	case *ExtractionResult:
		*v = ExtractionResult{CVEs: []string{"CVE-2099-4001"}, AffectedVendors: []string{"ExampleCo"}, AffectedProducts: []string{"Example Harbor"}, Summary: "Example Harbor permits unauthorized configuration changes."}
	default:
		return fmt.Errorf("unexpected JSON type %T", out)
	}
	return nil
}
func (c *assemblyEvidenceLLM) GenerateStructured(_ context.Context, prompt, system string, _ *llm.Schema, out any) error {
	switch out.(type) {
	case *generatedBrief:
		c.assemblies++
		if system != compactAdvisorySystemPrompt {
			c.t.Error("lost compact advisory profile")
		}
		for _, fact := range []string{"2.3", "2.4", "PR:L", "CVE-2099-4001"} {
			if !strings.Contains(prompt, fact) {
				c.t.Errorf("initial assembly lacks independently enforced primary fact %q", fact)
			}
		}
		return structuredFromText(syntheticCompletenessBrief(c.t, true), out)
	case *groundingReport:
		c.checks++
		if system != groundingSystem {
			c.t.Fatal("lost independent complete grounding")
		}
		for _, fact := range []string{"2.3", "2.4", "PR:L"} {
			if !strings.Contains(prompt, fact) {
				c.t.Errorf("grounding lost primary fact %q", fact)
			}
		}
		return nil
	default:
		return fmt.Errorf("unexpected structured type %T", out)
	}
}

// Moving primary evidence back after generation must fail at the actual LLM boundary.
func TestInitialAssemblyReceivesVerifiedEvidenceBeforeIndependentGrounding(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	client := &assemblyEvidenceLLM{t: t}
	p := New(Config{DB: db, LLMClient: client, Logger: quietLogger(), QualityThreshold: 1})
	p.cveVerifier = completenessVerifier(t)
	p.cveEnricher = NewCVEEnricher(p.cveVerifier)
	item := scraper.RawItem{SourceID: "assembly:verified", Source: "nvd", Title: "Example Harbor CVE-2099-4001", URL: "https://vendor.example/harbor", Content: strings.Repeat("Example Harbor permits configuration changes with low privileges (CVE-2099-4001). ", 3), Enriched: true}
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if client.assemblies != 1 || client.checks != 1 {
		t.Fatalf("assembly/check boundary counts: %d/%d", client.assemblies, client.checks)
	}
}

func evidenceAssemblyPipeline(t *testing.T, verifier *CVEVerifier) (*Pipeline, *[]string) {
	t.Helper()
	var prompts []string
	client := referenceTestLLM{respond: func(_ context.Context, prompt, _ string, _ *llm.Schema, out any) error {
		prompts = append(prompts, prompt)
		return structuredFromText(syntheticCompletenessBrief(t, true), out)
	}}
	return &Pipeline{assembler: NewBriefAssembler(client), cveVerifier: verifier}, &prompts
}
func verifiedAssemblyMeta(id, product, text string) *CVEMeta {
	return &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CachedAt: time.Now(), CNAChecked: true, CNAFacts: []cnaSourceFact{{CVEID: id, Product: product, Kind: "solution", Text: text}}}
}

func TestAssemblyFetchesPrimaryEvidenceBeforeGeneration(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	lookups := 0
	v.client = &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		if req.URL.Host == "cveawg.mitre.org" {
			lookups++
			rec.Write(syntheticCompletenessCNA(t))
		} else {
			rec.WriteString(`{"vulnerabilities":[]}`)
		}
		return rec.Result(), nil
	}}}
	p, prompts := evidenceAssemblyPipeline(t, v)
	item := scraper.RawItem{Source: "nvd", Title: "Example Harbor CVE-2099-4001", Content: "Example Harbor advisory."}
	if _, err := p.assembleWithVerifiedEvidence(context.Background(), item, nil, nil); err != nil {
		t.Fatal(err)
	}
	if lookups != 1 || len(*prompts) != 1 {
		t.Fatalf("lookups/generations=%d/%d", lookups, len(*prompts))
	}
	for _, fact := range []string{"2.3", "2.4", "PR:L"} {
		if !strings.Contains((*prompts)[0], fact) {
			t.Fatalf("fresh primary fact absent: %s", fact)
		}
	}
}

func TestAssemblyEvidenceKeepsTargetsScopedAndDiscoveryUnmodified(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = verifiedAssemblyMeta("CVE-2099-4001", "Example Harbor", "Update Example Harbor to 2.4.")
	v.cache["CVE-2099-4002"] = verifiedAssemblyMeta("CVE-2099-4002", "Other Product", "Update Other Product to 9.8.")
	v.cache["CVE-2099-4001"].CNAFacts = append(v.cache["CVE-2099-4001"].CNAFacts,
		cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Sibling Product", Kind: "solution", Text: "Update Sibling Product to 8.7."}, cnaSourceFact{CVEID: "CVE-2099-4999", Product: "Invented", Text: "unrelated forbidden fix"})
	p, prompts := evidenceAssemblyPipeline(t, v)
	item := scraper.RawItem{Source: "research", Title: "Example Harbor CVE-2099-4001", Content: "Background CVE-2099-4002.", Discovery: &scraper.DiscoveryContext{}}
	// The supplement must never be stored in the original discovery evidence.
	before, _ := json.Marshal(item)
	extraction := &ExtractionResult{CVEs: []string{"CVE-2099-4999", "CVE-2099-4001"}}
	if _, err := p.assembleWithVerifiedEvidence(context.Background(), item, extraction, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(item)
	if string(before) != string(after) || strings.Contains(groundingSource(item), "2.4") {
		t.Fatal("assembly supplement contaminated discovery claim authority")
	}
	prompt := (*prompts)[0]
	for _, want := range []string{`"cve_id":"CVE-2099-4001","product":"Example Harbor"`, `"cve_id":"CVE-2099-4002","product":"Other Product"`} {
		if !strings.Contains(prompt, want) {
			t.Errorf("lost explicit scope: %s", want)
		}
	}
	if strings.Contains(prompt, "unrelated forbidden fix") {
		t.Fatal("foreign-record fact became generation evidence")
	}
	brief := syntheticCompletenessBrief(t, true)
	checkerEvidence := p.groundingEvidence(item, brief)
	if strings.Contains(checkerEvidence, "Update Other Product") {
		t.Fatal("neighbor CVE became this brief's verified primary evidence")
	}
	issue := groundingIssue{Kind: groundingKindMaterialOmission, Subject: "CVE-2099-4001", SourceQuote: "Update Other Product to 9.8."}
	if err := validateMaterialOmission(issue, checkerEvidence, brief); err == nil {
		t.Fatal("neighbor product fix bypassed omission scope gate")
	}
	issue.SourceQuote = "Update Sibling Product to 8.7."
	if err := validateMaterialOmission(issue, checkerEvidence, brief); err == nil {
		t.Fatal("same-CVE sibling product fix bypassed product scope gate")
	}

}

func TestAssemblyEvidenceLookupBoundPreservesFallbackAndPriority(t *testing.T) {
	v := NewCVEVerifier(nil, nil)
	var mentions []string
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("CVE-2099-%04d", 5000+i)
		mentions = append(mentions, id)
		v.cache[id] = verifiedAssemblyMeta(id, "Product", fmt.Sprintf("scope-%04d", 5000+i))
	}
	p, prompts := evidenceAssemblyPipeline(t, v)
	item := scraper.RawItem{Source: "nvd", Title: "Advisory references " + strings.Join(mentions[:32], " "), Content: strings.Join(mentions, " "), Metadata: map[string]string{"cve_id": "CVE-2099-5039"}}
	extraction := &ExtractionResult{CVEs: []string{"CVE-2099-5038", "CVE-2099-9999"}}
	ids := assemblyEvidenceCVEs(item, extraction)
	if !reflect.DeepEqual(ids[:2], []string{"CVE-2099-5039", "CVE-2099-5038"}) {
		t.Fatalf("subject priority=%v", ids[:2])
	}
	if _, err := p.assembleWithVerifiedEvidence(context.Background(), item, extraction, nil); err != nil {
		t.Fatal(err)
	}
	prompt := (*prompts)[0]
	if !strings.Contains(prompt, "scope-5039") || !strings.Contains(prompt, "scope-5038") || !strings.Contains(prompt, assemblyEvidenceIncomplete) {
		t.Fatal("bounded evidence lost subject priority or honest partial coverage")
	}
	if strings.Contains(prompt, "scope-5037") {
		t.Fatal("lookup bound did not constrain appended evidence")
	}
	// The independent checker still sees a generated target outside assembly's cap.
	brief := "title: Product CVE-2099-5037\naffected_products: [Product]\n"
	if !strings.Contains(p.groundingEvidence(item, brief), "scope-5037") {
		t.Fatal("assembly lookup bound weakened grounding evidence")
	}
}

func TestAssemblyEvidenceMissingOutageAndCancellation(t *testing.T) {
	for _, scenario := range []string{"no_cve", "not_found", "outage", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			v := NewCVEVerifier(nil, nil)
			requests := 0
			v.client = &http.Client{Transport: &mockNVDTransport{handler: func(req *http.Request) (*http.Response, error) {
				requests++
				if scenario == "outage" {
					return nil, errors.New("synthetic outage")
				}
				rec := httptest.NewRecorder()
				if req.URL.Host == "cveawg.mitre.org" {
					rec.WriteHeader(http.StatusNotFound)
				} else {
					rec.WriteString(`{"vulnerabilities":[]}`)
				}
				return rec.Result(), nil
			}}}
			p, prompts := evidenceAssemblyPipeline(t, v)
			item := scraper.RawItem{Title: "Source CVE-2099-4001", Content: "Original source remains available."}
			if scenario == "no_cve" {
				item.Title = "Source without identifier"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel" {
				cancel()
			}
			_, err := p.assembleWithVerifiedEvidence(ctx, item, nil, nil)
			if scenario == "cancel" {
				if !errors.Is(err, context.Canceled) || len(*prompts) != 0 || requests != 0 {
					t.Fatal("cancellation bought work")
				}
				return
			}
			if err != nil || len(*prompts) != 1 {
				t.Fatalf("truthful original-source fallback lost: %v", err)
			}
			if strings.Contains((*prompts)[0], "Verified primary CVE evidence") {
				t.Fatal("missing record fabricated verified facts")
			}
			if scenario == "no_cve" && requests != 0 {
				t.Fatal("no-CVE source performed identity lookups")
			}
			if scenario == "outage" && !strings.Contains((*prompts)[0], assemblyEvidenceIncomplete) {
				t.Fatal("outage coverage hidden")
			}
			if scenario == "outage" {
				if _, err := p.assembleWithVerifiedEvidence(ctx, item, nil, nil); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains((*prompts)[1], assemblyEvidenceIncomplete) {
					t.Fatal("cached outage lost uncertainty on retry")
				}
			}
		})
	}
}

func TestAssemblyEvidenceBoundedUTF8AndChangedFactInvalidatesCache(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	v := NewCVEVerifier(nil, nil)
	v.cache["CVE-2099-4001"] = verifiedAssemblyMeta("CVE-2099-4001", "Example Harbor", "Update Example Harbor to 2.4.")
	p, prompts := evidenceAssemblyPipeline(t, v)
	p.assembler.client = llm.NewCachedClient(p.assembler.client, "synthetic-model", db, quietLogger())
	item := scraper.RawItem{Source: "nvd", Title: "Example Harbor CVE-2099-4001", Content: strings.Repeat("概要脆弱性。", 5000)}
	ctx := llm.WithCallMetadata(context.Background(), llm.CallMetadata{Stage: "assembly"})
	for range 2 {
		if _, err := p.assembleWithVerifiedEvidence(ctx, item, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(*prompts) != 1 {
		t.Fatal("unchanged source package repurchased assembly")
	}
	v.cache["CVE-2099-4001"] = verifiedAssemblyMeta("CVE-2099-4001", "Example Harbor", "Update Example Harbor to 2.5.")
	if _, err := p.assembleWithVerifiedEvidence(ctx, item, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(*prompts) != 2 || !strings.Contains((*prompts)[1], "Update Example Harbor to 2.5.") {
		t.Fatal("changed primary fact reused stale generation")
	}
	for i := 0; i < 20; i++ {
		v.cache["CVE-2099-4001"].CNAFacts = append(v.cache["CVE-2099-4001"].CNAFacts,
			cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Sibling Product", Kind: "solution", Text: "Update Sibling Product to 8.7."}, cnaSourceFact{CVEID: "CVE-2099-4001", Product: "Example Harbor", Kind: "description", Text: strings.Repeat("適用範囲。", 200)})
	}
	if _, err := p.assembleWithVerifiedEvidence(ctx, item, nil, nil); err != nil {
		t.Fatal(err)
	}
	prompt := (*prompts)[2]
	if !utf8.ValidString(prompt) || !strings.Contains(prompt, "Coverage incomplete") {
		t.Fatal("large evidence corrupted UTF8 or hid bounded coverage")
	}
	var baseline string
	raw := NewBriefAssembler(referenceTestLLM{respond: func(_ context.Context, prompt, _ string, _ *llm.Schema, out any) error {
		baseline = prompt
		return structuredFromText(syntheticCompletenessBrief(t, true), out)
	}})
	if _, err := raw.Assemble(context.Background(), item, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(prompt)-len(baseline) > maxCNAEvidenceBytes+len("\nOriginal source:\n") {
		t.Fatalf("primary evidence grew unbounded: %d bytes", len(prompt)-len(baseline))
	}
	if !strings.Contains(prompt, "Update Example Harbor to 2.5.") {
		t.Fatal("article truncation discarded primary remediation")
	}
}

// Batch-enabled clients only prefetch quality/extraction; structured assembly
// delegates through the same persistent cache and must keep the primary input.
func TestAssemblyEvidenceStructuredPrefetchUsesSameCachedInput(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	v := completenessVerifier(t)
	p, prompts := evidenceAssemblyPipeline(t, v)
	cached := llm.NewCachedClient(p.assembler.client, "synthetic-model", db, quietLogger())
	p.assembler.client = llm.NewPrefetchClient(cached, &llm.VertexBatch{}, 64, quietLogger())
	item := scraper.RawItem{Source: "nvd", Title: "Example Harbor CVE-2099-4001", Content: "Example Harbor source notice."}
	ctx := llm.WithCallMetadata(context.Background(), llm.CallMetadata{Stage: "assembly"})
	if _, err := p.assembleWithVerifiedEvidence(ctx, item, nil, nil); err != nil {
		t.Fatal(err)
	}
	p.assembler.client = cached
	if _, err := p.assembleWithVerifiedEvidence(ctx, item, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(*prompts) != 1 {
		t.Fatalf("batch/online wrapper mismatch repurchased assembly: %d", len(*prompts))
	}
	if !strings.Contains((*prompts)[0], "2.4") {
		t.Fatal("batch-enabled assembly lost primary evidence")
	}
}
