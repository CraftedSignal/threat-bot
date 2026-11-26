package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

// Production quarantine 2026-11 (BSI WID-SEC-2026-4772): the checker demanded
// GL.iNet versions while quoting the advisory's summary, which names no
// version. Short excerpt of the public advisory text.
const bsiGLiNetSentence = "Ein entfernter, authentisierter Angreifer kann mehrere Schwachstellen in GL.iNet KVM ausnutzen, um Sicherheitsvorkehrungen zu umgehen und Root-Zugriffe zu erlangen."

const bsiGLiNetBrief = "title: GL.iNet KVM vulnerabilities\naffected_vendors: [GL.iNet]\naffected_products: [GL.iNet KVM]\ncontent: Multiple vulnerabilities in GL.iNet KVM allow an authenticated remote attacker to gain root access.\n"

func TestVersionOmissionWithoutSourceVersionIsDropped(t *testing.T) {
	for _, tc := range []struct {
		name, source, field, reason, quote string
		blocks                             bool
	}{
		{"BSI summary names no version", bsiGLiNetSentence, "affected_products", "The brief lacks specific version information for the affected GL.iNet products, which is essential for determining the scope.", bsiGLiNetSentence, false},
		{"fixed firmware demanded from a sentence without one", bsiGLiNetSentence, "recommendation", "The brief omits the explicit minimum fixed firmware versions for GL.iNet KVM.", bsiGLiNetSentence, false},
		{"quote states a version", "GL.iNet KVM firmware before 4.6.8 is affected.", "affected_products", "The brief lacks the affected version range for GL.iNet KVM.", "GL.iNet KVM firmware before 4.6.8 is affected.", true},
		{"quote states a bare release number", "GL.iNet KVM versions before 161 are affected.", "affected_products", "The brief lacks the affected versions for GL.iNet KVM.", "GL.iNet KVM versions before 161 are affected.", true},
		{"authentication requirement", bsiGLiNetSentence, "content", "The brief omits that exploitation requires an authenticated attacker.", bsiGLiNetSentence, true},
		{"fact outside version fields", bsiGLiNetSentence, "severity", "The brief omits the affected version scope that drives severity.", bsiGLiNetSentence, true},
		{"no fix available", "Für GL.iNet KVM ist noch kein Patch verfügbar.", "recommendation", "The brief omits that no fixed version is available for GL.iNet KVM.", "Für GL.iNet KVM ist noch kein Patch verfügbar.", true},
		{"latest release instruction", "Users of GL.iNet KVM should update to the latest firmware.", "recommendation", "The brief omits the instruction to install the latest firmware version of GL.iNet KVM.", "Users of GL.iNet KVM should update to the latest firmware.", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			checker := NewGroundingChecker(scriptedGroundingLLM{report: groundingReport{Issues: []groundingIssue{{
				Kind: groundingKindMaterialOmission, Field: tc.field, Subject: "GL.iNet KVM", SourceQuote: tc.quote, Reason: tc.reason,
			}}}}).WithLogger(slog.New(slog.NewTextHandler(&logs, nil)))
			got, err := checker.Check(context.Background(), "GL.iNet KVM", tc.source, bsiGLiNetBrief)
			if err != nil {
				t.Fatal(err)
			}
			if tc.blocks {
				if got.Grounded || len(got.Issues) != 1 || len(got.Findings) != 1 || got.Findings[0].SourceQuote != tc.quote {
					t.Fatalf("omission must keep blocking with its structured finding: %+v", got)
				}
				if strings.Contains(logs.String(), "material omission dropped") {
					t.Fatalf("kept omission logged as dropped: %s", logs.String())
				}
				return
			}
			if !got.Grounded || len(got.Issues) != 0 || len(got.Findings) != 0 {
				t.Fatalf("unsatisfiable version omission still blocks: %+v", got)
			}
			if !strings.Contains(logs.String(), "material omission dropped: source quote states no version") || !strings.Contains(logs.String(), "subject=\"GL.iNet KVM\"") || !strings.Contains(logs.String(), "field="+tc.field) {
				t.Fatalf("drop not auditable: %s", logs.String())
			}
		})
	}
}

func TestQuoteStatesVersionTokens(t *testing.T) {
	for _, quote := range []string{
		"Fixed in 1.2.", "Affected: 1.2.3-rc1 and earlier.", "Upgrade to v2.", "Release 2024.1.131 fixes it.",
		"Check Point R81 is affected.", "Install build 1234.", "Apply KB5034441.", "Windows 11 version 26H1 is affected.",
		"Fixed package 0:2.56.4-1.el8_10.", "Firefox versions antérieures à 161",
		`{"cve_id":"CVE-2026-71220","product":"Red Hat Enterprise Linux 8","kind":"affected","text":"{\"vendor\":\"Red Hat\",\"product\":\"Red Hat Enterprise Linux 8\",\"packageName\":\"gfs2-utils\",\"defaultStatus\":\"affected\",\"versions\":[{\"version\":\"0:3.2.0-14.el8\",\"lessThan\":\"*\",\"versionType\":\"rpm\",\"status\":\"unaffected\"}]}"}`,
		"Linux kernel range 3a1296a38d0c to 7fc7e35212cf.",
	} {
		if !quoteStatesVersion(quote) {
			t.Errorf("version token missed in %q", quote)
		}
	}
	for _, quote := range []string{
		bsiGLiNetSentence, "GL-AX1800, GL-AXT1800, GL-SFT1200, GL-X3000, GL-XE3000", "RM1, RM1V2, RM10, RM10RC, RM1PE, RM4PE (KVM)",
		"[NEU] [hoch] Microsoft SharePoint: Schwachstelle ermöglicht Codeausführung (WID-SEC-2026-4772)",
		"CVE-2026-53672: Apache Solr: Zookeeper endpoint authorization bypass (CWE-863, GHSA-abcd-efgh-ijkl)",
		"See https://example.test/advisory/2026/11/42 for details.",
	} {
		if quoteStatesVersion(quote) {
			t.Errorf("identifier or model name counted as a version in %q", quote)
		}
	}
}

// A Red Hat record with defaultStatus affected has no mappable release range,
// so the pipeline records a machine gap for it. The checker was told not to
// report that unavailable range again but still demanded its fixed packages.
const redHatGFS2Record = `{"vendor":"Red Hat","product":"Red Hat Enterprise Linux 8","packageName":"gfs2-utils","defaultStatus":"affected","versions":[{"version":"0:3.2.0-14.el8_10","lessThan":"*","versionType":"rpm","status":"unaffected"}]}`

func redHatGapPipeline(t *testing.T, records map[string]string) *Pipeline {
	t.Helper()
	v := NewCVEVerifier(nil, nil)
	var facts []cnaSourceFact
	for product, record := range records {
		facts = append(facts, affectedFact("CVE-2026-71220", product, record))
	}
	facts = append(facts, cnaSourceFact{CVEID: "CVE-2026-71220", Kind: "description", Text: "A flaw was found in gfs2-utils."})
	v.cache["CVE-2026-71220"] = &CVEMeta{Exists: true, Verification: CVEVerification{Status: "verified", Source: "cve_program"}, CachedAt: time.Now(), CNAChecked: true, CNAFacts: facts}
	return &Pipeline{cveVerifier: v}
}

func redHatGapBrief(t *testing.T, p *Pipeline, item scraper.RawItem, products ...string) string {
	t.Helper()
	brief, err := yaml.Marshal(map[string]any{
		"title":             "gfs2-utils flaw (CVE-2026-71220)",
		"content":           "A flaw in gfs2-utils (CVE-2026-71220) affects Red Hat Enterprise Linux.",
		"affected_products": products,
	})
	if err != nil {
		t.Fatal(err)
	}
	withGap := p.injectSourceRanges(string(brief), item)
	if !strings.Contains(withGap, "cannot be mapped safely") {
		t.Fatalf("fixture must carry the machine scope gap:\n%s", withGap)
	}
	return withGap
}

func TestVersionOmissionCoveredByRecordedScopeGapIsDropped(t *testing.T) {
	item := scraper.RawItem{Source: "nvd", Title: "CVE-2026-71220 gfs2-utils", Content: "CVE-2026-71220: A flaw was found in gfs2-utils."}
	recordLine := func(product, record string) string {
		raw, _ := json.Marshal(affectedFact("CVE-2026-71220", product, record))
		return string(raw)
	}
	rhel9Record := strings.ReplaceAll(redHatGFS2Record, "Linux 8", "Linux 9")
	for _, tc := range []struct {
		name, subject, field, reason, quote string
		gapProducts                         []string
		blocks                              bool
	}{
		{"fixed packages of the gapped record", "Red Hat Enterprise Linux 8", "affected_products", "The brief fails to document the specific package version fixes for Red Hat Enterprise Linux 8 explicitly provided in the source evidence.", recordLine("Red Hat Enterprise Linux 8", redHatGFS2Record), []string{"Red Hat Enterprise Linux 8"}, false},
		{"decoded record text", "Red Hat Enterprise Linux 8", "affected_products", "The brief fails to list the unaffected package versions for Red Hat Enterprise Linux 8.", redHatGFS2Record, []string{"Red Hat Enterprise Linux 8"}, false},
		{"gap recorded for another product", "Red Hat Enterprise Linux 9", "affected_products", "The brief fails to document the fixed package versions for Red Hat Enterprise Linux 9.", recordLine("Red Hat Enterprise Linux 9", rhel9Record), []string{"Red Hat Enterprise Linux 8"}, true},
		{"non-version fact of the gapped record", "Red Hat Enterprise Linux 8", "affected_products", "The brief omits the affected gfs2-utils package name for Red Hat Enterprise Linux 8.", recordLine("Red Hat Enterprise Linux 8", redHatGFS2Record), []string{"Red Hat Enterprise Linux 8"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := map[string]string{"Red Hat Enterprise Linux 8": redHatGFS2Record, "Red Hat Enterprise Linux 9": rhel9Record}
			p := redHatGapPipeline(t, records)
			brief := redHatGapBrief(t, p, item, "Red Hat Enterprise Linux 8", "Red Hat Enterprise Linux 9")
			if len(tc.gapProducts) == 1 {
				// Keep only the gap for the listed product, as a brief
				// assembled before the other product was added would.
				var doc map[string]any
				if err := yaml.Unmarshal([]byte(brief), &doc); err != nil {
					t.Fatal(err)
				}
				assessment := doc["source_assessment"].(map[string]any)
				var kept []string
				for _, gap := range yamlStringList(assessment["gaps"]) {
					if strings.Contains(gap, "/ "+tc.gapProducts[0]+":") {
						kept = append(kept, gap)
					}
				}
				assessment["gaps"] = kept
				out, _ := yaml.Marshal(doc)
				brief = string(out)
			}
			var logs bytes.Buffer
			checker := NewGroundingChecker(scriptedGroundingLLM{report: groundingReport{Issues: []groundingIssue{{
				Kind: groundingKindMaterialOmission, Field: tc.field, Subject: tc.subject, SourceQuote: tc.quote, Reason: tc.reason,
			}}}}).WithLogger(slog.New(slog.NewTextHandler(&logs, nil)))
			got, err := checker.Check(context.Background(), item.Title, p.groundingEvidence(item, brief), groundingView(brief, item.URL))
			if err != nil {
				t.Fatal(err)
			}
			if tc.blocks {
				if got.Grounded || len(got.Findings) != 1 {
					t.Fatalf("omission outside the recorded gap must keep blocking: %+v\n%s", got, logs.String())
				}
				return
			}
			if !got.Grounded || len(got.Issues) != 0 {
				t.Fatalf("omission covered by the recorded scope gap still blocks: %+v", got)
			}
			if !strings.Contains(logs.String(), "material omission dropped: primary scope gap already recorded") || !strings.Contains(logs.String(), "cve=CVE-2026-71220") {
				t.Fatalf("gap drop not auditable: %s", logs.String())
			}
		})
	}
}

// releaseBoundRemediationRule makes X the fixed release of "before X". Such a
// quote states X, so the version rule keeps the omission blocking, and the
// record has a mappable range, so no scope gap can exempt it either.
func TestReleaseBoundFixOmissionKeepsBlocking(t *testing.T) {
	for _, quote := range []string{
		"Wing FTP Server before 8.2.8 contains a Lua code injection vulnerability.",
		`{"cve_id":"CVE-2026-0001","product":"PrestaShop","kind":"affected","text":"` + strings.ReplaceAll(recordPrestaShop, `"`, `\"`) + `"}`,
	} {
		issue := groundingIssue{Kind: groundingKindMaterialOmission, Field: "recommendation", Subject: "PrestaShop", SourceQuote: quote, Reason: "The brief omits the fixed release the source derives from the exclusive upper bound."}
		if !omissionDemandsVersion(issue) || !quoteStatesVersion(quote) {
			t.Fatalf("release-bound fix demand must be classified as a stated version: %q", quote)
		}
		if _, exempt := primaryScopeGapRecorded(issue, "Verified primary CVE evidence.\n"+quote+"\nOriginal source:\n", map[string]any{"source_assessment": map[string]any{"gaps": []any{"anything"}}}); exempt {
			t.Fatalf("release-bound record treated as an unmappable scope gap: %q", quote)
		}
	}
}

// contractStageLLM scripts the checker's first and later reports and the
// repair's revised brief, and records every paid model stage in call order.
type contractStageLLM struct {
	noopLLM
	t       *testing.T
	reports []groundingReport
	repair  string
	stages  []string
}

func (c *contractStageLLM) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	c.stages = append(c.stages, llm.CallMetadataFromContext(ctx).Stage)
	if report, ok := out.(*groundingReport); ok {
		if len(c.reports) == 0 {
			*report = groundingReport{}
			return nil
		}
		*report, c.reports = c.reports[0], c.reports[1:]
		return nil
	}
	if system != groundingRepairSystemPrompt {
		c.t.Fatalf("unexpected model stage %q", llm.CallMetadataFromContext(ctx).Stage)
	}
	return structuredFromText(c.repair, out)
}

const keptClaimSentence = "Attackers chained the flaw with a Windows kernel exploit to gain SYSTEM privileges."

func keptClaimBrief(content string) string {
	return strings.Replace(validWindowsPathBriefYAML, "content: Review Windows process creation telemetry for the binary path described by the source.", "content: "+content, 1)
}

func TestRepairThatKeepsFlaggedClaimSkipsRecheck(t *testing.T) {
	original := keptClaimBrief("Review Windows process creation telemetry. " + keptClaimSentence)
	if !strings.Contains(original, keptClaimSentence) {
		t.Fatal("fixture must state the flagged claim")
	}
	finding := groundingIssue{Kind: groundingKindUnsupported, Field: "content", BriefQuote: keptClaimSentence, Reason: "The source reports no exploit chain or privilege escalation."}
	for _, tc := range []struct {
		name, repair string
		stages       []string
		quarantined  bool
	}{
		{"repair kept the sentence", keptClaimBrief("Review Windows process creation telemetry for cmd.exe. " + keptClaimSentence), []string{"grounding", "grounding_repair"}, true},
		{"repair removed the sentence", keptClaimBrief("Review Windows process creation telemetry for cmd.exe."), []string{"grounding", "grounding_repair", "grounding_recheck"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			client := &contractStageLLM{t: t, reports: []groundingReport{{Issues: []groundingIssue{finding}}}, repair: tc.repair}
			var logs bytes.Buffer
			p := New(Config{DB: db, LLMClient: client, Logger: slog.New(slog.NewTextHandler(&logs, nil)), MaxGroundingAttempts: 5})
			item := scraper.RawItem{SourceID: "kept-claim:windows", Source: "research", URL: "https://vendor.example/windows", Title: "Windows path detection", Content: strings.Repeat("Windows process creation telemetry shows cmd.exe. ", 10), Enriched: true}
			key := p.processingInputKey(item)
			state := processingCandidate{Item: item, BriefYAML: original, Score: 5, Confidence: 1, AttemptID: "attempt-1"}
			if err := p.processCandidate(context.Background(), key, state); err != nil {
				t.Fatal(err)
			}
			if strings.Join(client.stages, ",") != strings.Join(tc.stages, ",") {
				t.Fatalf("paid model stages = %v, want %v", client.stages, tc.stages)
			}
			reason, quarantined, err := db.PipelineQuarantineReason(item.SourceID)
			if err != nil || quarantined != tc.quarantined {
				t.Fatalf("quarantined = %v (%q, %v), want %v", quarantined, reason, err, tc.quarantined)
			}
			if !tc.quarantined {
				if strings.Contains(logs.String(), "repair kept flagged claim") {
					t.Fatalf("removed claim logged as kept: %s", logs.String())
				}
				return
			}
			if !strings.Contains(reason, "ungrounded after 1 attempts") || !strings.Contains(reason, keptClaimSentence) {
				t.Fatalf("quarantine reason does not name the kept claim: %q", reason)
			}
			if !strings.Contains(logs.String(), "repair kept flagged claim; skipping recheck") || !strings.Contains(logs.String(), "fields=[content]") {
				t.Fatalf("skipped recheck not auditable: %s", logs.String())
			}
			if seen, err := db.HasSeen(item.SourceID); err != nil || !seen {
				t.Fatalf("quarantined item not marked seen: %v %v", seen, err)
			}
			summary, err := db.ProcessingSummary(time.Now().Add(-time.Hour))
			if err != nil || summary.GroundingRejected != 1 {
				t.Fatalf("kept claim did not record one rejected grounding event: %+v %v", summary, err)
			}
		})
	}
}

// A resumed candidate has only saved Issues strings: without the structured
// first-check findings, the pre-recheck shortcut must not apply.
func TestKeptClaimCheckNeedsStructuredFindings(t *testing.T) {
	brief := keptClaimBrief(keptClaimSentence)
	findings := []GroundingFinding{{Kind: groundingKindUnsupported, Field: "content", BriefQuote: keptClaimSentence}}
	if kept := keptFlaggedClaims(brief, brief, "", nil, nil); len(kept) != 0 {
		t.Fatalf("saved issue strings triggered the shortcut: %+v", kept)
	}
	for _, tc := range []struct {
		name     string
		finding  GroundingFinding
		resolved map[int]bool
		kept     bool
	}{
		{"kept sentence", findings[0], nil, true},
		{"resolved in code", findings[0], map[int]bool{0: true}, false},
		{"short quote", GroundingFinding{Kind: groundingKindUnsupported, Field: "content", BriefQuote: "SYSTEM"}, nil, false},
		{"material omission", GroundingFinding{Kind: groundingKindMaterialOmission, Field: "content", BriefQuote: keptClaimSentence}, nil, false},
		{"section name as field", GroundingFinding{Kind: groundingKindUnsupported, Field: "Attack Chain", BriefQuote: keptClaimSentence}, nil, true},
		{"identity field only", GroundingFinding{Kind: groundingKindUnsupported, Field: "slug", BriefQuote: "2026-10-windows-path"}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if kept := keptFlaggedClaims(brief, brief, "", []GroundingFinding{tc.finding}, tc.resolved); (len(kept) > 0) != tc.kept {
				t.Fatalf("kept = %+v, want %v", kept, tc.kept)
			}
		})
	}
}

// A flagged technique mapping is the claim of a ttps entry; its evidence
// sentence may stay when the repair corrects the mapping.
func TestKeptTTPClaimFollowsTheMapping(t *testing.T) {
	const evidence = "An unauthenticated attacker can send a crafted request to the management interface."
	entry := func(tactic, technique, name string) string {
		return "  - tactic_id: " + tactic + "\n    tactic_name: x\n    technique_id: " + technique + "\n    technique_name: " + name + "\n    evidence: " + evidence + "\n"
	}
	before := validWindowsPathBriefYAML + "ttps:\n" + entry("TA0004", "T1068", "Exploitation for Privilege Escalation")
	finding := GroundingFinding{Kind: groundingKindUnsupported, Field: "ttps", BriefQuote: evidence}
	if kept := keptFlaggedClaims(before, before, "", []GroundingFinding{finding}, nil); len(kept) != 1 {
		t.Fatalf("unchanged flagged mapping not detected: %+v", kept)
	}
	corrected := validWindowsPathBriefYAML + "ttps:\n" + entry("TA0001", "T1190", "Exploit Public-Facing Application")
	if kept := keptFlaggedClaims(before, corrected, "", []GroundingFinding{finding}, nil); len(kept) != 0 {
		t.Fatalf("corrected mapping with the same evidence counted as kept: %+v", kept)
	}
}
