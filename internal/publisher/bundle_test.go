package publisher

import (
	"errors"
	"gopkg.in/yaml.v3"
	"slices"
	"strings"
	"testing"
	"time"
)

const testPublicKey = "b66bb907fac442dc7a58f16f69efb96b27e6d657d6985f04666371324c17afe0"

func TestDeriveKey(t *testing.T) {
	key, err := DeriveKey(testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	// Same input should produce same key.
	key2, err := DeriveKey(testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != string(key2) {
		t.Error("expected deterministic key derivation")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	content := &BundleContent{
		Briefs: []BundleBrief{
			{
				ID:       "brief-2026-02-20-test",
				Slug:     "2026-02-20-test",
				Title:    "Test Brief",
				Summary:  "A test brief for roundtrip",
				Severity: "high",
				Rules: []BundleRule{
					{
						Title: "Detect Malware Execution",
						LogSource: BundleLogSource{
							Category: "process_creation",
							Product:  "windows",
						},
						Detection: map[string]any{
							"selection": map[string]any{
								"Image|endswith": "\\malware.exe",
							},
							"condition": "selection",
						},
						Level: "high",
						Tags:  []string{"attack.execution", "attack.t1059"},
					},
				},
				TTPs: []BundleTTP{
					{TacticID: "TA0002", TacticName: "Execution", TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter"},
				},
			},
		},
	}

	manifest, err := Encrypt(content, "1.0", "2026-02-20T10:00:00Z", testPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if manifest.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", manifest.Version)
	}
	if manifest.Content == "" {
		t.Error("expected non-empty encrypted content")
	}
	if manifest.Checksum == "" {
		t.Error("expected non-empty checksum")
	}

	decrypted, err := Decrypt(manifest, testPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(decrypted.Briefs) != 1 {
		t.Fatalf("expected 1 brief, got %d", len(decrypted.Briefs))
	}

	brief := decrypted.Briefs[0]
	if brief.ID != "brief-2026-02-20-test" {
		t.Errorf("expected ID 'brief-2026-02-20-test', got %q", brief.ID)
	}
	if brief.Title != "Test Brief" {
		t.Errorf("expected title 'Test Brief', got %q", brief.Title)
	}
	if len(brief.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(brief.Rules))
	}
	if brief.Rules[0].LogSource.Category != "process_creation" {
		t.Errorf("expected logsource category 'process_creation', got %q", brief.Rules[0].LogSource.Category)
	}
	if brief.Rules[0].Level != "high" {
		t.Errorf("expected level 'high', got %q", brief.Rules[0].Level)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	content := &BundleContent{Briefs: []BundleBrief{{ID: "test"}}}
	manifest, err := Encrypt(content, "1.0", "2026-02-20T10:00:00Z", testPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, err = Decrypt(manifest, wrongKey)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestParseBriefYAML(t *testing.T) {
	yamlStr := `id: "brief-2026-02-20-sigma"
slug: "2026-02-20-sigma"
title: "Sigma Rule Brief"
summary: "A brief with sigma rules"
content: |
  ## Overview
  Test content.
severity: high
published_at: "2026-02-20T10:00:00Z"
tags:
  - malware
  - windows
references:
  - https://example.com/advisory
rules:
  - title: "Detect Suspicious Process"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\evil.exe"
      condition: selection
    level: high
    tags:
      - attack.execution
      - attack.t1059.001
iocs:
  - type: ip
    value: "10.0.0.1"
  - type: domain
    value: "evil.example.com"
ttps:
  - tactic_id: "TA0002"
    tactic_name: "Execution"
    technique_id: "T1059"
    technique_name: "Command and Scripting Interpreter"
`

	brief, err := ParseBriefYAML(yamlStr)
	if err != nil {
		t.Fatal(err)
	}

	if brief.ID != "brief-2026-02-20-sigma" {
		t.Errorf("expected ID 'brief-2026-02-20-sigma', got %q", brief.ID)
	}
	if brief.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", brief.Severity)
	}
	if len(brief.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(brief.Rules))
	}
	if brief.Rules[0].LogSource.Category != "process_creation" {
		t.Errorf("expected logsource.category 'process_creation', got %q", brief.Rules[0].LogSource.Category)
	}
	if brief.Rules[0].Detection["condition"] != "selection" {
		t.Errorf("expected detection condition 'selection', got %v", brief.Rules[0].Detection["condition"])
	}
	if len(brief.IOCs) != 2 {
		t.Errorf("expected 2 IOCs, got %d", len(brief.IOCs))
	}
	if len(brief.TTPs) != 1 {
		t.Errorf("expected 1 TTP, got %d", len(brief.TTPs))
	}
}

func TestParseBriefYAMLMissingID(t *testing.T) {
	yamlStr := `title: "No ID Brief"
summary: "Missing ID field"
`
	_, err := ParseBriefYAML(yamlStr)
	if err == nil {
		t.Error("expected error for missing ID")
	}
}

func TestMergeBriefs(t *testing.T) {
	existing := []BundleBrief{
		{ID: "brief-1", Title: "First", PublishedAt: "2026-10-19T08:00:00Z"},
		{ID: "brief-2", Title: "Second", PublishedAt: "2026-10-19T08:00:00Z"},
	}
	incoming := []BundleBrief{
		{ID: "brief-2", Title: "Second Updated", PublishedAt: "2026-10-19T08:00:00Z"},
		{ID: "brief-3", Title: "Third", PublishedAt: "2026-10-20T08:00:00Z"},
	}

	merged, err := MergeBriefs(existing, incoming, time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	if len(merged) != 3 {
		t.Fatalf("expected 3 merged briefs, got %d", len(merged))
	}
	if merged[0].ID != "brief-1" {
		t.Errorf("expected first brief ID 'brief-1', got %q", merged[0].ID)
	}
	if merged[1].ID != "brief-2" || merged[1].Title != "Second Updated" {
		t.Errorf("expected brief-2 updated, got ID=%q Title=%q", merged[1].ID, merged[1].Title)
	}
	if merged[2].ID != "brief-3" {
		t.Errorf("expected third brief ID 'brief-3', got %q", merged[2].ID)
	}
}

func TestMergeBriefsEmpty(t *testing.T) {
	incoming := []BundleBrief{{
		ID: "new-1", Title: "New", Revision: 99,
		RevisionHistory: []BundleRevision{{Revision: 99, At: "2026-10-20T08:00:00Z", Checksum: "sha256:fabricated"}},
	}}
	merged, err := MergeBriefs(nil, incoming, time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 1 || merged[0].ID != "new-1" {
		t.Errorf("expected 1 brief from empty merge, got %d", len(merged))
	}
	if merged[0].EventID != "new-1" || merged[0].Revision != 1 {
		t.Fatalf("new brief metadata = event %q revision %d", merged[0].EventID, merged[0].Revision)
	}
	if len(merged[0].RevisionHistory) != 0 {
		t.Fatalf("new brief accepted caller-supplied history: %#v", merged[0].RevisionHistory)
	}
}

func TestNormalizePublicationMetadataLegacyDefaults(t *testing.T) {
	got := NormalizePublicationMetadata(BundleBrief{ID: "brief-1", Slug: "legacy", PublishedAt: "2026-10-01T00:00:00Z"})
	if got.EventID != "brief-1" {
		t.Fatalf("event_id = %q, want brief-1", got.EventID)
	}
	if got.Revision != 1 {
		t.Fatalf("revision = %d, want 1", got.Revision)
	}
	if len(got.RevisionHistory) != 0 {
		t.Fatalf("legacy history = %#v, want empty", got.RevisionHistory)
	}
}

func TestMergeBriefsRejectsImmutableIdentityChanges(t *testing.T) {
	base := BundleBrief{
		ID: "brief-1", Slug: "one", EventID: "event-1", Revision: 1,
		PublishedAt: "2026-10-01T00:00:00Z", Title: "Original",
	}
	revisedAt := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		incoming BundleBrief
	}{
		{name: "slug", incoming: BundleBrief{ID: "brief-1", Slug: "changed", EventID: "event-1", PublishedAt: base.PublishedAt}},
		{name: "event", incoming: BundleBrief{ID: "brief-1", Slug: "one", EventID: "event-2", PublishedAt: base.PublishedAt}},
		{name: "published", incoming: BundleBrief{ID: "brief-1", Slug: "one", EventID: "event-1", PublishedAt: "2026-10-02T00:00:00Z"}},
		{name: "id for existing event", incoming: BundleBrief{ID: "brief-2", Slug: "two", EventID: "event-1", PublishedAt: base.PublishedAt}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := MergeBriefs([]BundleBrief{base}, []BundleBrief{tt.incoming}, revisedAt); err == nil {
				t.Fatal("expected immutable identity error")
			}
		})
	}
}

func TestMergeBriefsRejectsInvalidStoredRevisionHistory(t *testing.T) {
	existing := BundleBrief{
		ID: "brief-1", Slug: "one", EventID: "event-1", Revision: 3,
		PublishedAt: "2026-10-01T00:00:00Z",
		RevisionHistory: []BundleRevision{{
			Revision: 3, At: "not-a-time", Checksum: "sha256:fabricated",
		}},
	}
	if _, err := MergeBriefs([]BundleBrief{existing}, nil, time.Now()); err == nil {
		t.Fatal("expected invalid stored revision history to fail")
	}
}

func TestMergeBriefsRejectsDisjointStructuredCVEs(t *testing.T) {
	existing := BundleBrief{ID: "brief-1", Slug: "one", PublishedAt: "2026-10-01T00:00:00Z", CVEs: []BundleCVE{{ID: "CVE-2026-1000"}}}
	incoming := existing
	incoming.CVEs = []BundleCVE{{ID: "CVE-2026-2000"}}
	if _, err := MergeBriefs([]BundleBrief{existing}, []BundleBrief{incoming}, time.Now()); err == nil {
		t.Fatal("expected disjoint CVE replacement to fail")
	}
}

func TestMergeBriefsAppendsOneRevisionForMaterialChange(t *testing.T) {
	existing := BundleBrief{
		ID: "brief-1", Slug: "one", PublishedAt: "2026-10-01T00:00:00Z",
		Title: "Original", CVEs: []BundleCVE{{ID: "CVE-2026-1000"}},
	}
	incoming := existing
	incoming.Title = "Corrected title"
	incoming.CVEs = append(incoming.CVEs, BundleCVE{ID: "CVE-2026-2000"})
	incoming.UpdateLog = []BundleUpdate{{Summary: "Added affected CVE", SourceURLs: []string{"https://vendor.example/advisory"}}}
	revisedAt := time.Date(2026, 10, 20, 8, 9, 10, 0, time.FixedZone("offset", 2*60*60))

	merged, err := MergeBriefs([]BundleBrief{existing}, []BundleBrief{incoming}, revisedAt)
	if err != nil {
		t.Fatal(err)
	}
	got := merged[0]
	if got.EventID != "brief-1" || got.Revision != 2 || len(got.RevisionHistory) != 1 {
		t.Fatalf("metadata = event %q revision %d history %#v", got.EventID, got.Revision, got.RevisionHistory)
	}
	rev := got.RevisionHistory[0]
	if rev.Revision != 2 || rev.At != "2026-10-20T06:09:10Z" || !strings.HasPrefix(rev.Checksum, "sha256:") {
		t.Fatalf("revision entry = %#v", rev)
	}
	if rev.Summary != "Added affected CVE" || !slices.Contains(rev.ChangedFields, "title") || !slices.Contains(rev.ChangedFields, "cves") {
		t.Fatalf("revision description = %#v", rev)
	}
	if !slices.Equal(rev.SourceURLs, []string{"https://vendor.example/advisory"}) {
		t.Fatalf("revision sources = %#v", rev.SourceURLs)
	}
}

func TestMergeBriefsMakesSameSecondRevisionTimestampsStrictlyIncreasing(t *testing.T) {
	revisedAt := time.Date(2026, 10, 20, 14, 44, 14, 0, time.UTC)
	existing := BundleBrief{
		ID: "brief-1", Slug: "one", PublishedAt: "2026-10-20T13:08:01Z", Title: "Original",
	}
	second := existing
	second.Title = "Second revision"

	merged, err := MergeBriefs([]BundleBrief{existing}, []BundleBrief{second}, revisedAt)
	if err != nil {
		t.Fatal(err)
	}
	third := merged[0]
	third.Title = "Third revision"
	merged, err = MergeBriefs(merged, []BundleBrief{third}, revisedAt)
	if err != nil {
		t.Fatal(err)
	}

	history := merged[0].RevisionHistory
	if len(history) != 2 {
		t.Fatalf("history length = %d, want 2", len(history))
	}
	previous, err := time.Parse(time.RFC3339Nano, history[0].At)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := time.Parse(time.RFC3339Nano, history[1].At)
	if err != nil {
		t.Fatal(err)
	}
	if !latest.After(previous) {
		t.Fatalf("revision timestamps are not strictly increasing: %q then %q", history[0].At, history[1].At)
	}
}

func TestMergeBriefsByteEquivalentRepublishIsNoOp(t *testing.T) {
	existing := NormalizePublicationMetadata(BundleBrief{
		ID: "brief-1", Slug: "one", PublishedAt: "2026-10-01T00:00:00Z", Title: "Same",
	})
	merged, err := MergeBriefs([]BundleBrief{existing}, []BundleBrief{existing}, time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if merged[0].Revision != 1 || len(merged[0].RevisionHistory) != 0 {
		t.Fatalf("no-op changed revision metadata: %#v", merged[0])
	}
}

// Merged drafts union CPEs from several CVEs and LLM output without the
// validator running again, so the bundle funnel itself must collapse builds.
func TestParseBriefYAMLCollapsesCPEBuilds(t *testing.T) {
	y := `id: brief-x
title: t
cpes:
  - cpe:2.3:a:adobe:coldfusion:2023:update1:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update2:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2025:update3:*:*:*:*:*:*
`
	b, err := ParseBriefYAML(y)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{
		"cpe:2.3:a:adobe:coldfusion:2023:*:*:*:*:*:*:*",
		"cpe:2.3:a:adobe:coldfusion:2025:update3:*:*:*:*:*:*",
	}
	if len(b.CPEs) != len(want) || b.CPEs[0] != want[0] || b.CPEs[1] != want[1] {
		t.Errorf("CPEs = %q, want %q", b.CPEs, want)
	}
}

// Merges union affected lists and CVE enrichment rewrites bare products to
// version-qualified ones, so repeated merges left "Chrome (< 124.0.6367.201)"
// six times in one brief.
func TestParseBriefYAMLDedupesAffectedLists(t *testing.T) {
	y := `id: brief-x
title: t
affected_vendors:
  - Google
  - google
affected_products:
  - Chrome (< 124.0.6367.201)
  - Edge
  - Chrome (< 124.0.6367.201)
  - unknown
affected_os:
  - Windows
  - Windows
`
	b, err := ParseBriefYAML(y)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := strings.Join(b.AffectedVendors, "|"); got != "Google" {
		t.Errorf("AffectedVendors = %q", b.AffectedVendors)
	}
	if got := strings.Join(b.AffectedProducts, "|"); got != "Chrome (< 124.0.6367.201)|Edge" {
		t.Errorf("AffectedProducts = %q", b.AffectedProducts)
	}
	if got := strings.Join(b.AffectedOS, "|"); got != "Windows" {
		t.Errorf("AffectedOS = %q", b.AffectedOS)
	}
}

func TestParseBriefYAMLCarriesEvidenceConfidence(t *testing.T) {
	y := `id: brief-x
title: t
ttps:
  - tactic_id: "TA0001"
    technique_id: "T1566"
    evidence: "spearphishing email observed"
    confidence: 0.9
    confidence_band: "high"
`
	b, err := ParseBriefYAML(y)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(b.TTPs) != 1 {
		t.Fatalf("want 1 ttp, got %d", len(b.TTPs))
	}
	got := b.TTPs[0]
	if got.Evidence != "spearphishing email observed" || got.Confidence != 0.9 || got.ConfidenceBand != "high" {
		t.Errorf("ttp fields not carried: %+v", got)
	}
}

func TestParseBriefYAMLCarriesCTIMetadata(t *testing.T) {
	y := `id: brief-x
title: t
source_assessment:
  rating: B2
  confidence: moderate
  flags:
    - type: single_source
      detail: one source
qa_status:
  verdict: pass_with_fixes
  manual_verification:
    - validate telemetry
action_plan:
  priority: elevated
  immediate_actions:
    - action: review rule
      owner: SOC
rules:
  - title: Rule
    description: Detects behavior
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\evil.exe"
      condition: selection
    level: high
    handoff:
      detection_confidence: high
      required_telemetry:
        - log_source: Sysmon
          required_fields:
            - Image
iocs:
  - type: domain
    value: evil.example
    context: Observed C2
    confidence: 0.8
    handling:
      recommended_action: monitor-only
      log_sources:
        - dns
`
	b, err := ParseBriefYAML(y)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if b.SourceAssessment == nil || b.SourceAssessment.Rating != "B2" || b.SourceAssessment.Flags[0].Type != "single_source" {
		t.Fatalf("source assessment not carried: %+v", b.SourceAssessment)
	}
	if b.QAStatus == nil || b.QAStatus.ManualVerification[0] != "validate telemetry" {
		t.Fatalf("QA status not carried: %+v", b.QAStatus)
	}
	if b.ActionPlan == nil || b.ActionPlan.ImmediateActions[0].Owner != "SOC" {
		t.Fatalf("action plan not carried: %+v", b.ActionPlan)
	}
	if b.Rules[0].Handoff == nil || b.Rules[0].Handoff.RequiredTelemetry[0].LogSource != "Sysmon" {
		t.Fatalf("handoff not carried: %+v", b.Rules[0].Handoff)
	}
	if b.IOCs[0].Context != "Observed C2" || b.IOCs[0].Confidence != 0.8 || b.IOCs[0].Handling == nil || b.IOCs[0].Handling.RecommendedAction != "monitor-only" {
		t.Fatalf("ioc metadata not carried: %+v", b.IOCs[0])
	}
}

func TestParseBriefYAMLBackwardCompatNoConfidence(t *testing.T) {
	y := `id: brief-x
title: t
ttps:
  - tactic_id: "TA0001"
    technique_id: "T1566"
`
	b, err := ParseBriefYAML(y)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := b.TTPs[0]
	if got.Evidence != "" || got.Confidence != 0 || got.ConfidenceBand != "" {
		t.Errorf("expected zero-value new fields on old YAML, got %+v", got)
	}
}

// The LLM sometimes emits cves as plain strings ("- CVE-2026-1234") instead
// of mappings; auto-publish of updated briefs failed on those.
func TestBundleCVEUnmarshalsScalarForm(t *testing.T) {
	var b BundleBrief
	err := yaml.Unmarshal([]byte(`id: "brief-x"
slug: "x"
title: "T"
published_at: "2026-07-30T00:00:00Z"
cves:
  - CVE-2026-1111
  - id: CVE-2026-2222
    cvss: 9.8
`), &b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(b.CVEs) != 2 || b.CVEs[0].ID != "CVE-2026-1111" || b.CVEs[1].ID != "CVE-2026-2222" || b.CVEs[1].CVSS != 9.8 {
		t.Fatalf("cves = %+v", b.CVEs)
	}
}

func TestMergeBriefsRevisionRejectionIsTyped(t *testing.T) {
	existing := BundleBrief{ID: "brief-1", Slug: "one", PublishedAt: "2026-10-01T00:00:00Z", CVEs: []BundleCVE{{ID: "CVE-2026-1000"}}}
	incoming := existing
	incoming.CVEs = []BundleCVE{{ID: "CVE-2026-2000"}}
	_, err := MergeBriefs([]BundleBrief{existing}, []BundleBrief{incoming}, time.Now())
	var rejected *RevisionRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err = %v, want *RevisionRejectedError", err)
	}
	if rejected.BriefID != "brief-1" {
		t.Fatalf("BriefID = %q", rejected.BriefID)
	}
	if want := `brief "brief-1" replaced its structured CVE set with a disjoint event`; err.Error() != want {
		t.Fatalf("message = %q, want %q", err.Error(), want)
	}

	slugChange := existing
	slugChange.Slug = "other"
	if _, err := MergeBriefs([]BundleBrief{existing}, []BundleBrief{slugChange}, time.Now()); !errors.As(err, &rejected) {
		t.Fatalf("slug change err = %v, want *RevisionRejectedError", err)
	}
}

func TestMergeBriefsExistingDataErrorsAreNotRevisionRejections(t *testing.T) {
	a := BundleBrief{ID: "brief-1", Slug: "one", PublishedAt: "2026-10-01T00:00:00Z"}
	bad := a
	bad.Revision = 3 // history length does not match
	for name, existing := range map[string][]BundleBrief{
		"duplicate existing id":    {a, a},
		"invalid revision history": {bad},
	} {
		_, err := MergeBriefs(existing, nil, time.Now())
		if err == nil {
			t.Fatalf("%s: expected error", name)
		}
		var rejected *RevisionRejectedError
		if errors.As(err, &rejected) {
			t.Fatalf("%s: must not be a RevisionRejectedError: %v", name, err)
		}
	}
}

// Counterpart of pipeline.TestRoundupFoldKeepsAlreadyListedCVEs, which cannot
// import this package (publisher imports pipeline). It pins the guard the
// pipeline must satisfy: a roundup fold that adds a CVE keeps the published
// structured set, while one that replaces it with a disjoint set is rejected.
func TestMergeBriefsAcceptsRoundupFoldThatKeepsPublishedCVEs(t *testing.T) {
	snapshot := func(cves ...string) []BundleBrief {
		doc := "id: brief-2026-11-microsoft-security-updates\n" +
			"title: Microsoft Security Updates\n" +
			"published_at: \"2026-11-11T08:52:22Z\"\n" +
			"lastmod: \"2026-11-11T08:52:22Z\"\n" +
			"cves:\n"
		for _, id := range cves {
			doc += "  - id: " + id + "\n"
		}
		brief, err := ParseBriefYAML(doc)
		if err != nil {
			t.Fatal(err)
		}
		return []BundleBrief{NormalizePublicationMetadata(*brief)}
	}
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	afterB := snapshot("CVE-2026-58934", "CVE-2026-109469")

	if _, err := MergeBriefs(afterB, snapshot("CVE-2026-58934", "CVE-2026-109469", "CVE-2026-60001"), now); err != nil {
		t.Fatalf("fold keeping the published CVEs must merge: %v", err)
	}
	if _, err := MergeBriefs(afterB, snapshot("CVE-2026-60001"), now); err == nil {
		t.Fatal("a disjoint structured CVE set must be rejected")
	}
}
