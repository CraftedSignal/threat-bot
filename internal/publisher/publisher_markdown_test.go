package publisher

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Sentinel strings injected into every withheld field. The test fails if any
// of them appear in the rendered Markdown — which catches regressions where
// someone adds a field to BundleBrief and forgets to keep briefToMarkdown
// minimal.
//
// IOC values and the full content body are PUBLIC by current schema, so
// their sentinels live in the must-contain list, not here.
const (
	sentinelDetectionQuery   = "SECRET_DETECTION_QUERY_TOKEN"
	sentinelTestPositive     = "SECRET_TEST_POSITIVE_DATA"
	sentinelTestNegative     = "SECRET_TEST_NEGATIVE_DATA"
	sentinelPriorityScore    = "SECRET_PRIORITY_SCORE_98765"
	sentinelPrioritySignal   = "SECRET_PRIORITY_SIGNAL_XYZ"
	sentinelPriorityCategory = "SECRET_PRIORITY_CATEGORY"
	sentinelSourceAssessment = "SECRET_SOURCE_ASSESSMENT_FLAG"
	sentinelQAStatus         = "SECRET_QA_STATUS_ITEM"
	sentinelActionPlan       = "SECRET_ACTION_PLAN_ITEM"
	sentinelRuleHandoff      = "SECRET_RULE_HANDOFF_ITEM"
	sentinelIOCHandling      = "SECRET_IOC_HANDLING_ITEM"
)

// Public sentinels that MUST appear.
const (
	publicSentinelIOCValue = "PUBLIC_IOC_VALUE_999_888_777"
	publicSentinelBodyTail = "PUBLIC_BODY_TAIL_RENDERED_VERBATIM"
)

func TestBriefToMarkdown_DoesNotLeakWithheldFields(t *testing.T) {
	t.Helper()

	brief := BundleBrief{
		ID:          "brief-2026-04-26-test",
		Slug:        "test-brief-slug",
		Title:       "Test brief",
		Summary:     "Public summary that's safe to publish.",
		Content:     "First public paragraph that's safe.\n\n" + publicSentinelBodyTail + " — full body now publishes.",
		Severity:    "high",
		ThreatActor: "TEST-ACTOR",
		PublishedAt: "2026-04-26T08:30:00Z",
		Tags:        []string{"a", "b"},
		References:  []string{"https://example.com/a"},

		// Priority fields — all withheld.
		Priority:        sentinelPriorityCategory,
		PriorityScore:   98765,
		PrioritySignals: []string{"active_exploitation", sentinelPrioritySignal},
		ExploitationEvidence: &BundleExploitationEvidence{
			Status: "confirmed_active", SourceURL: "https://example.com/a", ObservedAt: "2026-04-26T08:30:00Z", Confidence: "high",
		},
		SourceAssessment: &BundleSourceAssessment{
			Rating:        "B2",
			Corroboration: sentinelSourceAssessment,
			Flags:         []BundleSourceFlag{{Type: "single_source", Detail: sentinelSourceAssessment}},
		},
		QAStatus: &BundleQAStatus{Verdict: "pass_with_fixes", ManualVerification: []string{sentinelQAStatus}},
		ActionPlan: &BundleActionPlan{
			Priority: "elevated",
			Owners:   []string{"SOC"},
			ImmediateActions: []BundleActionItem{{
				Action: sentinelActionPlan,
				Owner:  "SOC",
				Due:    "24h",
			}},
			HuntLeads: []BundleHuntLead{{
				Lead:        "Review process execution from affected hosts",
				TechniqueID: "T1059",
				Priority:    "high",
			}},
		},

		Rules: []BundleRule{{
			Title:       "Test rule",
			Description: "rule desc",
			LogSource:   BundleLogSource{Category: "process_creation", Product: "windows"},
			Detection: map[string]any{
				"selection": map[string]any{
					"CommandLine|contains": sentinelDetectionQuery,
				},
				"condition": "selection",
			},
			Level: "high",
			Tags:  []string{"attack.execution", "attack.t1059.001"},
			Handoff: &BundleHandoff{
				DetectionConfidence: "medium",
				Limitations:         []string{sentinelRuleHandoff},
			},
			Tests: &BundleTestSuite{
				Positive: []BundleTestCase{{
					Name: "positive",
					Data: []map[string]interface{}{{"CommandLine": sentinelTestPositive}},
				}},
				Negative: []BundleTestCase{{
					Name: "negative",
					Data: []map[string]interface{}{{"CommandLine": sentinelTestNegative}},
				}},
			},
		}},

		IOCs: []BundleIOC{
			{Type: "ip", Value: publicSentinelIOCValue, Confidence: 0.9, Handling: &BundleIOCHandling{DetectionNotes: sentinelIOCHandling}},
			{Type: "domain", Value: "another-" + publicSentinelIOCValue},
		},

		TTPs: []BundleTTP{{
			TacticID: "TA0002", TacticName: "Execution",
			TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter",
		}},

		CVEs: []BundleCVE{{ID: "CVE-2026-0001", CVSS: 9.8, EPSS: 0.95, KEV: true}},

		AffectedVendors:  []string{"TestVendor"},
		AffectedProducts: []string{"TestProduct"},
		AffectedOS:       []string{"Linux"},
	}

	md, err := briefToMarkdown(brief)
	if err != nil {
		t.Fatalf("briefToMarkdown: %v", err)
	}
	out := string(md)

	withheld := []string{
		sentinelDetectionQuery,
		sentinelTestPositive,
		sentinelTestNegative,
		sentinelPriorityScore,
		sentinelPrioritySignal,
		sentinelPriorityCategory,
		sentinelSourceAssessment,
		sentinelQAStatus,
		sentinelRuleHandoff,
		sentinelIOCHandling,
	}
	for _, s := range withheld {
		if strings.Contains(out, s) {
			t.Errorf("withheld content leaked into public markdown: %q present in output", s)
		}
	}

	// Also assert the public surface IS present — catches the inverse bug
	// where everything gets withheld and nothing renders.
	mustContain := []string{
		"type: threat", // active_exploitation in PrioritySignals → threat
		"slug: test-brief-slug",
		"title: Test brief",
		"description: Public summary",
		"severities:",
		"- high",
		"actors:",
		"- TEST-ACTOR",
		"exploited: true", // PrioritySignals contains "active_exploitation"
		"vendors:",
		"- TestVendor",
		"products:",
		"- TestProduct",
		"affected_os:",
		"- Linux",
		"mitre_ttps:",
		"tactic_id: TA0002",
		"technique_id: T1059",
		"cves:",
		"id: CVE-2026-0001",
		"kev: true",
		"iocs:",
		"value: " + publicSentinelIOCValue,
		"value: another-" + publicSentinelIOCValue,
		"ioc_counts:",
		"ip: 1",
		"domain: 1",
		publicSentinelBodyTail,
		"rules:",
		"title: Test rule",
		"platform: sigma",
		"tactics:",
		"- execution",
		"techniques:",
		"- T1059.001",
		"data_sources:",
		"- process_creation",
		"- windows",
		"rules_count: 1",
		"action_plan:",
		"priority: elevated",
		"owners:",
		"- SOC",
		"immediate_actions:",
		"action: " + sentinelActionPlan,
		"due: 24h",
		"hunt_leads:",
		"lead: Review process execution from affected hosts",
		"technique_id: T1059",
		"First public paragraph",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("expected public field missing from markdown: %q", s)
		}
	}
}

func TestDisputedRumourRendersProminentHistoricalStatus(t *testing.T) {
	b := BundleBrief{ID: "brief-2026-10-rumour", Slug: "2026-10-rumour", Title: "Disputed report", Summary: "A disputed report.", Content: "## Recommendation\n\nBlock the service.", Severity: "rumour", ClaimState: "disputed", PublishedAt: "2026-10-27T10:00:00Z", References: []string{"https://x.com/a/status/1"}}
	out, err := briefToMarkdown(b)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{"claim_state: disputed", "Status: DISPUTED", "Replacement recommendation", "historical context"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestPublishBriefMarkdownRejectsUnsourcedThreatBeforeUpload(t *testing.T) {
	p := &Publisher{logger: slog.Default()}
	for _, brief := range []BundleBrief{
		{ID: "threat-no-source", Title: "Active exploitation", Severity: "high", PrioritySignals: []string{"active_exploitation"}},
		{ID: "rumour-no-source", Title: "Rumour", Severity: "rumour"},
	} {
		if err := p.publishBriefMarkdown(brief); err == nil {
			t.Fatalf("expected unsourced %s to be rejected before upload", brief.ID)
		}
	}
}

func TestRenderPublicBriefMarkdownEnforcesFeedContract(t *testing.T) {
	invalid := BundleBrief{ID: "brief-1", Slug: "brief-1", PublishedAt: "2026-10-20T00:00:00Z"}
	if _, _, _, _, err := RenderPublicBriefMarkdown(invalid, nil); err == nil {
		t.Fatal("expected invalid public Markdown to be rejected")
	}

	initial := BundleBrief{ID: "brief-1", Slug: "brief-1", Title: "Initial", PublishedAt: "2026-10-20T00:00:00Z"}
	_, previous, _, publish, err := RenderPublicBriefMarkdown(initial, nil)
	if err != nil || !publish {
		t.Fatalf("initial render: publish=%t err=%v", publish, err)
	}
	changed := initial
	changed.Title = "Changed without revision"
	if _, _, _, _, err := RenderPublicBriefMarkdown(changed, previous); err == nil {
		t.Fatal("expected changed public brief without a new revision to be rejected")
	}
}

func TestBackfillBriefSelectedBySlugOrID(t *testing.T) {
	wanted := newBackfillSelection([]string{"  OCTOBER-BRIEF  ", "brief-123"})

	if !wanted.matches(BundleBrief{ID: "other", Slug: "october-brief"}) {
		t.Fatal("expected case-insensitive slug match")
	}
	if !wanted.matches(BundleBrief{ID: "BRIEF-123", Slug: "different"}) {
		t.Fatal("expected case-insensitive brief ID match")
	}
	if wanted.matches(BundleBrief{ID: "unrelated", Slug: "unrelated"}) {
		t.Fatal("unexpected match for an unselected brief")
	}
	if !newBackfillSelection(nil).matches(BundleBrief{ID: "any"}) {
		t.Fatal("an empty selection must preserve full backfill behavior")
	}
}

func TestBriefToMarkdownCanonicalizesATTACKTechniqueName(t *testing.T) {
	md, err := briefToMarkdown(BundleBrief{
		ID:          "brief-attack-name",
		Slug:        "attack-name",
		Title:       "Canonical ATT&CK name",
		Summary:     "Test",
		Content:     "Test",
		Severity:    "medium",
		PublishedAt: "2026-10-20T12:00:00Z",
		TTPs: []BundleTTP{{
			TechniqueID:   "T1530",
			TechniqueName: "Data from Cloud Storage Object",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(md)
	if !strings.Contains(out, "technique_name: Data from Cloud Storage") {
		t.Fatalf("expected canonical ATT&CK name, got:\n%s", out)
	}
	if strings.Contains(out, "Data from Cloud Storage Object") {
		t.Fatalf("stale ATT&CK name leaked into public Markdown:\n%s", out)
	}
}

func TestPreserveExistingPublicIdentityKeepsFirstPublishedDate(t *testing.T) {
	existing := []byte("---\nbrief_id: brief-existing\nevent_id: brief-existing\nrevision: 1\ndate: \"2026-10-05T12:01:54Z\"\n---\n")
	incoming := BundleBrief{
		ID: "brief-existing", EventID: "brief-existing", Revision: 1,
		PublishedAt: "2026-10-20T12:16:17Z",
	}

	got, err := preserveExistingPublicIdentity(incoming, existing)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublishedAt != "2026-10-05T12:01:54Z" {
		t.Fatalf("published_at = %q, want original public date", got.PublishedAt)
	}
	if got.Lastmod != "" {
		t.Fatalf("lastmod = %q, want no synthetic material revision", got.Lastmod)
	}
}

func TestPreserveExistingPublicIdentityRejectsPathCollision(t *testing.T) {
	existing := []byte("---\nbrief_id: brief-other\nevent_id: event-other\nrevision: 1\ndate: \"2026-10-05T12:01:54Z\"\n---\n")
	_, err := preserveExistingPublicIdentity(BundleBrief{
		ID: "brief-incoming", EventID: "event-incoming", Revision: 1,
		PublishedAt: "2026-10-20T12:16:17Z",
	}, existing)
	if err == nil {
		t.Fatal("expected immutable public path collision to be rejected")
	}
}

func TestBriefToMarkdown_PublicationIntegrityFrontmatter(t *testing.T) {
	b := BundleBrief{
		ID:          "brief-2026-10-integrity",
		Slug:        "2026-10-integrity",
		EventID:     "event-integrity",
		Revision:    2,
		Title:       "Integrity brief",
		Summary:     "Safe summary",
		Severity:    "high",
		PublishedAt: "2026-10-19T10:00:00Z",
		RevisionHistory: []BundleRevision{{
			Revision: 2, At: "2026-10-20T11:12:13Z", Checksum: "sha256:abc", Summary: "Corrected CVE",
			ChangedFields: []string{"cves"}, SourceURLs: []string{"https://vendor.test/advisory"},
		}},
		ExploitationEvidence: &BundleExploitationEvidence{Status: "unknown"},
		CVEs:                 []BundleCVE{{ID: "CVE-2026-1000", KEVStatus: "unknown"}},
		SourceAssessment: &BundleSourceAssessment{
			Reliability: "A", Credibility: "2", Rating: "A2", Likelihood: "likely", Corroboration: "two sources",
			Confidence: "private-confidence", Flags: []BundleSourceFlag{{Detail: "private-flag"}}, Gaps: []string{"private-gap"},
		},
		QAStatus: &BundleQAStatus{
			Verdict: "pass", ValidationStatus: "validated", UnsupportedClaims: []string{"private-claim"},
			TechnicalChecks: []string{"private-check"}, ManualVerification: []string{"private-manual"},
		},
	}
	md, err := briefToMarkdown(b)
	if err != nil {
		t.Fatal(err)
	}
	got := string(md)
	for _, want := range []string{
		"brief_id: brief-2026-10-integrity",
		"event_id: event-integrity",
		"revision: 2",
		"activity_at: \"2026-10-20T11:12:13Z\"",
		"revision_history:",
		"checksum: sha256:abc",
		"exploitation_evidence:",
		"status: unknown",
		"kev_status: unknown",
		"source_assessment:",
		"rating: A2",
		"qa_status:",
		"validation_status: validated",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("frontmatter missing %q:\n%s", want, got)
		}
	}
	for _, withheld := range []string{"private-confidence", "private-flag", "private-gap", "private-claim", "private-check", "private-manual", "kev: false"} {
		if strings.Contains(got, withheld) {
			t.Fatalf("frontmatter leaked/flattened %q:\n%s", withheld, got)
		}
	}
}

func TestBriefToMarkdownDoesNotTreatLegacyLastmodAsMaterialRevision(t *testing.T) {
	md, err := briefToMarkdown(BundleBrief{
		ID: "legacy", Title: "Legacy", PublishedAt: "2026-10-19T10:00:00Z", Lastmod: "2026-10-20T11:12:13Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), `activity_at: "2026-10-19T10:00:00Z"`) {
		t.Fatalf("legacy lastmod changed material activity time:\n%s", md)
	}
}

func TestBriefToMarkdownDoesNotPromoteBareActiveSignalToEvidence(t *testing.T) {
	md, err := briefToMarkdown(BundleBrief{
		ID: "legacy", Title: "Legacy", PublishedAt: "2026-10-19T10:00:00Z",
		PrioritySignals: []string{"active_exploitation"}, References: []string{"https://example.test/advisory"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(md)
	if !strings.Contains(got, "status: unknown") || strings.Contains(got, "exploited: true") {
		t.Fatalf("bare priority signal became public confirmed evidence:\n%s", got)
	}
}

// Backfill re-emits Markdown straight from stored segment briefs, which never
// pass through ParseBriefYAML, so the public frontmatter cleans lists itself.
func TestBriefToMarkdown_DedupesStoredLists(t *testing.T) {
	md, err := briefToMarkdown(BundleBrief{
		ID:               "brief-x",
		Title:            "t",
		AffectedProducts: []string{"Chrome (< 124.0.6367.201)", "Edge", "Chrome (< 124.0.6367.201)"},
		CPEs: []string{
			"cpe:2.3:a:adobe:coldfusion:2023:update1:*:*:*:*:*:*",
			"cpe:2.3:a:adobe:coldfusion:2023:update2:*:*:*:*:*:*",
		},
	})
	if err != nil {
		t.Fatalf("briefToMarkdown: %v", err)
	}
	out := string(md)
	if n := strings.Count(out, "range: < 124.0.6367.201"); n != 1 || !strings.Contains(out, "- Chrome\n") {
		t.Errorf("product and version range not canonically projected:\n%s", out)
	}
	if strings.Contains(out, "update1") || !strings.Contains(out, "cpe:2.3:a:adobe:coldfusion:2023:*:*:*:*:*:*:*") {
		t.Errorf("CPE builds not collapsed:\n%s", out)
	}
}

func TestBriefToMarkdownSeparatesCanonicalProductsFromVersionRanges(t *testing.T) {
	md, err := briefToMarkdown(BundleBrief{
		ID: "brief-product-scope", Title: "Product scope",
		AffectedVendors:  []string{"  NGINX, Inc. ", "NGINX, Inc."},
		AffectedProducts: []string{"DSM (< 7.2.2-72806)", "n8n before 1.82.0", "DSM (< 7.2.2-72806)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var fm struct {
		Vendors         []string `yaml:"vendors"`
		Products        []string `yaml:"products"`
		ProductVersions []struct {
			Product string `yaml:"product"`
			Range   string `yaml:"range"`
		} `yaml:"product_versions"`
	}
	parts := strings.SplitN(string(md), "---\n", 3)
	if len(parts) != 3 {
		t.Fatalf("missing frontmatter: %s", md)
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &fm); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fm.Vendors, []string{"NGINX, Inc."}) {
		t.Fatalf("vendors = %#v", fm.Vendors)
	}
	if !reflect.DeepEqual(fm.Products, []string{"DSM", "n8n"}) {
		t.Fatalf("products = %#v", fm.Products)
	}
	want := []struct {
		Product string `yaml:"product"`
		Range   string `yaml:"range"`
	}{{"DSM", "< 7.2.2-72806"}, {"n8n", "before 1.82.0"}}
	if !reflect.DeepEqual(fm.ProductVersions, want) {
		t.Fatalf("product_versions = %#v, want %#v", fm.ProductVersions, want)
	}
}

func TestBriefToMarkdownCanonicalizesUnambiguousNginxVendorAlias(t *testing.T) {
	md, err := briefToMarkdown(BundleBrief{ID: "brief-nginx", Title: "NGINX", AffectedVendors: []string{"Nginx", "nginx"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "vendors:\n  - NGINX\n") {
		t.Fatalf("vendor alias was not canonicalized:\n%s", md)
	}
}

// Taxonomy terms become page paths on the public site, so none may outgrow
// a file name: a 325-character model list once failed every site build.
func TestBriefToMarkdown_KeepsTaxonomyTermsShort(t *testing.T) {
	long := strings.Repeat("Living off the Land Attack Detection ", 8)
	md, err := briefToMarkdown(BundleBrief{
		ID:               "brief-x",
		Title:            "t",
		AffectedVendors:  []string{"VIVOTEK"},
		AffectedProducts: []string{"VIVOTEK Camera Firmware (FD9187, FD9189, FD9365, FD9387, FD9389, FD9391, FE9180, FE9191, FE9382, FE9391, IB9365, IB9387, IB9389)"},
		Tags:             []string{long},
		ThreatActor:      "APT-Test",
	})
	if err != nil {
		t.Fatalf("briefToMarkdown: %v", err)
	}
	var fm struct {
		Tags     []string `yaml:"tags"`
		Vendors  []string `yaml:"vendors"`
		Products []string `yaml:"products"`
		Actors   []string `yaml:"actors"`
	}
	parts := strings.SplitN(string(md), "---\n", 3)
	if len(parts) < 3 {
		t.Fatalf("no front matter:\n%s", md)
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &fm); err != nil {
		t.Fatal(err)
	}
	if len(fm.Products) != 1 || fm.Products[0] != "VIVOTEK Camera Firmware" {
		t.Errorf("products = %q", fm.Products)
	}
	for _, terms := range [][]string{fm.Tags, fm.Vendors, fm.Products, fm.Actors} {
		for _, term := range terms {
			if len(term) > pipeline.MaxTermBytes {
				t.Errorf("term of %d bytes exceeds %d: %q", len(term), pipeline.MaxTermBytes, term)
			}
		}
	}
}

func TestClassifyType(t *testing.T) {
	cases := []struct {
		name string
		in   BundleBrief
		want string
	}{
		{
			name: "rumour-severity-short-circuits",
			in:   BundleBrief{Severity: "rumour", Rules: []BundleRule{{Title: "x", Detection: map[string]any{"a": 1}}}},
			want: "rumour",
		},
		{
			name: "active-exploitation-is-threat",
			in:   BundleBrief{Severity: "high", PrioritySignals: []string{"active_exploitation"}},
			want: "threat",
		},
		{
			name: "kev-cve-is-threat",
			in:   BundleBrief{Severity: "high", CVEs: []BundleCVE{{ID: "CVE-2026-1", KEV: true}}},
			want: "threat",
		},
		{
			name: "watchlist-match-is-threat",
			in:   BundleBrief{Severity: "medium", PrioritySignals: []string{"watchlist_match"}},
			want: "threat",
		},
		{
			name: "named-actor-on-trusted-source-is-threat",
			in:   BundleBrief{Severity: "high", ThreatActor: "APT29", PrioritySignals: []string{"high_confidence_source"}},
			want: "threat",
		},
		{
			name: "named-actor-medium-not-threat-without-confidence",
			in:   BundleBrief{Severity: "medium", ThreatActor: "APT29"},
			want: "advisory", // medium isn't high+, so the named-actor escalation skips; default is advisory
		},
		{
			name: "named-actor-high-severity-is-threat",
			in:   BundleBrief{Severity: "high", ThreatActor: "APT29"},
			want: "threat",
		},
		{
			name: "named-actor-critical-severity-is-threat",
			in:   BundleBrief{Severity: "critical", ThreatActor: "Lazarus Group"},
			want: "threat",
		},
		{
			name: "rule-feed-source-is-coverage",
			in:   BundleBrief{Severity: "medium", Source: "sigma-hq", Rules: []BundleRule{{Title: "rule", Detection: map[string]any{"selection": map[string]any{"a": 1}, "condition": "selection"}}}},
			want: "coverage",
		},
		{
			name: "splunk-escu-feed-is-coverage",
			in:   BundleBrief{Severity: "medium", Source: "splunk-escu"},
			want: "coverage",
		},
		{
			name: "synthesized-rule-without-rule-source-is-advisory",
			in:   BundleBrief{Severity: "medium", Source: "cisa", Rules: []BundleRule{{Title: "rule", Detection: map[string]any{"a": 1}}}},
			want: "advisory",
		},
		{
			name: "cve-only-no-rule-is-advisory",
			in:   BundleBrief{Severity: "high", CVEs: []BundleCVE{{ID: "CVE-2026-2", KEV: false}}},
			want: "advisory",
		},
		{
			name: "high-rce-cve-without-exploitation-is-advisory",
			in: BundleBrief{
				Severity: "high",
				Title:    "CVE-2026-58384: GIMP PSD Parser Integer Overflow Leads to RCE/DoS",
				Content:  "The issue can lead to denial of service or arbitrary code execution when a user opens a crafted PSD file. No active exploitation has been reported.",
				CVEs:     []BundleCVE{{ID: "CVE-2026-58384", CVSS: 7.3}},
			},
			want: "advisory",
		},
		{
			name: "rule-plus-non-kev-cve-from-non-rule-source-is-advisory",
			in: BundleBrief{Severity: "medium", Source: "cisa",
				CVEs:  []BundleCVE{{ID: "CVE-2026-3"}},
				Rules: []BundleRule{{Title: "rule", Detection: map[string]any{"selection": map[string]any{"a": 1}}}}},
			want: "advisory",
		},
		{
			name: "exploitation-beats-rule-feed",
			in: BundleBrief{Severity: "critical", Source: "sigma-hq",
				PrioritySignals: []string{"active_exploitation"},
				Rules:           []BundleRule{{Title: "rule", Detection: map[string]any{"a": 1}}}},
			want: "threat",
		},
		{
			name: "title-says-unpatched-high-severity-is-threat",
			in:   BundleBrief{Severity: "high", Title: "Unpatched Microsoft Windows RPC Vulnerability Allows Privilege Escalation"},
			want: "threat",
		},
		{
			name: "title-says-zero-day-critical-is-threat",
			in:   BundleBrief{Severity: "critical", Title: "Zero-Day RCE in Apache HTTPD"},
			want: "threat",
		},
		{
			name: "title-says-actively-exploited-is-threat",
			in:   BundleBrief{Severity: "high", Title: "Actively Exploited Bug in Foo"},
			want: "threat",
		},
		{
			name: "body-says-actively-exploited-is-threat",
			in:   BundleBrief{Severity: "high", Title: "Foo Vulnerability", Content: "This vulnerability is actively exploited in the wild by multiple actors."},
			want: "threat",
		},
		{
			name: "unpatched-medium-severity-stays-advisory",
			in:   BundleBrief{Severity: "medium", Title: "Unpatched Foo Vulnerability"},
			want: "advisory",
		},
		{
			name: "empty-brief-defaults-to-advisory",
			in:   BundleBrief{Severity: "low"},
			want: "advisory",
		},
		// Threat-intel source: named actor at medium severity (e.g. surveillance campaign).
		{
			name: "threat-intel-source-named-actor-medium-is-threat",
			in:   BundleBrief{Severity: "medium", Source: "securelist", ThreatActor: "Lazarus Group"},
			want: "threat",
		},
		// Threat-intel source: no named actor but rich TTP coverage — still a campaign report.
		{
			name: "threat-intel-source-rich-ttps-no-actor-is-threat",
			in: BundleBrief{Severity: "medium", Source: "dfir-report", TTPs: []BundleTTP{
				{TacticID: "TA0001", TechniqueID: "T1190"},
				{TacticID: "TA0003", TechniqueID: "T1053"},
			}},
			want: "threat",
		},
		// Threat-intel source: single TTP only — not enough to override advisory.
		{
			name: "threat-intel-source-single-ttp-no-actor-is-advisory",
			in: BundleBrief{Severity: "medium", Source: "securelist", TTPs: []BundleTTP{
				{TacticID: "TA0001", TechniqueID: "T1190"},
			}},
			want: "advisory",
		},
		// Non-threat-intel source (news site): named actor at medium stays advisory.
		{
			name: "non-threat-intel-source-named-actor-medium-stays-advisory",
			in:   BundleBrief{Severity: "medium", Source: "bleepingcomputer", ThreatActor: "APT29"},
			want: "advisory",
		},
		// Mandiant report about an actor: threat regardless of severity.
		{
			name: "mandiant-named-actor-low-severity-is-threat",
			in:   BundleBrief{Severity: "low", Source: "mandiant", ThreatActor: "UNC4736"},
			want: "threat",
		},
		// Vendor advisory language: "limited exploitation observed" (e.g. Palo Alto advisories).
		{
			name: "body-says-limited-exploitation-observed-is-threat",
			in:   BundleBrief{Severity: "critical", Title: "PAN-OS RCE", Content: "Palo Alto Networks has noted limited exploitation of this vulnerability."},
			want: "threat",
		},
		// "exploitation has been observed" phrasing.
		{
			name: "body-says-exploitation-has-been-observed-is-threat",
			in:   BundleBrief{Severity: "high", Title: "Foo RCE", Content: "Exploitation has been observed in targeted attacks against financial institutions."},
			want: "threat",
		},
		// Title with "exploitation observed".
		{
			name: "title-says-exploitation-observed-is-threat",
			in:   BundleBrief{Severity: "high", Title: "Cisco IOS Exploitation Observed in the Wild"},
			want: "threat",
		},
		// "under active exploitation" phrasing.
		{
			name: "body-says-under-active-exploitation-is-threat",
			in:   BundleBrief{Severity: "high", Title: "Foo Vuln", Content: "The vulnerability is under active exploitation by threat actors."},
			want: "threat",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyType(tc.in); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStripLeadingHeadings(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "Hello world.", "Hello world."},
		{"skip-h1", "# Title\n\nFirst para.", "First para."},
		{"skip-h1-h2", "# Title\n\n## Section\n\nBody.", "Body."},
		{"only-headings", "# A\n## B", ""},
		{"keeps-mid-headings", "Intro.\n\n## Mid heading\n\nMore.", "Intro.\n\n## Mid heading\n\nMore."},
		{"keeps-multi-paragraphs", "Para 1.\n\nPara 2.\n\nPara 3.", "Para 1.\n\nPara 2.\n\nPara 3."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripLeadingHeadings(tc.in)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPublicMarkdownPath(t *testing.T) {
	cases := []struct {
		name string
		in   BundleBrief
		want string
	}{
		{
			name: "uses-slug-verbatim",
			in:   BundleBrief{Slug: "fortigate-rce"},
			want: "site/content/briefs/fortigate-rce.md",
		},
		{
			name: "threat-bot-style-slug-with-date-prefix",
			in:   BundleBrief{Slug: "2024-01-02-unusual-windows-privileged-access"},
			want: "site/content/briefs/2024-01-02-unusual-windows-privileged-access.md",
		},
		{
			name: "threat-bot-style-slug-with-month-prefix",
			in:   BundleBrief{Slug: "2024-01-spike-remote-file-transfers"},
			want: "site/content/briefs/2024-01-spike-remote-file-transfers.md",
		},
		{
			name: "fallback-to-id-when-slug-empty",
			in:   BundleBrief{ID: "brief-x"},
			want: "site/content/briefs/brief-x.md",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := publicMarkdownPath(tc.in)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCleanActors(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"single-no-alias", "TeamPCP", []string{"TeamPCP"}},
		{"single-with-alias-expansion", "FIN7", []string{"FIN7", "Carbon Spider", "Sangria Tempest"}},
		{"alias-input-canonicalizes", "cozy bear", []string{"APT29", "Cozy Bear", "NOBELIUM", "UNC2452", "Midnight Blizzard", "The Dukes"}},
		{"crowdstrike-allcaps-expands", "LABYRINTH CHOLLIMA", []string{"Lazarus Group", "HIDDEN COBRA", "LABYRINTH CHOLLIMA", "Diamond Sleet", "Zinc"}},
		{"comma-split-with-expansion", "LABYRINTH CHOLLIMA, SCATTERED SPIDER", []string{"Lazarus Group", "HIDDEN COBRA", "LABYRINTH CHOLLIMA", "Diamond Sleet", "Zinc", "Scattered Spider", "UNC3944", "Octo Tempest", "Roasted 0ktapus", "Muddled Libra", "Star Fraud"}},
		{"and-split-dedupes-expanded", "LABYRINTH CHOLLIMA and SCATTERED SPIDER", []string{"Lazarus Group", "HIDDEN COBRA", "LABYRINTH CHOLLIMA", "Diamond Sleet", "Zinc", "Scattered Spider", "UNC3944", "Octo Tempest", "Roasted 0ktapus", "Muddled Libra", "Star Fraud"}},
		{"slash-split-mixed-aliases", "LockBit / HelloKitty", []string{"LockBit", "BITWISE SPIDER", "HelloKitty"}},
		{"drop-boilerplate", "Multiple Threat Actors", nil},
		{"drop-preamble-with-alias-expansion", "Multiple Threat Actors, Including UNC3944, UNC6201, and UNC5807", []string{"Scattered Spider", "UNC3944", "Octo Tempest", "Roasted 0ktapus", "Muddled Libra", "Star Fraud", "UNC6201", "Salt Typhoon", "GhostEmperor", "FamousSparrow", "UNC5807"}},
		{"strip-likely-suffix", "TeamPCP (Likely)", []string{"TeamPCP"}},
		{"strip-unspecified-suffix", "Russian APT (Unspecified)", []string{"Russian APT"}},
		{"strip-state-sponsored-suffix-expands", "Lazarus Group (State-Sponsored)", []string{"Lazarus Group", "HIDDEN COBRA", "LABYRINTH CHOLLIMA", "Diamond Sleet", "Zinc"}},
		{"strip-potentially-prefix-extract-alias", "Potentially Chinese-Nexus Threat Actor (TrueChaos)", []string{"TrueChaos"}},
		{"drop-countries-only", "China, Russia, North Korea, Iran (State-Sponsored)", nil},
		{"drop-unauth-attacker", "Unauthenticated Attacker", nil},
		{"drop-red-teams", "Red Teams", nil},
		{"drop-researchers-tail", "Palo Alto Networks Researchers (Simulated)", nil},
		{"keep-unc-with-alias-parens", "UNC4736 (Lazarus Group)", []string{"UNC4736 (Lazarus Group)"}},
		{"empty-input", "", nil},
		{"whitespace-input", "   ", nil},
		{"dedupe-case-insensitive-with-expansion", "FIN7 and fin7", []string{"FIN7", "Carbon Spider", "Sangria Tempest"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cleanActors(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("entry %d: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestConvertTTPsPublishesEvidenceAndBand(t *testing.T) {
	out := convertTTPs([]BundleTTP{{
		TacticID:       "TA0001",
		TechniqueID:    "T1566",
		Evidence:       "spearphishing email observed",
		Confidence:     0.9,
		ConfidenceBand: "high",
	}})
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].Evidence != "spearphishing email observed" {
		t.Errorf("evidence not published: %+v", out[0])
	}
	if out[0].ConfidenceBand != "high" {
		t.Errorf("band not published: %+v", out[0])
	}
}

func TestConvertTTPsCanonicalizesTacticName(t *testing.T) {
	out := convertTTPs([]BundleTTP{{
		TacticID: "TA0006", TacticName: "Resource Development",
		TechniqueID: "T1003", TechniqueName: "Credential Dumping",
	}})
	if len(out) != 1 || out[0].TacticName != "Credential Access" {
		t.Fatalf("canonical tactic = %#v", out)
	}
}

func TestBriefToMarkdownDeclaresEveryMentionedCVE(t *testing.T) {
	brief := BundleBrief{
		ID: "brief-cves", Slug: "brief-cves", Title: "CVE-2026-10001 advisory",
		Summary: "Related to CVE-2025-9999.", Content: "CVE-2026-10002 is also affected.",
		PublishedAt: "2026-10-20T12:00:00Z",
		CVEs:        []BundleCVE{{ID: "CVE-2026-10001", CVSS: 9.8}},
	}
	md, err := briefToMarkdown(brief)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"CVE-2026-10001", "CVE-2025-9999", "CVE-2026-10002"} {
		if !strings.Contains(string(md), "id: "+id) {
			t.Fatalf("public frontmatter did not declare %s:\n%s", id, md)
		}
	}
}

// A correction that removes a CVE leaves it named in the append-only revision
// history. The public CVE list describes the current snapshot, so it must not
// take the removed CVE back from that history.
func TestBriefToMarkdownDoesNotDeclareCVEsNamedOnlyInRevisionHistory(t *testing.T) {
	brief := BundleBrief{
		ID: "brief-corrected", EventID: "brief-corrected", Slug: "brief-corrected",
		Title: "Linux Kernel: io_uring privilege escalation (CVE-2024-0582)", Summary: "CVE-2024-0582 is a use-after-free.",
		Content: "A proof of concept for CVE-2024-0582 has been published.", Severity: "high",
		PublishedAt: "2026-10-23T19:48:50Z", Revision: 3,
		AffectedVendors: []string{"Linux"}, AffectedProducts: []string{"Linux Kernel"},
		CVEs: []BundleCVE{{ID: "CVE-2024-0582", KEVStatus: "false"}},
		RevisionHistory: []BundleRevision{
			{Revision: 2, At: "2026-10-29T15:53:38Z", Checksum: "sha256:" + strings.Repeat("a", 64),
				Summary: "added CVE-2026-98432", ChangedFields: []string{"cves"},
				SourceURLs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-99224"}},
			{Revision: 3, At: "2026-11-05T10:29:21Z", Checksum: "sha256:" + strings.Repeat("b", 64),
				Summary: "correction: it covers CVE-2024-0582 only", ChangedFields: []string{"cves"}},
		},
		ExploitationEvidence: &BundleExploitationEvidence{Status: "unknown"},
	}
	path, md, _, publish, err := RenderPublicBriefMarkdown(brief, nil)
	if err != nil || !publish {
		t.Fatalf("RenderPublicBriefMarkdown(%s) publish=%v err=%v", path, publish, err)
	}
	if !strings.Contains(string(md), "id: CVE-2024-0582") {
		t.Fatalf("public frontmatter lost the brief's own CVE:\n%s", md)
	}
	for _, removed := range []string{"CVE-2026-98432", "CVE-2026-99224"} {
		if strings.Contains(string(md), "id: "+removed) {
			t.Fatalf("public frontmatter declared %s, named only in revision history:\n%s", removed, md)
		}
	}
}

func TestDefangMarkdownBody(t *testing.T) {
	// Unfenced payload in prose is neutralized.
	got := defangMarkdownBody("A payload <script>alert('XSS')</script> here.")
	if strings.Contains(got, "<script") {
		t.Errorf("live <script survived: %q", got)
	}
	if !strings.Contains(got, "&lt;script>alert('XSS')&lt;/script>") {
		t.Errorf("payload not defanged as expected: %q", got)
	}

	// Unfenced img/onerror is neutralized.
	if g := defangMarkdownBody("bad <img src=x onerror=alert(1)>"); strings.Contains(g, "<img") {
		t.Errorf("live <img survived: %q", g)
	}

	// Fenced code block is left verbatim (must still contain the raw tag).
	fenced := "text\n```\n<script>alert(1)</script>\n```\nmore"
	if g := defangMarkdownBody(fenced); !strings.Contains(g, "<script>alert(1)</script>") {
		t.Errorf("fenced code was defanged (should be verbatim): %q", g)
	}

	// Inline code span is left verbatim; prose on the same line is defanged.
	inline := "use `<username>` then <script>x</script>"
	g := defangMarkdownBody(inline)
	if !strings.Contains(g, "`<username>`") {
		t.Errorf("inline code span was defanged: %q", g)
	}
	if strings.Contains(g, "<script>") {
		t.Errorf("prose payload survived alongside inline code: %q", g)
	}

	// Benign comparison operators are preserved.
	if g := defangMarkdownBody("affects version < 2.0 and 3 > 1"); g != "affects version < 2.0 and 3 > 1" {
		t.Errorf("benign '<'/'>' altered: %q", g)
	}
}

func TestPublishBriefMarkdownRecordsNewestPublicBrief(t *testing.T) {
	// A fake contents API that remembers the blob SHA of every file written.
	type storedFile struct {
		sha     string
		content []byte
	}
	files := map[string]storedFile{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			file, ok := files[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprintf(w, `{"sha":%q,"size":%d,"content":%q}`, file.sha, len(file.content), base64.StdEncoding.EncodeToString(file.content))
		case http.MethodPut:
			var req contentsRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decoding PUT: %v", err)
			}
			content, err := base64.StdEncoding.DecodeString(req.Content)
			if err != nil {
				t.Errorf("decoding content: %v", err)
			}
			files[r.URL.Path] = storedFile{sha: gitBlobSHA(content), content: content}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"content":{"sha":"new"}}`)
		}
	}))
	defer srv.Close()

	p := &Publisher{
		repoSlug:  "CraftedSignal/threat-feed",
		publicKey: testPublicKey,
		tokenFn:   func() string { return "test-token" },
		apiURL:    srv.URL,
		client:    srv.Client(),
		logger:    slog.Default(),
	}
	brief := func(slug, publishedAt string) BundleBrief {
		return BundleBrief{
			ID: "brief-" + slug, Slug: slug,
			Title: "Advisory for VendorX ProductY " + slug, Summary: "s",
			Content: "body", Severity: "high", PublishedAt: publishedAt,
			AffectedVendors: []string{"VendorX"}, AffectedProducts: []string{"ProductY"},
		}
	}
	publish := func(b BundleBrief) {
		t.Helper()
		if err := p.publishBriefMarkdown(b); err != nil {
			t.Fatalf("publishBriefMarkdown(%s): %v", b.Slug, err)
		}
	}
	assertNewest := func(wantPublished string, wantPushed time.Time) {
		t.Helper()
		published, pushed := p.NewestPublicBrief()
		if got := published.Format(time.RFC3339); got != wantPublished {
			t.Fatalf("newest published = %s, want %s", got, wantPublished)
		}
		if !pushed.Equal(wantPushed) {
			t.Fatalf("pushed = %s, want %s", pushed, wantPushed)
		}
	}

	newest := brief("2026-10-cve-a", "2026-10-18T02:09:24Z")
	publish(newest)
	_, pushed := p.NewestPublicBrief()
	if pushed.IsZero() {
		t.Fatal("pushing a new brief recorded no push time")
	}
	assertNewest("2026-10-18T02:09:24Z", pushed)

	// An update to an older brief doesn't move the feed's newest date.
	publish(brief("2026-10-cve-b", "2026-10-17T20:54:12Z"))
	assertNewest("2026-10-18T02:09:24Z", pushed)

	// Re-emitting unchanged Markdown pushes nothing.
	publish(newest)
	assertNewest("2026-10-18T02:09:24Z", pushed)

	publish(brief("2026-10-cve-c", "2026-10-18T09:00:00Z"))
	_, pushedC := p.NewestPublicBrief()
	if !pushedC.After(pushed) {
		t.Fatalf("pushed = %s, want after %s", pushedC, pushed)
	}
	assertNewest("2026-10-18T09:00:00Z", pushedC)
}
