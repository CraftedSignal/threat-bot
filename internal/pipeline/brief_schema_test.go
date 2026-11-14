package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/sigma"
	"gopkg.in/yaml.v3"
)

// schemaNode walks a response schema.
func walkSchema(s *llm.Schema, path string, visit func(path string, s *llm.Schema)) {
	visit(path, s)
	for name, p := range s.Properties {
		walkSchema(p, path+"."+name, visit)
	}
	if s.Items != nil {
		walkSchema(s.Items, path+"[]", visit)
	}
}

func schemaDepth(s *llm.Schema) int {
	deepest := 0
	for _, p := range s.Properties {
		if d := schemaDepth(p); d > deepest {
			deepest = d
		}
	}
	if s.Items != nil {
		if d := schemaDepth(s.Items); d > deepest {
			deepest = d
		}
	}
	if s.Type == llm.TypeObject || s.Type == llm.TypeArray {
		return deepest + 1
	}
	return deepest
}

func TestBriefResponseSchemaClosesVocabulariesAndRequiresIdentity(t *testing.T) {
	s := briefResponseSchema
	for _, name := range []string{"id", "slug", "title", "summary", "severity", "content"} {
		found := false
		for _, r := range s.Required {
			found = found || r == name
		}
		if !found {
			t.Errorf("%s must be required", name)
		}
	}
	if got := s.Properties["severity"].Enum; strings.Join(got, ",") != "critical,high,medium,low,informational" {
		t.Errorf("severity enum = %v", got)
	}
	// Pipeline-owned fields must not be writable by the model.
	for _, name := range []string{"published_at", "cves", "exploited", "priority", "priority_score", "source", "type", "claim_state", "exploitation_evidence"} {
		if _, ok := s.Properties[name]; ok {
			t.Errorf("%s is pipeline-owned and must not be in the brief schema", name)
		}
	}
	if _, ok := revisedBriefSchema.Properties["exploitation_evidence"]; !ok {
		t.Error("the repair schema must allow restating exploitation_evidence")
	}
}

func TestExploitationEvidenceObservedAtIsADateTimeString(t *testing.T) {
	observed := revisedBriefSchema.Properties["exploitation_evidence"].Properties["observed_at"]
	if observed.Type != llm.TypeString || observed.Format != "date-time" {
		t.Fatalf("observed_at = %+v, want a date-time string validated in Go", observed)
	}
	status := revisedBriefSchema.Properties["exploitation_evidence"].Properties["status"]
	if strings.Join(status.Enum, ",") != "confirmed_active,not_observed,unknown" {
		t.Errorf("status enum = %v", status.Enum)
	}
}

// Vertex accepts a bounded schema; the live check records what it accepted.
// This guards the shape against growing past it unnoticed.
func TestResponseSchemasStayWithinVerifiedLimits(t *testing.T) {
	for name, s := range map[string]*llm.Schema{"brief": briefResponseSchema, "revised": revisedBriefSchema, "detection": detectionResponseSchema} {
		if d := schemaDepth(s); d > 10 {
			t.Errorf("%s schema depth %d exceeds the 10 verified against Vertex", name, d)
		}
		walkSchema(s, name, func(path string, n *llm.Schema) {
			if len(n.Enum) > 12 {
				t.Errorf("%s: enum of %d values; Vertex limits enum size", path, len(n.Enum))
			}
			if n.Type == llm.TypeObject && len(n.Properties) == 0 {
				t.Errorf("%s: object without properties", path)
			}
		})
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 32<<10 {
			t.Errorf("%s schema is %d bytes", name, len(raw))
		}
	}
}

func TestDetectionSchemaIsAnExplicitKeyList(t *testing.T) {
	// A Sigma detection has arbitrary keys, which a Vertex object cannot
	// carry; the schema must hold no map-like object.
	walkSchema(briefResponseSchema, "brief", func(path string, n *llm.Schema) {
		if strings.HasSuffix(path, ".detection") {
			if n.Properties["selections"].Type != llm.TypeArray {
				t.Errorf("%s.selections is not a list", path)
			}
			fields := n.Properties["selections"].Items.Properties["fields"].Items
			for _, want := range []string{"field", "modifier", "values"} {
				if fields.Properties[want] == nil {
					t.Errorf("%s: selection fields lack %q", path, want)
				}
			}
		}
	})
}

func TestDetectionRebuildProducesSigmaMap(t *testing.T) {
	d := generatedDetection{
		Selections: []generatedSelection{
			{Name: "selection", Fields: []generatedMatch{
				{Field: "Image", Modifier: "endswith", Values: []string{`\powershell.exe`}},
				{Field: "CommandLine", Modifier: "contains", Values: []string{"-enc ", "-EncodedCommand"}},
				// The same field+modifier again, as the model sometimes does:
				// folded into one list, which duplicate YAML keys used to need
				// a repair pass for.
				{Field: "CommandLine", Modifier: "contains", Values: []string{"-nop"}},
			}},
			{Name: "filter", Fields: []generatedMatch{{Field: "ParentImage", Values: []string{`C:\Windows\explorer.exe`}}}},
			{Name: "keywords", Fields: []generatedMatch{{Values: []string{"mimikatz", "sekurlsa"}}}},
			{Name: "big", Fields: []generatedMatch{{Field: "sc-bytes", Modifier: "gt", Values: []string{"100000"}}}},
		},
		Condition: "selection and not filter or keywords",
		Timeframe: "5m",
	}
	got := d.rebuild()
	sel := got["selection"].(map[string]any)
	if sel["Image|endswith"] != `\powershell.exe` {
		t.Errorf("single value should stay a scalar: %#v", sel)
	}
	if v, _ := sel["CommandLine|contains"].([]any); len(v) != 3 {
		t.Errorf("duplicate field+modifier not folded into one list: %#v", sel["CommandLine|contains"])
	}
	if got["filter"].(map[string]any)["ParentImage"] != `C:\Windows\explorer.exe` {
		t.Errorf("modifier-less field: %#v", got["filter"])
	}
	if kw, _ := got["keywords"].([]any); len(kw) != 2 {
		t.Errorf("keyword selection must be a list: %#v", got["keywords"])
	}
	if n, ok := got["big"].(map[string]any)["sc-bytes|gt"].(int64); !ok || n != 100000 {
		t.Errorf("gt value must be numeric: %#v", got["big"])
	}
	if got["condition"] != "selection and not filter or keywords" || got["timeframe"] != "5m" {
		t.Errorf("condition/timeframe: %#v", got)
	}
	if problems, warnings := sigma.CheckDetection(got); len(problems) > 0 {
		t.Errorf("rebuilt detection rejected by the Sigma parser: %v %v", problems, warnings)
	}
}

func TestDetectionRebuildLeavesMixedKeywordSelectionToTheSigmaChecker(t *testing.T) {
	d := generatedDetection{
		Selections: []generatedSelection{{Name: "selection", Fields: []generatedMatch{
			{Field: "Image", Values: []string{"a"}}, {Values: []string{"keyword"}},
		}}},
		Condition: "selection",
	}
	got := d.rebuild()
	if _, ok := got["selection"]; ok {
		t.Fatalf("a selection mixing keywords and fields has no Sigma form: %#v", got)
	}
	if problems, _ := sigma.CheckDetection(got); len(problems) == 0 {
		t.Fatal("the dangling condition must be reported so the rule goes to repair")
	}
}

// goldenBriefJSON is what a schema-constrained model answers with.
const goldenBriefJSON = `{
  "id": "brief-2026-11-contoso-gateway-auth-bypass",
  "slug": "2026-11-contoso-gateway-auth-bypass",
  "title": "Contoso Gateway: Authentication bypass: session refresh (CVE-2026-9999)",
  "summary": "Contoso Gateway 4.2 to 4.7.1 lets an attacker obtain an admin session: [critical] \"unauthenticated\" > 5 requests.",
  "severity": "critical",
  "threat_actor": "",
  "content": "## Overview\nContoso fixed CVE-2026-9999 in 4.7.2.\n\n## Recommendation\n- Upgrade Contoso Gateway to 4.7.2.\n",
  "tags": ["authentication-bypass"],
  "affected_vendors": ["Contoso"],
  "affected_products": ["Contoso Gateway (>= 4.2, < 4.7.2)"],
  "references": ["https://example.com/advisory"],
  "rules": [{
    "title": "Detect Contoso Gateway session refresh bypass",
    "description": "Detects CVE-2026-9999 exploitation via the session refresh endpoint.",
    "logsource": {"category": "webserver"},
    "detection": {
      "selections": [
        {"name": "selection", "fields": [
          {"field": "cs-method", "values": ["POST"]},
          {"field": "cs-uri-stem", "modifier": "endswith", "values": ["/api/v1/session/refresh"]}
        ]},
        {"name": "filter", "fields": [{"field": "sc-status", "modifier": "startswith", "values": ["4"]}]}
      ],
      "condition": "selection and not filter"
    },
    "level": "high",
    "tags": ["attack.initial_access", "attack.t1190"],
    "falsepositives": ["Load balancers that inject X-Forwarded-User"],
    "tests": {
      "positive": [{"name": "bypass", "data": [{"fields": [
        {"field": "cs-method", "value": "POST"}, {"field": "cs-uri-stem", "value": "/api/v1/session/refresh"}, {"field": "sc-status", "value": "200"}]}]}],
      "negative": [{"name": "normal", "data": [{"fields": [
        {"field": "cs-method", "value": "GET"}, {"field": "cs-uri-stem", "value": "/index.html"}, {"field": "sc-status", "value": "200"}]}]}]
    }
  }],
  "iocs": [{"type": "ip", "value": "185.220.101.45", "context": "Download host", "confidence": 1.0}],
  "priority_signals": ["active_exploitation"]
}`

func TestGoldenAssembledBriefPassesExistingValidators(t *testing.T) {
	client := &briefScriptedLLM{replies: []briefLLMReply{{text: goldenBriefJSON}}}
	got, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{
		SourceID: "nvd:CVE-2026-9999", Source: "nvd", Title: "Contoso Gateway", Content: "Advisory text.", URL: "https://example.com/advisory",
	}, &ExtractionResult{CVEs: []string{"CVE-2026-9999"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Rendered by us: strict YAML, no model-written syntax.
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("rendered brief is not YAML: %v\n%s", err, got)
	}
	if doc["summary"] != `Contoso Gateway 4.2 to 4.7.1 lets an attacker obtain an admin session: [critical] "unauthenticated" > 5 requests.` {
		t.Errorf("YAML-hostile text was not preserved: %v", doc["summary"])
	}
	if _, ok := doc["threat_actor"]; ok {
		t.Error("an empty optional string must be omitted, not rendered")
	}
	if got := doc["published_at"]; got == nil {
		t.Error("published_at is the pipeline's to stamp")
	} else if _, err := time.Parse(time.RFC3339, got.(string)); err != nil {
		t.Errorf("published_at = %v", got)
	}

	cleaned, notes, err := NewBriefValidator().Validate(got)
	if err != nil {
		t.Fatalf("BriefValidator rejected the rendered brief: %v", err)
	}
	if err := ValidateBriefContract(cleaned); err != nil {
		t.Fatalf("brief contract: %v\n%s", err, cleaned)
	}
	for _, n := range notes {
		if strings.Contains(n, "rejected") {
			t.Errorf("validator dropped content: %s", n)
		}
	}
	var brief briefYAML
	if err := yaml.Unmarshal([]byte(cleaned), &brief); err != nil {
		t.Fatalf("typed decode: %v", err)
	}
	if len(brief.Rules) != 1 {
		t.Fatalf("rule was dropped; notes: %v", notes)
	}
	rule := brief.Rules[0]
	if problems := sigma.Problems(rule.Title, sigma.LogSource(rule.LogSource), rule.Detection); len(problems) != 0 {
		t.Errorf("sigma.Problems: %v", problems)
	}
	if len(rule.Tests.Positive) != 1 || rule.Tests.Positive[0].Data[0]["cs-method"] != "POST" {
		t.Errorf("test data not rebuilt: %#v", rule.Tests)
	}
	if brief.IOCs[0].Confidence != 1.0 || brief.Severity != "critical" {
		t.Errorf("iocs/severity: %#v %q", brief.IOCs, brief.Severity)
	}
}

// failureShape is one way the free-text path quarantined a brief, with the
// structured equivalent. old is the document the model hand-wrote; the old path
// accepted a brief only if it parsed as YAML into the brief struct and met the
// publication contract. reply is what a schema-constrained model answers for the
// same content, and want what the new path does with it.
type failureShape struct {
	name string
	old  string
	// oldAccepted marks shapes whose old rejection came from a validator that
	// this change relaxed, so it cannot be replayed; TestParseObservedAt covers
	// that one directly.
	oldAccepted bool
	reply       string
	// wantErr is the typed error the new path returns; nil means the brief is
	// accepted and check inspects it.
	wantErr func(error) bool
	check   func(t *testing.T, doc map[string]any)
}

func briefJSON(extra string) string {
	return `{"id":"brief-2026-11-x","slug":"2026-11-x","title":"T","summary":"S","severity":"high","content":"## Overview\nc"` + extra + `}`
}

func isErr[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

func oldPathRejects(rawYAML string) error {
	var brief briefYAML
	if err := yaml.Unmarshal([]byte(rawYAML), &brief); err != nil {
		return err
	}
	return validateBriefContractFields(brief)
}

func TestQuarantinedFailureShapesNowHandledByStructuredOutput(t *testing.T) {
	const head = "id: brief-2026-11-x\nslug: 2026-11-x\npublished_at: \"2026-11-10T10:00:00Z\"\ncontent: c\n"
	shapes := []failureShape{
		{
			name:  "yaml: text after closing quote",
			old:   head + "title: T\nsummary: \"Contoso\" Gateway bypass\nseverity: high\n",
			reply: `{"id":"brief-2026-11-x","slug":"2026-11-x","title":"T","summary":"\"Contoso\" Gateway bypass","severity":"high","content":"c"}`,
			check: func(t *testing.T, doc map[string]any) {
				if doc["summary"] != `"Contoso" Gateway bypass` {
					t.Errorf("title = %v", doc["title"])
				}
			},
		},
		{
			name:  "yaml: value starting with [",
			old:   head + "title: T\nsummary: [UPDATE] Patch released\nseverity: high\n",
			reply: `{"id":"brief-2026-11-x","slug":"2026-11-x","title":"T","summary":"[UPDATE] Patch released","severity":"high","content":"c"}`,
			check: func(t *testing.T, doc map[string]any) {
				if doc["summary"] != "[UPDATE] Patch released" {
					t.Errorf("summary = %v", doc["summary"])
				}
			},
		},
		{
			name:  "yaml: value starting with {",
			old:   head + "title: {{ template }} bug\nsummary: S\nseverity: high\n",
			reply: `{"id":"brief-2026-11-x","slug":"2026-11-x","title":"{{ template }} bug","summary":"S","severity":"high","content":"c"}`,
			check: func(t *testing.T, doc map[string]any) {
				if doc["title"] != "{{ template }} bug" {
					t.Errorf("title = %v", doc["title"])
				}
			},
		},
		{
			name:  "yaml: list item starting with >",
			old:   head + "title: T\nsummary: S\nseverity: high\naffected_products:\n  - >= 1.0, < 2.0 Foo\n",
			reply: `{"id":"brief-2026-11-x","slug":"2026-11-x","title":"T","summary":"S","severity":"high","content":"c","affected_products":[">= 1.0, < 2.0 Foo"]}`,
			check: func(t *testing.T, doc map[string]any) {
				if l, _ := doc["affected_products"].([]any); len(l) != 1 || l[0] != ">= 1.0, < 2.0 Foo" {
					t.Errorf("affected_products = %v", doc["affected_products"])
				}
			},
		},
		{
			name:  "yaml: unquoted colon-space in a scalar",
			old:   head + "title: CVE-2026-1: Foo remote code execution\nsummary: S\nseverity: high\n",
			reply: `{"id":"brief-2026-11-x","slug":"2026-11-x","title":"CVE-2026-1: Foo remote code execution","summary":"S","severity":"high","content":"c"}`,
			check: func(t *testing.T, doc map[string]any) {
				if doc["title"] != "CVE-2026-1: Foo remote code execution" {
					t.Errorf("title = %v", doc["title"])
				}
			},
		},
		{
			name:    "type: map where a string is expected",
			old:     head + "title: T\nsummary:\n  text: nested\nseverity: high\n",
			reply:   `{"id":"brief-2026-11-x","slug":"2026-11-x","title":"T","summary":{"text":"nested"},"severity":"high","content":"c"}`,
			wantErr: isErr[*llm.OutputError],
		},
		{
			name: "type: cves as scalars (pipeline-owned field, not in the schema)",
			// BundleCVE.UnmarshalYAML tolerates the scalar form now; the model
			// no longer writes the field at all.
			oldAccepted: true,
			reply:       briefJSON(`,"cves":["CVE-2026-1111"]`),
			check: func(t *testing.T, doc map[string]any) {
				if _, ok := doc["cves"]; ok {
					t.Error("the model must not write cves; the CVE verifier owns them")
				}
			},
		},
		{
			name:    "type: ioc confidence \"100%\" for a number",
			old:     head + "title: T\nsummary: S\nseverity: high\niocs:\n  - type: domain\n    value: evil.example\n    context: c2\n    confidence: 100%\n",
			reply:   briefJSON(`,"iocs":[{"type":"domain","value":"evil.example","context":"c2","confidence":"100%"}]`),
			wantErr: isErr[*llm.OutputError],
		},
		{
			name:    "type: action item as a bare string",
			old:     head + "title: T\nsummary: S\nseverity: high\naction_plan:\n  immediate_actions:\n    - Upgrade to 4.7.2\n",
			reply:   briefJSON(`,"action_plan":{"immediate_actions":["Upgrade to 4.7.2"]}`),
			wantErr: isErr[*llm.OutputError],
		},
		{
			name:  "enum: severity important",
			old:   head + "title: T\nsummary: S\nseverity: important\n",
			reply: strings.Replace(briefJSON(""), `"high"`, `"important"`, 1),
			check: func(t *testing.T, doc map[string]any) {
				if doc["severity"] != "high" {
					t.Errorf("severity = %v", doc["severity"])
				}
			},
		},
		{
			name:  "enum: severity moderate",
			old:   head + "title: T\nsummary: S\nseverity: moderate\n",
			reply: strings.Replace(briefJSON(""), `"high"`, `"moderate"`, 1),
			check: func(t *testing.T, doc map[string]any) {
				if doc["severity"] != "medium" {
					t.Errorf("severity = %v", doc["severity"])
				}
			},
		},
		{
			name:  "enum: severity numeric CVSS",
			old:   head + "title: T\nsummary: S\nseverity: \"9.8\"\n",
			reply: strings.Replace(briefJSON(""), `"high"`, `"9.8"`, 1),
			check: func(t *testing.T, doc map[string]any) {
				if doc["severity"] != "critical" {
					t.Errorf("severity = %v", doc["severity"])
				}
			},
		},
		{
			name:    "enum: severity unknown",
			old:     head + "title: T\nsummary: S\nseverity: unknown\n",
			reply:   strings.Replace(briefJSON(""), `"high"`, `"unknown"`, 1),
			wantErr: isErr[*InvalidFieldError],
		},
		{
			name:    "enum: severity elevated",
			old:     head + "title: T\nsummary: S\nseverity: elevated\n",
			reply:   strings.Replace(briefJSON(""), `"high"`, `"elevated"`, 1),
			wantErr: isErr[*InvalidFieldError],
		},
		{
			name:        "format: observed_at month only",
			oldAccepted: true,
			reply:       briefJSON(`,"exploitation_evidence":{"status":"confirmed_active","observed_at":"2026-10"}`),
			// exploitation_evidence is not part of a first draft; an unknown
			// field is dropped rather than failing the brief.
			check: func(t *testing.T, doc map[string]any) {
				if _, ok := doc["exploitation_evidence"]; ok {
					t.Error("a first draft must not carry exploitation evidence")
				}
			},
		},
		{
			name:    "contract: missing summary",
			old:     head + "title: T\nseverity: high\n",
			reply:   strings.Replace(briefJSON(""), `"summary":"S"`, `"summary":"  "`, 1),
			wantErr: func(err error) bool { var m *MissingFieldError; return errors.As(err, &m) && m.Field == "summary" },
		},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.oldAccepted {
				if err := oldPathRejects(tc.old); err == nil {
					t.Fatalf("the old path accepted this shape; it was quarantined in production:\n%s", tc.old)
				}
			}
			client := &briefScriptedLLM{replies: []briefLLMReply{{text: tc.reply}}}
			got, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{
				Title: "T", Content: "Enough source content for assembly.", Source: "rss",
			}, nil, nil)
			if len(client.prompts) != 1 {
				t.Fatalf("LLM calls = %d; there is no repair round trip any more", len(client.prompts))
			}
			if tc.wantErr != nil {
				var invalid *InvalidBriefYAMLError
				if !errors.As(err, &invalid) || !tc.wantErr(err) {
					t.Fatalf("err = %v (%T), want a typed quarantine error", err, err)
				}
				if invalid.Raw == "" {
					t.Error("quarantine needs the offending output")
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			var doc map[string]any
			if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
				t.Fatalf("not YAML: %v\n%s", err, got)
			}
			if _, _, err := NewBriefValidator().Validate(got); err != nil {
				t.Fatalf("validator: %v", err)
			}
			tc.check(t, doc)
		})
	}
}

func TestParseObservedAt(t *testing.T) {
	for raw, want := range map[string]string{
		"2026-10-02T09:30:00Z":      "2026-10-02T09:30:00Z",
		"2026-10-02T09:30:00+02:00": "2026-10-02T09:30:00+02:00",
		"2026-10-02T09:30:00":       "2026-10-02T09:30:00Z",
		"2026-10-02":                "2026-10-02T00:00:00Z",
		"2026-10":                   "2026-10-01T00:00:00Z", // month only: first instant of the month
		"2025":                      "2025-01-01T00:00:00Z", // year only: first instant of the year
		" 2026-11-08 ":              "2026-11-08T00:00:00Z",
	} {
		got, err := parseObservedAt(raw)
		if err != nil || got != want {
			t.Errorf("parseObservedAt(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "unknown", "last week", "2026-13", "2026-10-32", "10/02/2026", "202"} {
		if got, err := parseObservedAt(raw); err == nil {
			t.Errorf("parseObservedAt(%q) = %q, want an error rather than a guess", raw, got)
		}
	}
}

func TestRumourContractIsATypedError(t *testing.T) {
	incomplete := "references:\n  - https://www.huntress.com/blog/report\nid: brief-2026-11-r\nslug: r\ntitle: T\nsummary: S\nseverity: rumour\ntype: rumour\npublished_at: \"2026-11-10T10:00:00Z\"\ncontent: provisional\nsource_assessment:\n  likelihood: likely\nestablished_facts:\n  - f\n"
	_, _, err := NewBriefValidator().Validate(incomplete)
	var contract *RumourContractError
	if !errors.As(err, &contract) {
		t.Fatalf("err = %v (%T), want *RumourContractError", err, err)
	}
	if strings.Join(contract.Missing, ",") != "reported_claims,evidence,gaps,unverified_notice" || contract.BriefID != "brief-2026-11-r" {
		t.Errorf("missing = %v", contract.Missing)
	}

	complete := incomplete + "reported_claims:\n  - c\nevidence:\n  - type: artifact\n    detail: d\n    source_url: https://example.com\ngaps:\n  - g\nunverified_notice: n\n"
	complete = strings.Replace(complete, "content: provisional", "content: recommendations are final", 1)
	_, _, err = NewBriefValidator().Validate(complete)
	if !errors.As(err, &contract) || !contract.NonProvisional || len(contract.Missing) != 0 {
		t.Fatalf("err = %v, want a non-provisional *RumourContractError", err)
	}
}

func TestAssembleClassifiesTruncationAndSafetyBlocks(t *testing.T) {
	for _, reason := range []string{"MAX_TOKENS", "SAFETY"} {
		cut := briefLLMReply{err: &llm.FinishReasonError{Reason: reason, Text: `{"id":"brief-2026-11-x","title":"cut`}}
		client := &briefScriptedLLM{replies: []briefLLMReply{cut, cut}}
		_, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{Title: "T", Content: "Enough source content.", Source: "rss"}, nil, nil)
		var finish *llm.FinishReasonError
		var invalid *InvalidBriefYAMLError
		if !errors.As(err, &invalid) || !errors.As(err, &finish) || finish.Reason != reason {
			t.Fatalf("%s: err = %v, want InvalidBriefYAMLError wrapping the FinishReasonError", reason, err)
		}
		if !strings.Contains(invalid.Raw, `"title":"cut`) {
			t.Errorf("%s: partial output not kept for quarantine: %q", reason, invalid.Raw)
		}
		// A truncated answer is retried once; a safety stop is deterministic.
		want := 1
		if reason == "MAX_TOKENS" {
			want = 2
		}
		if got := len(client.prompts); got != want {
			t.Errorf("%s: LLM calls = %d, want %d", reason, got, want)
		}
	}
}

func TestAssembleDoesNotQuarantineTransportErrors(t *testing.T) {
	boom := errors.New("connection reset")
	client := &briefScriptedLLM{replies: []briefLLMReply{{err: boom}}}
	_, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{Title: "T", Content: "Enough source content.", Source: "rss"}, nil, nil)
	var invalid *InvalidBriefYAMLError
	if errors.As(err, &invalid) || !errors.Is(err, boom) {
		t.Fatalf("err = %v; a transport failure is retried, not quarantined", err)
	}
}

func TestAssemblePromptNoLongerAsksForYAML(t *testing.T) {
	for _, stale := range []string{"Raw YAML only", "YAML SAFETY", "single-quoted scalars", "Wrong (Go yaml.Unmarshal rejects duplicate keys)"} {
		if strings.Contains(briefSystemPrompt, stale) {
			t.Errorf("system prompt still carries %q", stale)
		}
	}
	if !strings.Contains(briefSystemPrompt, "response schema") || !strings.Contains(briefSystemPrompt, "{field, modifier, values}") {
		t.Error("system prompt must describe the structured answer and the detection form")
	}
}

func TestRuleRepairSendsDetectionSchemaAndRebuildsMap(t *testing.T) {
	var gotSchema *llm.Schema
	client := schemaRecordingLLM{reply: `{"selections":[{"name":"selection","fields":[{"field":"CommandLine","modifier":"contains","values":["-enc"]}]}],"condition":"selection"}`, schema: &gotSchema}
	rule := "title: R\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: -enc\n  condition: selection and missing\n"
	brief := "id: x\nrules:\n  - " + strings.ReplaceAll(strings.TrimSpace(rule), "\n", "\n    ") + "\n"
	out, notes, err := NewBriefAssembler(client).RepairRules(context.Background(), brief)
	if err != nil {
		t.Fatal(err)
	}
	if gotSchema != detectionResponseSchema {
		t.Error("rule repair must request the detection schema")
	}
	if !strings.Contains(out, "CommandLine|contains") || len(notes) == 0 {
		t.Errorf("repaired detection not applied: %s %v", out, notes)
	}
}

type schemaRecordingLLM struct {
	reply  string
	schema **llm.Schema
}

func (schemaRecordingLLM) Generate(context.Context, string, string) (string, error) {
	return "", errors.New("free-text generation must not be used")
}
func (schemaRecordingLLM) GenerateJSON(context.Context, string, string, any) error {
	return errors.New("unexpected GenerateJSON")
}
func (s schemaRecordingLLM) GenerateStructured(_ context.Context, _, _ string, schema *llm.Schema, out any) error {
	*s.schema = schema
	return structuredFromText(s.reply, out)
}

func TestAssembleRetriesTruncatedAnswerOnce(t *testing.T) {
	cut := briefLLMReply{err: &llm.FinishReasonError{Reason: "MAX_TOKENS", Text: `{"id":"x`}}
	client := &briefScriptedLLM{replies: []briefLLMReply{cut, {text: briefJSON("")}}}
	out, err := NewBriefAssembler(client).Assemble(context.Background(), scraper.RawItem{Title: "T", Content: "Enough source content.", Source: "rss"}, nil, nil)
	if err != nil || out == "" {
		t.Fatalf("a truncated first answer followed by a good one must succeed: %v", err)
	}
	if len(client.prompts) != 2 {
		t.Fatalf("LLM calls = %d, want 2", len(client.prompts))
	}
}

func TestSigmaIntegersStayIntegers(t *testing.T) {
	d := generatedDetection{Selections: []generatedSelection{{Name: "selection", Fields: []generatedMatch{
		{Field: "EventID", Values: []string{"4688"}},
		{Field: "ExitCode", Values: []string{"0", "-1"}},
		{Field: "Version", Values: []string{"0123", "1.5", "+7", "99999999999999999999"}},
		{Field: "Hash", Modifier: "contains", Values: []string{"1234567"}},
		{Field: "Port", Modifier: "re", Values: []string{"443"}},
		{Field: "Hash", Modifier: "startswith", Values: []string{"8675309"}},
		{Field: "Name", Modifier: "endswith", Values: []string{"42"}},
		{Field: "Ip", Modifier: "cidr", Values: []string{"10"}},
		{Field: "Id", Modifier: "contains|all", Values: []string{"1", "2"}},
	}}}}
	sel := d.rebuild()["selection"].(map[string]any)
	if sel["EventID"] != int64(4688) {
		t.Errorf("EventID = %#v, want int64 4688", sel["EventID"])
	}
	if v, _ := sel["ExitCode"].([]any); len(v) != 2 || v[0] != int64(0) || v[1] != int64(-1) {
		t.Errorf("ExitCode = %#v", sel["ExitCode"])
	}
	if v, _ := sel["Version"].([]any); len(v) != 4 || v[0] != "0123" || v[1] != "1.5" || v[2] != "+7" || v[3] != "99999999999999999999" {
		t.Errorf("non-canonical numbers must stay strings: %#v", sel["Version"])
	}
	for _, key := range []string{"Hash|contains", "Port|re", "Hash|startswith", "Name|endswith", "Ip|cidr"} {
		if _, isString := sel[key].(string); !isString {
			t.Errorf("%s = %#v, want a string", key, sel[key])
		}
	}
	if v, _ := sel["Id|contains|all"].([]any); len(v) != 2 || v[0] != "1" {
		t.Errorf("Id|contains|all = %#v", sel["Id|contains|all"])
	}
}

func TestSigmaTestEventsRoundTripIntegers(t *testing.T) {
	b := generatedBrief{Rules: []generatedRule{{
		Title: "R",
		Detection: generatedDetection{Selections: []generatedSelection{{Name: "selection", Fields: []generatedMatch{
			{Field: "EventID", Values: []string{"4688"}},
			{Field: "Hash", Modifier: "contains", Values: []string{"1234567"}},
		}}}, Condition: "selection"},
		Tests: generatedRuleTests{Positive: []generatedTestCase{{Name: "p", Data: []generatedTestEvent{{Fields: []generatedTestField{
			{Field: "EventID", Value: "4688"}, {Field: "Hash", Value: "1234567"}, {Field: "Other", Value: "007"},
		}}}}}},
	}}}
	rules, err := b.rulesDocument()
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0].(map[string]any)
	row := rule["tests"].(map[string]any)["positive"].([]any)[0].(map[string]any)["data"].([]any)[0].(map[string]any)
	if row["EventID"] != int64(4688) || row["Hash"] != "1234567" || row["Other"] != "007" {
		t.Errorf("test event = %#v", row)
	}
	if rule["detection"].(map[string]any)["selection"].(map[string]any)["EventID"] != int64(4688) {
		t.Errorf("detection = %#v", rule["detection"])
	}
}

func TestRulesDocumentKeepsEveryRuleWithItsOwnDetection(t *testing.T) {
	detection := func(field string) generatedDetection {
		return generatedDetection{Selections: []generatedSelection{{Name: "selection", Fields: []generatedMatch{{Field: field, Values: []string{"x"}}}}}, Condition: "selection"}
	}
	b := generatedBrief{Rules: []generatedRule{
		{Title: "first", Detection: detection("A")},
		{}, // an empty rule in the middle prunes down to nothing
		{Title: "third", Detection: detection("C")},
	}}
	rules, err := b.rulesDocument()
	if err != nil || len(rules) != 3 {
		t.Fatalf("rules = %d, %v", len(rules), err)
	}
	third := rules[2].(map[string]any)
	if third["title"] != "third" {
		t.Fatalf("third rule = %#v", third)
	}
	if _, ok := third["detection"].(map[string]any)["selection"].(map[string]any)["C"]; !ok {
		t.Errorf("third rule carries another rule's detection: %#v", third["detection"])
	}
	doc, err := b.document()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := doc["rules"].([]any); len(got) != 3 {
		t.Errorf("document rules = %d, want 3", len(got))
	}
}
