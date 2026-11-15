package pipeline

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"gopkg.in/yaml.v3"
)

// The types below are the shape the model is asked to write a brief in. They
// are the single source of the response schema sent to the provider
// (llm.SchemaOf reads their tags), so the schema and the decoder cannot drift
// apart: a field is required unless it is omitempty, enum tags close the
// vocabulary, and a type mismatch is impossible under constrained decoding.
//
// Two places cannot be expressed in a Vertex schema, which has fixed object
// keys: a Sigma detection block (selection names and field names are chosen
// by the model) and a rule test's data rows. Both are lists of explicit
// name/value structs here, and rebuildDetection / rebuildTestRows turn them
// back into the maps the rest of the pipeline works with.

// generatedBrief is a brief as the model writes it. Pipeline-owned fields
// (published_at, cves, cvss, epss, exploited, priority, source, ...) are not
// part of it.
type generatedBrief struct {
	ID          string `json:"id" desc:"brief-YYYY-MM-DD-short-slug"`
	Slug        string `json:"slug" desc:"YYYY-MM-short-slug"`
	Title       string `json:"title" desc:"Concise English title"`
	Summary     string `json:"summary" desc:"One detailed sentence summarizing the threat, actor, technique and impact"`
	Severity    string `json:"severity" enum:"critical,high,medium,low,informational"`
	ThreatActor string `json:"threat_actor,omitempty" desc:"Single canonical actor name; omit when unknown or disputed"`
	Content     string `json:"content" desc:"Markdown body with Overview, Attack Chain, Impact and Recommendation sections as the prompt describes"`

	Tags             []string `json:"tags,omitempty"`
	AffectedVendors  []string `json:"affected_vendors,omitempty"`
	AffectedProducts []string `json:"affected_products,omitempty"`
	AffectedOS       []string `json:"affected_os,omitempty"`
	CPEs             []string `json:"cpes,omitempty" desc:"CPE 2.3 URIs"`
	References       []string `json:"references,omitempty" desc:"Source URLs"`

	Rules            []generatedRule            `json:"rules,omitempty"`
	IOCs             []generatedIOC             `json:"iocs,omitempty"`
	TTPs             []generatedTTP             `json:"ttps,omitempty"`
	SourceAssessment *generatedSourceAssessment `json:"source_assessment,omitempty"`
	QAStatus         *generatedQAStatus         `json:"qa_status,omitempty"`
	ActionPlan       *generatedActionPlan       `json:"action_plan,omitempty"`
	PrioritySignals  []string                   `json:"priority_signals,omitempty" enum:"active_exploitation,high_confidence_source,watchlist_match"`
}

// revisedBrief is a brief the grounding repair step returns. Beyond what a
// first draft carries it may restate the exploitation evidence, which is the
// one pipeline-owned claim the repair step is asked to correct.
type revisedBrief struct {
	generatedBrief
	ExploitationEvidence *generatedExploitation `json:"exploitation_evidence,omitempty"`
}

// generatedExploitation is the exploitation state the repair step may restate.
// ObservedAt is typed as a date-time string, not trusted as one: models answer
// with partial dates ("2026-10", "2025"), which parseObservedAt widens or
// rejects in Go (see mergeGroundingRepair).
type generatedExploitation struct {
	Status     string `json:"status" enum:"confirmed_active,not_observed,unknown"`
	SourceURL  string `json:"source_url,omitempty" desc:"URL that shows the observed exploitation; required for confirmed_active"`
	ObservedAt string `json:"observed_at,omitempty" format:"date-time" desc:"When the exploitation was observed, RFC3339 (for example 2026-10-02T00:00:00Z). Omit when the source gives no date"`
	Confidence string `json:"confidence,omitempty" enum:"low,medium,high"`
}

type generatedRule struct {
	Title          string             `json:"title"`
	Description    string             `json:"description" desc:"What malicious behavior this detects and why"`
	LogSource      generatedLogSource `json:"logsource"`
	Detection      generatedDetection `json:"detection"`
	Level          string             `json:"level" enum:"critical,high,medium,low,informational"`
	Tags           []string           `json:"tags,omitempty" desc:"attack.tactic_name and attack.tXXXX[.XXX] tags"`
	Tests          generatedRuleTests `json:"tests"`
	FalsePositives []string           `json:"falsepositives,omitempty"`
	Handoff        *generatedHandoff  `json:"handoff,omitempty"`
}

type generatedLogSource struct {
	Category string `json:"category,omitempty" desc:"Sigma logsource category such as process_creation, network_connection, file_event, registry_set, dns_query, image_load or webserver"`
	Product  string `json:"product,omitempty" desc:"windows, linux or macos; omit for platform-agnostic categories such as webserver"`
	Service  string `json:"service,omitempty"`
}

// generatedDetection is a Sigma detection block with its free-form keys made
// explicit. rebuildDetection produces the map[string]any Sigma tooling reads.
type generatedDetection struct {
	Selections []generatedSelection `json:"selections" desc:"Named selections the condition refers to"`
	Condition  string               `json:"condition" desc:"Sigma condition over the selection names, for example 'selection and not filter'"`
	Timeframe  string               `json:"timeframe,omitempty" desc:"Window for a count() condition, for example 5m"`
}

type generatedSelection struct {
	Name   string           `json:"name" desc:"Selection name used in the condition, for example selection or filter_main"`
	Fields []generatedMatch `json:"fields" desc:"Field matches that must all hold. A match with an empty field is a keyword search over the raw event"`
}

type generatedMatch struct {
	Field    string   `json:"field" desc:"Event field such as Image or CommandLine; empty for a keyword match"`
	Modifier string   `json:"modifier,omitempty" desc:"Sigma field modifiers joined with |, for example contains, endswith, contains|all, re, cidr. Omit for exact equality"`
	Values   []string `json:"values" desc:"Values to match; any one matches unless the modifier includes all"`
}

type generatedRuleTests struct {
	Positive []generatedTestCase `json:"positive,omitempty"`
	Negative []generatedTestCase `json:"negative,omitempty"`
}

type generatedTestCase struct {
	Name string               `json:"name"`
	Data []generatedTestEvent `json:"data" desc:"Sample events"`
}

type generatedTestEvent struct {
	Fields []generatedTestField `json:"fields"`
}

type generatedTestField struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type generatedHandoff struct {
	DetectionConfidence string                        `json:"detection_confidence,omitempty" enum:"high,medium,low"`
	RequiredTelemetry   []generatedRequiredTelemetry  `json:"required_telemetry,omitempty"`
	Validation          *generatedDetectionValidation `json:"validation,omitempty"`
	KnownEvasions       []string                      `json:"known_evasions,omitempty"`
	Limitations         []string                      `json:"limitations,omitempty"`
	Tuning              []generatedTuning             `json:"tuning,omitempty"`
	PortabilityNotes    []generatedPortabilityNote    `json:"portability_notes,omitempty"`
	SuggestedOwner      string                        `json:"suggested_owner,omitempty"`
}

type generatedRequiredTelemetry struct {
	LogSource      string   `json:"log_source,omitempty"`
	EventOrChannel string   `json:"event_or_channel,omitempty"`
	RequiredFields []string `json:"required_fields,omitempty"`
	Availability   string   `json:"availability,omitempty" enum:"available,needs_enablement,unknown"`
	Notes          string   `json:"notes,omitempty"`
}

type generatedDetectionValidation struct {
	Status            string   `json:"status,omitempty" enum:"test_defined,needs_environment_validation,no_atomic_mapping"`
	Steps             []string `json:"steps,omitempty"`
	ExpectedTelemetry string   `json:"expected_telemetry,omitempty"`
	PassCriteria      string   `json:"pass_criteria,omitempty"`
	AtomicReference   string   `json:"atomic_reference,omitempty"`
}

type generatedTuning struct {
	Source   string `json:"source,omitempty"`
	Guidance string `json:"guidance,omitempty"`
}

type generatedPortabilityNote struct {
	Platform string `json:"platform,omitempty"`
	Note     string `json:"note,omitempty"`
}

type generatedIOC struct {
	Type       string             `json:"type" enum:"domain,ip,hash_sha256,hash_sha1,hash_md5,url,email"`
	Value      string             `json:"value" desc:"The exact indicator value observed in the source"`
	Context    string             `json:"context" desc:"Where and how the indicator was observed"`
	Confidence float64            `json:"confidence,omitempty" desc:"0.0 to 1.0"`
	Handling   *generatedHandling `json:"handling,omitempty"`
}

type generatedHandling struct {
	RecommendedAction  string   `json:"recommended_action,omitempty" enum:"block,monitor,hunt,enrich,monitor-only"`
	Priority           string   `json:"priority,omitempty" enum:"high,medium,low"`
	SourceSentence     string   `json:"source_sentence,omitempty" desc:"Verbatim sentence from the source containing or justifying the indicator"`
	SourceName         string   `json:"source_name,omitempty"`
	SourceURL          string   `json:"source_url,omitempty"`
	AssociatedThreats  []string `json:"associated_threats,omitempty"`
	EnrichmentStatus   string   `json:"enrichment_status,omitempty" enum:"enriched,to_enrich,unavailable"`
	LogSources         []string `json:"log_sources,omitempty"`
	EnvironmentTags    []string `json:"environment_tags,omitempty"`
	DetectionNotes     string   `json:"detection_notes,omitempty"`
	FalsePositiveNotes string   `json:"false_positive_notes,omitempty"`
}

type generatedTTP struct {
	TacticID         string  `json:"tactic_id" desc:"TA0001-TA0043"`
	TacticName       string  `json:"tactic_name"`
	TechniqueID      string  `json:"technique_id" desc:"T1xxx"`
	TechniqueName    string  `json:"technique_name"`
	SubtechniqueID   string  `json:"subtechnique_id,omitempty"`
	SubtechniqueName string  `json:"subtechnique_name,omitempty"`
	Evidence         string  `json:"evidence,omitempty" desc:"Verbatim source sentence that justifies the mapping"`
	Confidence       float64 `json:"confidence,omitempty" desc:"0.0 to 1.0"`
}

type generatedSourceAssessment struct {
	Reliability   string                `json:"reliability,omitempty" enum:"A,B,C,D,E,F"`
	Credibility   string                `json:"credibility,omitempty" enum:"1,2,3,4,5,6"`
	Rating        string                `json:"rating,omitempty" desc:"Combined rating such as B2, only when both axes are known"`
	Confidence    string                `json:"confidence,omitempty" enum:"low,moderate,high"`
	Likelihood    string                `json:"likelihood,omitempty" enum:"unlikely,roughly even chance,likely,very likely,almost certain"`
	Corroboration string                `json:"corroboration,omitempty"`
	Flags         []generatedSourceFlag `json:"flags,omitempty"`
	Gaps          []string              `json:"gaps,omitempty"`
}

type generatedSourceFlag struct {
	Type   string `json:"type,omitempty" enum:"single_source,circular_reporting,vendor_bias,anonymous,recency_drift,translation_context_loss"`
	Detail string `json:"detail,omitempty"`
	Impact string `json:"impact,omitempty"`
}

type generatedQAStatus struct {
	Verdict            string   `json:"verdict,omitempty" enum:"pass,pass_with_fixes,do_not_publish"`
	UnsupportedClaims  []string `json:"unsupported_claims,omitempty"`
	FormatGaps         []string `json:"format_gaps,omitempty"`
	TechnicalChecks    []string `json:"technical_checks,omitempty"`
	ManualVerification []string `json:"manual_verification,omitempty"`
	ValidationStatus   string   `json:"validation_status,omitempty"`
}

type generatedActionPlan struct {
	Priority         string                `json:"priority,omitempty" enum:"immediate_escalation,elevated,enrich_before_decision,monitor_or_close"`
	Owners           []string              `json:"owners,omitempty"`
	ImmediateActions []generatedAction     `json:"immediate_actions,omitempty"`
	EnrichmentNeeded []generatedEnrichment `json:"enrichment_needed,omitempty"`
	HuntLeads        []generatedHuntLead   `json:"hunt_leads,omitempty"`
	MitigationPlan   []generatedMitigation `json:"mitigation_plan,omitempty"`
	Gaps             []string              `json:"gaps,omitempty"`
}

type generatedAction struct {
	Action   string `json:"action"`
	Owner    string `json:"owner,omitempty"`
	Due      string `json:"due,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type generatedEnrichment struct {
	Item     string `json:"item"`
	Owner    string `json:"owner,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type generatedHuntLead struct {
	Lead        string   `json:"lead"`
	TechniqueID string   `json:"technique_id,omitempty"`
	DataNeeded  []string `json:"data_needed,omitempty"`
	Priority    string   `json:"priority,omitempty" enum:"high,medium,low"`
	Confidence  string   `json:"confidence,omitempty" enum:"high,medium,low"`
	Disposition string   `json:"disposition,omitempty" enum:"hunt_now,defer,close_gap_first,convert_to_detection"`
	Evidence    string   `json:"evidence,omitempty"`
}

type generatedMitigation struct {
	Priority  string `json:"priority,omitempty" enum:"immediate,short_term,medium_term"`
	Action    string `json:"action"`
	Owner     string `json:"owner,omitempty"`
	Addresses string `json:"addresses,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
}

// Response schemas, derived once from the types above.
var (
	briefResponseSchema     = llm.MustSchemaOf[generatedBrief]()
	revisedBriefSchema      = llm.MustSchemaOf[revisedBrief]()
	detectionResponseSchema = llm.MustSchemaOf[generatedDetection]()
)

// InvalidFieldError reports a generated field whose value is outside the closed
// vocabulary the response schema declares. Constrained decoding should make it
// impossible; the check keeps a provider that ignores an enum from slipping a
// value such as severity "elevated" into the feed.
type InvalidFieldError struct {
	Field string
	Value string
}

func (e *InvalidFieldError) Error() string {
	return fmt.Sprintf("brief has invalid %s %q", e.Field, e.Value)
}

// checkContract returns a *MissingFieldError for the first field the brief
// needs and the model left blank, and an *InvalidFieldError for a severity the
// schema's enum does not allow. Vendor wording that maps onto the enum
// ("important", a CVSS number) is accepted and normalised by document.
func (b generatedBrief) checkContract() error {
	for _, field := range []struct{ name, value string }{
		{"title", b.Title},
		{"summary", b.Summary},
		{"severity", b.Severity},
	} {
		if strings.TrimSpace(field.value) == "" {
			return &MissingFieldError{Field: field.name}
		}
	}
	if _, ok := canonicalSeverity(b.Severity); !ok {
		return &InvalidFieldError{Field: "severity", Value: b.Severity}
	}
	return nil
}

// ValidateLLMResponse keeps unusable but decodable assemblies out of the
// durable LLM cache. The assembler repeats the same contract check for clients
// that do not use that cache, preserving its quarantine error and raw candidate.
func (b generatedBrief) ValidateLLMResponse() error {
	if err := b.checkContract(); err != nil {
		doc, documentErr := b.document()
		if documentErr != nil {
			return documentErr
		}
		raw, _ := yaml.Marshal(doc)
		return &InvalidBriefYAMLError{Err: err, Raw: string(raw)}
	}
	return nil
}

// document converts a generated brief to the map the pipeline edits and
// re-encodes as YAML. Empty optional values the model wrote anyway (an empty
// string, an empty list, a handoff object with nothing in it) are dropped, so
// a field the model had nothing to say about is absent, as when it was
// omitted.
func (b generatedBrief) document() (map[string]any, error) {
	doc, err := toMap(b)
	if err != nil {
		return nil, err
	}
	pruneEmpty(doc)
	delete(doc, "rules")
	rules, err := b.rulesDocument()
	if err != nil {
		return nil, err
	}
	if len(rules) > 0 {
		doc["rules"] = rules
	}
	if severity, ok := canonicalSeverity(b.Severity); ok {
		doc["severity"] = severity
	}
	return doc, nil
}

// document is generatedBrief.document plus the exploitation evidence the
// repair step restated.
func (b revisedBrief) document() (map[string]any, error) {
	doc, err := b.generatedBrief.document()
	if err != nil {
		return nil, err
	}
	if b.ExploitationEvidence != nil {
		evidence, err := toMap(b.ExploitationEvidence)
		if err != nil {
			return nil, err
		}
		pruneEmpty(evidence)
		doc["exploitation_evidence"] = evidence
	}
	return doc, nil
}

func toMap(v any) (map[string]any, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encoding generated brief: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, fmt.Errorf("re-reading generated brief: %w", err)
	}
	return out, nil
}

// rulesDocument builds the map of every rule straight from its own struct, so
// a rule can never be paired with another rule's detection or tests. Empty
// optional values are pruned from the rule, but its detection and test data
// are rebuilt from the explicit-key form and not pruned: a test event may
// legitimately hold an empty value.
func (b generatedBrief) rulesDocument() ([]any, error) {
	rules := make([]any, 0, len(b.Rules))
	for _, rule := range b.Rules {
		m, err := toMap(rule)
		if err != nil {
			return nil, err
		}
		pruneEmpty(m)
		m["detection"] = rule.Detection.rebuild()
		tests := map[string]any{}
		stringOnly := rule.Detection.stringOnlyFields()
		if cases := rebuildTestCases(rule.Tests.Positive, stringOnly); len(cases) > 0 {
			tests["positive"] = cases
		}
		if cases := rebuildTestCases(rule.Tests.Negative, stringOnly); len(cases) > 0 {
			tests["negative"] = cases
		}
		if len(tests) > 0 {
			m["tests"] = tests
		} else {
			delete(m, "tests")
		}
		rules = append(rules, m)
	}
	return rules, nil
}

// pruneEmpty removes empty strings, empty lists and empty maps from v in place,
// recursively, dropping maps and lists that become empty as a result.
// Detection and test data are rebuilt afterwards and are not affected.
func pruneEmpty(v any) {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			pruneEmpty(value)
			if isEmptyValue(value) {
				delete(x, key)
			}
		}
	case []any:
		for _, value := range x {
			pruneEmpty(value)
		}
	}
}

func isEmptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(x) == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// rebuild turns the explicit-key form back into a Sigma detection map:
// selection name -> {field|modifier: value(s)}, plus condition and timeframe.
// Repeated selection names and repeated field+modifier keys are folded into
// one entry whose values are combined, which is what the old duplicate-key
// repair did for hand-written YAML. A selection mixing keyword matches and
// field matches has no Sigma form; it is left out so the condition's reference
// to it is reported by the Sigma checker, which sends the rule to repair.
func (d generatedDetection) rebuild() map[string]any {
	out := map[string]any{}
	selections := map[string]map[string][]any{}
	keywords := map[string][]any{}
	var order []string
	for _, sel := range d.Selections {
		name := strings.TrimSpace(sel.Name)
		if name == "" {
			continue
		}
		if _, seen := selections[name]; !seen {
			selections[name] = map[string][]any{}
			order = append(order, name)
		}
		for _, match := range sel.Fields {
			field := strings.TrimSpace(match.Field)
			if field == "" {
				for _, v := range match.Values {
					keywords[name] = append(keywords[name], v)
				}
				continue
			}
			key := field
			if modifier := strings.Trim(strings.TrimSpace(match.Modifier), "|"); modifier != "" {
				key += "|" + modifier
			}
			selections[name][key] = append(selections[name][key], sigmaValues(key, match.Values)...)
		}
	}
	for _, name := range order {
		fields := selections[name]
		kws := keywords[name]
		switch {
		case len(kws) > 0 && len(fields) > 0:
			// no Sigma form; left out
		case len(kws) > 0:
			out[name] = kws
		default:
			m := make(map[string]any, len(fields))
			for key, values := range fields {
				switch len(values) {
				case 0:
				case 1:
					m[key] = values[0]
				default:
					m[key] = values
				}
			}
			if len(m) > 0 {
				out[name] = m
			}
		}
	}
	if condition := strings.TrimSpace(d.Condition); condition != "" {
		out["condition"] = condition
	}
	if timeframe := strings.TrimSpace(d.Timeframe); timeframe != "" {
		out["timeframe"] = timeframe
	}
	return out
}

// stringOnlyModifiers are the Sigma modifiers that match text. A value under
// one of them is a string even when it looks like a number (a hash, a path
// fragment), so it is never retyped.
var stringOnlyModifiers = map[string]bool{
	"contains": true, "startswith": true, "endswith": true, "re": true,
	"cidr": true, "windash": true, "base64": true, "base64offset": true,
	"utf16le": true, "utf16be": true, "utf16": true, "wide": true,
	"expand": true, "fieldref": true, "cased": true,
}

func hasStringOnlyModifier(modifiers []string) bool {
	for _, m := range modifiers {
		if stringOnlyModifiers[m] {
			return true
		}
	}
	return false
}

// plainInteger returns v as an integer when it is a canonical decimal integer
// ("4688", "-1", "0") that survives the round trip unchanged; "0123", "+5",
// "1e3" and values beyond int64 stay strings.
func plainInteger(v string) (int64, bool) {
	if !plainIntegerRe.MatchString(v) {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

var plainIntegerRe = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// stringOnlyFields lists the event fields some selection matches with a
// string-only modifier. Test events for those fields keep string values.
func (d generatedDetection) stringOnlyFields() map[string]bool {
	out := map[string]bool{}
	for _, sel := range d.Selections {
		for _, match := range sel.Fields {
			field := strings.TrimSpace(match.Field)
			modifiers := strings.Split(strings.Trim(strings.TrimSpace(match.Modifier), "|"), "|")
			if field != "" && hasStringOnlyModifier(modifiers) {
				out[field] = true
			}
		}
	}
	return out
}

// sigmaValues types the model's string values the way Sigma expects them:
// comparison modifiers take numbers, exists takes a boolean, and a plain
// integer under a modifier that does not match text (EventID: 4688) stays an
// integer, since typed backends compare an integer column with a string
// literal wrongly. Everything else stays a string.
func sigmaValues(key string, values []string) []any {
	modifiers := strings.Split(key, "|")[1:]
	numeric, exists := false, false
	for _, m := range modifiers {
		switch m {
		case "gt", "gte", "lt", "lte":
			numeric = true
		case "exists":
			exists = true
		}
	}
	textOnly := hasStringOnlyModifier(modifiers)
	out := make([]any, 0, len(values))
	for _, v := range values {
		switch {
		case numeric:
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				out = append(out, n)
				continue
			}
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				out = append(out, f)
				continue
			}
		case exists:
			if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
				out = append(out, b)
				continue
			}
		case !textOnly:
			if n, ok := plainInteger(v); ok {
				out = append(out, n)
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

func rebuildTestCases(cases []generatedTestCase, stringOnly map[string]bool) []any {
	var out []any
	for _, c := range cases {
		var rows []any
		for _, event := range c.Data {
			row := map[string]any{}
			for _, f := range event.Fields {
				if field := strings.TrimSpace(f.Field); field != "" {
					row[field] = testValue(f.Value, !stringOnly[field])
				}
			}
			if len(row) > 0 {
				rows = append(rows, row)
			}
		}
		out = append(out, map[string]any{"name": c.Name, "data": rows})
	}
	return out
}

// testValue types a test event value like the detection values it is matched
// against: a plain integer becomes an integer unless its field is matched as
// text.
func testValue(v string, mayBeInteger bool) any {
	if mayBeInteger {
		if n, ok := plainInteger(v); ok {
			return n
		}
	}
	return v
}
