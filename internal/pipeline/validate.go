package pipeline

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/craftedsignal/threat-bot/internal/mitre"
	"github.com/craftedsignal/threat-bot/internal/sigma"

	"gopkg.in/yaml.v3"
)

// BriefValidator parses LLM-generated threat brief YAML, validates and cleans
// it, and returns cleaned YAML along with validation notes.
type BriefValidator struct{}

// NewBriefValidator creates a new BriefValidator.
func NewBriefValidator() *BriefValidator {
	return &BriefValidator{}
}

// briefYAML is the typed struct for parsing the brief YAML schema.
type briefYAML struct {
	ID          string      `yaml:"id"`
	Slug        string      `yaml:"slug"`
	Title       string      `yaml:"title"`
	Summary     string      `yaml:"summary"`
	Severity    string      `yaml:"severity"`
	Type        string      `yaml:"type,omitempty"`
	ClaimState  string      `yaml:"claim_state,omitempty"`
	ThreatActor string      `yaml:"threat_actor,omitempty"`
	PublishedAt string      `yaml:"published_at"`
	Content     string      `yaml:"content"`
	Tags        []string    `yaml:"tags"`
	References  []string    `yaml:"references"`
	CPEs        []string    `yaml:"cpes,omitempty"`
	Rules       []briefRule `yaml:"rules,omitempty"`
	IOCs        []briefIOC  `yaml:"iocs,omitempty"`
	TTPs        []briefTTP  `yaml:"ttps,omitempty"`
	CVEs        []BundleCVE `yaml:"cves,omitempty"`

	Priority        string   `yaml:"priority,omitempty"`
	PriorityScore   int      `yaml:"priority_score,omitempty"`
	PrioritySignals []string `yaml:"priority_signals,omitempty"`
	Exploited       bool     `yaml:"exploited,omitempty"`
	// HasPOC and PocReferences are set from the source before validation
	// (sourceReportsPublicExploit); Validate re-encodes this struct, so a
	// field missing here is dropped from the brief.
	HasPOC        bool     `yaml:"has_poc,omitempty"`
	PocReferences []string `yaml:"poc_references,omitempty"`

	ExploitationEvidence *ExploitationEvidence `yaml:"exploitation_evidence,omitempty"`

	SourceAssessment *briefSourceAssessment `yaml:"source_assessment,omitempty"`
	QAStatus         *briefQAStatus         `yaml:"qa_status,omitempty"`
	ActionPlan       *briefActionPlan       `yaml:"action_plan,omitempty"`

	AffectedVendors  []string        `yaml:"affected_vendors,omitempty"`
	AffectedProducts []string        `yaml:"affected_products,omitempty"`
	AffectedOS       []string        `yaml:"affected_os,omitempty"`
	EstablishedFacts []string        `yaml:"established_facts,omitempty"`
	ReportedClaims   []string        `yaml:"reported_claims,omitempty"`
	Evidence         []ClaimEvidence `yaml:"evidence,omitempty"`
	Gaps             []string        `yaml:"gaps,omitempty"`
	UnverifiedNotice string          `yaml:"unverified_notice,omitempty"`
}

// ExploitationEvidence is the tri-state, attributed boundary for public
// exploitation claims. A confirmed state is invalid without its source.
type ExploitationEvidence struct {
	Status     string `json:"status" yaml:"status"`
	SourceURL  string `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	ObservedAt string `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
	Confidence string `json:"confidence,omitempty" yaml:"confidence,omitempty"`
}

var mentionedCVERe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

var negatedExploitationRe = regexp.MustCompile(`(?i)\b(no (?:known )?evidence of exploitation|not actively exploited|has not been exploited|no (?:known )?exploitation|not observed in attacks|no exploitation in the wild)\b`)

type briefRule struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id,omitempty"`
	Status         string         `yaml:"status,omitempty"`
	Description    string         `yaml:"description"`
	LogSource      briefLogSource `yaml:"logsource"`
	Detection      map[string]any `yaml:"detection"`
	Level          string         `yaml:"level"`
	Tags           []string       `yaml:"tags,omitempty"`
	Tests          briefRuleTests `yaml:"tests,omitempty"`
	Handoff        *briefHandoff  `yaml:"handoff,omitempty"`
	FalsePositives []string       `yaml:"falsepositives,omitempty"`
	// Fields that may appear when LLM generates SPL/KQL instead of Sigma.
	Query    string `yaml:"query,omitempty"`
	Platform string `yaml:"platform,omitempty"`
}

type briefLogSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product,omitempty"`
	Service  string `yaml:"service,omitempty"`
}

type briefRuleTests struct {
	Positive []briefTestCase `yaml:"positive,omitempty"`
	Negative []briefTestCase `yaml:"negative,omitempty"`
}

type briefTestCase struct {
	Name string                   `yaml:"name"`
	Data []map[string]interface{} `yaml:"data"`
}

type briefIOC struct {
	Type       string            `yaml:"type"`
	Value      string            `yaml:"value"`
	Context    string            `yaml:"context"`
	Confidence float64           `yaml:"confidence,omitempty"`
	Handling   *briefIOCHandling `yaml:"handling,omitempty"`
}

type briefTTP struct {
	TacticID         string  `yaml:"tactic_id"`
	TacticName       string  `yaml:"tactic_name"`
	TechniqueID      string  `yaml:"technique_id"`
	TechniqueName    string  `yaml:"technique_name"`
	SubtechniqueID   string  `yaml:"subtechnique_id,omitempty"`
	SubtechniqueName string  `yaml:"subtechnique_name,omitempty"`
	Evidence         string  `yaml:"evidence,omitempty"`
	Confidence       float64 `yaml:"confidence,omitempty"`
	ConfidenceBand   string  `yaml:"confidence_band,omitempty"`
}

type briefSourceAssessment struct {
	Reliability   string            `yaml:"reliability,omitempty"`
	Credibility   string            `yaml:"credibility,omitempty"`
	Rating        string            `yaml:"rating,omitempty"`
	Confidence    string            `yaml:"confidence,omitempty"`
	Likelihood    string            `yaml:"likelihood,omitempty"`
	Corroboration string            `yaml:"corroboration,omitempty"`
	Flags         []briefSourceFlag `yaml:"flags,omitempty"`
	Gaps          []string          `yaml:"gaps,omitempty"`
}

type briefSourceFlag struct {
	Type   string `yaml:"type,omitempty"`
	Detail string `yaml:"detail,omitempty"`
	Impact string `yaml:"impact,omitempty"`
}

type briefQAStatus struct {
	Verdict            string   `yaml:"verdict,omitempty"`
	UnsupportedClaims  []string `yaml:"unsupported_claims,omitempty"`
	FormatGaps         []string `yaml:"format_gaps,omitempty"`
	TechnicalChecks    []string `yaml:"technical_checks,omitempty"`
	ManualVerification []string `yaml:"manual_verification,omitempty"`
	ValidationStatus   string   `yaml:"validation_status,omitempty"`
}

type briefActionPlan struct {
	Priority         string                  `yaml:"priority,omitempty"`
	Owners           []string                `yaml:"owners,omitempty"`
	ImmediateActions []briefActionItem       `yaml:"immediate_actions,omitempty"`
	EnrichmentNeeded []briefEnrichmentNeeded `yaml:"enrichment_needed,omitempty"`
	HuntLeads        []briefHuntLead         `yaml:"hunt_leads,omitempty"`
	MitigationPlan   []briefMitigation       `yaml:"mitigation_plan,omitempty"`
	Gaps             []string                `yaml:"gaps,omitempty"`
}

type briefActionItem struct {
	Action   string `yaml:"action,omitempty"`
	Owner    string `yaml:"owner,omitempty"`
	Due      string `yaml:"due,omitempty"`
	Evidence string `yaml:"evidence,omitempty"`
	Status   string `yaml:"status,omitempty"`
}

type briefEnrichmentNeeded struct {
	Item     string `yaml:"item,omitempty"`
	Owner    string `yaml:"owner,omitempty"`
	Reason   string `yaml:"reason,omitempty"`
	Evidence string `yaml:"evidence,omitempty"`
}

type briefHuntLead struct {
	Lead        string   `yaml:"lead,omitempty"`
	TechniqueID string   `yaml:"technique_id,omitempty"`
	DataNeeded  []string `yaml:"data_needed,omitempty"`
	Priority    string   `yaml:"priority,omitempty"`
	Confidence  string   `yaml:"confidence,omitempty"`
	Disposition string   `yaml:"disposition,omitempty"`
	Evidence    string   `yaml:"evidence,omitempty"`
}

type briefMitigation struct {
	Priority  string `yaml:"priority,omitempty"`
	Action    string `yaml:"action,omitempty"`
	Owner     string `yaml:"owner,omitempty"`
	Addresses string `yaml:"addresses,omitempty"`
	Evidence  string `yaml:"evidence,omitempty"`
}

type briefHandoff struct {
	DetectionConfidence string                     `yaml:"detection_confidence,omitempty"`
	RequiredTelemetry   []briefRequiredTelemetry   `yaml:"required_telemetry,omitempty"`
	Validation          *briefDetectionValidation  `yaml:"validation,omitempty"`
	KnownEvasions       []string                   `yaml:"known_evasions,omitempty"`
	Limitations         []string                   `yaml:"limitations,omitempty"`
	Tuning              []briefFalsePositiveTuning `yaml:"tuning,omitempty"`
	PortabilityNotes    []briefPortabilityNote     `yaml:"portability_notes,omitempty"`
	SuggestedOwner      string                     `yaml:"suggested_owner,omitempty"`
	Gaps                []string                   `yaml:"gaps,omitempty"`
}

type briefRequiredTelemetry struct {
	LogSource      string   `yaml:"log_source,omitempty"`
	EventOrChannel string   `yaml:"event_or_channel,omitempty"`
	RequiredFields []string `yaml:"required_fields,omitempty"`
	Availability   string   `yaml:"availability,omitempty"`
	Notes          string   `yaml:"notes,omitempty"`
}

type briefDetectionValidation struct {
	Status            string   `yaml:"status,omitempty"`
	Steps             []string `yaml:"steps,omitempty"`
	ExpectedTelemetry string   `yaml:"expected_telemetry,omitempty"`
	PassCriteria      string   `yaml:"pass_criteria,omitempty"`
	AtomicReference   string   `yaml:"atomic_reference,omitempty"`
}

type briefFalsePositiveTuning struct {
	Source   string `yaml:"source,omitempty"`
	Guidance string `yaml:"guidance,omitempty"`
}

type briefPortabilityNote struct {
	Platform string `yaml:"platform,omitempty"`
	Note     string `yaml:"note,omitempty"`
}

type briefIOCHandling struct {
	RecommendedAction  string   `yaml:"recommended_action,omitempty"`
	Priority           string   `yaml:"priority,omitempty"`
	SourceSentence     string   `yaml:"source_sentence,omitempty"`
	SourceName         string   `yaml:"source_name,omitempty"`
	SourceURL          string   `yaml:"source_url,omitempty"`
	AssociatedThreats  []string `yaml:"associated_threats,omitempty"`
	EnrichmentStatus   string   `yaml:"enrichment_status,omitempty"`
	LogSources         []string `yaml:"log_sources,omitempty"`
	EnvironmentTags    []string `yaml:"environment_tags,omitempty"`
	DetectionNotes     string   `yaml:"detection_notes,omitempty"`
	FalsePositiveNotes string   `yaml:"false_positive_notes,omitempty"`
}

// confidenceBand maps an LLM-emitted confidence (0..1) to a display band.
// A non-positive confidence means "unscored" and yields an empty band so
// downstream consumers do not penalise it as low.
func confidenceBand(c float64) string {
	switch {
	case c <= 0:
		return ""
	case c >= 0.8:
		return "high"
	case c >= 0.5:
		return "med"
	default:
		return "low"
	}
}

// placeholders is the set of values considered as placeholder/empty.
var placeholders = map[string]bool{
	"unknown":     true,
	"n/a":         true,
	"tbd":         true,
	"none":        true,
	"null":        true,
	"na":          true,
	"unspecified": true,
}

// dosSignals are phrases that indicate a denial-of-service vulnerability.
var dosSignals = []string{
	"denial of service",
	"denial-of-service",
	" dos ",
	" dos.",
	" dos,",
	"(dos)",
	"crash",
	"hang",
	"freeze",
	"resource exhaustion",
	"memory exhaustion",
	"cpu exhaustion",
	"amplification attack",
	"null pointer dereference",
	"null-pointer dereference",
	"infinite loop",
	"reachable assertion",
}

// escalationSignals are phrases that indicate the vulnerability is more than
// plain DoS — presence of any disables the downgrade.
var escalationSignals = []string{
	"remote code execution",
	" rce ",
	" rce.",
	" rce,",
	"(rce)",
	"arbitrary code",
	"code execution",
	"command execution",
	"command injection",
	"privilege escalation",
	"privilege-escalation",
	" privesc",
	"auth bypass",
	"authentication bypass",
	"authorization bypass",
	"unauthenticated access",
	"sensitive data exposure",
	"information disclosure",
	"data exfiltration",
	"credential theft",
	"credential harvesting",
	"session hijack",
	"sql injection",
	"path traversal",
	"directory traversal",
	"memory corruption",
	"heap overflow",
	"stack overflow",
	"use-after-free",
	"type confusion",
	"sandbox escape",
	"container escape",
	"kernel escape",
	"actively exploited",
	"exploitation in the wild",
	"zero-day",
	"0-day",
	"ransomware",
	"persistence",
	"lateral movement",
}

// isPureDoS returns true when the brief describes a vulnerability whose worst
// documented impact is denial of service. It looks for DoS signals in title /
// summary / content / tags, and requires none of the escalation signals are
// present — if any stronger impact is mentioned, the brief is not "pure DoS".
func isPureDoS(title, summary, content string, tags []string) bool {
	haystack := strings.ToLower(title + " " + summary + " " + content)
	for _, t := range tags {
		haystack += " " + strings.ToLower(t)
	}

	hasDoS := false
	for _, s := range dosSignals {
		if strings.Contains(haystack, s) {
			hasDoS = true
			break
		}
	}
	if !hasDoS {
		return false
	}
	for _, s := range escalationSignals {
		if strings.Contains(haystack, s) {
			return false
		}
	}
	return true
}

// CleanAffectedList normalizes names (see affectedName), drops
// placeholder/empty values, and deduplicates case-insensitively while
// preserving first-seen casing.
func CleanAffectedList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		trimmed := affectedName(v)
		if trimmed == "" || isPlaceholder(trimmed) {
			continue
		}
		key := strings.ToLower(trimmed)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// MaxTermBytes caps a public site taxonomy term (vendor, product, tag or
// actor). The site writes a page per term under a directory named after it,
// and a name longer than the file system allows (255 bytes) fails the build.
const MaxTermBytes = 120

// parentheticalRe matches a parenthesized part of a name.
var parentheticalRe = regexp.MustCompile(`\s*\(([^()]*)\)`)

// versionWordRe matches words that mark a parenthetical as a version range.
var versionWordRe = regexp.MustCompile(`(?i)\b(through|before|prior|later|earlier|versions?)\b`)

// affectedName normalizes a vendor, product or OS name. A name too long for a
// site term first loses its parenthesized version or model lists ("VIVOTEK
// Camera Firmware (FD9187, FD9189, ...)", "IBM MQ (9.1.0.0 through ...)"),
// which describe affected versions rather than the product; a qualifier such
// as "(WSL)" stays.
func affectedName(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if len(name) <= MaxTermBytes {
		return name
	}
	name = parentheticalRe.ReplaceAllStringFunc(name, func(part string) string {
		inner := parentheticalRe.FindStringSubmatch(part)[1]
		if strings.ContainsAny(inner, ",0123456789") || versionWordRe.MatchString(inner) {
			return ""
		}
		return part
	})
	return CapTerm(strings.Join(strings.Fields(name), " "))
}

// CapTerm shortens a term to at most MaxTermBytes, cutting at a word boundary
// where there is one.
func CapTerm(term string) string {
	if len(term) <= MaxTermBytes {
		return term
	}
	cut := strings.LastIndex(term[:MaxTermBytes+1], " ")
	if cut <= 0 {
		cut = MaxTermBytes
		for cut > 0 && !utf8.RuneStart(term[cut]) {
			cut--
		}
	}
	return strings.TrimRight(term[:cut], " ,;:-/")
}

// CleanCPEList trims, validates and de-duplicates CPE 2.3 URIs. NVD lists one
// CPE per build of a product version (coldfusion:2023:update1 through update22,
// windows_10_1607 on x64 and x86); URIs that differ only in those build
// components collapse into one URI with them wildcarded. A lone build keeps
// its exact URI.
func CleanCPEList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	var keys []string
	first := make(map[string]string, len(in))
	builds := make(map[string]map[string]bool, len(in))
	for _, v := range in {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" || isPlaceholder(trimmed) || !strings.HasPrefix(strings.ToLower(trimmed), "cpe:2.3:") {
			continue
		}
		key := strings.ToLower(cpeBuildKey(trimmed))
		if _, ok := first[key]; !ok {
			first[key] = trimmed
			builds[key] = map[string]bool{}
			keys = append(keys, key)
		}
		builds[key][strings.ToLower(trimmed)] = true
	}
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if len(builds[key]) == 1 {
			out = append(out, first[key])
			continue
		}
		out = append(out, cpeBuildKey(first[key]))
	}
	return out
}

// cpeBuildComponents are the CPE 2.3 components that only distinguish builds
// of one product version: update, edition, language, target_hw and other.
var cpeBuildComponents = []int{6, 7, 8, 11, 12}

// cpeBuildKey wildcards the build components of a CPE 2.3 URI. URIs without
// the 13 components of the formatted-string binding are returned unchanged,
// so they only de-duplicate exactly.
func cpeBuildKey(cpe string) string {
	parts := splitCPE(cpe)
	if len(parts) != 13 {
		return cpe
	}
	for _, i := range cpeBuildComponents {
		parts[i] = "*"
	}
	return strings.Join(parts, ":")
}

// splitCPE splits a CPE 2.3 formatted string on colons that are not
// backslash-escaped, e.g. a product bound as "widget\:pro".
func splitCPE(cpe string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(cpe); i++ {
		switch cpe[i] {
		case '\\':
			i++
		case ':':
			parts = append(parts, cpe[start:i])
			start = i + 1
		}
	}
	return append(parts, cpe[start:])
}

// isPlaceholder reports whether a value is a placeholder.
func isPlaceholder(v string) bool {
	return placeholders[strings.ToLower(strings.TrimSpace(v))]
}

// isFakeHash detects obviously fabricated hex hashes (sequential patterns, well-known test values).
var fakeHashRe = regexp.MustCompile(`^(?:deadbeef|cafebabe|a1b2c3d4|b2c3d4e5|c3d4e5f6|d4e5f6a7|e5f6a7b8|0123456789|abcdef0123)`)

// slugDateRe matches a YYYY-MM- prefix at the start of a slug.
var slugDateRe = regexp.MustCompile(`^\d{4}-\d{2}-`)

// emptyFileSHA256 is the SHA-256 of an empty file — commonly hallucinated by LLMs.
const emptyFileSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// isFakeIOC detects placeholder/fabricated IOC values.
func isFakeIOC(ioc briefIOC) bool {
	v := strings.ToLower(strings.TrimSpace(ioc.Value))

	// Placeholder domains
	if strings.Contains(v, "example.com") || strings.Contains(v, "example.org") || strings.Contains(v, "example.net") {
		return true
	}

	// Well-known test/documentation IPs
	if strings.HasPrefix(v, "192.0.2.") || strings.HasPrefix(v, "198.51.100.") || strings.HasPrefix(v, "203.0.113.") {
		return true
	}

	// Private/loopback IPs that can't be real IOCs
	if ip := net.ParseIP(v); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
		return true
	}

	// URLs whose host resolves to a private/loopback IP (e.g. PoC infrastructure
	// like http://10.100.200.19:8000/...) are researcher-controlled, not attacker IOCs.
	if ioc.Type == "url" {
		if parsed, err := url.Parse(v); err == nil {
			host := parsed.Hostname()
			if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
				return true
			}
		}
	}

	// Fake hashes
	if ioc.Type == "hash_sha256" || ioc.Type == "hash_md5" || ioc.Type == "hash_sha1" {
		if v == emptyFileSHA256 {
			return true
		}
		if fakeHashRe.MatchString(v) {
			return true
		}
		// Detect sequential hex patterns (each byte increments by 0x11)
		if len(v) >= 16 && isSequentialHex(v) {
			return true
		}
	}

	return false
}

// isSequentialHex detects hex strings with an obvious sequential/repeating pattern.
func isSequentialHex(s string) bool {
	if len(s) < 16 {
		return false
	}
	// Check if the first 8 hex pairs form an arithmetic sequence
	diffs := make(map[byte]int)
	for i := 0; i < 14 && i+2 < len(s); i += 2 {
		a := hexVal(s[i])*16 + hexVal(s[i+1])
		b := hexVal(s[i+2])*16 + hexVal(s[i+3])
		if a < 0 || b < 0 {
			return false
		}
		diff := byte((int(b) - int(a) + 256) % 256)
		diffs[diff]++
	}
	// If most diffs are the same, it's sequential
	for _, count := range diffs {
		if count >= 5 {
			return true
		}
	}
	return false
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// isFakeReference detects placeholder/example reference URLs.
func isFakeReference(ref string) bool {
	r := strings.ToLower(strings.TrimSpace(ref))
	return strings.Contains(r, "example.com") ||
		strings.Contains(r, "example.org") ||
		strings.Contains(r, "example.net") ||
		r == "" ||
		r == "https://" ||
		r == "http://"
}

// validSigmaLevels is the set of valid Sigma rule severity levels.
var validSigmaLevels = map[string]bool{
	"informational": true,
	"low":           true,
	"medium":        true,
	"high":          true,
	"critical":      true,
}

// validLogSourceCategories is the set of common Sigma logsource categories.
var validLogSourceCategories = map[string]bool{
	"process_creation":     true,
	"network_connection":   true,
	"file_event":           true,
	"file_change":          true,
	"file_rename":          true,
	"file_delete":          true,
	"file_access":          true,
	"registry_set":         true,
	"registry_add":         true,
	"registry_delete":      true,
	"registry_event":       true,
	"dns_query":            true,
	"image_load":           true,
	"driver_load":          true,
	"pipe_created":         true,
	"ps_script":            true,
	"ps_module":            true,
	"ps_classic_start":     true,
	"create_remote_thread": true,
	"process_access":       true,
	"create_stream_hash":   true,
	"sysmon_error":         true,
	"wmi_event":            true,
	"clipboard_capture":    true,
	"sysmon_status":        true,
	"firewall":             true,
	"webserver":            true,
	"proxy":                true,
	"antivirus":            true,
}

// Validate parses the raw YAML brief, validates and cleans it, and returns
// the cleaned YAML string, a list of validation notes, and any error.
func (v *BriefValidator) Validate(rawYAML string) (string, []string, error) {
	var brief briefYAML
	if err := yaml.Unmarshal([]byte(rawYAML), &brief); err != nil {
		return "", nil, fmt.Errorf("parsing brief YAML: %w", err)
	}

	var notes []string
	if normalizeBriefProse(&brief) {
		notes = append(notes, "normalized generated prose punctuation")
	}

	// Strip placeholder threat_actor.
	if brief.ThreatActor != "" && isPlaceholder(brief.ThreatActor) {
		notes = append(notes, fmt.Sprintf("stripped placeholder threat_actor: %q", brief.ThreatActor))
		brief.ThreatActor = ""
	}

	// Clean IOCs: remove placeholder and fabricated entries.
	if len(brief.IOCs) > 0 {
		var cleanIOCs []briefIOC
		for _, ioc := range brief.IOCs {
			if isPlaceholder(ioc.Value) {
				notes = append(notes, fmt.Sprintf("removed IOC with placeholder value: %q", ioc.Value))
				continue
			}
			if isFakeIOC(ioc) {
				notes = append(notes, fmt.Sprintf("removed fabricated IOC: type=%s value=%q", ioc.Type, ioc.Value))
				continue
			}
			cleanIOCs = append(cleanIOCs, ioc)
		}
		if len(cleanIOCs) == 0 {
			notes = append(notes, "removed entire iocs section (all entries were fabricated/placeholder)")
			brief.IOCs = nil
		} else {
			brief.IOCs = cleanIOCs
		}
	}

	// Clean references: remove placeholder URLs.
	if len(brief.References) > 0 {
		var cleanRefs []string
		for _, ref := range brief.References {
			if isFakeReference(ref) {
				notes = append(notes, fmt.Sprintf("removed placeholder reference: %q", ref))
				continue
			}
			cleanRefs = append(cleanRefs, ref)
		}
		brief.References = cleanRefs
	}

	// Synchronize every public CVE mention into the structured list. Existing
	// enrichment is retained; newly discovered IDs enter with unknown KEV state
	// until the CVE verifier evaluates them.
	cvesByID := make(map[string]BundleCVE, len(brief.CVEs))
	for _, cve := range brief.CVEs {
		id := strings.ToUpper(strings.TrimSpace(cve.ID))
		if id == "" {
			continue
		}
		cve.ID = id
		if cve.KEV {
			cve.KEVStatus = "true"
		} else if cve.KEVStatus == "" {
			cve.KEVStatus = "unknown"
		}
		cvesByID[id] = cve
	}
	for _, id := range mentionedCVERe.FindAllString(rawYAML, -1) {
		id = strings.ToUpper(id)
		if _, ok := cvesByID[id]; !ok {
			cvesByID[id] = BundleCVE{ID: id, KEVStatus: "unknown"}
		}
	}
	brief.CVEs = make([]BundleCVE, 0, len(cvesByID))
	for _, cve := range cvesByID {
		brief.CVEs = append(brief.CVEs, cve)
	}
	sort.Slice(brief.CVEs, func(i, j int) bool { return brief.CVEs[i].ID < brief.CVEs[j].ID })

	// Validate TTPs.
	if len(brief.TTPs) > 0 {
		var cleanTTPs []briefTTP
		for _, ttp := range brief.TTPs {
			// Check tactic_id.
			if !mitre.ValidTactic(ttp.TacticID) {
				notes = append(notes, fmt.Sprintf("removed TTP with invalid tactic_id: %q", ttp.TacticID))
				continue
			}
			// Check technique_id.
			if !mitre.ValidTechnique(ttp.TechniqueID) {
				notes = append(notes, fmt.Sprintf("removed TTP with invalid technique_id: %q", ttp.TechniqueID))
				continue
			}
			// Check subtechnique_id if present and not a placeholder.
			if ttp.SubtechniqueID != "" && !isPlaceholder(ttp.SubtechniqueID) {
				if !mitre.ValidTechnique(ttp.SubtechniqueID) {
					notes = append(notes, fmt.Sprintf("removed TTP with invalid subtechnique_id: %q", ttp.SubtechniqueID))
					continue
				}
			}

			// Strip placeholder subtechnique fields (YAML null unmarshals to "").
			if ttp.SubtechniqueID != "" && isPlaceholder(ttp.SubtechniqueID) {
				ttp.SubtechniqueID = ""
			}
			if ttp.SubtechniqueName != "" && isPlaceholder(ttp.SubtechniqueName) {
				ttp.SubtechniqueName = ""
			}
			ttp.TacticName = mitre.TacticName(ttp.TacticID)
			ttp.TechniqueName = mitre.TechniqueName(ttp.TechniqueID)
			if ttp.SubtechniqueID != "" {
				ttp.SubtechniqueName = mitre.TechniqueName(ttp.SubtechniqueID)
			}

			// Derive the display band from the LLM-emitted confidence. Done once
			// here so downstream (bundle, threat-feed, platform) never re-derives.
			ttp.ConfidenceBand = confidenceBand(ttp.Confidence)

			cleanTTPs = append(cleanTTPs, ttp)
		}
		brief.TTPs = cleanTTPs
	}

	// Clean affected vendor/product/OS lists: trim, drop placeholders/empties,
	// dedupe case-insensitively.
	brief.AffectedVendors = CleanAffectedList(brief.AffectedVendors)
	brief.AffectedProducts = CleanProductList(brief.AffectedProducts)
	brief.AffectedOS = CleanAffectedList(brief.AffectedOS)
	brief.CPEs = CleanCPEList(brief.CPEs)

	// Validate required brief-level fields (must match feedgen's validateBrief).
	if brief.ID == "" {
		brief.ID = fmt.Sprintf("brief-%s", brief.Slug)
		if brief.ID == "brief-" {
			brief.ID = "brief-unknown"
		}
		notes = append(notes, fmt.Sprintf("added missing id: %q", brief.ID))
	}
	if brief.Slug == "" && brief.ID != "" {
		brief.Slug = strings.TrimPrefix(brief.ID, "brief-")
		notes = append(notes, fmt.Sprintf("added missing slug from id: %q", brief.Slug))
	}

	// Fix slug date prefix: the slug must begin with the actual brief publish date
	// (YYYY-MM-), not the CVE assignment year. LLMs sometimes use the CVE year
	// (e.g., "2024-01-") for a brief published in 2026. Correct it in place so
	// the filename and URL reflect when the brief was written, not when the CVE
	// was assigned.
	if brief.Slug != "" && brief.PublishedAt != "" {
		if t, err := time.Parse(time.RFC3339, brief.PublishedAt); err == nil {
			expectedPrefix := t.Format("2006-01")
			if slugDateRe.MatchString(brief.Slug) {
				actualPrefix := brief.Slug[:7]
				if actualPrefix != expectedPrefix {
					notes = append(notes, fmt.Sprintf("corrected slug date prefix: %q → %q", actualPrefix, expectedPrefix))
					correctedSlug := expectedPrefix + brief.Slug[7:]
					brief.ID = strings.Replace(brief.ID, actualPrefix, expectedPrefix, 1)
					brief.Slug = correctedSlug
				}
			}
		}
	}

	if brief.Title == "" {
		notes = append(notes, "brief is missing required field 'title'")
	}
	if brief.Summary == "" {
		notes = append(notes, "brief is missing required field 'summary'")
	}
	if brief.Severity == "" {
		brief.Severity = "medium"
		notes = append(notes, "added missing severity, defaulted to \"medium\"")
	} else if canon, ok := canonicalSeverity(brief.Severity); ok && canon != brief.Severity {
		notes = append(notes, fmt.Sprintf("normalized severity %q → %q", brief.Severity, canon))
		brief.Severity = canon
	}

	// Downgrade pure-DoS vulnerabilities. Service-crash bugs without privilege
	// escalation, code execution, or auth bypass don't deserve high/critical
	// severity — SOC teams pattern-match on severity and DoS alerts create fatigue.
	if sev := strings.ToLower(brief.Severity); sev == "high" || sev == "critical" {
		if isPureDoS(brief.Title, brief.Summary, brief.Content, brief.Tags) {
			notes = append(notes, fmt.Sprintf("downgraded %s→medium: pure DoS vulnerability without RCE/auth-bypass/privesc signals", sev))
			brief.Severity = "medium"
		}
	}
	if brief.PublishedAt == "" {
		notes = append(notes, "brief is missing required field 'published_at'")
	} else if t, err := time.Parse(time.RFC3339, brief.PublishedAt); err == nil {
		// Clamp future-dated briefs to now (LLMs sometimes hallucinate future dates).
		if t.After(time.Now().Add(24 * time.Hour)) {
			notes = append(notes, fmt.Sprintf("clamped future published_at %q to now", brief.PublishedAt))
			brief.PublishedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}

	if err := normalizeExploitationEvidence(&brief); err != nil {
		return "", notes, err
	}
	if (strings.EqualFold(brief.Severity, "rumour") || brief.ThreatActor != "" || brief.ExploitationEvidence.Status == "confirmed_active") && !hasAttributedSource(brief) {
		return "", notes, fmt.Errorf("brief %q is a threat or rumour without an attributed source URL", brief.ID)
	}
	if strings.EqualFold(brief.Type, "rumour") {
		if err := checkRumourContract(brief); err != nil {
			return "", notes, err
		}
	}

	// Validate Sigma rules — reject non-Sigma (SPL/KQL) rules.
	var validRules []briefRule
	for i := range brief.Rules {
		rule := &brief.Rules[i]

		if rule.Title == "" {
			rule.Title = fmt.Sprintf("Untitled Rule %d", i+1)
			notes = append(notes, fmt.Sprintf("rule[%d]: added missing title", i))
		}

		if isSPLOrKQL(rule) {
			notes = append(notes, fmt.Sprintf("rule %q: rejected — contains SPL/KQL query syntax instead of native Sigma YAML", rule.Title))
			continue
		}

		validateSigmaRule(rule, &notes)
		// validateSigmaRule nils Detection to signal rejection (e.g. missing logsource).
		if rule.Detection == nil {
			continue
		}
		validRules = append(validRules, *rule)
	}
	brief.Rules = validRules

	// Re-serialize to clean YAML.
	out, err := yaml.Marshal(&brief)
	if err != nil {
		return "", nil, fmt.Errorf("serializing cleaned brief: %w", err)
	}

	return string(out), notes, nil
}

// RumourContractError reports a brief typed as a likely rumour that lacks what
// that classification promises. A response schema cannot express the rule, since
// it depends on the brief's type, so it is checked here. Missing names the
// absent pieces; NonProvisional is set when the recommendations are not marked
// provisional.
type RumourContractError struct {
	BriefID        string
	Missing        []string
	NonProvisional bool
}

func (e *RumourContractError) Error() string {
	if len(e.Missing) == 0 && e.NonProvisional {
		return fmt.Sprintf("brief %q has non-provisional rumour recommendations", e.BriefID)
	}
	return fmt.Sprintf("brief %q has an incomplete likely-rumour contract: missing %s", e.BriefID, strings.Join(e.Missing, ", "))
}

// checkRumourContract returns a *RumourContractError when brief, a rumour, does
// not carry the likely-rumour contract: severity rumour, a "likely" source
// assessment, established facts, reported claims, evidence, gaps and an
// unverified notice, with recommendations marked provisional.
func checkRumourContract(brief briefYAML) error {
	var missing []string
	if !strings.EqualFold(brief.Severity, "rumour") {
		missing = append(missing, "severity rumour")
	}
	if brief.SourceAssessment == nil || brief.SourceAssessment.Likelihood != "likely" {
		missing = append(missing, "source_assessment.likelihood likely")
	}
	for _, field := range []struct {
		name string
		n    int
	}{
		{"established_facts", len(brief.EstablishedFacts)},
		{"reported_claims", len(brief.ReportedClaims)},
		{"evidence", len(brief.Evidence)},
		{"gaps", len(brief.Gaps)},
	} {
		if field.n == 0 {
			missing = append(missing, field.name)
		}
	}
	if strings.TrimSpace(brief.UnverifiedNotice) == "" {
		missing = append(missing, "unverified_notice")
	}
	if len(missing) > 0 {
		return &RumourContractError{BriefID: brief.ID, Missing: missing}
	}
	if !strings.Contains(strings.ToLower(brief.Content), "provisional") {
		return &RumourContractError{BriefID: brief.ID, NonProvisional: true}
	}
	return nil
}

func normalizeExploitationEvidence(brief *briefYAML) error {
	if brief.ExploitationEvidence == nil {
		brief.ExploitationEvidence = &ExploitationEvidence{Status: "unknown"}
	}
	evidence := brief.ExploitationEvidence
	evidence.Status = strings.ToLower(strings.TrimSpace(evidence.Status))
	evidence.Confidence = strings.ToLower(strings.TrimSpace(evidence.Confidence))
	if evidence.Status == "" {
		evidence.Status = "unknown"
	}
	switch evidence.Status {
	case "confirmed_active":
		prose := strings.Join([]string{brief.Title, brief.Summary, brief.Content}, "\n")
		if negatedExploitationRe.MatchString(prose) {
			return fmt.Errorf("brief %q confirms active exploitation while its prose negates exploitation", brief.ID)
		}
		if !validSourceURL(evidence.SourceURL) {
			return fmt.Errorf("brief %q confirms active exploitation without a valid source_url", brief.ID)
		}
		if evidence.ObservedAt == "" {
			evidence.ObservedAt = brief.PublishedAt
		}
		observed, err := parseObservedAt(evidence.ObservedAt)
		if err != nil {
			return fmt.Errorf("brief %q has invalid exploitation observed_at: %w", brief.ID, err)
		}
		evidence.ObservedAt = observed
		if evidence.Confidence == "" {
			evidence.Confidence = "medium"
		}
		if evidence.Confidence != "low" && evidence.Confidence != "medium" && evidence.Confidence != "high" {
			return fmt.Errorf("brief %q has invalid exploitation confidence %q", brief.ID, evidence.Confidence)
		}
		brief.Exploited = true
	case "not_observed", "unknown":
		if evidence.Confidence != "" && evidence.Confidence != "low" && evidence.Confidence != "medium" && evidence.Confidence != "high" {
			evidence.Confidence = ""
		}
		brief.Exploited = false
	default:
		return fmt.Errorf("brief %q has invalid exploitation status %q", brief.ID, evidence.Status)
	}
	brief.Exploited = evidence.Status == "confirmed_active"
	if !brief.Exploited {
		filtered := brief.PrioritySignals[:0]
		for _, signal := range brief.PrioritySignals {
			if !strings.EqualFold(strings.TrimSpace(signal), "active_exploitation") {
				filtered = append(filtered, signal)
			}
		}
		brief.PrioritySignals = filtered
	}
	return nil
}

func validSourceURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func hasAttributedSource(brief briefYAML) bool {
	for _, ref := range brief.References {
		if validSourceURL(ref) {
			return true
		}
	}
	return brief.ExploitationEvidence != nil && validSourceURL(brief.ExploitationEvidence.SourceURL)
}

func normalizeBriefProse(brief *briefYAML) bool {
	changed := false
	normalize := func(s *string) {
		if s == nil || *s == "" {
			return
		}
		next := normalizePublicProse(*s)
		if next != *s {
			*s = next
			changed = true
		}
	}

	normalize(&brief.Title)
	normalize(&brief.Summary)
	normalize(&brief.Content)
	if brief.SourceAssessment != nil {
		normalize(&brief.SourceAssessment.Corroboration)
		for i := range brief.SourceAssessment.Flags {
			normalize(&brief.SourceAssessment.Flags[i].Detail)
			normalize(&brief.SourceAssessment.Flags[i].Impact)
		}
		for i := range brief.SourceAssessment.Gaps {
			normalize(&brief.SourceAssessment.Gaps[i])
		}
	}
	if brief.QAStatus != nil {
		for i := range brief.QAStatus.UnsupportedClaims {
			normalize(&brief.QAStatus.UnsupportedClaims[i])
		}
		for i := range brief.QAStatus.FormatGaps {
			normalize(&brief.QAStatus.FormatGaps[i])
		}
		for i := range brief.QAStatus.TechnicalChecks {
			normalize(&brief.QAStatus.TechnicalChecks[i])
		}
		for i := range brief.QAStatus.ManualVerification {
			normalize(&brief.QAStatus.ManualVerification[i])
		}
	}
	if brief.ActionPlan != nil {
		for i := range brief.ActionPlan.ImmediateActions {
			normalize(&brief.ActionPlan.ImmediateActions[i].Action)
			normalize(&brief.ActionPlan.ImmediateActions[i].Evidence)
		}
		for i := range brief.ActionPlan.EnrichmentNeeded {
			normalize(&brief.ActionPlan.EnrichmentNeeded[i].Item)
			normalize(&brief.ActionPlan.EnrichmentNeeded[i].Reason)
			normalize(&brief.ActionPlan.EnrichmentNeeded[i].Evidence)
		}
		for i := range brief.ActionPlan.HuntLeads {
			normalize(&brief.ActionPlan.HuntLeads[i].Lead)
			normalize(&brief.ActionPlan.HuntLeads[i].Evidence)
		}
		for i := range brief.ActionPlan.MitigationPlan {
			normalize(&brief.ActionPlan.MitigationPlan[i].Action)
			normalize(&brief.ActionPlan.MitigationPlan[i].Addresses)
			normalize(&brief.ActionPlan.MitigationPlan[i].Evidence)
		}
		for i := range brief.ActionPlan.Gaps {
			normalize(&brief.ActionPlan.Gaps[i])
		}
	}
	for i := range brief.Rules {
		normalize(&brief.Rules[i].Title)
		normalize(&brief.Rules[i].Description)
		for j := range brief.Rules[i].FalsePositives {
			normalize(&brief.Rules[i].FalsePositives[j])
		}
		for j := range brief.Rules[i].Tests.Positive {
			normalize(&brief.Rules[i].Tests.Positive[j].Name)
		}
		for j := range brief.Rules[i].Tests.Negative {
			normalize(&brief.Rules[i].Tests.Negative[j].Name)
		}
		if brief.Rules[i].Handoff != nil {
			for j := range brief.Rules[i].Handoff.RequiredTelemetry {
				normalize(&brief.Rules[i].Handoff.RequiredTelemetry[j].Notes)
			}
			if brief.Rules[i].Handoff.Validation != nil {
				for j := range brief.Rules[i].Handoff.Validation.Steps {
					normalize(&brief.Rules[i].Handoff.Validation.Steps[j])
				}
				normalize(&brief.Rules[i].Handoff.Validation.ExpectedTelemetry)
				normalize(&brief.Rules[i].Handoff.Validation.PassCriteria)
			}
			for j := range brief.Rules[i].Handoff.KnownEvasions {
				normalize(&brief.Rules[i].Handoff.KnownEvasions[j])
			}
			for j := range brief.Rules[i].Handoff.Limitations {
				normalize(&brief.Rules[i].Handoff.Limitations[j])
			}
			for j := range brief.Rules[i].Handoff.Tuning {
				normalize(&brief.Rules[i].Handoff.Tuning[j].Source)
				normalize(&brief.Rules[i].Handoff.Tuning[j].Guidance)
			}
			for j := range brief.Rules[i].Handoff.PortabilityNotes {
				normalize(&brief.Rules[i].Handoff.PortabilityNotes[j].Note)
			}
			for j := range brief.Rules[i].Handoff.Gaps {
				normalize(&brief.Rules[i].Handoff.Gaps[j])
			}
		}
	}
	for i := range brief.IOCs {
		normalize(&brief.IOCs[i].Context)
		if brief.IOCs[i].Handling != nil {
			normalize(&brief.IOCs[i].Handling.SourceSentence)
			normalize(&brief.IOCs[i].Handling.DetectionNotes)
			normalize(&brief.IOCs[i].Handling.FalsePositiveNotes)
		}
	}
	return changed
}

func normalizePublicProse(s string) string {
	replacer := strings.NewReplacer(
		"—", " - ",
		"–", " - ",
		"‑", "-",
	)
	s = replacer.Replace(s)
	return proseSpaceRe.ReplaceAllString(s, " ")
}

var proseSpaceRe = regexp.MustCompile(`[ \t]{2,}`)

// splKQLPatterns detects SPL/KQL query syntax that should not appear in Sigma rules.
var splKQLPatterns = regexp.MustCompile(`(?i)(?:` +
	`\bindex\s*=` + `|` + // SPL: index=main
	`\bsourcetype\s*=` + `|` + // SPL: sourcetype="..."
	`\|\s*(?:stats|where|table|eval|rex|lookup|dedup|sort|head|tail|rename|fields)\b` + `|` + // SPL pipe commands
	`\|\s*(?:extend|project|summarize|render|join|union|parse|invoke)\b` + `|` + // KQL pipe commands
	`\bdeviceEvents\b` + `|` + // KQL: Defender tables
	`\bSecurityEvent\b` + `)`) // KQL: Sentinel tables

// isSPLOrKQL detects if a rule was generated as SPL/KQL instead of native Sigma.
func isSPLOrKQL(rule *briefRule) bool {
	// If the rule has a raw "query" field, it's definitely not Sigma.
	if rule.Query != "" {
		return true
	}
	// If platform is set to spl/kql, it's not Sigma.
	if rule.Platform == "spl" || rule.Platform == "kql" || rule.Platform == "splunk" || rule.Platform == "kusto" {
		return true
	}
	// Check detection values for SPL/KQL query strings.
	for key, val := range rule.Detection {
		if key == "condition" {
			if s, ok := val.(string); ok && splKQLPatterns.MatchString(s) {
				return true
			}
			continue
		}
		// If a detection "selection" is a raw string (not a map), it's likely SPL.
		if s, ok := val.(string); ok && splKQLPatterns.MatchString(s) {
			return true
		}
	}
	return false
}

// validateSigmaRule validates a single Sigma rule in-place, fixing what it can
// and appending notes for anything it can't.
func validateSigmaRule(rule *briefRule, notes *[]string) {
	// Default missing level.
	if rule.Level == "" {
		rule.Level = "medium"
		*notes = append(*notes, fmt.Sprintf("rule %q: added missing level, defaulted to \"medium\"", rule.Title))
	} else if !validSigmaLevels[strings.ToLower(rule.Level)] {
		*notes = append(*notes, fmt.Sprintf("rule %q: invalid level %q, defaulted to \"medium\"", rule.Title, rule.Level))
		rule.Level = "medium"
	}

	// Reject rules with no logsource (category or service required for conversion).
	if rule.LogSource.Category == "" && rule.LogSource.Service == "" {
		*notes = append(*notes, fmt.Sprintf("rule %q: rejected — missing logsource (no category or service)", rule.Title))
		rule.Detection = nil // signal caller to drop this rule
		return
	}
	if rule.LogSource.Category != "" && !validLogSourceCategories[rule.LogSource.Category] {
		*notes = append(*notes, fmt.Sprintf("rule %q: uncommon logsource category %q", rule.Title, rule.LogSource.Category))
	}

	// Reject rules that are not valid Sigma: every consumer of the feed would
	// get a rule that cannot compile.
	if problems := sigma.Problems(rule.Title, sigma.LogSource(rule.LogSource), rule.Detection); len(problems) > 0 {
		*notes = append(*notes, fmt.Sprintf("rule %q: rejected — invalid Sigma: %s", rule.Title, strings.Join(problems, "; ")))
		rule.Detection = nil // signal caller to drop this rule
		return
	}

	// Validate technique tags.
	var cleanTags []string
	for _, tag := range rule.Tags {
		if strings.HasPrefix(tag, "attack.t") || strings.HasPrefix(tag, "attack.T") {
			tid := strings.ToUpper(tag[7:])
			// Normalize dots in subtechniques: t1059.001 -> T1059.001.
			tid = strings.ReplaceAll(tid, "_", ".")
			if !mitre.ValidTechnique(tid) {
				*notes = append(*notes, fmt.Sprintf("rule %q: removed invalid technique tag %q", rule.Title, tag))
				continue
			}
		}
		cleanTags = append(cleanTags, tag)
	}
	rule.Tags = cleanTags

	// Check test data field alignment against Sigma detection fields.
	baseFields := extractSigmaBaseFields(rule.Detection)
	if len(baseFields) > 0 {
		checkSigmaTestFieldAlignment(rule.Title, baseFields, rule.Tests.Positive, "positive", notes)
		checkSigmaTestFieldAlignment(rule.Title, baseFields, rule.Tests.Negative, "negative", notes)
	}
}

// extractSigmaDetectionFields returns all field keys (including modifiers)
// from Sigma detection selections (excluding "condition").
func extractSigmaDetectionFields(detection map[string]any) []string {
	var fields []string
	for key, val := range detection {
		if key == "condition" {
			continue
		}
		switch v := val.(type) {
		case map[string]any:
			for field := range v {
				fields = append(fields, field)
			}
		case []any:
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					for field := range m {
						fields = append(fields, field)
					}
				}
			}
		}
	}
	return fields
}

// extractSigmaBaseFields returns the set of base field names (before |modifier)
// from all Sigma detection selections.
func extractSigmaBaseFields(detection map[string]any) map[string]bool {
	fields := make(map[string]bool)
	for _, fullField := range extractSigmaDetectionFields(detection) {
		base := strings.SplitN(fullField, "|", 2)[0]
		fields[base] = true
	}
	return fields
}

// checkSigmaTestFieldAlignment checks that test data rows contain at least one
// field that appears in the Sigma detection. Appends a warning note if not.
func checkSigmaTestFieldAlignment(ruleTitle string, detectionFields map[string]bool, tests []briefTestCase, testType string, notes *[]string) {
	for _, tc := range tests {
		for _, row := range tc.Data {
			hasMatch := false
			for field := range row {
				if detectionFields[field] {
					hasMatch = true
					break
				}
			}
			if !hasMatch {
				*notes = append(*notes, fmt.Sprintf(
					"rule %q %s test %q: test data fields do not match any Sigma detection fields",
					ruleTitle, testType, tc.Name,
				))
				break
			}
		}
	}
}

// canonicalSeverity maps vendor severity vocabulary (Microsoft/Red Hat
// "important"/"moderate", numeric CVSS scores) onto the brief severity enum.
// Unknown words are reported as not ok so callers keep the original value and
// the contract check still rejects them.
func canonicalSeverity(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "critical", "high", "medium", "low", "rumour", "informational":
		return s, true
	case "important", "severe":
		return "high", true
	case "moderate":
		return "medium", true
	case "minor", "negligible":
		return "low", true
	case "info", "none":
		return "informational", true
	}
	score, err := strconv.ParseFloat(s, 64)
	if err != nil || score < 0 || score > 10 {
		return "", false
	}
	switch {
	case score >= 9.0:
		return "critical", true
	case score >= 7.0:
		return "high", true
	case score >= 4.0:
		return "medium", true
	case score > 0:
		return "low", true
	}
	return "informational", true
}

// parseObservedAt normalises an exploitation observation time to RFC3339 UTC.
//
// Models give the date at the precision the source has, so besides RFC3339 it
// accepts a date-time without zone (read as UTC), a date (midnight UTC), a
// month ("2026-10") and a year ("2025"). A partial date widens to the first
// instant of its period: the claim is that exploitation was seen in that
// month or year, the start of the period is the conventional expansion of an
// ISO 8601 reduced-precision date, and it never lands after the real
// observation the way an end-of-period guess would. The cost is false
// precision, which is why a reduced-precision date is the only widening
// done; anything else unparseable ("sometime last week", "unknown") is an
// error rather than a guess. A period that has not begun yet (a future month
func parseObservedAt(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty observed_at")
	}
	if _, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return raw, nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02", "2006-01", "2006"} {
		t, err := time.Parse(layout, raw)
		if err != nil {
			continue
		}
		return t.UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("observed_at %q is not RFC3339 or a YYYY-MM-DD, YYYY-MM or YYYY date", raw)
}
