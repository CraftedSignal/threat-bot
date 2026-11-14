// Package publicfeed validates public Markdown briefs and their append-only revisions.
package publicfeed

import (
	"bytes"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/pkg/mitre"
	"gopkg.in/yaml.v3"
)

// Mode controls whether append-only publication metadata is required.
type Mode int

const (
	ModeStrict Mode = iota
	ModeLegacy
)

// Severity is the validation issue severity.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warning"
)

// Issue is a stable, human-readable validation result.
type Issue struct {
	Path     string   `json:"path"`
	Field    string   `json:"field,omitempty"`
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

func issue(path, field, code, message string) Issue {
	return Issue{Path: path, Field: field, Code: code, Severity: SeverityError, Message: message}
}

func sorted(issues []Issue) []Issue {
	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Message < b.Message
	})
	return issues
}

type briefDocument struct {
	Title                string                 `yaml:"title"`
	Description          string                 `yaml:"description"`
	ActionPlan           map[string]any         `yaml:"action_plan"`
	Slug                 string                 `yaml:"slug"`
	BriefID              string                 `yaml:"brief_id"`
	EventID              string                 `yaml:"event_id"`
	Revision             int                    `yaml:"revision"`
	ActivityAt           string                 `yaml:"activity_at"`
	Date                 string                 `yaml:"date"`
	Type                 string                 `yaml:"type"`
	Exploited            bool                   `yaml:"exploited"`
	ExploitationEvidence exploitationEvidence   `yaml:"exploitation_evidence"`
	CVEs                 []briefCVE             `yaml:"cves"`
	TTPs                 []briefTTP             `yaml:"mitre_ttps"`
	References           []string               `yaml:"references"`
	RevisionHistory      []briefRevision        `yaml:"revision_history"`
	SourceAssessment     map[string]interface{} `yaml:"source_assessment"`
	QAStatus             map[string]interface{} `yaml:"qa_status"`
}

type exploitationEvidence struct {
	Status     string `yaml:"status"`
	SourceURL  string `yaml:"source_url"`
	ObservedAt string `yaml:"observed_at"`
	Confidence string `yaml:"confidence"`
}

type briefCVE struct {
	ID        string `yaml:"id"`
	KEVStatus string `yaml:"kev_status"`
}

type briefTTP struct {
	TacticID         string `yaml:"tactic_id"`
	TacticName       string `yaml:"tactic_name"`
	TechniqueID      string `yaml:"technique_id"`
	TechniqueName    string `yaml:"technique_name"`
	SubtechniqueID   string `yaml:"subtechnique_id"`
	SubtechniqueName string `yaml:"subtechnique_name"`
}

type briefRevision struct {
	Revision      int      `yaml:"revision"`
	At            string   `yaml:"at"`
	Checksum      string   `yaml:"checksum"`
	Summary       string   `yaml:"summary"`
	ChangedFields []string `yaml:"changed_fields"`
	SourceURLs    []string `yaml:"source_urls"`
	Maintenance   bool     `yaml:"maintenance"`
}

var (
	frontMatterDelimiter = []byte("---")
	cvePattern           = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)
	checksumPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	activeHTMLPattern    = regexp.MustCompile(`(?is)<\s*(script|iframe|object|embed|form|meta|base|link)\b|<\s*[a-z][^>]*\son[a-z]+\s*=`)
	fencedCodePattern    = regexp.MustCompile("(?s)```.*?```")
	inlineCodePattern    = regexp.MustCompile("`[^`\n]*`")
)

// CheckBrief validates a newly changed public brief using the strict contract.
func CheckBrief(path string, data []byte) []Issue {
	return CheckBriefWithMode(path, data, ModeStrict)
}

// CheckBriefWithMode validates a public brief. Legacy mode skips fields that
// predate append-only publication metadata, but keeps safety checks active.
func CheckBriefWithMode(path string, data []byte, mode Mode) []Issue {
	front, body, ok := splitFrontMatter(data)
	if !ok {
		return []Issue{issue(path, "frontmatter", "brief.frontmatter", "missing or malformed YAML front matter")}
	}
	var brief briefDocument
	if err := yaml.Unmarshal(front, &brief); err != nil {
		return []Issue{issue(path, "frontmatter", "brief.yaml", err.Error())}
	}

	var issues []Issue
	if strings.TrimSpace(brief.Title) == "" || strings.TrimSpace(brief.Slug) == "" {
		issues = append(issues, issue(path, "title/slug", "brief.identity", "title and slug are required"))
	}
	if mode == ModeStrict {
		if brief.BriefID == "" || brief.EventID == "" || brief.Revision < 1 || !validRFC3339(brief.Date) || !validRFC3339(brief.ActivityAt) {
			issues = append(issues, issue(path, "brief_id,event_id,revision,date,activity_at", "brief.identity", "append-only identity fields are required and date/activity_at must be RFC3339"))
		}
		issues = append(issues, checkRevisionHistory(path, brief)...)
		issues = append(issues, checkActivityAt(path, brief)...)
		issues = append(issues, checkExploitation(path, brief)...)
		issues = append(issues, checkAllowedMapFields(path, "source_assessment", brief.SourceAssessment, map[string]bool{
			"reliability": true,
			"credibility": true,
			"rating":      true,
			"likelihood":  true,
		})...)
		issues = append(issues, checkAllowedMapFields(path, "qa_status", brief.QAStatus, map[string]bool{
			"verdict":           true,
			"validation_status": true,
		})...)
		for i, cve := range brief.CVEs {
			if cve.KEVStatus != "true" && cve.KEVStatus != "false" && cve.KEVStatus != "unknown" {
				issues = append(issues, issue(path, fmt.Sprintf("cves[%d].kev_status", i), "brief.kev_status", "kev_status must be true, false, or unknown"))
			}
		}
	}

	declaredCVEs := make(map[string]bool, len(brief.CVEs))
	for _, cve := range brief.CVEs {
		declaredCVEs[strings.ToUpper(cve.ID)] = true
	}
	for _, token := range cvePattern.FindAllString(currentSnapshotText(front, body), -1) {
		if !declaredCVEs[strings.ToUpper(token)] {
			issues = append(issues, issue(path, "cves", "brief.cve_undeclared", strings.ToUpper(token)+" appears in public content but is absent from structured cves"))
		}
	}

	for i, ttp := range brief.TTPs {
		if expected := mitre.TacticName(ttp.TacticID); expected == "" || ttp.TacticName != expected {
			issues = append(issues, issue(path, fmt.Sprintf("mitre_ttps[%d].tactic_name", i), "brief.attack_name", fmt.Sprintf("%s must use canonical name %q", ttp.TacticID, expected)))
		}
		techniqueID, techniqueName := ttp.TechniqueID, ttp.TechniqueName
		if ttp.SubtechniqueID != "" {
			techniqueID, techniqueName = ttp.SubtechniqueID, ttp.SubtechniqueName
		}
		if expected := mitre.TechniqueName(techniqueID); expected == "" || techniqueName != expected {
			issues = append(issues, issue(path, fmt.Sprintf("mitre_ttps[%d].technique_name", i), "brief.attack_name", fmt.Sprintf("%s must use canonical name %q", techniqueID, expected)))
		}
	}

	if (brief.Type == "threat" || brief.Type == "rumour") && len(brief.References) == 0 {
		issues = append(issues, issue(path, "references", "brief.references", brief.Type+" briefs require at least one public source"))
	}
	visibleBody := inlineCodePattern.ReplaceAllString(fencedCodePattern.ReplaceAllString(string(body), ""), "")
	if activeHTMLPattern.MatchString(visibleBody) {
		issues = append(issues, issue(path, "body", "brief.active_html", "active raw HTML is not allowed in public brief content"))
	}
	for _, message := range ContentQualityIssues(ContentQualityInput{Summary: brief.Description, Content: string(body), HasCVE: len(brief.CVEs) > 0 || cvePattern.MatchString(brief.Title+"\n"+brief.Description+"\n"+string(body)), ActionPlan: brief.ActionPlan}) {
		issues = append(issues, issue(path, "body", "brief.quality", message))
	}
	return sorted(issues)
}

// CheckBriefAppendOnly compares a changed brief with its previously published
// form. Shape validation remains the responsibility of CheckBrief; this check
// protects identity and earlier audit entries that cannot be proven from the
// current document alone.
func CheckBriefAppendOnly(path string, previous, current []byte) []Issue {
	previousFront, _, ok := splitFrontMatter(previous)
	if !ok {
		return []Issue{issue(path, "frontmatter", "brief.append_only", "previous brief has missing or malformed YAML front matter")}
	}
	currentFront, _, ok := splitFrontMatter(current)
	if !ok {
		return []Issue{issue(path, "frontmatter", "brief.append_only", "current brief has missing or malformed YAML front matter")}
	}
	var before, after briefDocument
	if err := yaml.Unmarshal(previousFront, &before); err != nil {
		return []Issue{issue(path, "frontmatter", "brief.append_only", "cannot parse previous brief: "+err.Error())}
	}
	if err := yaml.Unmarshal(currentFront, &after); err != nil {
		return []Issue{issue(path, "frontmatter", "brief.append_only", "cannot parse current brief: "+err.Error())}
	}

	var issues []Issue
	immutable := []struct {
		field  string
		before string
		after  string
	}{
		{"brief_id", before.BriefID, after.BriefID},
		{"event_id", before.EventID, after.EventID},
		{"slug", before.Slug, after.Slug},
		{"date", before.Date, after.Date},
	}
	for _, value := range immutable {
		// Legacy briefs may not have the new identity fields. Once present, the
		// strict current-document check requires them and later changes freeze them.
		if value.before != "" && value.before != value.after {
			issues = append(issues, issue(path, value.field, "brief.append_only", value.field+" is immutable after publication"))
		}
	}
	if before.Revision >= 1 && after.Revision <= before.Revision {
		issues = append(issues, issue(path, "revision", "brief.append_only", "a changed brief must advance its revision"))
	}
	historyRewritten := len(after.RevisionHistory) < len(before.RevisionHistory)
	for i := 0; !historyRewritten && i < len(before.RevisionHistory); i++ {
		historyRewritten = !reflect.DeepEqual(after.RevisionHistory[i], before.RevisionHistory[i])
	}
	if historyRewritten {
		issues = append(issues, issue(path, "revision_history", "brief.append_only", "previous revision history entries are immutable and may only be appended"))
	}
	beforeActivity, beforeErr := time.Parse(time.RFC3339, before.ActivityAt)
	afterActivity, afterErr := time.Parse(time.RFC3339, after.ActivityAt)
	if before.Revision >= 1 && beforeErr == nil && afterErr == nil {
		if appendedRevisionsAreMaintenance(before, after) {
			if !afterActivity.Equal(beforeActivity) {
				issues = append(issues, issue(path, "activity_at", "brief.append_only", "a maintenance-only revision must preserve activity_at"))
			}
		} else if !afterActivity.After(beforeActivity) {
			issues = append(issues, issue(path, "activity_at", "brief.append_only", "a material change must advance activity_at"))
		}
	}
	return sorted(issues)
}

func appendedRevisionsAreMaintenance(before, after briefDocument) bool {
	if len(after.RevisionHistory) <= len(before.RevisionHistory) {
		return false
	}
	for _, revision := range after.RevisionHistory[len(before.RevisionHistory):] {
		if !revision.Maintenance {
			return false
		}
	}
	return true
}

func checkAllowedMapFields(path, field string, values map[string]interface{}, allowed map[string]bool) []Issue {
	var issues []Issue
	for key := range values {
		if !allowed[key] {
			issues = append(issues, issue(path, field+"."+key, "brief.redaction", key+" is not part of the redacted public "+field+" contract"))
		}
	}
	return issues
}

// currentSnapshotText returns the public text that the structured cves list
// must cover: the body and every front matter value except revision_history.
// The history records earlier states, so after a correction it still names
// CVEs the brief no longer covers.
func currentSnapshotText(front, body []byte) string {
	var document yaml.Node
	if err := yaml.Unmarshal(front, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return string(front) + "\n" + string(body)
	}
	var text strings.Builder
	var collect func(node *yaml.Node)
	collect = func(node *yaml.Node) {
		switch node.Kind {
		case yaml.ScalarNode:
			text.WriteString(node.Value)
			text.WriteByte('\n')
		case yaml.AliasNode:
			collect(node.Alias)
		}
		for _, child := range node.Content {
			collect(child)
		}
	}
	mapping := document.Content[0]
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "revision_history" {
			continue
		}
		collect(mapping.Content[i])
		collect(mapping.Content[i+1])
	}
	text.Write(body)
	return text.String()
}

func splitFrontMatter(data []byte) ([]byte, []byte, bool) {
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if !bytes.HasPrefix(normalized, append(frontMatterDelimiter, '\n')) {
		return nil, nil, false
	}
	end := bytes.Index(normalized[4:], []byte("\n---\n"))
	if end < 0 {
		return nil, nil, false
	}
	end += 4
	return normalized[4:end], normalized[end+5:], true
}

func validRFC3339(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

func validURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != ""
}

func checkRevisionHistory(path string, brief briefDocument) []Issue {
	if len(brief.RevisionHistory) == 0 {
		if brief.Revision == 1 {
			return nil
		}
		return []Issue{issue(path, "revision_history", "brief.revision_history", "revisions after the initial snapshot require append-only history entries")}
	}
	var issues []Issue
	publishedAt, _ := time.Parse(time.RFC3339, brief.Date)
	if len(brief.RevisionHistory) != brief.Revision-1 {
		issues = append(issues, issue(path, "revision_history", "brief.revision_history", "revision_history must contain exactly revisions 2 through the current revision"))
	}
	var previousAt time.Time
	for i, revision := range brief.RevisionHistory {
		field := fmt.Sprintf("revision_history[%d]", i)
		expected := i + 2
		if revision.Revision != expected {
			issues = append(issues, issue(path, field+".revision", "brief.revision_order", fmt.Sprintf("revision history entry must be revision %d", expected)))
		}
		revisedAt, err := time.Parse(time.RFC3339, revision.At)
		if err != nil {
			issues = append(issues, issue(path, field+".at", "brief.revision_time", "revision timestamp must be RFC3339"))
		} else if !publishedAt.IsZero() && !revisedAt.After(publishedAt) {
			issues = append(issues, issue(path, field+".at", "brief.revision_time", "revision timestamps must be after first publication"))
		} else if !previousAt.IsZero() && !revisedAt.After(previousAt) {
			issues = append(issues, issue(path, field+".at", "brief.revision_time", "revision timestamps must be strictly increasing"))
		} else {
			previousAt = revisedAt
		}
		if !checksumPattern.MatchString(revision.Checksum) {
			issues = append(issues, issue(path, field+".checksum", "brief.revision_checksum", "revision checksum must be sha256:<64 lowercase hex>"))
		}
		if strings.TrimSpace(revision.Summary) == "" || len(revision.ChangedFields) == 0 {
			issues = append(issues, issue(path, field, "brief.revision_detail", "revision summary and changed_fields are required"))
		}
		for j, source := range revision.SourceURLs {
			if !validURL(source) {
				issues = append(issues, issue(path, fmt.Sprintf("%s.source_urls[%d]", field, j), "brief.revision_source", "revision source must be an absolute HTTP(S) URL"))
			}
		}
	}
	if brief.RevisionHistory[len(brief.RevisionHistory)-1].Revision != brief.Revision {
		issues = append(issues, issue(path, "revision_history", "brief.revision_history", "revision_history must end with the current revision"))
	}
	return issues
}

func checkActivityAt(path string, brief briefDocument) []Issue {
	publishedAt, publishedErr := time.Parse(time.RFC3339, brief.Date)
	activityAt, activityErr := time.Parse(time.RFC3339, brief.ActivityAt)
	if publishedErr != nil || activityErr != nil {
		return nil
	}
	expected := publishedAt
	for _, revision := range brief.RevisionHistory {
		if revision.Maintenance {
			continue
		}
		revisedAt, err := time.Parse(time.RFC3339, revision.At)
		if err == nil && revisedAt.After(expected) {
			expected = revisedAt
		}
	}
	if !activityAt.Equal(expected) {
		return []Issue{issue(path, "activity_at", "brief.activity_at", "activity_at must equal the later of first publication and the latest material revision")}
	}
	return nil
}

func checkExploitation(path string, brief briefDocument) []Issue {
	evidence := brief.ExploitationEvidence
	validStatus := evidence.Status == "confirmed_active" || evidence.Status == "not_observed" || evidence.Status == "unknown"
	if !validStatus {
		return []Issue{issue(path, "exploitation_evidence.status", "brief.exploitation", "status must be confirmed_active, not_observed, or unknown")}
	}
	var issues []Issue
	if brief.Exploited != (evidence.Status == "confirmed_active") {
		issues = append(issues, issue(path, "exploited", "brief.exploitation", "legacy exploited must be derived only from confirmed_active"))
	}
	if evidence.Status == "confirmed_active" && !validURL(evidence.SourceURL) {
		issues = append(issues, issue(path, "exploitation_evidence.source_url", "brief.exploitation", "confirmed active exploitation requires a public source URL"))
	} else if evidence.SourceURL != "" && !validURL(evidence.SourceURL) {
		issues = append(issues, issue(path, "exploitation_evidence.source_url", "brief.exploitation", "source_url must be an absolute HTTP(S) URL"))
	}
	if evidence.ObservedAt != "" && !validRFC3339(evidence.ObservedAt) {
		issues = append(issues, issue(path, "exploitation_evidence.observed_at", "brief.exploitation", "observed_at must be RFC3339"))
	}
	if evidence.Confidence != "" && evidence.Confidence != "low" && evidence.Confidence != "medium" && evidence.Confidence != "high" {
		issues = append(issues, issue(path, "exploitation_evidence.confidence", "brief.exploitation", "confidence must be low, medium, or high"))
	}
	return issues
}
