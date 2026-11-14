package publisher

// Public Markdown emitter — produces one .md per brief for the Hugo site at
// threat-feed/site/content/briefs/. The schema is intentionally narrower than
// BundleBrief: rule queries, IOC values, full content body, and priority
// scoring fields are withheld. The emitter is the redaction boundary.
//
// Add a sentinel-string regression test (publisher_markdown_test.go) any time
// a new field is added to BundleBrief, so we catch accidental leakage.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/pkg/mitre"
	feedcontract "github.com/craftedsignal/threat-bot/pkg/publicfeed"
	"gopkg.in/yaml.v3"
)

// backfillSleep paces backfill PUTs so 1500+ briefs don't blow the 5000/h
// GitHub API budget. 500ms × ~3000 calls (GET SHA + PUT per brief) ≈ 25 min.
const backfillSleep = 500 * time.Millisecond

// genericCVERe matches a CVE identifier in a brief's text. Used by
// isGenericCVEBundleBrief and isPlaceholderCVEBrief.
var genericCVERe = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// isGenericCVEBundleBrief returns true when the brief mentions a CVE
// but neither affected_vendors nor affected_products lists a real
// entry. Without one of those, defenders have nothing to scope a
// detection rule to or to patch.
func isGenericCVEBundleBrief(b BundleBrief) bool {
	if !genericCVERe.MatchString(b.Title) && !genericCVERe.MatchString(b.Summary) {
		return false
	}
	if hasMeaningfulString(b.AffectedVendors) || hasMeaningfulString(b.AffectedProducts) {
		return false
	}
	return true
}

// boilerplateCVEPhrases are LLM telltale strings produced when a CVE has no
// real public detail yet. The model generates generic placeholder prose rather
// than leave fields empty — these phrases identify that state.
var boilerplateCVEPhrases = []string{
	"details are currently unavailable",
	"details remain unavailable",
	"details are limited",
	"detailed information regarding the nature of the vulnerability",
	"information is not available",
	"requires further investigation upon release of additional information",
	"at the time of this publication, detailed information",
	"nature of the vulnerability, affected products, and potential impact remains unavailable",
}

// isPlaceholderCVEBrief returns true when a CVE-tagged brief contains only
// LLM-generated boilerplate because the CVE had no public detail at ingest
// time. These briefs are unactionable and are suppressed until the pipeline
// re-ingests richer content.
func isPlaceholderCVEBrief(b BundleBrief) bool {
	if !genericCVERe.MatchString(b.Title) && !genericCVERe.MatchString(b.Summary) {
		return false
	}
	combined := strings.ToLower(b.Summary + " " + b.Content)
	for _, phrase := range boilerplateCVEPhrases {
		if strings.Contains(combined, phrase) {
			return true
		}
	}
	return false
}

// placeholderStrings are values the pipeline/LLM emits in place of a real
// vendor/product/etc. when it doesn't know one, rather than leaving the
// field empty. Treated as "no data" everywhere in this package.
var placeholderStrings = map[string]bool{
	"": true, "unknown": true, "n/a": true, "tbd": true,
	"none": true, "null": true, "na": true, "unspecified": true,
}

// isPlaceholderValue reports whether s is a known placeholder (after
// trimming and case-folding) rather than a real value.
func isPlaceholderValue(s string) bool {
	return placeholderStrings[strings.ToLower(strings.TrimSpace(s))]
}

func hasMeaningfulString(items []string) bool {
	for _, raw := range items {
		if !isPlaceholderValue(raw) {
			return true
		}
	}
	return false
}

// maxPublishAttempts caps the per-brief retry loop in publishBriefMarkdown.
// Retries fire only on 409 SHA-conflict, which happens when concurrent
// writers (live scraper + backfill) race on the same file.
const maxPublishAttempts = 3

const publishRetryDelay = 500 * time.Millisecond

const publicMarkdownDir = "site/content/briefs/"

// publicBriefFrontmatter is the redacted view of a brief that appears on the
// public Hugo site. Field tags MUST match the keys used by the site's layouts
// and existing sample briefs (see threat-feed/site/content/briefs/*.md).
type publicBriefFrontmatter struct {
	BriefID              string                      `yaml:"brief_id"`
	EventID              string                      `yaml:"event_id"`
	Revision             int                         `yaml:"revision"`
	ActivityAt           string                      `yaml:"activity_at"`
	RevisionHistory      []BundleRevision            `yaml:"revision_history,omitempty"`
	Title                string                      `yaml:"title"`
	Slug                 string                      `yaml:"slug"`
	Description          string                      `yaml:"description,omitempty"`
	Date                 string                      `yaml:"date"`
	Lastmod              string                      `yaml:"lastmod,omitempty"`
	Type                 string                      `yaml:"type"`
	ClaimState           string                      `yaml:"claim_state,omitempty"`
	StatusNotice         string                      `yaml:"status_notice,omitempty"`
	Types                []string                    `yaml:"types,omitempty"` // taxonomy mirror of Type
	Severities           []string                    `yaml:"severities"`
	Actors               []string                    `yaml:"actors,omitempty"`
	Exploited            bool                        `yaml:"exploited,omitempty"`
	ExploitationEvidence *BundleExploitationEvidence `yaml:"exploitation_evidence"`
	SourceAssessment     *publicSourceAssessment     `yaml:"source_assessment,omitempty"`
	QAStatus             *publicQAStatus             `yaml:"qa_status,omitempty"`
	CPEs                 []string                    `yaml:"cpes,omitempty"`
	HasPOC               bool                        `yaml:"has_poc,omitempty"`
	PocReferences        []string                    `yaml:"poc_references,omitempty"`
	Tags                 []string                    `yaml:"tags,omitempty"`
	Vendors              []string                    `yaml:"vendors,omitempty"`
	Products             []string                    `yaml:"products,omitempty"`
	ProductVersions      []publicProductVersion      `yaml:"product_versions,omitempty"`
	AffectedOS           []string                    `yaml:"affected_os,omitempty"`
	MitreTTPs            []publicTTP                 `yaml:"mitre_ttps,omitempty"`
	CVEs                 []publicCVE                 `yaml:"cves,omitempty"`
	References           []string                    `yaml:"references,omitempty"`
	IOCs                 []publicIOC                 `yaml:"iocs,omitempty"`
	IOCCounts            map[string]int              `yaml:"ioc_counts,omitempty"`
	Rules                []publicRule                `yaml:"rules,omitempty"`
	RulesCount           int                         `yaml:"rules_count,omitempty"`
	ActionPlan           *BundleActionPlan           `yaml:"action_plan,omitempty"`
	Updates              []publicUpdate              `yaml:"updates,omitempty"`
}

// publicProductVersion keeps the affected product's queryable canonical name
// separate from its source-provided version scope.
type publicProductVersion struct {
	Product string `yaml:"product"`
	Range   string `yaml:"range"`
}

type publicSourceAssessment struct {
	Reliability string `yaml:"reliability,omitempty"`
	Credibility string `yaml:"credibility,omitempty"`
	Rating      string `yaml:"rating,omitempty"`
	Likelihood  string `yaml:"likelihood,omitempty"`
}

type publicQAStatus struct {
	Verdict          string `yaml:"verdict,omitempty"`
	ValidationStatus string `yaml:"validation_status,omitempty"`
}

// publicUpdate is the frontmatter projection of a storage.UpdateEvent —
// rendered by Hugo into the "What's new" bar on detail pages.
type publicUpdate struct {
	At         string   `yaml:"at"`
	Level      string   `yaml:"level"`
	Summary    string   `yaml:"summary"`
	Sources    []string `yaml:"sources,omitempty"`
	SourceURLs []string `yaml:"source_urls,omitempty"`
}

// publicIOC publishes the indicator's type and value. Confidence is internal
// scoring metadata and stays withheld.
type publicIOC struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

type publicTTP struct {
	TacticID         string `yaml:"tactic_id"`
	TacticName       string `yaml:"tactic_name"`
	TechniqueID      string `yaml:"technique_id"`
	TechniqueName    string `yaml:"technique_name"`
	SubtechniqueID   string `yaml:"subtechnique_id,omitempty"`
	SubtechniqueName string `yaml:"subtechnique_name,omitempty"`
	// Evidence (a quote from the already-public source) and the derived band
	// are published; the raw Confidence float stays internal (cf. publicIOC).
	Evidence       string `yaml:"evidence,omitempty"`
	ConfidenceBand string `yaml:"confidence_band,omitempty"`
}

type publicCVE struct {
	ID        string  `yaml:"id"`
	Product   string  `yaml:"product,omitempty"`
	CVSS      float64 `yaml:"cvss,omitempty"`
	EPSS      float64 `yaml:"epss,omitempty"`
	KEV       bool    `yaml:"kev,omitempty"`
	KEVStatus string  `yaml:"kev_status"`
}

// publicRule omits Detection (the query) and Tests (sample TTP data).
// These are the operationally valuable fields and stay inside the platform.
type publicRule struct {
	Title       string   `yaml:"title"`
	Description string   `yaml:"description,omitempty"`
	Platform    string   `yaml:"platform"`
	Severity    string   `yaml:"severity,omitempty"`
	Tactics     []string `yaml:"tactics,omitempty"`
	Techniques  []string `yaml:"techniques,omitempty"`
	DataSources []string `yaml:"data_sources,omitempty"`
}

// defangMarkdownBody neutralizes raw HTML in the prose of a Markdown body so
// that, even with goldmark unsafe rendering enabled on the public site, an
// attacker payload quoted in a brief (e.g. <script>, <img onerror=…>) renders
// as inert, visible text instead of executing. Code is left verbatim (defanging
// it would display a literal "&lt;"): fenced blocks (``` / ~~~), indented code
// (4 spaces or a tab), and inline `code` spans are preserved. On unbalanced
// inline backticks it errs toward defanging — under-defanging is a security
// hole, over-defanging is only a cosmetic entity in a rare code sample.
func defangMarkdownBody(md string) string {
	lines := strings.Split(md, "\n")
	inFence := false
	fenceMarker := ""
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if inFence {
			if strings.HasPrefix(trimmed, fenceMarker) {
				inFence = false
			}
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "```"):
			inFence, fenceMarker = true, "```"
		case strings.HasPrefix(trimmed, "~~~"):
			inFence, fenceMarker = true, "~~~"
		case strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t"):
			// indented code block — leave verbatim
		default:
			lines[i] = defangLineOutsideInlineCode(line)
		}
	}
	return strings.Join(lines, "\n")
}

// defangLineOutsideInlineCode applies defangHTML to the parts of a line that are
// not inside `inline code` spans. Unbalanced backticks are ambiguous, so the
// whole line is defanged rather than risk leaving a payload verbatim.
func defangLineOutsideInlineCode(line string) string {
	if strings.Count(line, "`")%2 != 0 {
		return defangHTML(line)
	}
	var b strings.Builder
	inCode := false
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '`' {
			if seg := line[start:i]; inCode {
				b.WriteString(seg)
			} else {
				b.WriteString(defangHTML(seg))
			}
			b.WriteByte('`')
			inCode = !inCode
			start = i + 1
		}
	}
	b.WriteString(defangHTML(line[start:]))
	return b.String()
}

// briefToMarkdown converts a BundleBrief to its public Markdown representation.
// The output is `---\n<yaml>\n---\n\n<first paragraph>\n`.
// siteTerms caps taxonomy terms the site builds a page for, dropping terms
// that become duplicates (vendors and products are capped when cleaned).
func siteTerms(terms []string) []string {
	var out []string
	for _, term := range terms {
		term = pipeline.CapTerm(strings.TrimSpace(term))
		if term != "" && !slices.Contains(out, term) {
			out = append(out, term)
		}
	}
	return out
}

func briefToMarkdown(b BundleBrief) ([]byte, error) {
	b = NormalizePublicationMetadata(b)
	briefType := classifyType(b)
	evidence := publicExploitationEvidence(b)
	// Lists are cleaned again here: backfills re-emit stored segment briefs
	// that never passed through ParseBriefYAML.
	fm := publicBriefFrontmatter{
		BriefID:              b.ID,
		EventID:              b.EventID,
		Revision:             b.Revision,
		ActivityAt:           briefActivityAt(b),
		RevisionHistory:      append([]BundleRevision(nil), b.RevisionHistory...),
		Title:                b.Title,
		Slug:                 strings.ToLower(firstNonEmpty(b.Slug, b.ID)),
		Description:          b.Summary,
		Date:                 b.PublishedAt,
		Lastmod:              b.Lastmod,
		Type:                 briefType,
		ClaimState:           b.ClaimState,
		Types:                []string{briefType},
		Severities:           []string{firstNonEmpty(b.Severity, "medium")},
		Tags:                 siteTerms(b.Tags),
		Vendors:              canonicalTextList(pipeline.CleanAffectedList(b.AffectedVendors)),
		Products:             canonicalProductProjection(b.AffectedProducts),
		ProductVersions:      productVersionProjection(b.AffectedProducts),
		AffectedOS:           pipeline.CleanAffectedList(b.AffectedOS),
		References:           b.References,
		CPEs:                 pipeline.CleanCPEList(b.CPEs),
		Exploited:            evidence.Status == "confirmed_active",
		ExploitationEvidence: evidence,
		SourceAssessment:     publicSourceAssessmentFor(b.SourceAssessment),
		QAStatus:             publicQAStatusFor(b.QAStatus),
		HasPOC:               b.HasPOC,
		PocReferences:        b.PocReferences,
		MitreTTPs:            convertTTPs(b.TTPs),
		CVEs:                 convertCVEs(b.CVEs),
		Updates:              convertUpdates(b.UpdateLog),
		IOCs:                 convertIOCs(b.IOCs),
		IOCCounts:            countIOCs(b.IOCs),
		Rules:                convertRules(b.Rules),
		RulesCount:           len(b.Rules),
		ActionPlan:           b.ActionPlan,
	}
	if actors := cleanActors(b.ThreatActor); len(actors) > 0 {
		fm.Actors = siteTerms(actors)
	}
	if state := strings.ToLower(b.ClaimState); state == "disputed" || state == "retracted" {
		fm.StatusNotice = "This report is " + state + " and is retained for historical context. Do not act on its original recommendations."
	}

	body := defangMarkdownBody(stripLeadingHeadings(b.Content))
	if fm.StatusNotice != "" {
		body = "> **Status: " + strings.ToUpper(b.ClaimState) + "** — " + fm.StatusNotice + "\n\n## Replacement recommendation\n\nPreserve relevant telemetry, reverse any claim-specific blocking or escalation, and follow the cited correction.\n\n" + body
	}
	// The revision history records earlier states and may name CVEs a later
	// correction removed, so only the current snapshot completes the list.
	current := fm
	current.RevisionHistory = nil
	currentFrontmatter, err := yaml.Marshal(current)
	if err != nil {
		return nil, fmt.Errorf("marshalling provisional frontmatter: %w", err)
	}
	fm.CVEs = convertCVEs(completePublicCVEs(b.CVEs, string(currentFrontmatter)+"\n"+body))

	var fmBuf bytes.Buffer
	enc := yaml.NewEncoder(&fmBuf)
	enc.SetIndent(2)
	if err := enc.Encode(fm); err != nil {
		return nil, fmt.Errorf("marshalling frontmatter: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("closing yaml encoder: %w", err)
	}

	var out bytes.Buffer
	out.WriteString("---\n")
	out.Write(fmBuf.Bytes())
	out.WriteString("---\n")
	if body != "" {
		out.WriteString("\n")
		out.WriteString(body)
		out.WriteString("\n")
	}
	return out.Bytes(), nil
}

func briefActivityAt(b BundleBrief) string {
	activity := b.PublishedAt
	activityAt, _ := time.Parse(time.RFC3339Nano, activity)
	consider := func(raw string) {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err == nil && parsed.After(activityAt) {
			activity, activityAt = raw, parsed
		}
	}
	for _, revision := range b.RevisionHistory {
		if revision.Maintenance {
			continue
		}
		consider(revision.At)
	}
	return activity
}

func publicExploitationEvidence(b BundleBrief) *BundleExploitationEvidence {
	if b.ExploitationEvidence != nil {
		copy := *b.ExploitationEvidence
		if copy.Status == "" {
			copy.Status = "unknown"
		}
		return &copy
	}
	evidence := &BundleExploitationEvidence{Status: "unknown"}
	return evidence
}

func publicSourceAssessmentFor(in *BundleSourceAssessment) *publicSourceAssessment {
	if in == nil {
		return nil
	}
	return &publicSourceAssessment{
		Reliability: in.Reliability, Credibility: in.Credibility, Rating: in.Rating,
		Likelihood: in.Likelihood,
	}
}

func publicQAStatusFor(in *BundleQAStatus) *publicQAStatus {
	if in == nil {
		return nil
	}
	return &publicQAStatus{Verdict: in.Verdict, ValidationStatus: in.ValidationStatus}
}

// publicMarkdownPath returns the repo-relative path for a brief's Markdown file.
// The slug is lowercased before joining: GitHub's filesystem is
// case-sensitive but Apple HFS+/APFS is not, so a brief published as
// "Charlotte-AI-AgentWorks" and one published as
// "charlotte-ai-agentworks" land as two separate files in the repo
// but as one phantom-modified entry on every Mac developer's clone.
// Normalising at write time keeps the repo case-consistent.
func publicMarkdownPath(b BundleBrief) string {
	return publicMarkdownDir + strings.ToLower(firstNonEmpty(b.Slug, b.ID)) + ".md"
}

// RenderPublicBriefMarkdown applies the same redaction, suppression, and
// existing-identity checks as the live publisher without performing I/O. It
// supports atomic repository migrations that rebuild many pages in one Git
// commit instead of one Contents API commit per brief.
func RenderPublicBriefMarkdown(b BundleBrief, existing []byte) (path string, content []byte, rendered BundleBrief, publish bool, err error) {
	path = publicMarkdownPath(b)
	if isGenericCVEBundleBrief(b) || isPlaceholderCVEBrief(b) {
		return path, nil, b, false, nil
	}
	if err := validatePublicSourceReferences(b); err != nil {
		return path, nil, b, false, err
	}
	b, err = preserveExistingPublicIdentity(b, existing)
	if err != nil {
		return path, nil, b, false, err
	}
	content, err = briefToMarkdown(b)
	if err != nil {
		return path, nil, b, false, err
	}
	issues := feedcontract.CheckBrief(path, content)
	if len(existing) > 0 && !bytes.Equal(existing, content) {
		issues = append(issues, feedcontract.CheckBriefAppendOnly(path, existing, content)...)
	}
	if len(issues) > 0 {
		return path, nil, b, false, fmt.Errorf("public feed contract %s: %s", issues[0].Code, issues[0].Message)
	}
	return path, content, b, true, nil
}

type existingPublicIdentity struct {
	BriefID    string `yaml:"brief_id"`
	EventID    string `yaml:"event_id"`
	Date       string `yaml:"date"`
	Lastmod    string `yaml:"lastmod"`
	ActivityAt string `yaml:"activity_at"`
}

// preserveExistingPublicIdentity keeps the first public timestamp immutable
// when a legacy path is adopted by the append-only publisher. A later incoming
// publication timestamp becomes activity/last-modified time. Existing identity
// fields, when present, must still match the canonical bundle identity.
func preserveExistingPublicIdentity(incoming BundleBrief, existing []byte) (BundleBrief, error) {
	if len(existing) == 0 {
		return incoming, nil
	}
	if !bytes.HasPrefix(existing, []byte("---\n")) {
		return incoming, fmt.Errorf("existing public brief has no YAML frontmatter")
	}
	end := bytes.Index(existing[4:], []byte("\n---"))
	if end < 0 {
		return incoming, fmt.Errorf("existing public brief has unterminated YAML frontmatter")
	}
	var current existingPublicIdentity
	if err := yaml.Unmarshal(existing[4:4+end], &current); err != nil {
		return incoming, fmt.Errorf("decoding existing public identity: %w", err)
	}
	normalized := NormalizePublicationMetadata(incoming)
	if current.BriefID != "" && current.BriefID != normalized.ID {
		return incoming, fmt.Errorf("public path belongs to brief_id %q, not %q", current.BriefID, normalized.ID)
	}
	if current.EventID != "" && current.EventID != normalized.EventID {
		return incoming, fmt.Errorf("public path belongs to event_id %q, not %q", current.EventID, normalized.EventID)
	}
	if _, err := time.Parse(time.RFC3339Nano, current.Date); err != nil {
		return incoming, fmt.Errorf("existing public date %q is not RFC3339: %w", current.Date, err)
	}
	normalized.PublishedAt = current.Date
	return normalized, nil
}

// putMarkdownFile uploads raw bytes to the GitHub Contents API.
func (p *Publisher) putMarkdownFile(path string, content []byte, sha, message string) error {
	if p.publication != nil {
		_, err := p.stageGitFile(path, content)
		return err
	}
	payload, err := p.contentsPayload(message, sha, len(content), writeBytes(content))
	if err != nil {
		return err
	}

	return p.putContentsWithRetry(context.Background(), path, payload, "putMarkdownFile")
}

// BackfillMarkdown emits public Markdown for every brief in every encrypted
// segment. One-shot. Idempotent — re-running after a partial failure is safe
// because publishBriefMarkdown re-fetches the file SHA before each PUT.
//
// Paced with a 500ms sleep between briefs to stay under the GitHub API rate
// limit. 1500 briefs × 2 calls each × 500ms ≈ 25 minutes.
func (p *Publisher) BackfillMarkdown() error {
	return p.BackfillMarkdownSlugs(nil)
}

type backfillSelection struct {
	all     bool
	wanted  map[string]struct{}
	matched map[string]struct{}
}

func newBackfillSelection(values []string) *backfillSelection {
	selection := &backfillSelection{
		wanted:  make(map[string]struct{}),
		matched: make(map[string]struct{}),
	}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			selection.wanted[value] = struct{}{}
		}
	}
	selection.all = len(selection.wanted) == 0
	return selection
}

func (s *backfillSelection) matches(brief BundleBrief) bool {
	if s.all {
		return true
	}
	matched := false
	for _, value := range []string{brief.ID, brief.Slug} {
		value = strings.ToLower(strings.TrimSpace(value))
		if _, ok := s.wanted[value]; ok {
			s.matched[value] = struct{}{}
			matched = true
		}
	}
	return matched
}

func (s *backfillSelection) missing() []string {
	var missing []string
	for value := range s.wanted {
		if _, ok := s.matched[value]; !ok {
			missing = append(missing, value)
		}
	}
	sort.Strings(missing)
	return missing
}

// BackfillMarkdownSlugs performs the same idempotent reconciliation as
// BackfillMarkdown, limited to the requested slugs or immutable brief IDs.
// An empty selection keeps the original full-corpus behavior.
func (p *Publisher) BackfillMarkdownSlugs(slugs []string) error {
	selection := newBackfillSelection(slugs)
	entries, err := p.listDir("output/briefs")
	if err != nil {
		return fmt.Errorf("listing briefs dir: %w", err)
	}
	sort.Strings(entries)

	totalSuccess, totalFail := 0, 0
	for _, name := range entries {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		segPath := "output/briefs/" + name
		raw, _, fetchErr := p.fetchJSONFile(segPath)
		if fetchErr != nil || raw == nil {
			p.logger.Warn("skipping unreadable segment", "file", name, "err", fetchErr)
			continue
		}
		var enc BundleManifest
		if jsonErr := json.Unmarshal(raw, &enc); jsonErr != nil {
			p.logger.Warn("skipping non-manifest segment", "file", name)
			continue
		}
		seg, decErr := DecryptSegment(&enc, p.publicKey)
		if decErr != nil {
			p.logger.Warn("skipping undecryptable segment", "file", name, "err", decErr)
			continue
		}

		segSuccess, segFail := 0, 0
		for _, brief := range seg.Briefs {
			if !selection.matches(brief) {
				continue
			}
			if err := p.publishBriefMarkdown(brief); err != nil {
				p.logger.Error("backfill: brief failed", "brief", brief.ID, "err", err)
				segFail++
			} else {
				segSuccess++
			}
			time.Sleep(backfillSleep)
		}
		p.logger.Info("backfill segment done", "file", name, "success", segSuccess, "failed", segFail)
		totalSuccess += segSuccess
		totalFail += segFail
	}
	p.logger.Info("backfill complete", "success", totalSuccess, "failed", totalFail)
	if missing := selection.missing(); len(missing) > 0 {
		return fmt.Errorf("requested briefs were not found: %s", strings.Join(missing, ", "))
	}
	if totalFail > 0 {
		return fmt.Errorf("%d brief(s) failed to backfill (see logs); rerun is safe", totalFail)
	}
	return nil
}

// CheckDriftMarkdown compares the bundle's view of every brief against
// the public Markdown file published for it. Returns a list of
// human-readable drift descriptions (one per mismatch). Uses the same
// segment-iteration pattern as BackfillMarkdown but never writes —
// only reads, hashes, and compares. Suitable for a daily reconciliation
// cron.
type DriftEntry struct {
	BriefID string
	Path    string
	Reason  string // "missing", "stale-content", "unreadable", "skipped-generic"
}

func (p *Publisher) CheckDriftMarkdown() ([]DriftEntry, error) {
	entries, err := p.listDir("output/briefs")
	if err != nil {
		return nil, fmt.Errorf("listing briefs dir: %w", err)
	}
	sort.Strings(entries)

	var drift []DriftEntry
	for _, name := range entries {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, _, fetchErr := p.fetchJSONFile("output/briefs/" + name)
		if fetchErr != nil || raw == nil {
			continue
		}
		var enc BundleManifest
		if err := json.Unmarshal(raw, &enc); err != nil {
			continue
		}
		seg, err := DecryptSegment(&enc, p.publicKey)
		if err != nil {
			continue
		}
		for _, brief := range seg.Briefs {
			if isGenericCVEBundleBrief(brief) || isPlaceholderCVEBrief(brief) {
				continue // intentionally not published; not drift
			}
			path := publicMarkdownPath(brief)
			expected, err := briefToMarkdown(brief)
			if err != nil {
				drift = append(drift, DriftEntry{BriefID: brief.ID, Path: path, Reason: "render-failed: " + err.Error()})
				continue
			}
			expectedSHA := gitBlobSHA(expected)
			actualSHA, err := p.getFileSHA(path)
			if err != nil {
				drift = append(drift, DriftEntry{BriefID: brief.ID, Path: path, Reason: "unreadable: " + err.Error()})
				continue
			}
			if actualSHA == "" {
				drift = append(drift, DriftEntry{BriefID: brief.ID, Path: path, Reason: "missing"})
				continue
			}
			if actualSHA != expectedSHA {
				drift = append(drift, DriftEntry{BriefID: brief.ID, Path: path, Reason: "stale-content"})
			}
		}
		p.logger.Info("drift segment done", "file", name)
	}
	return drift, nil
}

// publishBriefMarkdown writes one brief's public Markdown file. Idempotent:
// fetches the current SHA so re-emission overwrites in place.
//
// Retries up to maxPublishAttempts on 409 (stale SHA — happens when the live
// scraper races with the backfill on the same path). Each retry re-fetches
// the SHA so the conflict resolves naturally.
func (p *Publisher) publishBriefMarkdown(b BundleBrief) error {
	// Suppress briefs that mention a CVE but never identified a vendor
	// or product. They render as "Unauthenticated remote access via
	// unsecured configuration interface (CVE-…)" — accurate but
	// unactionable. The pipeline rejects new ones at the quality gate;
	// this guard catches stragglers from older bundles when backfill
	// re-runs and stops them being re-emitted.
	if isGenericCVEBundleBrief(b) {
		p.logger.Info("skipping generic CVE brief (no affected vendor/product)", "brief", b.ID)
		return nil
	}
	// Suppress CVE briefs that contain only LLM-generated placeholder prose
	// ("details are currently unavailable"). These are published when the CVE
	// drops but NVD/vendor have not released real detail yet. The pipeline
	// will re-ingest and publish once richer content is available.
	if isPlaceholderCVEBrief(b) {
		p.logger.Info("skipping placeholder CVE brief (no real detail yet)", "brief", b.ID)
		return nil
	}
	if err := validatePublicSourceReferences(b); err != nil {
		return err
	}
	path := publicMarkdownPath(b)
	msg := fmt.Sprintf("chore(public): update %s", firstNonEmpty(b.Slug, b.ID))

	var lastErr error
	for attempt := 1; attempt <= maxPublishAttempts; attempt++ {
		existing, sha, fetchErr := p.fetchJSONFile(path)
		if fetchErr != nil {
			lastErr = fmt.Errorf("fetching %s: %w", path, fetchErr)
			p.logger.Warn("markdown publish: existing file lookup failed, retrying", "path", path, "attempt", attempt, "error", fetchErr)
			if attempt < maxPublishAttempts {
				time.Sleep(publishRetryDelay)
			}
			continue
		}
		_, md, rendered, publish, renderErr := RenderPublicBriefMarkdown(b, existing)
		if renderErr != nil {
			return fmt.Errorf("reconciling %s: %w", path, renderErr)
		}
		if !publish {
			return nil
		}
		// Backfill skip-when-complete: a Git blob SHA only depends on
		// the file's bytes, so if the existing object's hash matches
		// the hash of the bytes we are about to write, the PUT would
		// be a no-op commit. Skip it. Saves the API call, the commit,
		// and (for backfill runs) one Site Deploy trigger.
		if sha != "" && sha == gitBlobSHA(md) {
			return nil
		}
		err := p.putMarkdownFile(path, md, sha, msg)
		if err == nil {
			p.afterPublicationCommit(func() { p.notePublicBriefPushed(rendered, time.Now()) })
			return nil
		}
		lastErr = err
		// Retry on 409 (stale SHA) and on 422 sha-missing: the contents API
		// is eventually consistent under commit churn, so the SHA lookup can
		// 404 while the file exists and the create-PUT bounces. Other errors
		// aren't transient.
		shaMissing422 := strings.Contains(err.Error(), "HTTP 422") && strings.Contains(err.Error(), "sha")
		if !strings.Contains(err.Error(), "HTTP 409") && !shaMissing422 {
			return fmt.Errorf("pushing %s: %w", path, err)
		}
		if attempt < maxPublishAttempts {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
	}
	return fmt.Errorf("pushing %s after %d attempts: %w", path, maxPublishAttempts, lastErr)
}

func validatePublicSourceReferences(b BundleBrief) error {
	briefType := classifyType(b)
	if briefType != "threat" && briefType != "rumour" {
		return nil
	}
	for _, raw := range b.References {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			return nil
		}
	}
	return fmt.Errorf("public %s brief %q has no attributed source URL", briefType, b.ID)
}

// gitBlobSHA returns the SHA-1 hex digest Git uses for an object of the
// given bytes. Git blobs are hashed as `"blob " + len + "\x00" + content`.
// We use this to short-circuit no-op PUTs in publishBriefMarkdown.
func gitBlobSHA(content []byte) string {
	h := sha1.New()
	// hash.Hash writes cannot fail.
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Helpers

// ruleFeedSources is the set of upstream sources that publish detection
// rules as their primary content. Briefs originating here are about a
// rule, not a vulnerability — so they're the only ones that should
// render as "Rule" on the public site. Everything else (vendor PSIRTs,
// CERTs, news, vuln databases, vendor research blogs) is treated as a
// vulnerability writeup even if the brief assembler synthesized a Sigma
// rule for it.
var ruleFeedSources = map[string]struct{}{
	"sigma-hq":    {},
	"sigma_hq":    {},
	"elastic":     {},
	"splunk-escu": {},
	"splunk_escu": {},
}

// threatIntelSources is the set of upstream sources whose primary output is
// threat actor campaign analysis, APT research, and malware investigations
// (as opposed to CVE advisories or product marketing). Briefs from these
// sources with a named actor or structured TTP coverage are classified as
// "threat" regardless of severity — a surveillance campaign at medium
// severity is still a threat to defenders.
var threatIntelSources = map[string]struct{}{
	"securelist":               {},
	"mandiant":                 {},
	"unit42":                   {},
	"volexity":                 {},
	"dfir-report":              {},
	"google-tag":               {},
	"eset":                     {},
	"sentinelone-labs":         {},
	"talos":                    {},
	"microsoft-threat-intel":   {},
	"recorded-future":          {},
	"any-run":                  {},
	"objective-see":            {},
	"malware-traffic-analysis": {},
}

// classifyType returns one of "threat" | "coverage" | "advisory" | "rumour"
// describing what KIND of brief this is, on an axis distinct from severity.
//
// Order of checks matters — the strongest signal wins:
//   - rumour: severity already classified upstream as unconfirmed
//   - threat: active exploitation evidence (KEV, priority_signals,
//     in-the-wild language in the body, "unpatched"/"zero-day" in the
//     title at high+ severity), or a named threat actor at high+
//     severity (cleanActors has already filtered boilerplate), or any
//     brief from a primary threat-intel source with a named actor or
//     structured TTP coverage
//   - coverage: source is one of the rule-feed sources (Sigma HQ /
//     Splunk ESCU / Elastic detections). The brief assembler emits a
//     synthesized Sigma rule on almost every brief, so rule-presence
//     alone is not a signal — only rule-feed origin is.
//   - advisory: everything else with at least the shape of a
//     vulnerability writeup, including CVE-backed briefs and briefs
//     from CERT-Bund / cisa / vendor PSIRT / NVD / news where the
//     LLM didn't extract a CVE. The user-facing "Rule" label is
//     reserved exclusively for the coverage tier above.
//
// The classifier reads from BundleBrief alone (no pipeline state) so it
// works at backfill time too. PrioritySignals carries the upstream
// detections (active_exploitation, watchlist_match, high_confidence_source).
func classifyType(b BundleBrief) string {
	severity := strings.ToLower(strings.TrimSpace(b.Severity))
	if severity == "rumour" {
		return "rumour"
	}

	hasKEV := false
	for _, c := range b.CVEs {
		if c.KEV {
			hasKEV = true
			break
		}
	}
	hasActiveExploit := slices.Contains(b.PrioritySignals, "active_exploitation")
	hasWatchlist := slices.Contains(b.PrioritySignals, "watchlist_match")
	hasNamedActor := strings.TrimSpace(b.ThreatActor) != ""
	hasHighConfActor := hasNamedActor &&
		(slices.Contains(b.PrioritySignals, "high_confidence_source") ||
			slices.Contains(b.PrioritySignals, "medium_confidence_source"))

	isHighStakes := severity == "high" || severity == "critical"

	if hasActiveExploit || hasKEV || hasWatchlist || hasHighConfActor {
		return "threat"
	}
	// Named actor + high+ severity: cleanActors already drops boilerplate
	// like "Multiple Threat Actors" and country names, so a non-empty
	// actor at this point is meaningful enough to escalate without a
	// confidence-bearing priority_signal.
	if hasNamedActor && isHighStakes {
		return "threat"
	}
	// Title hedge phrases — "unpatched", "zero-day", "in the wild",
	// "actively exploited" — at high+ severity. These read as threat
	// to a defender even when the LLM didn't manage to extract a CVE
	// or set the priority_signal.
	if isHighStakes && (titleSuggestsThreat(b.Title) || bodySuggestsThreat(b.Content)) {
		return "threat"
	}

	if isRuleFeedSource(b.Source) {
		return "coverage"
	}

	// Primary threat-intel sources: a named actor or two or more MITRE
	// ATT&CK TTPs signals a campaign analysis, not a CVE writeup.
	// Severity is irrelevant here — a medium-severity APT campaign is
	// still a threat, and the severity field already communicates urgency.
	if isThreatIntelSource(b.Source) && (hasNamedActor || len(b.TTPs) >= 2) {
		return "threat"
	}

	// Everything else is a vulnerability writeup. The user-facing
	// label "Rule" is reserved for rule-feed sources above.
	return "advisory"
}

func isRuleFeedSource(source string) bool {
	_, ok := ruleFeedSources[strings.ToLower(strings.TrimSpace(source))]
	return ok
}

func isThreatIntelSource(source string) bool {
	_, ok := threatIntelSources[strings.ToLower(strings.TrimSpace(source))]
	return ok
}

// titleSuggestsThreat checks for hedge phrases that mark a brief as an
// active threat regardless of whether a CVE was successfully extracted
// or active_exploitation made it into priority_signals.
func titleSuggestsThreat(s string) bool {
	s = strings.ToLower(s)
	for _, p := range []string{
		"unpatched", "zero-day", "0-day", "0day",
		"in the wild", "actively exploited", "exploited in the wild",
		"exploitation observed", "exploitation in the wild", "under active exploitation",
	} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// bodySuggestsThreat looks at the prose body for unambiguous
// in-the-wild exploitation evidence the title may have omitted. The
// phrase set is deliberately tight — "observed exploitation" or "active
// exploitation" alone are too ambiguous (they appear in body text that
// just describes the exploit mechanism). We require explicit "in the
// wild" / "actively exploited" framing, or vendor-advisory phrasing
// like "limited exploitation observed" / "exploitation has been observed".
func bodySuggestsThreat(s string) bool {
	if len(s) == 0 {
		return false
	}
	s = strings.ToLower(s)
	for _, p := range []string{
		"actively exploited", "exploited in the wild", "in-the-wild exploitation", "in the wild by",
		"limited exploitation", "exploitation has been observed", "exploitation in the wild",
		"under active exploitation", "being actively exploited",
	} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// actorConfidenceSuffixRe strips trailing confidence / sponsorship
// qualifiers from LLM-extracted threat actor names: "(Likely)",
// "(Suspected)", "(State-Sponsored)" and friends. Those belong in
// priority_signals or a confidence field, not on the actor label —
// they leak into URLs (/actors/blacksuit-likely/) and brief listings.
var actorConfidenceSuffixRe = regexp.MustCompile(`(?i)\s*\((likely|suspected|possibly|unconfirmed|tentative|alleged|attributed|unspecified|unattributed|unknown|state-sponsored|nation-state|simulated)\)\s*$`)

// actorHedgePrefixRe strips leading hedge words. The model sometimes
// emits "Potentially X" / "Likely X" / "Suspected X" — same problem as
// the suffix form, just on the front.
var actorHedgePrefixRe = regexp.MustCompile(`(?i)^(potentially|likely|suspected|possibly|alleged|attributed to)\s+`)

// actorIncludingPrefixRe drops any "Multiple Threat Actors, including"
// or similar boilerplate preamble so the names that actually follow
// can be emitted as separate actors.
var actorIncludingPrefixRe = regexp.MustCompile(`(?i)^.*?\bincluding\s+`)

// actorSplitRe splits compound actor strings on the separators we've
// observed: comma, " and ", " / ", " & ", " + ".
var actorSplitRe = regexp.MustCompile(`(?i)\s*(?:,|\band\b|\s/\s|\s&\s|\s\+\s)\s*`)

// actorBoilerplateLower lists placeholder strings that should never
// appear as an actor entry. Compared case-insensitively after the rest
// of the cleanup runs.
var actorBoilerplateLower = map[string]struct{}{
	"actors":                   {},
	"threat actors":            {},
	"multiple threat actors":   {},
	"various actors":           {},
	"various threat actors":    {},
	"unattributed":             {},
	"unknown":                  {},
	"unspecified":              {},
	"unidentified":             {},
	"n/a":                      {},
	"none":                     {},
	"red teams":                {},
	"red team":                 {},
	"individual developer":     {},
	"unauthenticated attacker": {},
	"researchers":              {},
	"security researchers":     {},
}

// actorCountryOnlyRe matches a value that is purely a country name (or
// a list of country names like "China, Russia, North Korea") with no
// actual actor codename. Countries describe sponsorship, not actors.
var actorCountryOnlyRe = regexp.MustCompile(`(?i)^(china|russia|iran|north korea|dprk|usa|united states|israel|ukraine|belarus)$`)

// actorResearcherTailRe drops values that resolve to research-team-shaped
// names — the LLM occasionally reports security-firm research teams (Palo
// Alto Networks Researchers, Theori Xint Code Research Team, Mandiant
// Researchers, etc.) as the threat actor. They aren't actors. Keep them
// out of the taxonomy. Matches "researchers", "research team", "research
// group", "research lab" as a trailing token.
var actorResearcherTailRe = regexp.MustCompile(`(?i)\b(?:researchers?|research\s+(?:team|group|lab))$`)

// actorParenAliasRe matches "<descriptor> Threat Actor (<alias>)" so we
// can keep just the alias. The descriptor is generic and the parenthetical
// is the codename — flipping these keeps URLs / chips clean.
var actorParenAliasRe = regexp.MustCompile(`(?i)^.*\bthreat actors?\s*\(([^)]+)\)\s*$`)

// cleanActors normalizes a free-text threat_actor string from the LLM
// into zero or more canonical actor entries. It splits compound
// strings, strips hedge prefixes / suffixes, drops boilerplate, and
// dedupes. Returns nil for input that ends up entirely empty.
func cleanActors(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if actorIncludingPrefixRe.MatchString(s) {
		s = actorIncludingPrefixRe.ReplaceAllString(s, "")
	}
	parts := actorSplitRe.Split(s, -1)
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = actorHedgePrefixRe.ReplaceAllString(p, "")
		p = actorConfidenceSuffixRe.ReplaceAllString(p, "")
		// "<descriptor> Threat Actor (<alias>)" — keep just the alias.
		if m := actorParenAliasRe.FindStringSubmatch(p); m != nil {
			p = strings.TrimSpace(m[1])
		}
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key := strings.ToLower(p)
		if _, bad := actorBoilerplateLower[key]; bad {
			continue
		}
		if actorCountryOnlyRe.MatchString(p) {
			continue
		}
		if actorResearcherTailRe.MatchString(p) {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	// Expand each cleaned actor through the alias map. A brief about
	// "APT29" gains "Cozy Bear", "NOBELIUM", "Midnight Blizzard" so a
	// reader hunting any one alias finds it. Names with no alias entry
	// pass through untouched.
	expanded := make([]string, 0, len(out))
	expandedSeen := make(map[string]struct{}, len(out))
	addOnce := func(s string) {
		k := strings.ToLower(s)
		if _, dup := expandedSeen[k]; dup {
			return
		}
		expandedSeen[k] = struct{}{}
		expanded = append(expanded, s)
	}
	for _, name := range out {
		if g := expandAliases(name); g != nil {
			for _, alias := range g {
				addOnce(alias)
			}
		} else {
			addOnce(name)
		}
	}
	return expanded
}

// stripLeadingHeadings drops any leading "#"/"##"/blank lines so the published
// body doesn't render a duplicate H1 alongside the page title generated by Hugo
// from the frontmatter `title`. Everything after the first prose line is kept
// verbatim.
func stripLeadingHeadings(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	start := 0
	for start < len(lines) {
		t := strings.TrimSpace(lines[start])
		if t == "" || strings.HasPrefix(t, "#") {
			start++
			continue
		}
		break
	}
	return strings.TrimRight(strings.Join(lines[start:], "\n"), "\n")
}

func convertUpdates(in []BundleUpdate) []publicUpdate {
	if len(in) == 0 {
		return nil
	}
	out := make([]publicUpdate, 0, len(in))
	for _, u := range in {
		out = append(out, publicUpdate(u))
	}
	return out
}

func convertTTPs(in []BundleTTP) []publicTTP {
	if len(in) == 0 {
		return nil
	}
	out := make([]publicTTP, 0, len(in))
	for _, t := range in {
		tacticName := t.TacticName
		if canonical := mitre.TacticName(strings.ToUpper(strings.TrimSpace(t.TacticID))); canonical != "" {
			tacticName = canonical
		}
		techniqueName := t.TechniqueName
		if canonical := mitre.TechniqueName(strings.ToUpper(strings.TrimSpace(t.TechniqueID))); canonical != "" {
			techniqueName = canonical
		}
		subtechniqueName := t.SubtechniqueName
		if canonical := mitre.TechniqueName(strings.ToUpper(strings.TrimSpace(t.SubtechniqueID))); canonical != "" {
			subtechniqueName = canonical
		}
		out = append(out, publicTTP{
			TacticID:         t.TacticID,
			TacticName:       tacticName,
			TechniqueID:      t.TechniqueID,
			TechniqueName:    techniqueName,
			SubtechniqueID:   t.SubtechniqueID,
			SubtechniqueName: subtechniqueName,
			Evidence:         t.Evidence,
			ConfidenceBand:   t.ConfidenceBand,
		})
	}
	return out
}

// completePublicCVEs makes the structured public list complete for legacy
// records whose public projection mentions CVEs that predate structured
// enrichment. It preserves existing scores and appends only identifiers that
// the current snapshot already shows in frontmatter or body text.
func completePublicCVEs(existing []BundleCVE, visible string) []BundleCVE {
	out := append([]BundleCVE(nil), existing...)
	seen := make(map[string]struct{}, len(out))
	for _, cve := range out {
		seen[strings.ToUpper(strings.TrimSpace(cve.ID))] = struct{}{}
	}
	for _, match := range genericCVERe.FindAllString(visible, -1) {
		id := strings.ToUpper(match)
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, BundleCVE{ID: id})
	}
	return out
}

func convertCVEs(in []BundleCVE) []publicCVE {
	if len(in) == 0 {
		return nil
	}
	out := make([]publicCVE, 0, len(in))
	for _, c := range in {
		out = append(out, publicCVE{
			ID:        c.ID,
			Product:   c.Product,
			CVSS:      c.CVSS,
			EPSS:      c.EPSS,
			KEV:       c.KEV,
			KEVStatus: publicKEVStatus(c),
		})
	}
	return out
}

func publicKEVStatus(c BundleCVE) string {
	if c.KEV {
		return "true"
	}
	if c.KEVStatus == "false" {
		return "false"
	}
	return "unknown"
}

// convertIOCs publishes the type+value of each indicator. Confidence is
// internal scoring data and is omitted.
func convertIOCs(in []BundleIOC) []publicIOC {
	if len(in) == 0 {
		return nil
	}
	out := make([]publicIOC, 0, len(in))
	for _, ioc := range in {
		out = append(out, publicIOC{
			Type:  ioc.Type,
			Value: ioc.Value,
		})
	}
	return out
}

// countIOCs aggregates IOCs by Type so card listings can show "12 hashes,
// 4 IPs" without iterating the full IOCs list. Kept alongside the published
// IOCs list.
func countIOCs(in []BundleIOC) map[string]int {
	if len(in) == 0 {
		return nil
	}
	m := make(map[string]int, len(in))
	for _, ioc := range in {
		t := strings.TrimSpace(ioc.Type)
		if t == "" {
			t = "other"
		}
		m[t]++
	}
	return m
}

// convertRules strips Detection (the query) and Tests (real TTP samples) from
// each rule. Tactics/techniques are derived from Sigma-style "attack.*" tags.
func convertRules(in []BundleRule) []publicRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]publicRule, 0, len(in))
	for _, r := range in {
		tactics, techniques := mitreTagsFromRule(r.Tags)
		out = append(out, publicRule{
			Title:       r.Title,
			Description: r.Description,
			Platform:    "sigma",
			Severity:    r.Level,
			Tactics:     tactics,
			Techniques:  techniques,
			DataSources: dataSourcesFrom(r.LogSource),
		})
	}
	return out
}

// mitreTagsFromRule parses Sigma-style tags ("attack.execution",
// "attack.t1059.001") into MITRE tactic and technique lists.
// Tags that don't match the prefix are ignored.
func mitreTagsFromRule(tags []string) (tactics, techniques []string) {
	for _, raw := range tags {
		t := strings.TrimSpace(strings.ToLower(raw))
		t = strings.TrimPrefix(t, "attack.")
		if t == raw || t == "" {
			continue
		}
		if strings.HasPrefix(t, "t") && len(t) > 1 && (t[1] >= '0' && t[1] <= '9') {
			techniques = append(techniques, strings.ToUpper(t))
		} else {
			tactics = append(tactics, t)
		}
	}
	sort.Strings(tactics)
	sort.Strings(techniques)
	return tactics, techniques
}

func dataSourcesFrom(ls BundleLogSource) []string {
	var out []string
	if c := strings.TrimSpace(ls.Category); c != "" {
		out = append(out, c)
	}
	if p := strings.TrimSpace(ls.Product); p != "" {
		out = append(out, p)
	}
	if s := strings.TrimSpace(ls.Service); s != "" {
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
