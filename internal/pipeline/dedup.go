package pipeline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// Pre-compiled regexes for NormalizeTitleHash (avoid recompiling on every call).
var (
	bracketRe          = regexp.MustCompile(`\[.*?\]`)
	dateRe             = regexp.MustCompile(`\d{4}[-/]\d{2}[-/]\d{2}`)
	whitespaceRe       = regexp.MustCompile(`\s+`)
	versionQualifierRe = regexp.MustCompile(`\s*\([^)]*\d[^)]*\)\s*$`)
	nonAlphaNumRe      = regexp.MustCompile(`[^a-z0-9]+`)
	corporateSuffixRe  = regexp.MustCompile(`\b(inc\.?|ltd\.?|limited|corp\.?|corporation|llc|plc|ag|gmbh|s\.a\.?|b\.v\.?|s\.l\.?|k\.k\.?|co\.?)\b`)
)

// DedupDecision indicates what the deduplicator decided about an item.
type DedupDecision int

const (
	DedupNew    DedupDecision = iota // No prior match — process normally
	DedupSkip                        // Cross-source duplicate, existing draft is rich — drop
	DedupUpdate                      // Same CVE but significant new info — process as update
	DedupMerge                       // Cross-source duplicate, existing draft is thin — extract new item and union structured fields into the existing draft
)

// productMergeWindow bounds the same-specific-product merge axis. A one-week
// window lets reports about one vulnerability that arrive days apart collapse,
// while keeping month-apart disclosures separate.
const productMergeWindow = 7 * 24 * time.Hour

// CVEContext captures what we know about a CVE at indexing time,
// so future items can be compared without an LLM call.
type CVEContext struct {
	HasExploit         bool     `json:"has_exploit"`
	HasPatch           bool     `json:"has_patch"`
	ActiveExploitation bool     `json:"active_exploitation"`
	Severity           string   `json:"severity,omitempty"`
	Source             string   `json:"source"`
	IOCCount           int      `json:"ioc_count"`
	Techniques         []string `json:"techniques,omitempty"`
}

var cveRegex = regexp.MustCompile(`(?i)(CVE-\d{4}-\d{4,})`)

// Update signal keyword groups for heuristic scoring.
var (
	// exploitTerms signal a public exploit or PoC (see mentionsPublicExploit).
	// Exploitation in the wild is activeExploitTerms: an exploit being out is
	// not observed exploitation, nor the other way round.
	exploitTerms = []string{
		"proof of concept", "proof-of-concept", "poc released", "poc available",
		"exploit released", "exploit available", "exploit code", "weaponized",
		"exploit for", "remote exploit", "local exploit", "public exploit",
		"exploit published", "exploit submitted",
	}
	patchTerms = []string{
		"patch released", "patch available", "patched in", "security update",
		"hotfix", "firmware update", "vendor fix", "advisory update",
		"apply appropriate updates", "apply the vendor update", "upgrade to",
	}
	activeExploitTerms = []string{
		"actively exploited", "exploitation in the wild", "wild exploitation",
		"active exploitation", "observed in attacks", "used in attacks",
		"zero-day", "0-day", "under active attack",
	}
	severityTerms = []string{
		"critical", "severity upgrade", "cvss upgraded", "severity escalation",
		"upgraded to critical", "score increased",
	}
)

// Source authority levels. Higher means more authoritative; used to
// break ties when two sources report the same CVE so the higher-quality
// brief replaces or merges into the lower-quality one. Looked up via
// getSourceAuthority which supports prefix matching, so reddit-netsec
// matches the reddit prefix entry.
var sourceAuthority = map[string]int{
	// Government / CERT / authoritative
	"cisa-kev":    5,
	"cisa":        4,
	"ccb-belgium": 4,
	"cert-eu":     4,
	"ncsc-uk":     4,
	"ncsc-nl":     4,
	"anssi":       4,
	"bsi":         4,
	"jpcert":      4,
	"nvd":         4,
	"ghsa":        4,
	"msrc":        4,
	"cisco-psirt": 4,
	// Vendor research / IR firms (deep technical writeups)
	"mandiant":               3,
	"talos":                  3,
	"unit42":                 3,
	"crowdstrike":            3,
	"microsoft-threat-intel": 3,
	"sophos-xops":            3,
	"huntress":               3,
	"arctic-wolf":            3,
	"checkpoint":             3,
	"eset":                   3,
	"volexity":               3,
	"wiz":                    3,
	"securelist":             3,
	"google-project-zero":    3,
	"watchtowr":              3,
	"mozilla-security":       4,
	"ars-security":           3,
	// New sources — added 2026-05-06
	"sentinelone-labs":         3,
	"bitdefender":              3,
	"fortiguard":               3,
	"proofpoint":               3,
	"rapid7":                   3,
	"red-canary":               3,
	"recorded-future":          3,
	"flashpoint":               3,
	"intel471":                 3,
	"greynoise":                3,
	"cofense":                  3,
	"any-run":                  2,
	"qualys-threat-research":   3,
	"malware-traffic-analysis": 3,
	"objective-see":            3,
	"attackiq":                 2,
	// Government / CERT
	"fbi-cyber": 4,
	"cccs":      4,
	"acsc":      4,
	"ms-isac":   4,
	// Independent research
	"google-tag": 3,
	"abuse-ch":   3,
	"circl-misp": 3,
	// Detection-focused / rule sources
	"sigma_hq":    3,
	"elastic":     3,
	"splunk_escu": 3,
	"dfir-report": 3,
	// News / aggregators
	"bleepingcomputer":     2,
	"the-record":           2,
	"securityweek":         2,
	"the-hacker-news":      2,
	"dark-reading":         2,
	"risky-biz":            2,
	"risky-biz-bulletin":   2,
	"pwn-watch":            1,
	"isc-stormcast":        2,
	"sonatype":             2,
	"reddit-netsec":        1,
	"reddit-blueteamsec":   1,
	"reddit-cybersecurity": 1,
	// Exploit tracking — PoC publication is a strong update signal
	"exploit-db": 3,
	"sploitus":   3,
	// Detection-focused research
	"socprime": 2,
	// Tier 1 alongside reddit: the account doing the linking must never win a
	// tie against the publisher being linked to.
	"ronin66": 1,
	// Original detection content, same tier as the other rule sources above.
	"gossithedog-threathunting": 3,
	// Same tie-break reasoning as ronin66: the Mastodon post promotes an
	// outbound link, so it must not outrank the actual publisher of that
	// link in a merge — regardless of how trustworthy the poster is.
	"gossithedog-mastodon": 1,
}

// isExploitTracker returns true for sources that index public exploits and
// PoCs. Used to set has_poc on the merged brief.
func isExploitTracker(source string) bool {
	return source == "exploit-db" || source == "sploitus"
}

// getSourceAuthority returns the authority level for a source name.
// It first tries an exact match, then falls back to prefix matching.
func getSourceAuthority(source string) int {
	if a, ok := sourceAuthority[source]; ok {
		return a
	}
	// Prefix fallback for sources like "reddit-*".
	bestAuth := 0
	for prefix, auth := range sourceAuthority {
		if strings.HasPrefix(source, prefix) && auth > bestAuth {
			bestAuth = auth
		}
	}
	return bestAuth
}

// Deduplicator handles cross-source deduplication.
type Deduplicator struct {
	db     *storage.DB
	logger *slog.Logger
}

// NewDeduplicator creates a Deduplicator backed by the given DB.
func NewDeduplicator(db *storage.DB, logger *slog.Logger) *Deduplicator {
	return &Deduplicator{db: db, logger: logger}
}

// activeEntries removes index rows that can no longer lead to a live draft.
// Rejected and missing targets must never suppress or absorb new intelligence;
// stale rows can remain after older retirement paths or interrupted repairs.
func (d *Deduplicator) activeEntries(entries []storage.ContentIndexEntry) []storage.ContentIndexEntry {
	active := entries[:0]
	status := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.DraftID == "" {
			active = append(active, entry)
			continue
		}
		eligible, checked := status[entry.DraftID]
		if !checked {
			draft, err := d.db.GetDraft(entry.DraftID)
			// Historical/test indexes may intentionally have no draft row and
			// still provide CVE overlap evidence. Only a known rejected owner is
			// categorically ineligible as a dedup or merge target.
			eligible = err != nil || draft == nil || draft.Status != storage.StatusRejected
			status[entry.DraftID] = eligible
		}
		if eligible {
			active = append(active, entry)
		}
	}
	return active
}

// citedEntries keeps the content, source-URL and title rows whose draft still
// cites the source they were indexed from. Those rows say that one item is in
// a draft, and they are written when it is indexed; a later correction can
// remove the item from the draft, and its rows must not keep routing the item,
// or a copy of it, there. A row without a URL, or whose draft is unreadable or
// cites nothing, stays: there is no citation to check.
func (d *Deduplicator) citedEntries(entries []storage.ContentIndexEntry) []storage.ContentIndexEntry {
	kept := entries[:0]
	cited := make(map[string]map[string]bool)
	for _, entry := range entries {
		if entry.DraftID == "" || entry.SourceURLHash == "" {
			kept = append(kept, entry)
			continue
		}
		hashes, checked := cited[entry.DraftID]
		if !checked {
			hashes = d.draftCitedURLHashes(entry.DraftID)
			cited[entry.DraftID] = hashes
		}
		if hashes == nil || hashes[entry.SourceURLHash] {
			kept = append(kept, entry)
		}
	}
	return kept
}

// draftCitedURLHashes returns the source-URL hashes of every URL the draft
// cites: its references, PoC references and update-log sources, and the
// corroborating sources in its validation notes. A merge that adds nothing else
// records its source in the update log; one that adds nothing at all records it
// as a corroboration note and still indexes the item. It returns nil when the
// draft cannot be read or cites no URL.
func (d *Deduplicator) draftCitedURLHashes(draftID string) map[string]bool {
	draft, err := d.db.GetDraft(draftID)
	if err != nil || draft == nil {
		return nil
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(draft.BriefYAML), &fm); err != nil {
		return nil
	}
	urls := append(yamlStringList(fm["references"]), yamlStringList(fm["poc_references"])...)
	for _, update := range yamlAnyList(fm["updates"]) {
		if fields, ok := update.(map[string]any); ok {
			urls = append(urls, yamlStringList(fields["source_urls"])...)
		}
	}
	urls = append(urls, draft.ValidationNotes)
	hashes := SourceURLHashes(urls...)
	if len(hashes) == 0 {
		return nil
	}
	set := make(map[string]bool, len(hashes))
	for _, hash := range hashes {
		set[hash] = true
	}
	return set
}

// cveEntries returns the live index rows for cve whose draft still covers it.
// Rows are written when a source is indexed; a later correction can remove
// the CVE from the draft, and its old rows must not keep routing it there.
func (d *Deduplicator) cveEntries(cve string) ([]storage.ContentIndexEntry, error) {
	entries, err := d.db.FindByCVE(cve)
	if err != nil {
		return nil, err
	}
	entries = d.activeEntries(entries)
	kept := entries[:0]
	for _, e := range entries {
		if d.draftMatchesCVEs(e.DraftID, []string{cve}, nil) {
			kept = append(kept, e)
		}
	}
	return kept, nil
}

// draftMatchesCVEs applies the CVE rule (cve_identity.go) to an index match:
// a report naming cves only matches a draft that lists one of them or a CVE
// chained with one. Missing drafts are left to the callers' own checks.
func (d *Deduplicator) draftMatchesCVEs(draftID string, cves []string, chains [][]string) bool {
	if draftID == "" || len(cves) == 0 {
		return true
	}
	draft, err := d.db.GetDraft(draftID)
	if err != nil || draft == nil {
		return true
	}
	return cvesOverlap(briefCVEIDs(parseBriefFrontmatter(draft.BriefYAML)), cves, cveChains(chains))
}

// reportCVEs returns the CVEs a report names: those the item asserts as its
// subject and those its extraction found.
func reportCVEs(item scraper.RawItem, extraction *ExtractionResult) []string {
	cves := subjectCVEs(item)
	if extraction != nil {
		for _, raw := range extraction.CVEs {
			cves = appendUniqueString(cves, normalizeCVEID(raw))
		}
	}
	return cves
}

// ExtractCVEsFromText extracts unique CVE IDs from title and content using regex.
func ExtractCVEsFromText(title, content string) []string {
	text := title + " " + content
	matches := cveRegex.FindAllStringSubmatch(text, -1)
	seen := make(map[string]bool)
	var cves []string
	for _, m := range matches {
		id := strings.ToUpper(m[1])
		if !seen[id] {
			seen[id] = true
			cves = append(cves, id)
		}
	}
	return cves
}

// subjectCVEs returns identifiers asserted by the feed item itself. Narrative
// body mentions are insufficient: they can be historical comparisons or links
// to distinct vulnerabilities and must not become deduplication keys.
func subjectCVEs(item scraper.RawItem) []string {
	content := item.Metadata["cve"] + " " + item.Metadata["cves"]
	if item.BodyCVEsAreSubjects {
		content += " " + item.Content
	}
	return ExtractCVEsFromText(item.Title, content)
}

// confirmedExtractionCVEs accepts a model's subject IDs only when the source
// actually names them. IDs used for an explicit historical comparison are not
// identities for this item, even if extraction included them by mistake.
func confirmedExtractionCVEs(item scraper.RawItem, extraction *ExtractionResult) []string {
	if extraction == nil {
		return nil
	}
	asserted := make(map[string]bool)
	for _, cve := range subjectCVEs(item) {
		asserted[cve] = true
	}
	content := strings.ToLower(item.Content)
	var confirmed []string
	for _, raw := range extraction.CVEs {
		cve := strings.ToUpper(raw)
		if asserted[cve] || isExploitTracker(item.Source) {
			confirmed = append(confirmed, cve)
			continue
		}
		needle := strings.ToLower(cve)
		for offset := 0; offset < len(content); {
			index := strings.Index(content[offset:], needle)
			if index < 0 {
				break
			}
			index += offset
			start := strings.LastIndexAny(content[:index], ".!?\n;") + 1
			end := len(content)
			if boundary := strings.IndexAny(content[index+len(needle):], ".!?\n;"); boundary >= 0 {
				end = index + len(needle) + boundary
			}
			clause := content[start:end]
			if !containsAny(clause, []string{"for comparison", "compared with", "similar to", "separate from", "unrelated to", "previous", "previously", "earlier", "historical", "older", "prior cve", "past cve"}) {
				confirmed = append(confirmed, cve)
				break
			}
			offset = index + len(needle)
		}
	}
	return confirmed
}

// NormalizeTitleHash produces a deterministic hash of the title after removing
// noise (source tags, dates, punctuation variations).
func NormalizeTitleHash(title string) string {
	t := strings.ToLower(title)
	// Remove common source prefixes/brackets.
	t = bracketRe.ReplaceAllString(t, "")
	// Remove dates in various formats.
	t = dateRe.ReplaceAllString(t, "")
	// Collapse whitespace and trim.
	t = whitespaceRe.ReplaceAllString(t, " ")
	t = strings.TrimSpace(t)
	h := sha256.Sum256([]byte(t))
	return fmt.Sprintf("%x", h)
}

// NormalizeContentHash returns a SHA-256 hex digest of the title+content after
// lowercasing and collapsing all whitespace. It backs the literal-duplicate
// axis: syndicated republications of the same article arrive from different
// sources, share no CVE, and differ only by a source tag — identical
// normalized content is treated as a duplicate.
func NormalizeContentHash(title, content string) string {
	norm := func(s string) string {
		return strings.TrimSpace(whitespaceRe.ReplaceAllString(strings.ToLower(s), " "))
	}
	joined := norm(title) + "\x00" + norm(content)
	sum := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("%x", sum)
}

// CheckPreExtraction performs cheap regex-based dedup before any LLM calls.
// Returns the decision, extracted CVEs, and matching content index entries.
func (d *Deduplicator) CheckPreExtraction(item scraper.RawItem) (DedupDecision, []string, []storage.ContentIndexEntry) {
	return d.checkPreExtraction(item, true)
}

// Prefetch needs the same decision without applying the corroboration boost.
func (d *Deduplicator) checkPreExtraction(item scraper.RawItem, corroborate bool) (DedupDecision, []string, []storage.ContentIndexEntry) {
	if decision, entries, ok := d.sourceRevisionMatch(item); ok {
		return decision, subjectCVEs(item), entries
	}
	// Literal-duplicate guard: identical normalized content from a *different*
	// source is a syndicated republication — skip it before any further work.
	// Gated on substantial content so thin/degenerate items can't false-match;
	// same-source repeats are already handled by seen_items upstream.
	if len(strings.TrimSpace(item.Content)) >= 120 {
		if ch := NormalizeContentHash(item.Title, item.Content); ch != "" {
			if hits, err := d.db.FindByContentHash(ch); err == nil {
				hits = d.citedEntries(d.activeEntries(hits))
				for _, e := range hits {
					if e.Source != item.Source {
						return DedupSkip, nil, []storage.ContentIndexEntry{e}
					}
				}
			}
		}
	}

	for _, urlHash := range sourceURLHashesForRawItem(item) {
		if hits, err := d.db.FindBySourceURLHash(urlHash); err == nil {
			hits = d.citedEntries(d.activeEntries(hits))
			for _, e := range hits {
				if e.DraftID == "" {
					continue
				}
				if e.SourceID == item.SourceID {
					return DedupSkip, nil, []storage.ContentIndexEntry{e}
				}
				return DedupMerge, nil, []storage.ContentIndexEntry{e}
			}
		}
	}

	// Only identifiers presented as the subject of the item are safe for
	// pre-extraction dedup. Body text often cites an older CVE for comparison;
	// treating it as the subject can silently discard a new disclosure.
	cves := subjectCVEs(item)

	// Check each CVE against the index.
	for _, cve := range cves {
		entries, err := d.cveEntries(cve)
		if err != nil || len(entries) == 0 {
			continue
		}
		// Found a prior entry for this CVE — evaluate overlap.
		decision := d.evaluateCVEOverlap(item, cve, entries)
		if decision == DedupSkip {
			// A draft missing publication content, guidance or detection
			// coverage can benefit even without an exploit/patch signal.
			for _, e := range entries {
				if e.DraftID != "" && d.isDraftThin(e.DraftID) {
					return DedupMerge, cves, []storage.ContentIndexEntry{e}
				}
			}
			// Multi-source corroboration: boost draft score when multiple
			// distinct sources report the same CVE.
			if corroborate {
				d.applyCorroborationBoost(cve, entries)
			}
			return decision, cves, entries
		}
		if decision != DedupNew {
			return decision, cves, entries
		}
	}

	// Fallback: title hash check for non-CVE duplicates.
	titleHash := NormalizeTitleHash(item.Title)
	entries, err := d.db.FindByTitleHash(titleHash)
	entries = d.citedEntries(d.activeEntries(entries))
	if err == nil && len(entries) > 0 {
		// Same title from a different source. If the existing draft is
		// thin (no CVEs, no products-with-version, no IOCs) the new item
		// likely has structured data the original didn't — merge it.
		// Otherwise drop to preserve the original.
		for _, e := range entries {
			if e.Source != item.Source {
				// Generic advisory titles repeat across CVEs; a title
				// match against a brief about another CVE is no duplicate.
				if !d.draftMatchesCVEs(e.DraftID, cves, nil) {
					continue
				}
				if d.isDraftThin(e.DraftID) {
					return DedupMerge, cves, entries
				}
				return DedupSkip, cves, entries
			}
		}
	}

	return DedupNew, cves, nil
}

func sourceURLHashesForRawItem(item scraper.RawItem) []string {
	values := []string{item.URL}
	for _, value := range item.Metadata {
		values = append(values, value)
	}
	return SourceURLHashes(values...)
}

// sourceRevisionMatch routes changed evidence back to the source's own live
// draft before URL, title, CVE or syndication matching can discard it. A known
// prior seen baseline is required: a new item cannot claim revision precedence.
// The route does not consume the revision; the caller must validate and save it.
func (d *Deduplicator) sourceRevisionMatch(item scraper.RawItem) (DedupDecision, []storage.ContentIndexEntry, bool) {
	if item.SourceID == "" || item.Revision == "" {
		return DedupNew, nil, false
	}
	known, err := d.db.HasSeen(item.SourceID)
	if err != nil || !known {
		return DedupNew, nil, false
	}
	seen, err := d.db.HasSeenRevision(item.SourceID, item.Revision)
	if err != nil {
		return DedupNew, nil, false
	}
	entries, err := d.db.FindBySourceID(item.SourceID)
	if err != nil {
		return DedupNew, nil, false
	}
	var target *storage.ContentIndexEntry
	for i := range entries {
		entry := &entries[i]
		if entry.DraftID == "" || entry.Source != item.Source {
			continue
		}
		draft, err := d.db.GetDraft(entry.DraftID)
		if err != nil || draft == nil || draft.Status == storage.StatusRejected {
			continue
		}
		if target == nil {
			target = entry
		}
		// Prefer an approved canonical owner over a pending derivative.
		if draft.Status == storage.StatusApproved {
			target = entry
			break
		}
	}
	if target == nil {
		return DedupNew, nil, false
	}
	decision := DedupMerge
	if seen {
		decision = DedupSkip
	}
	return decision, []storage.ContentIndexEntry{*target}, true
}

// isDraftThin reports whether the stored brief lacks the body, response,
// detection coverage or asset scope required for publication. Identifiers,
// version labels and IOCs alone do not establish semantic completeness.
// Unreadable/rejected targets remain ineligible for automatic enrichment.
func (d *Deduplicator) isDraftThin(draftID string) bool {
	if draftID == "" {
		return false
	}
	draft, err := d.db.GetDraft(draftID)
	if err != nil || draft == nil || draft.Status == storage.StatusRejected {
		return false
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(draft.BriefYAML), &fm); err != nil {
		return false
	}
	if len(publicationQualityIssues(fm)) > 0 || lacksDetectionCoverage(fm) {
		return true
	}
	return len(briefCVEIDs(fm)) > 0 && len(yamlStringList(fm["affected_vendors"])) == 0 && len(yamlStringList(fm["affected_products"])) == 0
}

// isProductDraft reports whether the referenced draft is a product-scoped
// brief (vulnerability advisory or detection coverage for a specific product,
// and not a roundup or campaign umbrella). Product-merge paths only fold
// product-scoped briefs together; patch-cycle roundups and campaign umbrellas
// must stay separate.
func (d *Deduplicator) isProductDraft(draftID string) bool {
	if draftID == "" {
		return false
	}
	draft, err := d.db.GetDraft(draftID)
	if err != nil || draft == nil || draft.Status == storage.StatusRejected {
		return false
	}
	return briefType(draft.BriefYAML) == "product"
}

// evaluateCVEOverlap uses heuristic scoring to decide if an item about an
// already-seen CVE is a meaningful update or a plain duplicate.
func (d *Deduplicator) evaluateCVEOverlap(item scraper.RawItem, cve string, entries []storage.ContentIndexEntry) DedupDecision {
	// Parse prior context from the most recent entry.
	var prevCtx CVEContext
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].CVEContext != "" {
			if err := json.Unmarshal([]byte(entries[i].CVEContext), &prevCtx); err == nil {
				break
			}
		}
	}

	// Same source reporting same CVE again — always skip.
	for _, e := range entries {
		if e.Source == item.Source {
			return DedupSkip
		}
	}

	text := strings.ToLower(item.Title + " " + item.Content)
	score := 0

	if !prevCtx.HasExploit && sourceReportsPublicExploit(item) {
		score += 2
	}
	if !prevCtx.HasPatch && containsAny(text, patchTerms) {
		score += 2
	}
	if !prevCtx.ActiveExploitation && containsAny(text, activeExploitTerms) {
		score += 2
	}
	if containsAny(text, severityTerms) {
		score++
	}

	// Higher-authority source than existing.
	itemAuth := getSourceAuthority(item.Source)
	bestExistingAuth := 0
	for _, e := range entries {
		if a := getSourceAuthority(e.Source); a > bestExistingAuth {
			bestExistingAuth = a
		}
	}
	if itemAuth > bestExistingAuth {
		score++
	}

	if score >= 2 {
		return DedupUpdate
	}
	return DedupSkip
}

// CheckPostExtraction checks subject CVEs confirmed by extraction, then runs
// the vendor+product+class and product fallbacks for items that share a
// vulnerability target with an already-indexed brief. The fallbacks never
// match a draft about a different CVE (cve_identity.go).
func (d *Deduplicator) CheckPostExtraction(item scraper.RawItem, extraction *ExtractionResult) (DedupDecision, []storage.ContentIndexEntry) {
	if decision, entries, ok := d.sourceRevisionMatch(item); ok {
		return decision, entries
	}
	if extraction == nil {
		return DedupNew, nil
	}
	if item.Discovery != nil {
		if key := ClaimKey(extraction); key != "" {
			if entries, err := d.db.FindByClaimKey(key); err == nil {
				entries = d.activeEntries(entries)
				for _, e := range entries {
					if e.SourceID != item.SourceID && e.DraftID != "" {
						return DedupMerge, entries
					}
				}
			}
			return DedupNew, nil
		}
	}

	for _, cve := range confirmedExtractionCVEs(item, extraction) {
		entries, err := d.cveEntries(cve)
		if err != nil || len(entries) == 0 {
			continue
		}
		decision := d.evaluateCVEOverlap(item, cve, entries)
		if decision == DedupSkip {
			for _, entry := range entries {
				if entry.DraftID != "" && d.isDraftThin(entry.DraftID) {
					return DedupMerge, []storage.ContentIndexEntry{entry}
				}
			}
		}
		if decision != DedupNew {
			return decision, entries
		}
	}

	cves := reportCVEs(item, extraction)

	// Secondary path: vendor + product + vuln_class fingerprint within a 14
	// day window. Catches Sourcecodester Pharmacy / Totolink / Tenda
	// near-duplicates that share a target and bug class but differ in minor
	// title wording. Falls through (does not return early) so the tertiary
	// path below still runs when the class-fingerprint fails.
	fp := Fingerprint(extraction.AffectedVendors, extraction.AffectedProducts, effectiveVulnClass(item.Title, extraction))
	if fp != "" {
		if fpEntries, err := d.db.FindByFingerprint(fp, 14*24*time.Hour); err == nil && len(fpEntries) > 0 {
			fpEntries = d.activeEntries(fpEntries)
			titleTokens := titleTokenSet(item.Title)
			for _, e := range fpEntries {
				if e.Source == item.Source || !d.draftMatchesCVEs(e.DraftID, cves, extraction.ChainedCVEs) {
					continue
				}
				if d.isDraftThin(e.DraftID) {
					// Thin drafts benefit from cross-source enrichment even
					// when title wording diverges (e.g. "Authentication Portal
					// RCE" vs "Captive Portal Zero Day"). The vendor+product+
					// class fingerprint is specific enough to be the sole merge
					// signal here — adding a title-similarity gate causes high-
					// authority IOC-rich sources to be silently skipped.
					return DedupMerge, []storage.ContentIndexEntry{e}
				}
				if jaccard(titleTokens, parseTokens(e.TitleNorm)) < 0.6 {
					continue
				}
				return DedupSkip, []storage.ContentIndexEntry{e}
			}
		}
	}

	// Tertiary path: same vendor+product, no CVE indexed on the existing
	// brief, new item carries extracted CVEs, within 48 h. This catches the
	// pattern where one source describes the mechanism ("out-of-bounds write")
	// and another describes the effect ("remote code execution") for the same
	// product without a shared CVE id in the earlier report.
	if len(extraction.CVEs) > 0 {
		productFP := ProductFingerprint(extraction.AffectedVendors, extraction.AffectedProducts)
		if productFP != "" {
			noCVEEntries, err := d.db.FindByProductAndNoCVE(productFP, 48*time.Hour)
			if err == nil {
				noCVEEntries = d.activeEntries(noCVEEntries)
				for _, e := range noCVEEntries {
					if e.Source == item.Source || e.DraftID == "" {
						continue
					}
					// Only merge into thin drafts — a draft with CVEs or IOCs
					// already indexed is authoritative and should not be merged
					// with a loosely-matched product-only hit.
					if d.isDraftThin(e.DraftID) {
						return DedupMerge, []storage.ContentIndexEntry{e}
					}
				}
			}
		}
	}

	if productFP := ProductFingerprint(extraction.AffectedVendors, extraction.AffectedProducts); productFP != "" {
		if entries, err := d.db.FindByProduct(productFP, productMergeWindow); err == nil {
			entries = d.activeEntries(entries)
			titleTokens := titleTokenSet(item.Title)
			for _, e := range entries {
				if e.DraftID == "" || e.SourceID == item.SourceID {
					continue
				}
				if !d.isProductDraft(e.DraftID) || !d.draftMatchesCVEs(e.DraftID, cves, extraction.ChainedCVEs) {
					continue
				}
				if d.isDraftThin(e.DraftID) || jaccard(titleTokens, parseTokens(e.TitleNorm)) >= 0.45 {
					return DedupMerge, []storage.ContentIndexEntry{e}
				}
			}
		}
	}

	// Quaternary path: same *specific* product within a one-week window, keyed
	// on named product identity only (never on vuln_class) and gated on product
	// specificity + type match so patch-cycle roundups and campaign umbrellas
	// stay separate. Different CVEs in the same product are different
	// vulnerabilities and stay separate too (cve_identity.go).
	if p := firstNonPlaceholder(extraction.AffectedProducts); isSpecificProduct(p) {
		if productFP := ProductFingerprint(extraction.AffectedVendors, extraction.AffectedProducts); productFP != "" {
			if entries, err := d.db.FindByProduct(productFP, productMergeWindow); err == nil {
				entries = d.activeEntries(entries)
				for _, e := range entries {
					if e.Source == item.Source || e.DraftID == "" {
						continue
					}
					if !d.isProductDraft(e.DraftID) || !d.draftMatchesCVEs(e.DraftID, cves, extraction.ChainedCVEs) {
						continue
					}
					return DedupMerge, []storage.ContentIndexEntry{e}
				}
			}
		}
	}

	return DedupNew, nil
}

// ProductFingerprint returns the SHA-256 hex of "vendor|product" — used as
// the dedup key for the product-only tertiary axis. Unlike Fingerprint it
// omits the vulnerability class, so two briefs describing the same product
// via different mechanism labels ("rce" vs "oob-write") can still be matched.
// Product must be specific enough even when vendor is present; otherwise
// broad keys like "Microsoft|Windows" would collapse unrelated CVEs.
func ProductFingerprint(vendors, products []string) string {
	p := firstNonPlaceholder(products)
	v := firstNonPlaceholder(vendors)
	if p == "" || !isProductMergeKey(v, p) {
		return ""
	}
	h := sha256.Sum256([]byte(normalizeVendorName(v) + "|" + normalizeProductName(p)))
	return fmt.Sprintf("%x", h)
}

// Fingerprint returns the SHA-256 hex of "vendor|product|class" — used
// as the dedup key for the vendor+product+class axis. All inputs are
// trimmed and lowercased; the first non-empty vendor and product are
// used. Returns "" if any of the three is missing.
func Fingerprint(vendors, products []string, vulnClass string) string {
	v := firstNonPlaceholder(vendors)
	p := firstNonPlaceholder(products)
	c := strings.ToLower(strings.TrimSpace(vulnClass))
	if v == "" || p == "" || c == "" {
		return ""
	}
	h := sha256.Sum256([]byte(normalizeVendorName(v) + "|" + normalizeProductName(p) + "|" + c))
	return fmt.Sprintf("%x", h)
}

// normalizeVendorName returns a stable vendor identifier for merge-key
// purposes: lowercased, common legal suffixes stripped, and all
// punctuation/whitespace collapsed. This makes "GL.iNet", "GL-INet" and
// "GLiNet" share a single key without losing meaningful distinctions
// between unrelated vendors.
// vendorAliases maps known alternate vendor names to a canonical merge key.
// Keep this small and grounded in real feed noise — it is a safety net, not
// a substitute for clean extraction.
var vendorAliases = map[string]string{
	"flowiseai": "flowise",
}

// productAliases maps known alternate product names to a canonical family key.
// These collapse sub-components or branding variants that the feed should treat
// as one product (e.g. Flowise CSVAgent / FlowiseAI Flowise → Flowise).
var productAliases = map[string]string{
	"flowiseai":        "flowise",
	"flowiseaiflowise": "flowise",
	"flowisecsvagent":  "flowise",
}

func normalizeVendorName(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	s = corporateSuffixRe.ReplaceAllString(s, "")
	s = nonAlphaNumRe.ReplaceAllString(s, "")
	if alias, ok := vendorAliases[s]; ok {
		return alias
	}
	return s
}

// normalizeProductName returns a stable product identifier for merge-key
// purposes: lowercased, trailing parenthesized version qualifiers stripped,
// and all punctuation/whitespace collapsed. This lets "HUMANIST Digital
// Human Resources (26.0)" and "HUMANIST Digital Human Resources" match,
// as well as "GL-MT3000" / "GL MT3000" / "GLMT3000".
func normalizeProductName(p string) string {
	s := strings.ToLower(strings.TrimSpace(p))
	s = versionQualifierRe.ReplaceAllString(s, "")
	s = nonAlphaNumRe.ReplaceAllString(s, "")
	if alias, ok := productAliases[s]; ok {
		return alias
	}
	return s
}

func firstNonPlaceholder(items []string) string {
	for _, raw := range items {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" || s == "unknown" || s == "n/a" || s == "tbd" || s == "none" || s == "null" || s == "na" {
			continue
		}
		return strings.TrimSpace(raw)
	}
	return ""
}

// briefType classifies a brief YAML so product-merge logic only folds
// same-kind coverage together. Product-scoped briefs (vulnerability advisories
// and detection coverage) merge with each other; patch-cycle roundups and
// campaign umbrellas stay separate.
func briefType(briefYAML string) string {
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &fm); err != nil {
		return "other"
	}
	for _, t := range yamlStringList(fm["tags"]) {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "roundup":
			return "roundup"
		case "clickfix", "filefix", "shai-hulud":
			return "campaign"
		}
	}
	if len(yamlStringList(fm["affected_products"])) > 0 {
		return "product"
	}
	return "other"
}

// genericProducts are product names too broad to be a safe sole merge key —
// keying a merge on these would collapse unrelated vulnerabilities. Lowercased.
var genericProducts = map[string]bool{
	"wordpress": true, "wordpress plugin": true, "linux": true, "windows": true,
	"macos": true, "android": true, "ios": true, "node.js": true, "nodejs": true,
	"npm": true, "pypi": true, "github": true, "gitlab": true, "kubernetes": true,
	"docker": true, "python": true, "java": true, "php": true, "javascript": true,
	"browser": true, "firefox": true,
}

// isSpecificProduct reports whether a product name is specific enough to key a
// merge on: not a placeholder, not a broad platform, and of real length.
func isSpecificProduct(p string) bool {
	s := strings.ToLower(strings.TrimSpace(p))
	if len(s) < 3 || genericProducts[s] {
		return false
	}
	return firstNonPlaceholder([]string{p}) != ""
}

func isProductMergeKey(vendor, product string) bool {
	if isSpecificProduct(product) {
		return true
	}
	return isCanonicalVendorProduct(vendor, product)
}

func isCanonicalVendorProduct(vendor, product string) bool {
	v := strings.ToLower(strings.TrimSpace(vendor))
	p := strings.ToLower(strings.TrimSpace(product))
	if v == "" || p == "" || !genericProducts[p] {
		return false
	}
	switch p {
	case "python":
		return v == "python" || v == "python software foundation"
	default:
		return false
	}
}

// patchCycleVendors publish batched, scheduled advisories (Patch Tuesday and
// equivalents) whose individual CVEs are better presented as one monthly
// roundup brief than as dozens of separate briefs. Lowercased.
var patchCycleVendors = map[string]bool{
	"microsoft": true, "adobe": true, "apple": true, "oracle": true,
	"sap": true, "qualcomm": true, "google": true, "android": true,
	"cisco": true, "siemens": true, "mozilla": true, "atlassian": true,
}

// isPatchCycleVendor reports whether a vendor publishes roundup-worthy
// scheduled advisories.
func isPatchCycleVendor(vendor string) bool {
	return patchCycleVendors[strings.ToLower(strings.TrimSpace(vendor))]
}

// vendorCycleKey returns the roundup grouping key "normalize(vendor)|YYYY-MM"
// for a patch-cycle vendor, or "" when the vendor is empty or not a
// scheduled-advisory vendor. The month bounds the cycle.
func vendorCycleKey(vendor string, published time.Time) string {
	v := strings.ToLower(strings.TrimSpace(vendor))
	if v == "" || !patchCycleVendors[v] {
		return ""
	}
	return v + "|" + published.Format("2006-01")
}

// campaignFamilies maps lowercased name variants to a canonical campaign /
// technique-family label. These are specific, industry-named campaigns (never
// generic weakness classes), so folding every brief of a family into one
// umbrella is the intent, not over-merging.
var campaignFamilies = map[string]string{
	"clickfix":   "clickfix",
	"filefix":    "filefix",
	"shai-hulud": "shai-hulud",
	"shaihulud":  "shai-hulud",
}

// campaignDisplay gives the human-facing label for a canonical family.
var campaignDisplay = map[string]string{
	"clickfix": "ClickFix", "filefix": "FileFix", "shai-hulud": "Shai-Hulud",
}

// matchCampaignFamily returns the canonical family label if the item's title
// names a known campaign family, else "". The body is not consulted: roundups
// and unrelated intrusions mention ClickFix in passing, and folding them into
// the umbrella imports their vendors, products and CVEs.
func matchCampaignFamily(title string) string {
	text := strings.ToLower(title)
	for pat, canon := range campaignFamilies {
		if strings.Contains(text, pat) {
			return canon
		}
	}
	return ""
}

// displayCampaignFamily returns the human-facing name for a canonical family.
func displayCampaignFamily(family string) string {
	if d := campaignDisplay[family]; d != "" {
		return d
	}
	return family
}

// vulnClassPatterns maps regex patterns to a canonical class label.
// Order matters: more specific patterns sit higher.
var vulnClassPatterns = []struct {
	rx    *regexp.Regexp
	class string
}{
	{regexp.MustCompile(`(?i)\b(stack[- ]based|heap[- ]based)?\s*buffer\s+overflow\b`), "buffer-overflow"},
	{regexp.MustCompile(`(?i)\bout[- ]of[- ]bounds\s+(write|read)\b`), "oob"},
	{regexp.MustCompile(`(?i)\boob[- ]?(write|read)\b`), "oob"},
	{regexp.MustCompile(`(?i)\b(sql\s*injection|sqli)\b`), "sql-injection"},
	{regexp.MustCompile(`(?i)\b(command\s+injection|cmd\s+injection|os\s+command)\b`), "command-injection"},
	{regexp.MustCompile(`(?i)\b(server[- ]side\s+request\s+forgery|ssrf)\b`), "ssrf"},
	{regexp.MustCompile(`(?i)\b(cross[- ]site\s+scripting|xss)\b`), "xss"},
	{regexp.MustCompile(`(?i)\b(cross[- ]site\s+request\s+forgery|csrf)\b`), "csrf"},
	{regexp.MustCompile(`(?i)\b(remote\s+code\s+execution|rce)\b`), "rce"},
	{regexp.MustCompile(`(?i)\b(path\s+traversal|directory\s+traversal)\b`), "path-traversal"},
	{regexp.MustCompile(`(?i)\b(authentication\s+bypass|auth\s+bypass)\b`), "auth-bypass"},
	{regexp.MustCompile(`(?i)\b(privilege\s+escalation|privesc)\b`), "privilege-escalation"},
	{regexp.MustCompile(`(?i)\b(use[- ]after[- ]free|uaf)\b`), "use-after-free"},
	{regexp.MustCompile(`(?i)\bdeserialization\b`), "deserialization"},
	{regexp.MustCompile(`(?i)\b(denial\s+of\s+service|dos\b)`), "dos"},
	{regexp.MustCompile(`(?i)\bxxe\b`), "xxe"},
	{regexp.MustCompile(`(?i)\bopen\s+redirect\b`), "open-redirect"},
}

// InferVulnClass returns a canonical vulnerability-class label inferred
// from the brief title (and optionally MITRE tactics as a tiebreaker).
// Returns "" when no pattern matches; callers fall back to no-fingerprint.
func InferVulnClass(title string, tactics []string) string {
	for _, p := range vulnClassPatterns {
		if p.rx.MatchString(title) {
			return p.class
		}
	}
	return ""
}

// effectiveVulnClass returns the best available vulnerability class for a
// given item. It prefers the LLM-extracted VulnClass (populated by the
// extraction prompt) and falls back to regex-based InferVulnClass when the
// LLM field is empty or extraction is nil (e.g. sigma-only items).
func effectiveVulnClass(title string, extraction *ExtractionResult) string {
	if extraction != nil && extraction.VulnClass != "" {
		return extraction.VulnClass
	}
	var tactics []string
	if extraction != nil {
		tactics = extraction.Tactics
	}
	return InferVulnClass(title, tactics)
}

// jaccard returns the Jaccard similarity of two token sets, in [0,1].
// Empty sets count as zero similarity.
func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for t := range a {
		if _, ok := b[t]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// titleTokenSet returns the lowercased token set of a title with
// punctuation and stop tokens stripped, suitable for jaccard comparison.
func titleTokenSet(title string) map[string]struct{} {
	return parseTokens(normalizeTitleTokens(title))
}

func parseTokens(s string) map[string]struct{} {
	tokens := strings.Fields(s)
	out := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		if len(t) <= 2 {
			continue // drop in / on / of / a / the / etc.
		}
		out[t] = struct{}{}
	}
	return out
}

// normalizeTitleTokens lowercases and strips brackets, dates, CVE ids,
// version specifiers like "(<= 0.4.1)", and most punctuation. The
// result is what gets stored in content_index.title_norm.
func normalizeTitleTokens(title string) string {
	t := strings.ToLower(title)
	t = bracketRe.ReplaceAllString(t, " ")
	t = dateRe.ReplaceAllString(t, " ")
	t = cveRegex.ReplaceAllString(t, " ")
	t = regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(t, " ") // version parens
	t = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(t, " ")
	return whitespaceRe.ReplaceAllString(t, " ")
}

// applyCorroborationBoost checks if a CVE has been reported by multiple distinct
// sources and boosts the associated draft's score if it was below 4.5.
func (d *Deduplicator) applyCorroborationBoost(cve string, entries []storage.ContentIndexEntry) {
	// Count distinct sources including the current item (which hasn't been indexed yet,
	// so we rely on the DB count which reflects already-indexed entries plus this new one).
	// The new item's source is different (same-source duplicates return DedupSkip earlier
	// in evaluateCVEOverlap), so the actual distinct count is DB count + 1.
	dbCount, err := d.db.CountDistinctSourcesForCVE(cve)
	if err != nil {
		d.logger.Warn("corroboration count failed", "cve", cve, "error", err)
		return
	}
	// Add 1 for the current (not-yet-indexed) source.
	totalSources := dbCount + 1
	if totalSources < 2 {
		return
	}

	// Find the draft associated with this CVE and boost if score < 4.5.
	// Use the first entry's draft ID (the original draft for this CVE).
	draftID := entries[0].DraftID
	draft, err := d.db.GetDraft(draftID)
	if err != nil {
		d.logger.Warn("corroboration boost: draft lookup failed", "draft_id", draftID, "error", err)
		return
	}
	if draft.Score >= 4.5 {
		return
	}

	if err := d.db.BoostDraftScore(draftID, 0.5, 5.0); err != nil {
		d.logger.Warn("corroboration boost: update failed", "draft_id", draftID, "error", err)
		return
	}
	d.logger.Info("corroboration boost: CVE reported by multiple sources, boosting score",
		"cve", cve, "sources", totalSources, "draft_id", draftID, "old_score", draft.Score)
}

// BuildCVEContext creates a CVEContext snapshot from the item and extraction.
func BuildCVEContext(item scraper.RawItem, extraction *ExtractionResult) CVEContext {
	text := strings.ToLower(item.Title + " " + item.Content)

	ctx := CVEContext{
		HasExploit:         sourceReportsPublicExploit(item),
		HasPatch:           containsAny(text, patchTerms),
		ActiveExploitation: containsAny(text, activeExploitTerms),
		Source:             item.Source,
	}
	if extraction != nil {
		ctx.IOCCount = len(extraction.IOCs)
		ctx.Techniques = extraction.Techniques
	}
	return ctx
}

// containsAny checks if text contains any of the given terms.
func containsAny(text string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}
