package pipeline

import (
	"encoding/json"
	"regexp"
	"strings"
)

// The checker's own contract requires a material omission's source_quote to
// contain both its subject and the missing fact. In production it routinely
// demanded release versions while quoting a sentence that states none (a BSI
// summary naming only the product, a model list without firmware numbers).
// No repair can add a version the source never states: the code forbids
// inventing one, so every such finding ended in quarantine after a paid
// repair and recheck. These helpers enforce the contract in code.

// versionOmissionFields are the brief fields a missing affected range, fixed
// release or patch level is written into. Omissions about other fields
// (severity, exploitation, CVEs) are never dropped by the version rules.
var versionOmissionFields = map[string]bool{
	"affected_products": true,
	"affected_os":       true,
	"recommendation":    true,
	"content":           true,
	"mitigation_plan":   true,
	"action_plan":       true,
}

// versionDemandPattern recognises a finding whose missing fact is a version,
// a version range, a fixed release or a patch level.
var versionDemandPattern = regexp.MustCompile(`(?i)\bversion|\b(?:affected|vulnerable|fixed|patched|minimum|release)\s+(?:ranges?|releases?|builds?|firmware)\b|\bfixed\s+in\b|\bpatch[- ]?levels?\b|\bbuild\s+numbers?\b|\brelease\s+(?:branch(?:es)?|streams?|trains?)\b`)

// nonVersionOmissionPattern marks findings that concern another fact even when
// they mention versions: prerequisites, a "latest release" instruction that
// needs no number, or an explicit statement that no fix exists. Those facts
// can be true without any version and must keep blocking publication.
var nonVersionOmissionPattern = regexp.MustCompile(`(?i)authenticat|privileg|user interaction|\binteract|dependenc|prerequisite|configur|\blatest\b|\bnewest\b|most recent|\bno\s+(?:fix|fixes|fixed|patch|patches|patched|update|updates)\b|\bnot\s+(?:yet\s+)?(?:been\s+)?(?:fixed|patched)\b|unpatched|ungepatcht|unfixed|end[- ]of[- ](?:life|support)|\beol\b|no longer (?:supported|maintained)|workaround|\bwill not\b|\bwon't\b|kein(?:e|en)?\s+(?:patch|update|fix|korrektur)|pas de correctif|aucun correctif`)

// Identifiers carry digits without stating a release: CVE, GHSA and CWE IDs
// and national advisory numbers (WID-SEC-2026-4772, RHSA-2026:1234).
var (
	ghsaIDPattern     = regexp.MustCompile(`(?i)\bGHSA(?:-[0-9a-z]{4}){3}\b`)
	cweIDPattern      = regexp.MustCompile(`(?i)\b(?:CWE|CAPEC)-\d+\b`)
	advisoryIDPattern = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{2,4}(?:[-:][0-9A-Za-z]+)+\b`)
)

// versionTokenPattern matches anything that could state a release: dotted or
// epoch versions (1.2, 1.2.3-rc1, 2024.1.131, 0:2.56.4-1.el8_10), v2, R81,
// SP2, CU23, KB5034441, build 1234, 22H2 and bare release numbers ("before
// 161"). Model names such as GL-MT3000 or RM10 do not match: their digits
// are attached to letters.
var versionTokenPattern = regexp.MustCompile(`(?i)\d+(?:[.:_]\d+)+|\bv\d+|\b(?:R|SP|CU|KB)\d+\b|\bbuild\s*\d+|\b\d{2}H\d\b|\b\d+\b`)

// commitIDPattern matches abbreviated or full Git commit IDs, which bound
// releases in kernel and rolling-release records.
var commitIDPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{7,40}\b`)

func groundingFieldHead(field string) string {
	field = strings.ToLower(strings.TrimSpace(field))
	if i := strings.IndexAny(field, ".["); i >= 0 {
		field = field[:i]
	}
	return strings.TrimSpace(field)
}

// omissionDemandsVersion reports whether a material omission asks for a
// version, range, fixed release or patch level, judged from the checker's
// structured finding: its field and its stated reason. A quote announcing
// that no fix exists keeps the finding, whatever the reason says.
func omissionDemandsVersion(issue groundingIssue) bool {
	if !versionOmissionFields[groundingFieldHead(issue.Field)] {
		return false
	}
	if !versionDemandPattern.MatchString(issue.Reason) || nonVersionOmissionPattern.MatchString(issue.Reason) {
		return false
	}
	return !nonVersionOmissionPattern.MatchString(quotedFactText(issue.SourceQuote))
}

// quotedFactText is the text a quote states. A structured primary record is
// judged by its product and decoded value, not its JSON keys or record ID.
func quotedFactText(quote string) string {
	var fact cnaSourceFact
	if json.Unmarshal([]byte(quote), &fact) == nil && fact.CVEID != "" {
		return fact.Product + "\n" + fact.Text
	}
	return quote
}

// quoteStatesVersion reports whether a source quote contains any token that
// could state a release. It errs towards true: a false positive only keeps
// today's behaviour, a false negative would drop a real omission.
func quoteStatesVersion(quote string) bool {
	text := quotedFactText(quote)
	text = groundingURLPattern.ReplaceAllString(text, " ")
	for _, id := range []*regexp.Regexp{sourceCVEPattern, ghsaIDPattern, cweIDPattern, advisoryIDPattern} {
		text = id.ReplaceAllString(text, " ")
	}
	if versionTokenPattern.MatchString(text) {
		return true
	}
	for _, id := range commitIDPattern.FindAllString(text, -1) {
		if strings.ContainsAny(id, "0123456789") {
			return true
		}
	}
	return false
}

// primaryEvidenceFacts returns the structured CVE record facts of the
// verified primary evidence the checker received, in order.
func primaryEvidenceFacts(source string) []cnaSourceFact {
	var facts []cnaSourceFact
	primary := false
	for _, line := range strings.Split(source, "\n") {
		switch {
		case strings.HasPrefix(line, "Verified primary CVE evidence."):
			primary = true
			continue
		case primary && line == "Original source:":
			primary = false
		}
		if !primary {
			continue
		}
		var fact cnaSourceFact
		if json.Unmarshal([]byte(line), &fact) == nil && fact.CVEID != "" {
			facts = append(facts, fact)
		}
	}
	return facts
}

// quotedPrimaryFact returns the primary record a material omission cites: the
// complete record line, or one record whose decoded text the quote repeats.
func quotedPrimaryFact(quote string, facts []cnaSourceFact) (cnaSourceFact, bool) {
	var quoted cnaSourceFact
	if json.Unmarshal([]byte(quote), &quoted) == nil && quoted.CVEID != "" {
		for _, fact := range facts {
			if fact == quoted {
				return fact, true
			}
		}
		return cnaSourceFact{}, false
	}
	want := normalizeForQuote(quote)
	var match cnaSourceFact
	found := false
	for _, fact := range facts {
		if normalizeForQuote(fact.Text) != want {
			continue
		}
		if found && fact != match {
			return cnaSourceFact{}, false
		}
		match, found = fact, true
	}
	return match, found
}

// primaryScopeGapRecorded reports whether a material omission cites a primary
// affected record whose release scope cannot be mapped safely and whose
// machine gap the brief already records in source_assessment.gaps. The
// checker is told not to report that unavailable range again; this enforces
// it. The gap is rebuilt with the same helper and grouping that added it, so
// it matches only for the same CVE and product. A record from which the
// release-bound rule derives a fixed release is never exempt.
func primaryScopeGapRecorded(issue groundingIssue, source string, doc map[string]any) (cnaSourceFact, bool) {
	facts := primaryEvidenceFacts(source)
	quoted, ok := quotedPrimaryFact(issue.SourceQuote, facts)
	if !ok || quoted.Kind != "affected" {
		return quoted, false
	}
	var entry cnaAffectedEntry
	if json.Unmarshal([]byte(quoted.Text), &entry) != nil || len(entry.exclusiveReleaseBounds()) > 0 {
		return quoted, false
	}
	assessment, _ := asStringMap(doc["source_assessment"])
	recorded := map[string]bool{}
	for _, gap := range yamlStringList(assessment["gaps"]) {
		recorded[normalizeForQuote(normalizePublicProse(gap))] = true
	}
	if len(recorded) == 0 {
		return quoted, false
	}
	key := primaryScopeGapKey(quoted, entry)
	var group []cnaSourceFact
	for _, fact := range facts {
		var other cnaAffectedEntry
		if fact.Kind == "affected" && json.Unmarshal([]byte(fact.Text), &other) == nil && primaryScopeGapKey(fact, other) == key {
			group = append(group, fact)
		}
	}
	products := nonEmptyTrimmed(yamlStringList(doc["affected_products"]))
	for _, gap := range unresolvedPrimaryScopeGaps(primaryRecordFacts{Included: group}, products) {
		if recorded[normalizeForQuote(normalizePublicProse(gap))] {
			return quoted, true
		}
	}
	return quoted, false
}

// primaryScopeGapKey mirrors unresolvedPrimaryScopeGaps' grouping: the CVE
// and the record's product (falling back to the affected entry's product).
func primaryScopeGapKey(fact cnaSourceFact, entry cnaAffectedEntry) string {
	product := strings.TrimSpace(fact.Product)
	if product == "" {
		product = strings.TrimSpace(entry.Product)
	}
	return strings.ToUpper(fact.CVEID) + "\x00" + scopeProductKey(product)
}
