package pipeline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/llm"
)

// A reference is minted only from the source that the checker sees, and only
// for target bindings accepted by the existing quote/identity validator.
// Selecting it never lets model-generated text become evidence.
type scopedGroundingEvidence struct {
	ID       string   `json:"id"`
	Subjects []string `json:"subjects"`
	Quote    string   `json:"quote"`
}

// The catalogue supplements the full source; cap all serialized metadata so
// long registry entries cannot multiply checker input tokens. Unlisted source
// facts can still use the existing fully validated verbatim-quote path.
const maxOmissionReferenceBytes = 6000

var evidenceSentenceEnd = regexp.MustCompile(`[.!?](?:[ \t]+|$)`)

func scopedOmissionEvidence(source, brief string) []scopedGroundingEvidence {
	source = materialOmissionSource(source)
	subjects := materialOmissionSubjects(brief)
	refs := []scopedGroundingEvidence{}
	seen := map[string]bool{}
	referenceBytes := 2 // JSON array brackets
	add := func(quote string) {
		quote = strings.TrimSpace(quote)
		key := normalizeForQuote(quote)
		if key == "" || seen[key] || len(quote) > 4000 {
			return
		}
		seen[key] = true
		var eligible []string
		for _, subject := range subjects {
			if validateMaterialOmission(groundingIssue{Subject: subject, SourceQuote: quote}, source, brief) == nil {
				eligible = append(eligible, subject)
			}
		}
		if len(eligible) > 0 {
			digest := sha256.Sum256([]byte(quote))
			ref := scopedGroundingEvidence{ID: fmt.Sprintf("src-%x", digest[:8]), Subjects: eligible, Quote: quote}
			encoded, _ := json.Marshal(ref)
			if referenceBytes+len(encoded)+1 > maxOmissionReferenceBytes {
				return
			}
			referenceBytes += len(encoded) + 1
			refs = append(refs, ref)
		}
	}
	for _, line := range strings.Split(source, "\n") {
		var fact cnaSourceFact
		if json.Unmarshal([]byte(line), &fact) == nil && fact.CVEID != "" {
			// The decoded text alone can be identical across CVEs and may not
			// repeat its record identity. Keep the full scoped field through
			// reference deduplication and the downstream repair instruction.
			add(line)
			continue
		}
		start := 0
		for _, end := range evidenceSentenceEnd.FindAllStringIndex(line, -1) {
			add(line[start:end[1]])
			start = end[1]
		}
		add(line[start:])
		// A whole paragraph can carry the subject in an earlier sentence. Retain
		// that attribution option, but never combine disconnected source passages.
		add(line)
	}
	return refs
}

func omissionEvidencePrompt(refs []scopedGroundingEvidence) string {
	data, _ := json.Marshal(refs)
	return "\n\n## Scoped source evidence (JSON)\n" + string(data)
}

const omissionQuoteBinding = "__quote__"

func canonicalOmissionSubject(subject string, subjects []string) (string, bool) {
	if id := normalizeCVEID(subject); id != "" {
		for _, candidate := range subjects {
			if normalizeCVEID(candidate) == id {
				return candidate, true
			}
		}
		return "", false
	}
	key := scopeProductKey(subject)
	if key == "" {
		return "", false
	}
	for _, candidate := range subjects {
		if scopeProductKey(candidate) == key {
			return candidate, true
		}
	}
	return "", false
}

// omissionEvidenceBindings represents a target and reference as one schema
// choice. A plain source_evidence_id enum permits the model to pair a valid
// reference for one product with a different eligible product. When the
// original target is eligible, keep the repair bound to it; only malformed
// original targets may be corrected to another brief target.
func omissionEvidenceBindings(issueSubjects, subjects []string, refs []scopedGroundingEvidence) []string {
	choices := []string{omissionQuoteBinding}
	seen := map[string]bool{omissionQuoteBinding: true}
	usedBytes := len(omissionQuoteBinding)
	const maxBindingBytes = 2 * maxOmissionReferenceBytes
	for _, originalSubject := range issueSubjects {
		eligible := subjects
		if canonical, ok := canonicalOmissionSubject(originalSubject, subjects); ok {
			eligible = []string{canonical}
		}
		for _, ref := range refs {
			for _, subject := range eligible {
				if !containsString(ref.Subjects, subject) {
					continue
				}
				encoded, _ := json.Marshal([]string{subject, ref.ID})
				choice := string(encoded)
				if seen[choice] || usedBytes+len(choice) > maxBindingBytes {
					continue
				}
				choices = append(choices, choice)
				seen[choice] = true
				usedBytes += len(choice)
			}
		}
	}
	return choices
}

func resolveMaterialOmission(issue groundingIssue, source, brief string, refs []scopedGroundingEvidence) (groundingIssue, error) {
	if issue.SourceEvidenceID != "" {
		found := false
		for _, ref := range refs {
			if ref.ID != issue.SourceEvidenceID {
				continue
			}
			if !containsString(ref.Subjects, issue.Subject) {
				return issue, fmt.Errorf("material omission reference does not bind its selected target")
			}
			issue.SourceQuote = ref.Quote
			found = true
			break
		}
		if !found {
			return issue, fmt.Errorf("material omission has an unknown source evidence reference")
		}
	}
	if err := validateMaterialOmission(issue, source, brief); err != nil {
		return issue, err
	}
	eligibleSource := materialOmissionSource(source)
	var fullRecord cnaSourceFact
	if issue.SourceEvidenceID != "" || json.Unmarshal([]byte(issue.SourceQuote), &fullRecord) == nil && fullRecord.CVEID != "" || materialQuoteInProse(issue.SourceQuote, eligibleSource) {
		return issue, nil
	}
	// Decoded text fields are accepted for provider fidelity, but they cannot
	// discard the identity that made them eligible. Bind an unambiguous field
	// back to its complete source record before forming a repair instruction.
	quote := normalizeForQuote(issue.SourceQuote)
	var scopedQuote string
	seen := map[cnaSourceFact]bool{}
	doc := parseBriefFrontmatter(brief)
	for _, line := range strings.Split(eligibleSource, "\n") {
		var fact cnaSourceFact
		if json.Unmarshal([]byte(line), &fact) != nil || fact.CVEID == "" || normalizeForQuote(fact.Text) != quote || seen[fact] {
			continue
		}
		candidate := issue
		candidate.SourceQuote = line
		if !materialQuoteInScopedFact(candidate, eligibleSource, doc) {
			continue
		}
		seen[fact] = true
		if scopedQuote != "" {
			return issue, fmt.Errorf("material omission decoded quote matches multiple scoped primary records; select a scoped source evidence reference")
		}
		scopedQuote = line
	}
	if scopedQuote != "" {
		issue.SourceQuote = scopedQuote
		return issue, validateMaterialOmission(issue, source, brief)
	}
	return issue, nil
}

// This is a deterministic output-contract failure, not a provider outage or
// a factual verdict. Its digest covers the entire request and evidence,
// including source past the checker truncation boundary. The candidate adds
// configured model and policy identity before persisting the hold.
type omissionEvidenceContractError struct{ Digest, Detail string }

func (e *omissionEvidenceContractError) Error() string         { return e.Detail }
func (e *omissionEvidenceContractError) FailureKind() string   { return "omission_evidence_contract" }
func (e *omissionEvidenceContractError) RequestDigest() string { return e.Digest }

func groundingRequestDigest(title, content, brief, prompt, system string, schema *llm.Schema) string {
	data, _ := json.Marshal([]any{title, content, brief, prompt, system, schema, materialOmissionEvidenceSystem, llm.MustSchemaOf[materialOmissionEvidenceReport](), processingPolicyVersion})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
