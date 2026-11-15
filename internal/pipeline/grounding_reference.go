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
			add(fact.Text)
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
	return issue, validateMaterialOmission(issue, source, brief)
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
