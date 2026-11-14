package pipeline

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// groundingEvidence supplements only identities already asserted by the source
// and present in the brief. Merely verifying an invented CVE must never make it
// part of the source. Primary fields precede long article text so truncation
// cannot silently discard the affected range or fixed release.
func (p *Pipeline) groundingEvidence(item scraper.RawItem, briefYAML string) string {
	source := groundingSource(item)
	if p.cveVerifier == nil {
		return source
	}
	targets := groundingTargetCVEs(parseBriefFrontmatter(briefYAML))
	asserted := map[string]bool{}
	for _, id := range sourceCVEPattern.FindAllString(item.Title+"\n"+source, -1) {
		asserted[strings.ToUpper(id)] = true
	}
	var ids []string
	for id := range targets {
		if asserted[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var evidence strings.Builder
	omitted := false
	add := func(line string) {
		if evidence.Len()+len(line)+1 > maxCNAEvidenceBytes-512 {
			omitted = true
			return
		}
		evidence.WriteString(line)
		evidence.WriteByte('\n')
	}
	for _, id := range ids {
		meta := p.cveVerifier.GetMeta(id)
		if meta == nil || !meta.Exists || meta.Verification.Status != "verified" {
			continue
		}
		add("CVE Program source for " + id + ": https://cveawg.mitre.org/api/cve/" + id)
		for _, fact := range meta.CNAFacts {
			if fact.CVEID != id {
				omitted = true
				continue
			}
			crossRecord := false
			for _, cited := range sourceCVEPattern.FindAllString(fact.Product+"\n"+fact.Text, -1) {
				if !strings.EqualFold(cited, id) {
					crossRecord = true
				}
			}
			if crossRecord {
				omitted = true
				continue
			}
			raw, err := json.Marshal(fact)
			if err == nil {
				add(string(raw))
			}
		}
		gap := meta.CNAGap
		if len(meta.CNAFacts) == 0 && gap == "" {
			gap = "unknown: primary applicability and remediation coverage has not been established"
		}
		if gap != "" {
			add(id + " coverage: " + gap)
		}
	}
	if evidence.Len() == 0 {
		return source
	}
	if omitted {
		evidence.WriteString("Coverage incomplete: size limits or cross-record references omitted source fields. Do not infer missing facts.\n")
	}
	return "Verified primary CVE evidence. Keep each fact attached to its CVE and product; a record-wide solution is not a fix for every product. Resolve conflicts through explicit uncertainty or editorial review.\n" + evidence.String() + "\nOriginal source:\n" + source
}

// Generated briefs do not yet carry the pipeline-owned cves list. Narrative
// identities are eligible too; IDs in slugs, URLs or verification bookkeeping
// alone cannot establish a grounding target.
func groundingTargetCVEs(doc map[string]any) map[string]bool {
	ids := briefCVEIDs(doc)
	for _, field := range []string{"title", "summary", "content"} {
		for _, id := range sourceCVEPattern.FindAllString(publicationString(doc[field]), -1) {
			ids[strings.ToUpper(id)] = true
		}
	}
	return ids
}
