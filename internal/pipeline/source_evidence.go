package pipeline

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/sigma"
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
	primary := p.verifiedPrimaryEvidence(ids)
	if primary == "" {
		return source
	}
	return primary + "\nOriginal source:\n" + source
}

// Both generation and independent grounding use this bounded representation.
// Every record retains its CVE/product identity; truncation never splices facts.
func (p *Pipeline) verifiedPrimaryEvidence(ids []string) string {
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
		return ""
	}
	if omitted {
		evidence.WriteString("Coverage incomplete: size limits or cross-record references omitted source fields. Do not infer missing facts.\n")
	}
	return "Verified primary CVE evidence. Keep each fact attached to its CVE and product; a record-wide solution is not a fix for every product. Resolve conflicts through explicit uncertainty or editorial review.\n" + evidence.String()
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

// Bound external verification before generation; independent grounding still
// verifies generated targets that fall outside this initial lookup budget.
const maxAssemblyEvidenceCVEs = 32
const assemblyEvidenceIncomplete = "Initial primary evidence coverage incomplete: some source CVEs could not be checked or exceeded the lookup budget. Do not infer their applicability or remediation.\n"

func (p *Pipeline) assembleWithVerifiedEvidence(ctx context.Context, item scraper.RawItem, extraction *ExtractionResult, rules []sigma.Rule) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var primary string
	if p.cveVerifier != nil {
		ids := assemblyEvidenceCVEs(item, extraction)
		incomplete := len(ids) > maxAssemblyEvidenceCVEs
		ids = ids[:min(len(ids), maxAssemblyEvidenceCVEs)]
		for _, id := range ids {
			if _, err := p.cveVerifier.checkCVE(ctx, id); err != nil {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				incomplete = true
			}
			if meta := p.cveVerifier.GetMeta(id); meta == nil || meta.CNAUnavailable || meta.Verification.Status == "unavailable" {
				incomplete = true
			}
		}
		primary = p.verifiedPrimaryEvidence(ids)
		if incomplete {
			primary += assemblyEvidenceIncomplete
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return p.assembler.assemble(ctx, item, extraction, rules, primary)
}

// Prioritize source-declared subjects and confirmed extraction subjects before
// background mentions. Extraction alone never authorizes a primary lookup.
func assemblyEvidenceCVEs(item scraper.RawItem, extraction *ExtractionResult) []string {
	asserted := map[string]bool{}
	for _, id := range sourceCVEPattern.FindAllString(item.Title+"\n"+groundingSource(item), -1) {
		asserted[strings.ToUpper(id)] = true
	}
	var ids []string
	add := func(group []string) {
		group = append([]string(nil), group...)
		sort.Strings(group)
		for _, raw := range group {
			id := strings.ToUpper(raw)
			if asserted[id] {
				ids = append(ids, id)
				delete(asserted, id)
			}
		}
	}
	// Dedicated feed identity outranks background mentions, including those in
	// a long title; otherwise those mentions can exhaust the lookup budget.
	if item.Source == "nvd" || item.Source == "ghsa" || item.Source == "cisa-kev" {
		add(sourceCVEPattern.FindAllString(item.Metadata["cve_id"]+" "+item.Metadata["cve"]+" "+item.Metadata["cves"], -1))
	}
	add(confirmedExtractionCVEs(item, extraction))
	add(subjectCVEs(item))
	var remaining []string
	for id := range asserted {
		remaining = append(remaining, id)
	}
	add(remaining)
	return ids
}
