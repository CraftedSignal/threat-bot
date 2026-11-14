package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/cna"
	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

const vendorInferSystemPrompt = `You are a vulnerability analyst. From the threat brief, identify the AFFECTED vendor(s) and product(s) — the software or service that is vulnerable, not detection tools.

Rules:
- Use canonical vendor names, no version numbers (e.g. "Foxit", "Microsoft", "Cisco").
- Use the most common/corporate name for the vendor, not a product or project name. For example, use "Flowise" rather than "FlowiseAI".
- Infer the specific affected product when the vendor's product line and the vulnerability context make it clear. Example: a Foxit vulnerability involving PDF page/form objects affects "Foxit PDF Reader" and "Foxit PDF Editor".
- Do not repeat the vendor name inside the product name; use the product name alone (e.g. "Flowise" not "FlowiseAI Flowise").
- For sub-components or nodes of a product (e.g. "CSVAgent" in Flowise), prefer the parent product name unless the vulnerability is strictly limited to a clearly distinct, separately distributed component.
- A reference URL's hostname often identifies the vendor (e.g. a foxit.com advisory ⇒ vendor Foxit) — use it, but still never invent a product that isn't supported by the text.
- Never invent version numbers, CVE-specific claims, or products unrelated to the brief.
- If you can identify the vendor but not a specific product, use the vendor name as the product.
- Ground every answer in the provided text. If no vendor is identifiable, return empty lists.

Respond ONLY with JSON: {"affected_vendors": [], "affected_products": []}`

const vendorInferPrompt = `Identify affected vendor(s) product(s):

Title: %s

Content:
%s`

type vendorProductResult struct {
	AffectedVendors  []string `json:"affected_vendors"`
	AffectedProducts []string `json:"affected_products"`
}

// InferVendorProduct asks the LLM to identify the affected vendor(s) and
// product(s) for a threat brief, permitting grounded inference of the
// product when the source did not name one. references are the brief's
// source/citation URLs (e.g. the item URL and any linked advisories); their
// hostnames are a strong vendor signal, so when non-empty they are appended
// to the prompt as a "Reference URLs" section. It returns sanitized,
// de-duplicated vendor and product lists.
func InferVendorProduct(ctx context.Context, client llm.Client, title, content string, references []string) (vendors, products []string, err error) {
	c := content
	if len(c) > 12000 {
		c = truncateUTF8(c, 12000)
	}
	prompt := fmt.Sprintf(vendorInferPrompt, title, c) + referencesSection(references)

	var res vendorProductResult
	if err := client.GenerateJSON(ctx, prompt, vendorInferSystemPrompt, &res); err != nil {
		return nil, nil, fmt.Errorf("vendor/product inference LLM call: %w", err)
	}
	return CleanAffectedList(res.AffectedVendors), CleanAffectedList(res.AffectedProducts), nil
}

// referencesSection renders the "Reference URLs" prompt section from a list
// of reference URLs, dropping empties. Returns "" when no non-empty
// reference is present, so the section is omitted from the prompt entirely.
func referencesSection(references []string) string {
	var nonEmpty []string
	for _, r := range references {
		if r != "" {
			nonEmpty = append(nonEmpty, r)
		}
	}
	if len(nonEmpty) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\nReference URLs:\n")
	for _, r := range nonEmpty {
		b.WriteString("- ")
		b.WriteString(r)
		b.WriteString("\n")
	}
	return b.String()
}

// applyVendorProductFallback fills empty affected vendor/product on a CVE brief
// by inferring them from the item. Returns true if it changed the extraction.
// Only fires for CVE-bearing items where both fields are empty — exactly the
// briefs isGenericCVEBundleBrief would otherwise suppress. Ordinary LLM errors
// are logged and reported as "did not fire"; parent cancellation stays quiet
// so the caller can stop before persisting the item.
func applyVendorProductFallback(ctx context.Context, client llm.Client, logger *slog.Logger, item scraper.RawItem, extraction *ExtractionResult) bool {
	if client == nil || extraction == nil {
		return false
	}
	if !cveRe.MatchString(item.Title) && !cveRe.MatchString(item.Content) {
		return false
	}
	if hasMeaningfulEntry(extraction.AffectedVendors) || hasMeaningfulEntry(extraction.AffectedProducts) {
		return false
	}
	// NVD items carry the CVE's own vulnerable CPEs; they name the affected
	// vendor/product authoritatively, so use them before asking the LLM.
	if vendors, products := vendorProductFromItemCPEs(item); len(vendors) > 0 || len(products) > 0 {
		extraction.AffectedVendors = vendors
		extraction.AffectedProducts = products
		logger.Info("derived vendor/product from NVD CPEs",
			"source_id", item.SourceID, "vendors", vendors, "products", products)
		return true
	}
	// scraper.RawItem carries only a single source URL (no separate
	// References list), so that's the whole reference set available here.
	var references []string
	if item.URL != "" {
		references = append(references, item.URL)
	}
	vendors, products, err := InferVendorProduct(ctx, client, item.Title, item.Content, references)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return false
		}
		logger.Warn("vendor/product inference failed", "source_id", item.SourceID, "error", err)
		return false
	}
	if len(vendors) == 0 && len(products) == 0 {
		return false
	}
	extraction.AffectedVendors = vendors
	extraction.AffectedProducts = products
	logger.Info("inferred vendor/product for generic CVE brief",
		"source_id", item.SourceID, "vendors", vendors, "products", products)
	return true
}

// vendorProductFromItemCPEs derives vendor and product names from the NVD
// CPE list recorded on the item's metadata (see nvdItemMetadata).
func vendorProductFromItemCPEs(item scraper.RawItem) (vendors, products []string) {
	for _, cpe := range strings.Fields(item.Metadata["cpes"]) {
		v, p := cpeVendorProduct(cpe)
		if v != "" && v != "*" && v != "-" {
			vendors = append(vendors, v)
		}
		if p != "" && p != "*" && p != "-" {
			products = append(products, p)
		}
	}
	return CleanAffectedList(vendors), CleanAffectedList(products)
}

// rejectGenericCVEBrief reports whether a brief should be dropped for naming
// a CVE without any affected vendor/product. Sigma-sourced items are exempt:
// the rule itself is the actionable artifact (logsource-scoped detection).
func rejectGenericCVEBrief(item scraper.RawItem, briefYAML string) bool {
	if item.SigmaRule != nil {
		return false
	}
	return isGenericCVEBrief(briefYAML)
}

// vendorFromCNA names the vendor behind an NVD sourceIdentifier such as
// security@grafana.com, using the registrable domain label. It returns "" for
// generic or third-party CNAs, which say nothing about which vendor owns a CVE.
func vendorFromCNA(sourceIdentifier string) string {
	domain := cna.VendorDomain(sourceIdentifier)
	if domain == "" || thirdPartyCNALocalPart(sourceIdentifier) {
		return ""
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return ""
	}
	sld := labels[len(labels)-2]
	switch sld {
	case "co", "com", "org", "net", "gov", "ac", "or", "ne":
		if len(labels) < 3 {
			return ""
		}
		sld = labels[len(labels)-3]
	}
	if sld == "" {
		return ""
	}
	return strings.ToUpper(sld[:1]) + sld[1:]
}

// backfillAffectedFromSources fills empty affected_vendors / affected_products
// in an assembled brief. applyVendorProductFallback only fills the extraction
// struct, but rejectGenericCVEBrief reads the assembled YAML, so a value the
// assembler dropped must be restored from every source, in order: the
// extraction, the NVD CPEs, then the NVD CNA. It returns the brief and the
// stages that supplied a value (empty when nothing changed). Briefs that are
// not generic CVE briefs are returned untouched.
func backfillAffectedFromSources(item scraper.RawItem, extraction *ExtractionResult, briefYAML string) (string, []string) {
	if item.SigmaRule != nil || !isGenericCVEBrief(briefYAML) {
		return briefYAML, nil
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil || doc == nil {
		return briefYAML, nil
	}
	type stage struct {
		name              string
		vendors, products []string
	}
	var stages []stage
	if extraction != nil {
		stages = append(stages, stage{"extraction", CleanAffectedList(extraction.AffectedVendors), CleanAffectedList(extraction.AffectedProducts)})
	}
	cpeVendors, cpeProducts := vendorProductFromItemCPEs(item)
	stages = append(stages, stage{"nvd_cpes", cpeVendors, cpeProducts})
	var cna []string
	if v := vendorFromCNA(item.Metadata["source_identifier"]); v != "" {
		cna = []string{v}
	}
	stages = append(stages, stage{"nvd_cna", cna, nil})

	has := func(key string) bool {
		list, _ := doc[key].([]any)
		var ss []string
		for _, e := range list {
			ss = append(ss, fmt.Sprint(e))
		}
		return hasMeaningfulEntry(ss)
	}
	var used []string
	for _, s := range stages {
		changed := false
		if !has("affected_vendors") && hasMeaningfulEntry(s.vendors) {
			doc["affected_vendors"] = s.vendors
			changed = true
		}
		if !has("affected_products") && hasMeaningfulEntry(s.products) {
			doc["affected_products"] = s.products
			changed = true
		}
		if changed {
			used = append(used, s.name)
		}
	}
	if len(used) == 0 {
		return briefYAML, nil
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML, nil
	}
	return string(out), used
}
