package pipeline

import (
	"strings"

	"github.com/craftedsignal/threat-bot/internal/cna"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// nvdContradictsVendor reports whether NVD's own data for an NVD-sourced item's
// CVEs positively names a different vendor than the LLM-extracted one. The
// extraction alone is not trusted: an Android CVE was once routed into the
// Microsoft roundup on an LLM vendor guess. Data comes from the NVD item's
// metadata, falling back to the cached NVD record; with no data the extraction
// is kept (no new NVD requests). Non-NVD sources are unaffected.
func (p *Pipeline) nvdContradictsVendor(item scraper.RawItem, extraction *ExtractionResult, vendor string) bool {
	if strings.ToLower(strings.TrimSpace(item.Source)) != "nvd" || extraction == nil {
		return false
	}
	term := normalizeVendorName(vendor)
	for _, cve := range extraction.CVEs {
		meta := nvdMetaForItem(item, cve)
		if meta == nil && p.cveVerifier != nil {
			meta = p.cveVerifier.GetMeta(cve)
		}
		if meta != nil && nvdMetaContradictsVendor(meta, term) {
			return true
		}
	}
	return false
}

// nvdMetaForItem builds vendor evidence from the NVD scraper item's metadata
// when it is for this CVE.
func nvdMetaForItem(item scraper.RawItem, cve string) *CVEMeta {
	if !strings.EqualFold(item.Metadata["cve"], cve) {
		return nil
	}
	cna := strings.TrimSpace(item.Metadata["source_identifier"])
	cpes := strings.Fields(item.Metadata["cpes"])
	if cna == "" && len(cpes) == 0 {
		return nil
	}
	return &CVEMeta{SourceIdentifier: cna, CPEs: cpes}
}

// cpeVendorProductAliases lists the exact normalised "vendor:product" CPE pairs
// that identify a roundup vendor whose CPE vendor field differs from its name.
// Keyed by normalised roundup vendor.
var cpeVendorProductAliases = map[string]map[string]bool{
	"android": {"google:android": true},
}

// thirdPartyCNALocalPart reports CNA identifiers that sit on a vendor domain
// but are independent research CNAs (e.g. talos-cna@cisco.com).
func thirdPartyCNALocalPart(id string) bool {
	i := strings.LastIndex(id, "@")
	if i < 0 {
		return false
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(id[:i])), "talos")
}

// nvdMetaContradictsVendor: CPEs are the strongest evidence; when there are
// none the CNA decides, but only when it is itself a different patch-cycle
// vendor. Third-party CNAs (CISA ICS, ZDI, GitHub, VulDB...) assign CVEs for
// any vendor and say nothing about ownership. No evidence means no
// contradiction.
func nvdMetaContradictsVendor(meta *CVEMeta, vendorTerm string) bool {
	if vendorTerm == "" {
		return false
	}
	if len(meta.CPEs) > 0 {
		for _, cpe := range meta.CPEs {
			v, prod := cpeVendorProduct(cpe)
			// Exact matches only; no substrings (samsung:android,
			// acme:pineapple must not agree).
			if normalizeVendorName(v) == vendorTerm ||
				cpeVendorProductAliases[vendorTerm][normalizeVendorName(v)+":"+normalizeVendorName(prod)] {
				return false
			}
		}
		return true
	}
	domain := cna.Domain(meta.SourceIdentifier)
	if domain == "" || cna.IsNonVendor(domain) || thirdPartyCNALocalPart(meta.SourceIdentifier) {
		return false
	}
	identified := false
	labels := strings.Split(domain, ".")
	sld := ""
	if len(labels) >= 2 {
		sld = labels[len(labels)-2]
	}
	for v := range patchCycleVendors {
		isThis := hostnameMatchesVendor("https://"+domain, v) ||
			(sld != "" && normalizeVendorName(v) == normalizeVendorName(sld))
		if !isThis {
			continue
		}
		identified = true
		googleFamily := (v == "google" || v == "android") &&
			(vendorTerm == "google" || vendorTerm == "android")
		if googleFamily || vendorTerm == normalizeVendorName(v) {
			return false
		}
	}
	return identified
}
