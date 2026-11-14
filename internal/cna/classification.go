// Package cna centralizes classification of NVD source identifiers. Some
// CNAs coordinate vulnerabilities across vendors, so their domains cannot by
// themselves establish affected-vendor ownership.
package cna

import "strings"

var nonVendorDomains = map[string]struct{}{
	"mitre.org": {}, "nist.gov": {}, "cisa.gov": {}, "github.com": {},
	"vuldb.com": {}, "zerodayinitiative.com": {}, "hackerone.com": {},
	"huntr.dev": {}, "patchstack.com": {}, "wordfence.com": {}, "wpscan.com": {},
	"jpcert.or.jp": {}, "cert.org": {}, "certcc.org": {}, "cert.pl": {}, "icscert.gov": {},
	"redhat.com": {}, "debian.org": {}, "openwall.com": {}, "snyk.io": {},
	"sonatype.com": {}, "vulncheck.com": {}, "mozilla.org": {},
}

// Domain returns the normalized domain portion of an NVD source identifier.
// It accepts email-style identifiers (security@example.com) and bare domains.
func Domain(sourceIdentifier string) string {
	id := strings.ToLower(strings.TrimSpace(sourceIdentifier))
	if at := strings.LastIndex(id, "@"); at >= 0 {
		id = id[at+1:]
	}
	id = strings.TrimPrefix(strings.TrimSuffix(id, "."), "www.")
	if !strings.Contains(id, ".") {
		return ""
	}
	return id
}

// IsNonVendor reports whether domain is a generic coordinator or third-party
// CNA whose source domain is not reliable affected-vendor evidence.
func IsNonVendor(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if _, ok := nonVendorDomains[domain]; ok {
		return true
	}
	for excluded := range nonVendorDomains {
		if strings.HasSuffix(domain, "."+excluded) {
			return true
		}
	}
	return false
}

// VendorDomain returns a source domain only when it is curated as
// vendor-specific rather than a coordinator or third-party CNA.
func VendorDomain(sourceIdentifier string) string {
	domain := Domain(sourceIdentifier)
	if domain == "" || IsNonVendor(domain) {
		return ""
	}
	return domain
}
