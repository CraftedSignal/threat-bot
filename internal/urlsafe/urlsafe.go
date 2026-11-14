// Package urlsafe guards outbound fetches against SSRF. It lives in its own
// leaf package because both internal/pipeline (article enrichment) and
// internal/scraper (shortener resolution) need it, and scraper cannot import
// pipeline — pipeline already imports scraper.
package urlsafe

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

var (
	ipv6GlobalUnicastSpace = netip.MustParsePrefix("2000::/3")
	nonPublicIPPrefixes    = mustParsePrefixes([]string{
		// IPv4 unspecified, private, shared, loopback and link-local ranges.
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
		// IPv4 special-purpose, documentation, benchmarking and reserved ranges.
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		// IPv6 translation, discard, protocol-assignment, tunnel and documentation ranges.
		"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
		"fc00::/7", "fe80::/10", "ff00::/8",
	})
)

// IsPublicHTTPURL validates that a URL is safe to fetch. It blocks non-HTTP
// schemes and IPs outside public unicast space, including private, shared,
// link-local, documentation, benchmark, translation and reserved ranges.
func IsPublicHTTPURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Hostname() == "" {
		return false
	}

	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return IsPublicIP(ip)
	}

	// Hostname (not an IP). Resolve and verify none of the addresses are
	// internal. Also block common internal names.
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(host, ".local") {
		return false
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		// Cannot resolve safely: deny.
		return false
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && !IsPublicIP(ip) {
			return false
		}
	}
	return true
}

// IsPublicIP reports whether ip is routable on the public internet.
func IsPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	if addr.Is6() && !ipv6GlobalUnicastSpace.Contains(addr) {
		return false
	}
	for _, prefix := range nonPublicIPPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func mustParsePrefixes(raw []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
