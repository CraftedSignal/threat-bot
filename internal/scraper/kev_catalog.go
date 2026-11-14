package scraper

import (
	"errors"
	"strings"
	"sync/atomic"
)

// ErrKEVCatalogEmpty reports a KEV download that decoded but listed no CVEs.
// It is refused rather than installed: an empty set would report every CVE
// as not exploited.
var ErrKEVCatalogEmpty = errors.New("CISA KEV catalog lists no CVEs")

// KEVCatalog is the set of CVE IDs in CISA's Known Exploited Vulnerabilities
// catalog. The CISA KEV source fills it once at startup and again on every
// poll. Until a download succeeds, membership is unknown, which is not the
// same as "not listed". A failed download keeps the last good set. A
// KEVCatalog is safe for concurrent use: refreshes swap in a whole new set,
// so readers never see a partial one.
type KEVCatalog struct {
	ids atomic.Pointer[map[string]struct{}]
}

// NewKEVCatalog returns a catalog with no set loaded yet.
func NewKEVCatalog() *KEVCatalog { return &KEVCatalog{} }

// Lookup reports whether cveID is in the catalog. known is false while no
// download has succeeded (or c is nil); listed is then false as well and means
// nothing.
func (c *KEVCatalog) Lookup(cveID string) (listed, known bool) {
	if c == nil {
		return false, false
	}
	ids := c.ids.Load()
	if ids == nil {
		return false, false
	}
	_, listed = (*ids)[normalizeKEVID(cveID)]
	return listed, true
}

// Len returns the number of CVEs in the loaded set, 0 before the first load.
func (c *KEVCatalog) Len() int {
	if c == nil {
		return 0
	}
	if ids := c.ids.Load(); ids != nil {
		return len(*ids)
	}
	return 0
}

// Replace installs ids as the catalog. A list with no IDs is refused with
// ErrKEVCatalogEmpty and the current set is kept.
func (c *KEVCatalog) Replace(ids []string) error {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id = normalizeKEVID(id); id != "" {
			set[id] = struct{}{}
		}
	}
	if len(set) == 0 {
		return ErrKEVCatalogEmpty
	}
	c.ids.Store(&set)
	return nil
}

func normalizeKEVID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}
