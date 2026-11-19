package scraper

import (
	"errors"
	"maps"
	"strings"
	"sync/atomic"
)

// ErrKEVCatalogEmpty reports a KEV download that decoded but listed no CVEs.
// It is refused rather than installed: an empty set would report every CVE
// as not exploited.
var ErrKEVCatalogEmpty = errors.New("CISA KEV catalog lists no CVEs")

// KEVCatalog is the set of CVE IDs in CISA's Known Exploited Vulnerabilities
// catalog, each with the date CISA added it. The CISA KEV source fills it once
// at startup and again on every poll. Until a download succeeds, membership is
// unknown, which is not the same as "not listed". A failed download keeps the
// last good set. A KEVCatalog is safe for concurrent use: refreshes swap in a
// whole new set, so readers never see a partial one.
type KEVCatalog struct {
	// CVE ID to its catalog dateAdded (YYYY-MM-DD), empty when unknown.
	entries atomic.Pointer[map[string]string]
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
	entries := c.entries.Load()
	if entries == nil {
		return false, false
	}
	_, listed = (*entries)[normalizeKEVID(cveID)]
	return listed, true
}

// Len returns the number of CVEs in the loaded set, 0 before the first load.
func (c *KEVCatalog) Len() int {
	if c == nil {
		return 0
	}
	if entries := c.entries.Load(); entries != nil {
		return len(*entries)
	}
	return 0
}

// Entries returns a copy of the loaded set: each listed CVE ID with the date
// CISA added it (empty when the download had none). It is nil before the
// first successful load.
func (c *KEVCatalog) Entries() map[string]string {
	if c == nil {
		return nil
	}
	if entries := c.entries.Load(); entries != nil {
		return maps.Clone(*entries)
	}
	return nil
}

// Replace installs ids as the catalog, without catalog dates. A list with no
// IDs is refused with ErrKEVCatalogEmpty and the current set is kept.
func (c *KEVCatalog) Replace(ids []string) error {
	added := make(map[string]string, len(ids))
	for _, id := range ids {
		added[id] = ""
	}
	return c.ReplaceEntries(added)
}

// ReplaceEntries installs the catalog from CVE IDs and their dateAdded. A set
// with no IDs is refused with ErrKEVCatalogEmpty and the current set is kept.
func (c *KEVCatalog) ReplaceEntries(added map[string]string) error {
	set := make(map[string]string, len(added))
	for id, date := range added {
		if id = normalizeKEVID(id); id != "" {
			set[id] = strings.TrimSpace(date)
		}
	}
	if len(set) == 0 {
		return ErrKEVCatalogEmpty
	}
	c.entries.Store(&set)
	return nil
}

func normalizeKEVID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}
