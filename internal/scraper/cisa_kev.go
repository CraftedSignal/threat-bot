package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const cisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVAdmissionStatement is CISA's criterion for listing a CVE in KEV.
const KEVAdmissionStatement = "CISA adds a CVE to this catalog only when there is reliable evidence that it has been exploited in the wild, which includes attempted as well as successful exploitation."

// CISAKEV scrapes the CISA Known Exploited Vulnerabilities catalog. Every
// download also refreshes its KEVCatalog, the set CVE enrichment reads.
type CISAKEV struct {
	client  *http.Client
	url     string
	catalog *KEVCatalog
}

// NewCISAKEV returns the KEV source. catalog receives the full CVE set on
// every successful download; nil keeps no set.
func NewCISAKEV(catalog *KEVCatalog) *CISAKEV {
	return &CISAKEV{
		client:  &http.Client{Timeout: 30 * time.Second},
		url:     cisaKEVURL,
		catalog: catalog,
	}
}

func (c *CISAKEV) Name() string { return "cisa-kev" }

// Poll downloads the catalog, refreshes the KEV set from it, and returns the
// entries added since.
func (c *CISAKEV) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	catalog, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	return kevItems(catalog, since), nil
}

// LoadCatalog downloads the catalog and refreshes the KEV set without
// producing items, so enrichment has the set before the first poll. On error
// the previous set is kept.
func (c *CISAKEV) LoadCatalog(ctx context.Context) error {
	_, err := c.fetch(ctx)
	return err
}

// fetch downloads and decodes the catalog and installs its CVEs in c.catalog.
// A failed or empty download leaves the installed set alone.
func (c *CISAKEV) fetch(ctx context.Context) (*kevCatalog, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, statusErrorf(resp.StatusCode, "CISA KEV: HTTP %d", resp.StatusCode)
	}

	var catalog kevCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decoding KEV catalog: %w", err)
	}

	added := make(map[string]string, len(catalog.Vulnerabilities))
	for _, vuln := range catalog.Vulnerabilities {
		added[vuln.CVEID] = vuln.DateAdded
	}
	if c.catalog != nil {
		if err := c.catalog.ReplaceEntries(added); err != nil {
			return nil, fmt.Errorf("CISA KEV catalog %q: %w", catalog.CatalogVersion, err)
		}
	} else if len(added) == 0 {
		return nil, fmt.Errorf("CISA KEV catalog %q: %w", catalog.CatalogVersion, ErrKEVCatalogEmpty)
	}
	return &catalog, nil
}

// kevItems turns the catalog entries added since into raw items.
func kevItems(catalog *kevCatalog, since time.Time) []RawItem {
	var items []RawItem
	for _, vuln := range catalog.Vulnerabilities {
		added, err := time.Parse("2006-01-02", vuln.DateAdded)
		if err != nil {
			continue
		}
		if added.Before(since) {
			continue
		}

		// The catalog's admission criterion is the exploitation evidence. The
		// item states it, or no checker could ground exploitation against it.
		content := fmt.Sprintf(
			"CVE: %s\nCatalog: CISA Known Exploited Vulnerabilities (KEV), added %s. %s\nVendor: %s\nProduct: %s\nVulnerability: %s\nDescription: %s\nAction: %s\nDue Date: %s\nRansomware Use: %s\nNotes: %s",
			vuln.CVEID, vuln.DateAdded, KEVAdmissionStatement, vuln.VendorProject, vuln.Product, vuln.VulnerabilityName,
			vuln.ShortDescription, vuln.RequiredAction, vuln.DueDate,
			vuln.KnownRansomwareCampaignUse, vuln.Notes,
		)

		items = append(items, RawItem{
			SourceID:    fmt.Sprintf("cisa-kev:%s", vuln.CVEID),
			Source:      "cisa-kev",
			Title:       fmt.Sprintf("%s - %s %s", vuln.CVEID, vuln.VendorProject, vuln.Product),
			URL:         fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", vuln.CVEID),
			Content:     content,
			PublishedAt: added,
			Metadata: map[string]string{
				"cve":        vuln.CVEID,
				"vendor":     vuln.VendorProject,
				"product":    vuln.Product,
				"ransomware": vuln.KnownRansomwareCampaignUse,
			},
		})
	}
	return items
}

type kevCatalog struct {
	Title           string             `json:"title"`
	CatalogVersion  string             `json:"catalogVersion"`
	DateReleased    string             `json:"dateReleased"`
	Count           int                `json:"count"`
	Vulnerabilities []kevVulnerability `json:"vulnerabilities"`
}

type kevVulnerability struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}
