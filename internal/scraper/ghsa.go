package scraper

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const ghsaAPIURL = "https://api.github.com/advisories"

// GHSA scrapes GitHub Security Advisories for high/critical vulnerabilities.
type GHSA struct {
	client  *http.Client
	tokenFn func() string
}

func NewGHSA(tokenFn func() string) *GHSA {
	return &GHSA{
		client:  &http.Client{Timeout: 30 * time.Second},
		tokenFn: tokenFn,
	}
}

func (g *GHSA) Name() string { return "ghsa" }

func (g *GHSA) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	// GitHub API only accepts a single severity value, so we query twice.
	var allItems []RawItem
	for _, severity := range []string{"critical", "high"} {
		items, err := g.pollSeverity(ctx, since, severity)
		if err != nil {
			return nil, fmt.Errorf("GHSA %s: %w", severity, err)
		}
		allItems = append(allItems, items...)
	}
	return allItems, nil
}

func (g *GHSA) pollSeverity(ctx context.Context, since time.Time, severity string) ([]RawItem, error) {
	sinceDate := since.UTC().Format("2006-01-02")
	url := fmt.Sprintf("%s?type=reviewed&severity=%s&published=>=%s&per_page=100",
		ghsaAPIURL, severity, sinceDate)
	return g.pollSeverityFrom(ctx, since, severity, url)
}

func (g *GHSA) pollSeverityFrom(ctx context.Context, since time.Time, severity, url string) ([]RawItem, error) {
	var allAdvisories []ghsaAdvisory
	for url != "" {
		advisories, nextURL, err := fetchGitHubPage[[]ghsaAdvisory](ctx, g.client, g.tokenFn(), url)
		if err != nil {
			return nil, fmt.Errorf("GHSA API: %w", err)
		}
		allAdvisories = append(allAdvisories, advisories...)
		url = nextURL
	}

	var items []RawItem
	for _, adv := range allAdvisories {
		sev := strings.ToLower(adv.Severity)
		published, _ := time.Parse(time.RFC3339, adv.PublishedAt)

		if published.Before(since) {
			continue
		}

		content := g.buildContent(adv)

		meta := map[string]string{
			"ghsa":     adv.GHSAID,
			"severity": sev,
		}
		if adv.CVEID != "" {
			meta["cve"] = adv.CVEID
		}
		if packages := ghsaAffectedPackages(adv); packages != "" {
			meta["affected_packages"] = packages
		}
		if adv.CVSS.Score != nil && *adv.CVSS.Score > 0 {
			meta["cvss"] = fmt.Sprintf("%.1f", *adv.CVSS.Score)
			if adv.CVSS.VectorString != "" {
				meta["cvss_vector"] = adv.CVSS.VectorString
			}
		}

		items = append(items, RawItem{
			SourceID:    fmt.Sprintf("ghsa:%s", adv.GHSAID),
			Source:      "ghsa",
			Title:       adv.Summary,
			URL:         adv.HTMLURL,
			Content:     content,
			PublishedAt: published,
			Metadata:    meta,
		})
	}

	return items, nil
}

// ghsaAffectedPackages renders the advisory's structured package, version
// range and patched-version data one package per line, so brief generation can
// copy them verbatim instead of inferring ranges from prose.
func ghsaAffectedPackages(adv ghsaAdvisory) string {
	var lines []string
	for _, v := range adv.Vulnerabilities {
		if v.Package.Name == "" {
			continue
		}
		line := fmt.Sprintf("%s/%s", v.Package.Ecosystem, v.Package.Name)
		if v.VulnerableVersionRange != "" {
			line += " | vulnerable: " + v.VulnerableVersionRange
		}
		if v.PatchedVersions != "" {
			line += " | patched: " + v.PatchedVersions
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (g *GHSA) buildContent(adv ghsaAdvisory) string {
	var parts []string

	if adv.Description != "" {
		parts = append(parts, adv.Description)
	}

	if len(adv.Vulnerabilities) > 0 {
		parts = append(parts, "\nAffected Packages:")
		for _, v := range adv.Vulnerabilities {
			pkg := v.Package
			line := fmt.Sprintf("- %s/%s", pkg.Ecosystem, pkg.Name)
			if v.VulnerableVersionRange != "" {
				line += fmt.Sprintf(" (vulnerable: %s)", v.VulnerableVersionRange)
			}
			if v.PatchedVersions != "" {
				line += fmt.Sprintf(" (patched: %s)", v.PatchedVersions)
			}
			parts = append(parts, line)
		}
	}

	if adv.CVEID != "" {
		parts = append(parts, fmt.Sprintf("\nCVE: %s", adv.CVEID))
	}
	parts = append(parts, fmt.Sprintf("Severity: %s", adv.Severity))

	return strings.Join(parts, "\n")
}

// GHSA API response types.

type ghsaAdvisory struct {
	GHSAID          string              `json:"ghsa_id"`
	CVEID           string              `json:"cve_id"`
	Summary         string              `json:"summary"`
	Description     string              `json:"description"`
	Severity        string              `json:"severity"`
	HTMLURL         string              `json:"html_url"`
	PublishedAt     string              `json:"published_at"`
	Vulnerabilities []ghsaVulnerability `json:"vulnerabilities"`
	CVSS            struct {
		Score        *float64 `json:"score"`
		VectorString string   `json:"vector_string"`
	} `json:"cvss"`
}

type ghsaVulnerability struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	PatchedVersions        string `json:"patched_versions"`
}
