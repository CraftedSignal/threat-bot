package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// DigestConfig controls the lookback window for digest generation.
type DigestConfig struct {
	LookbackHours int        // default 24; use 168 for weekly
	LLMClient     llm.Client // optional; nil means use fallback summaries
	Now           time.Time  // optional; defaults to time.Now()
}

// Digest is a roll-up of published briefs over a time period.
type Digest struct {
	GeneratedAt   time.Time
	Period        string // e.g., "2026-03-22"
	LookbackHours int
	Categories    []DigestCategory
	TotalBriefs   int
}

// DigestCategory groups briefs under a heading.
type DigestCategory struct {
	Name   string
	Briefs []DigestEntry
}

// DigestEntry is a single brief summary within a digest category.
type DigestEntry struct {
	Title        string
	Severity     string
	Source       string
	Summary      string
	Rules        int
	IOCs         int
	TTPs         int
	URL          string
	CVEs         []string // CVE IDs in the cluster
	BriefCount   int      // number of briefs merged into this entry
	IsUpdate     bool     // true if this is a previously-reported update
	PreviousDate string   // date of previous digest that first reported this
	UpdateLine   string   // describes what changed since previous report
}

// tacticIsActiveCampaign checks whether a tactic ID falls in TA0001-TA0010
// (the "active campaign" range covering Initial Access through Exfiltration).
func tacticIsActiveCampaign(tacticID string) bool {
	switch tacticID {
	case "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
		"TA0006", "TA0007", "TA0008", "TA0009", "TA0010":
		return true
	}
	return false
}

// classifyBrief assigns a brief to one of the four digest categories.
func classifyBrief(brief *BundleBrief) string {
	// 1. Critical Vulnerabilities
	if strings.EqualFold(brief.Severity, "critical") {
		return "Critical Vulnerabilities"
	}

	// 2. Active Campaigns (has threat_actor or TTPs with TA0001-TA0010)
	if brief.ThreatActor != "" {
		return "Active Campaigns"
	}
	for _, ttp := range brief.TTPs {
		if tacticIsActiveCampaign(ttp.TacticID) {
			return "Active Campaigns"
		}
	}

	// 3. New Detection Rules
	if len(brief.Rules) > 0 {
		return "New Detection Rules"
	}

	// 4. Everything else
	return "Threat Intelligence"
}

// severityBadge returns a Markdown badge string for the severity level.
func severityBadge(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "**CRITICAL**"
	case "high":
		return "**HIGH**"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "informational":
		return "INFO"
	default:
		return strings.ToUpper(severity)
	}
}

// GenerateDigest queries approved drafts from the last N hours, clusters them
// by normalized title, detects updates from previous digests, and produces a
// categorised Digest.
func GenerateDigest(ctx context.Context, db *storage.DB, cfg DigestConfig) (*Digest, error) {
	if cfg.LookbackHours <= 0 {
		cfg.LookbackHours = 24
	}
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	since := now.Add(-time.Duration(cfg.LookbackHours) * time.Hour)

	// 1. Parse approved drafts into BundleBriefs as they are read, track source per brief ID.
	var briefs []*BundleBrief
	sourceMap := make(map[string]string) // brief ID -> source
	for draft, err := range db.ApprovedDraftsSince(since) {
		if err != nil {
			return nil, fmt.Errorf("querying approved drafts: %w", err)
		}
		brief, err := ParseBriefYAML(draft.BriefYAML)
		if err != nil {
			continue // skip unparseable briefs
		}
		if strings.EqualFold(brief.ClaimState, "disputed") || strings.EqualFold(brief.ClaimState, "retracted") {
			continue
		}
		briefs = append(briefs, brief)
		sourceMap[brief.ID] = draft.Source
	}

	// 2. Cluster briefs by normalized title.
	clusters := clusterBriefs(briefs)

	// 3. Load previous digest clusters from DB.
	kind := "daily"
	if cfg.LookbackHours > 24 {
		kind = "weekly"
	}
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
	previousDigestID := fmt.Sprintf("%s-%s", kind, yesterday)
	previousClusters, _ := db.ListDigestClusters(previousDigestID)

	// Build a lookup: cluster key -> previous cluster.
	prevByKey := make(map[string]storage.DigestCluster)
	for _, pc := range previousClusters {
		prevByKey[pc.ClusterKey] = pc
	}

	// 4. Classify clusters into categories.
	categoryOrder := []string{
		"Previously Reported \u2014 Updates",
		"Critical Vulnerabilities",
		"Active Campaigns",
		"New Detection Rules",
		"Threat Intelligence",
	}

	buckets := make(map[string][]DigestEntry)
	currentDigestID := fmt.Sprintf("%s-%s", kind, time.Now().UTC().Format("2006-01-02"))

	for _, cluster := range clusters {
		// Check if this cluster existed in the previous digest.
		if prev, ok := prevByKey[cluster.Key]; ok {
			// Parse previous brief IDs.
			var prevIDs []string
			_ = json.Unmarshal([]byte(prev.BriefIDs), &prevIDs)
			prevSet := make(map[string]bool, len(prevIDs))
			for _, id := range prevIDs {
				prevSet[id] = true
			}

			// Find new brief IDs not in previous set.
			var newIDs []string
			var newCVEs []string
			for _, id := range cluster.BriefIDs {
				if !prevSet[id] {
					newIDs = append(newIDs, id)
				}
			}
			// Collect CVEs from new briefs.
			for _, b := range briefs {
				for _, nid := range newIDs {
					if b.ID == nid {
						for _, cve := range b.CVEs {
							newCVEs = append(newCVEs, cve.ID)
						}
					}
				}
			}

			if len(newIDs) > 0 {
				// Cluster grew — this is an update.
				updateLine := fmt.Sprintf("%d new brief(s) added", len(newIDs))
				if len(newCVEs) > 0 {
					updateLine += fmt.Sprintf("; new CVE(s): %s", strings.Join(newCVEs, ", "))
				}

				entry := DigestEntry{
					Title:        cluster.DisplayTitle,
					Severity:     cluster.HighestSeverity,
					Source:       resolveSource(cluster, sourceMap),
					Summary:      prev.Summary,
					Rules:        cluster.TotalRules,
					IOCs:         cluster.TotalIOCs,
					TTPs:         cluster.TotalTTPs,
					URL:          cluster.OriginalURL,
					CVEs:         cluster.CVEs,
					BriefCount:   len(cluster.BriefIDs),
					IsUpdate:     true,
					PreviousDate: yesterday,
					UpdateLine:   updateLine,
				}

				buckets["Previously Reported \u2014 Updates"] = append(buckets["Previously Reported \u2014 Updates"], entry)

				// Save updated cluster to DB.
				idsJSON, _ := json.Marshal(cluster.BriefIDs)
				_ = db.SaveDigestCluster(storage.DigestCluster{
					DigestID:   currentDigestID,
					ClusterKey: cluster.Key,
					BriefIDs:   string(idsJSON),
					Summary:    prev.Summary,
				})
				continue
			}
		}

		// 5. Not an update — classify normally.
		// Use the first brief in the cluster for classification.
		var repBrief *BundleBrief
		for _, b := range briefs {
			if b.ID == cluster.BriefIDs[0] {
				repBrief = b
				break
			}
		}
		if repBrief == nil {
			continue
		}

		category := classifyBrief(repBrief)

		// Generate summary: use LLM for multi-brief clusters, original for singles.
		var summary string
		if len(cluster.BriefIDs) == 1 {
			summary = cluster.OriginalSummary
		} else {
			summary = generateClusterSummary(ctx, cfg.LLMClient, cluster)
		}

		entry := DigestEntry{
			Title:      cluster.DisplayTitle,
			Severity:   cluster.HighestSeverity,
			Source:     resolveSource(cluster, sourceMap),
			Summary:    summary,
			Rules:      cluster.TotalRules,
			IOCs:       cluster.TotalIOCs,
			TTPs:       cluster.TotalTTPs,
			URL:        cluster.OriginalURL,
			CVEs:       cluster.CVEs,
			BriefCount: len(cluster.BriefIDs),
		}

		buckets[category] = append(buckets[category], entry)

		// Save cluster to DB.
		idsJSON, _ := json.Marshal(cluster.BriefIDs)
		_ = db.SaveDigestCluster(storage.DigestCluster{
			DigestID:   currentDigestID,
			ClusterKey: cluster.Key,
			BriefIDs:   string(idsJSON),
			Summary:    summary,
		})
	}

	var categories []DigestCategory
	total := 0
	for _, name := range categoryOrder {
		entries := buckets[name]
		if len(entries) == 0 {
			continue
		}
		categories = append(categories, DigestCategory{
			Name:   name,
			Briefs: entries,
		})
		total += len(entries)
	}

	return &Digest{
		GeneratedAt:   now,
		Period:        now.Format("2006-01-02"),
		LookbackHours: cfg.LookbackHours,
		Categories:    categories,
		TotalBriefs:   total,
	}, nil
}

// resolveSource picks the first available source from the cluster's brief IDs.
func resolveSource(cluster briefCluster, sourceMap map[string]string) string {
	for _, id := range cluster.BriefIDs {
		if src, ok := sourceMap[id]; ok {
			return src
		}
	}
	return ""
}

// generateClusterSummary produces a summary for a multi-brief cluster.
// If no LLM client is available, it returns a fallback string.
func generateClusterSummary(ctx context.Context, client llm.Client, cluster briefCluster) string {
	fallback := fmt.Sprintf("%d related vulnerabilities disclosed in %s.", len(cluster.BriefIDs), cluster.DisplayTitle)

	if client == nil {
		return fallback
	}

	prompt := fmt.Sprintf(
		"Summarize the following cluster of %d related threat intelligence briefs about %q.\n"+
			"CVEs: %s\n"+
			"Combined severity: %s\n"+
			"Total rules: %d, IOCs: %d, TTPs: %d\n\n"+
			"Write 2-3 sentences summarizing the threat, then end with an \"Action:\" line recommending what defenders should do.",
		len(cluster.BriefIDs),
		cluster.DisplayTitle,
		strings.Join(cluster.CVEs, ", "),
		cluster.HighestSeverity,
		cluster.TotalRules,
		cluster.TotalIOCs,
		cluster.TotalTTPs,
	)

	system := "You are a concise threat intelligence analyst writing digest summaries for a security operations team."

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := client.Generate(ctx, prompt, system)
	if err != nil {
		return fallback
	}

	result = strings.TrimSpace(result)
	if result == "" {
		return fallback
	}
	return result
}

// Summary produces a human-readable description of the digest contents,
// e.g. "3 critical vulnerabilities, 2 active campaigns, and 1 detection rule".
func (d *Digest) Summary() string {
	if d.TotalBriefs == 0 {
		return "No briefs in this period"
	}

	var parts []string
	for _, cat := range d.Categories {
		n := len(cat.Briefs)
		name := strings.ToLower(cat.Name)
		if n == 1 {
			// Singularize category names.
			if strings.HasSuffix(name, "ies") {
				name = name[:len(name)-3] + "y"
			} else if strings.HasSuffix(name, "s") {
				name = name[:len(name)-1]
			}
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, name))
	}

	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
	}
}

// RenderMarkdown produces a Markdown string from the digest.
func (d *Digest) RenderMarkdown() string {
	var b strings.Builder

	kind := "Daily"
	if d.LookbackHours > 24 {
		kind = "Weekly"
	}
	fmt.Fprintf(&b, "# %s Threat Intelligence Digest - %s\n\n", kind, d.Period)
	fmt.Fprintf(&b, "*Generated: %s | %d brief(s)*\n\n", d.GeneratedAt.Format(time.RFC3339), d.TotalBriefs)

	if d.TotalBriefs == 0 {
		b.WriteString("No approved briefs in this period.\n")
		return b.String()
	}

	for _, cat := range d.Categories {
		fmt.Fprintf(&b, "## %s\n\n", cat.Name)

		for _, entry := range cat.Briefs {
			// Build title: multi-brief clusters show CVE count; updates get suffix.
			title := entry.Title
			if entry.BriefCount > 1 && len(entry.CVEs) > 0 {
				title = fmt.Sprintf("%s (%d CVEs)", title, len(entry.CVEs))
			}
			if entry.IsUpdate {
				title += " \u2014 Updated"
			}
			if entry.URL != "" {
				title = fmt.Sprintf("[%s](%s)", title, entry.URL)
			}
			fmt.Fprintf(&b, "### %s\n\n", title)
			fmt.Fprintf(&b, "**Severity:** %s | **Source:** %s\n\n", severityBadge(entry.Severity), entry.Source)

			// Update metadata.
			if entry.IsUpdate && entry.PreviousDate != "" {
				fmt.Fprintf(&b, "*Previously reported on %s*\n\n", entry.PreviousDate)
			}
			if entry.UpdateLine != "" {
				fmt.Fprintf(&b, "**Update:** %s\n\n", entry.UpdateLine)
			}

			if entry.Summary != "" {
				fmt.Fprintf(&b, "%s\n\n", entry.Summary)
			}

			// CVE list for multi-brief clusters.
			if entry.BriefCount > 1 && len(entry.CVEs) > 0 {
				fmt.Fprintf(&b, "**CVEs:** %s\n\n", strings.Join(entry.CVEs, ", "))
			}

			var counts []string
			if entry.Rules > 0 {
				counts = append(counts, fmt.Sprintf("%d rule(s)", entry.Rules))
			}
			if entry.IOCs > 0 {
				counts = append(counts, fmt.Sprintf("%d IOC(s)", entry.IOCs))
			}
			if entry.TTPs > 0 {
				counts = append(counts, fmt.Sprintf("%d TTP(s)", entry.TTPs))
			}
			if len(counts) > 0 {
				fmt.Fprintf(&b, "*%s*\n\n", strings.Join(counts, " | "))
			}

			b.WriteString("---\n\n")
		}
	}

	return b.String()
}
