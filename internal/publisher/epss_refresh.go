package publisher

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// EPSSRefreshConfig holds parameters for the periodic EPSS refresh job.
type EPSSRefreshConfig struct {
	Interval      time.Duration
	MinScoreDelta float64
}

// kevMembership is a CVE's standing in the CISA KEV catalog.
type kevMembership int

const (
	kevUnknown   kevMembership = iota // the catalog has not loaded
	kevNotListed                      // the loaded catalog does not list the CVE
	kevListed
)

func lookupKEV(kev *scraper.KEVCatalog, cveID string) kevMembership {
	listed, known := kev.Lookup(cveID)
	switch {
	case !known:
		return kevUnknown
	case listed:
		return kevListed
	}
	return kevNotListed
}

// applyEPSSUpdate checks if a CVE's EPSS score or KEV listing has changed
// enough to warrant an update. While KEV membership is unknown the CVE's KEV
// fields are left as they are.
func applyEPSSUpdate(old BundleCVE, newEPSS, newPct float64, kev kevMembership, minDelta float64) (changed bool, updated BundleCVE) {
	updated = old
	updated.EPSS = newEPSS
	updated.EPSSPercentile = newPct
	kevFlipped := false
	if kev != kevUnknown {
		updated.KEV = kev == kevListed
		updated.KEVStatus = "false"
		if updated.KEV {
			updated.KEVStatus = "true"
		}
		kevFlipped = updated.KEV != old.KEV || old.KEVStatus == "unknown"
	}

	epssDelta := math.Abs(newEPSS - old.EPSS)
	changed = epssDelta >= minDelta || kevFlipped
	return changed, updated
}

// RefreshEPSS runs the daily EPSS refresh job. It downloads fresh EPSS scores
// and walks the feed one segment at a time: briefs whose CVE scores moved get
// their priority recomputed, and each changed segment blob is staged before
// the next one is fetched, so the refresh never holds more than one segment.
// The segments, CVE metadata, changelog, and manifest become visible through
// one branch update. The CVE metadata index is rebuilt from every segment.
// kev is the CISA KEV catalog; while it has not loaded, KEV fields are kept.
func (p *Publisher) RefreshEPSS(epssCache *scraper.EPSSCache, kev *scraper.KEVCatalog, cfg EPSSRefreshConfig, logger *slog.Logger) error {
	if err := epssCache.Refresh(); err != nil {
		return fmt.Errorf("refreshing EPSS cache: %w", err)
	}
	return p.withAtomicPublication("chore: publish EPSS refresh", func() error {
		return p.refreshEPSSRelease(epssCache, kev, cfg, logger)
	})
}

func (p *Publisher) refreshEPSSRelease(epssCache *scraper.EPSSCache, kev *scraper.KEVCatalog, cfg EPSSRefreshConfig, logger *slog.Logger) error {
	manifest, manifestSHA, err := p.fetchManifest()
	if err != nil {
		logger.Info("no existing manifest, nothing to refresh")
		return nil
	}

	changelog, changelogSHA, err := p.fetchChangelog()
	if err != nil {
		return fmt.Errorf("fetching changelog: %w", err)
	}

	scores := make(map[string]CVEScore)
	modifiedSegments := 0
	now := bundleTimestamp()
	for i := range manifest.Segments {
		seg := &manifest.Segments[i]
		segContent, segSHA, fetchErr := p.fetchSegment("output/" + seg.Path)
		if fetchErr != nil {
			logger.Warn("failed to fetch segment", "path", seg.Path, "error", fetchErr)
			continue
		}

		if refreshSegmentEPSS(segContent, epssCache, kev, cfg.MinScoreDelta, changelog) {
			// Extract key from path: "briefs/YYYY-MM.json" -> "YYYY-MM"
			key := strings.TrimSuffix(strings.TrimPrefix(seg.Path, "briefs/"), ".json")
			encrypted, encErr := EncryptSegment(segContent, bundleVersion(), now, p.publicKey)
			if encErr != nil {
				return fmt.Errorf("encrypting segment %s: %w", key, encErr)
			}

			commitMsg := fmt.Sprintf("chore: EPSS refresh segment %s", key)
			checksum, err := p.putFile("output/"+seg.Path, encrypted, segSHA, commitMsg)
			if err != nil {
				return fmt.Errorf("pushing segment %s: %w", key, err)
			}

			// Update manifest segment entry with new checksum.
			seg.Checksum = checksum
			seg.BriefCount = len(segContent.Briefs)
			seg.LastModified = now
			modifiedSegments++
		}
		addCVEScores(scores, segContent.Briefs)
	}

	if modifiedSegments == 0 {
		logger.Info("EPSS refresh: no changes detected")
		return nil
	}

	// Build and upload CVE metadata.
	cveJSON, err := json.Marshal(&CVEMetadata{
		LastRefresh: time.Now().UTC().Format(time.RFC3339),
		Scores:      scores,
	})
	if err != nil {
		return fmt.Errorf("marshalling CVE metadata: %w", err)
	}
	cveManifest, err := encryptRaw(cveJSON, bundleVersion(), now, p.publicKey)
	if err != nil {
		return fmt.Errorf("encrypting CVE metadata: %w", err)
	}
	cveSHA, shaErr := p.getFileSHA(cveMetadataPath)
	if shaErr != nil {
		return fmt.Errorf("checking existing CVE metadata: %w", shaErr)
	}
	cveChecksum, err := p.putFile(cveMetadataPath, cveManifest, cveSHA, "chore: update CVE metadata (EPSS refresh)")
	if err != nil {
		return fmt.Errorf("pushing CVE metadata: %w", err)
	}
	manifest.CVEMeta = &CVEMetaEntry{
		Path:     cveMetadataPath,
		Checksum: cveChecksum,
	}

	// Prune and upload changelog.
	changelog.Prune(7*24*time.Hour, 50)
	if err := p.putJSONFile(changelogPath, changelog, changelogSHA, "chore: update changelog (EPSS refresh)"); err != nil {
		return fmt.Errorf("pushing changelog: %w", err)
	}
	if len(changelog.Entries) > 0 {
		manifest.ChangelogRef = &ChangelogEntry{
			Path:  changelogPath,
			Since: changelog.Entries[0].Timestamp,
		}
	}

	// Upload manifest.
	if err := p.putJSONFile(manifestPath, manifest, manifestSHA, "chore: update manifest (EPSS refresh)"); err != nil {
		return fmt.Errorf("pushing manifest: %w", err)
	}

	logger.Info("EPSS refresh complete", "modified_segments", modifiedSegments)
	return nil
}

// refreshSegmentEPSS applies fresh EPSS scores and KEV status to the briefs of
// one segment, recomputing the priority of every brief whose CVE scores moved,
// and reports whether any brief changed.
func refreshSegmentEPSS(segContent *SegmentContent, epssCache *scraper.EPSSCache, kev *scraper.KEVCatalog, minScoreDelta float64, changelog *Changelog) bool {
	segModified := false
	for i, brief := range segContent.Briefs {
		briefChanged := false
		for j, cve := range brief.CVEs {
			epssScore, found := epssCache.Lookup(cve.ID)
			if !found {
				continue
			}
			changed, updated := applyEPSSUpdate(cve, epssScore.EPSS, epssScore.Percentile, lookupKEV(kev, cve.ID), minScoreDelta)
			if changed {
				segContent.Briefs[i].CVEs[j] = updated
				briefChanged = true
			}
		}

		if briefChanged {
			// Preserve non-CVE signals and recompute CVE signals from fresh data.
			cveSignalSet := map[string]bool{
				"epss_high": true, "epss_medium": true, "kev": true,
				"cvss_critical": true, "cvss_high": true,
			}
			signalPoints := map[string]int{
				"high_confidence_source": 2, "medium_confidence_source": 1,
				"corroborated": 2, "watchlist_match": 2,
				"has_rules": 1, "has_iocs": 1, "active_exploitation": 3,
			}
			nonCVEScore := 0
			var nonCVESignals []string
			for _, s := range brief.PrioritySignals {
				if !cveSignalSet[s] {
					nonCVESignals = append(nonCVESignals, s)
					nonCVEScore += signalPoints[s]
				}
			}

			// Compute fresh CVE score.
			var pipelineCVEs []pipeline.BundleCVE
			for _, c := range segContent.Briefs[i].CVEs {
				pipelineCVEs = append(pipelineCVEs, pipeline.BundleCVE{
					ID: c.ID, EPSS: c.EPSS, EPSSPercentile: c.EPSSPercentile,
					CVSS: c.CVSS, KEV: c.KEV,
				})
			}
			cveResult := pipeline.ComputePriority(pipeline.PriorityInput{CVEs: pipelineCVEs})

			// Merge non-CVE + fresh CVE signals.
			totalScore := nonCVEScore + cveResult.Score
			allSignals := append(nonCVESignals, cveResult.Signals...)

			tier := "low"
			if totalScore >= 7 {
				tier = "critical"
			} else if totalScore >= 4 {
				tier = "high"
			} else if totalScore >= 2 {
				tier = "medium"
			}

			segContent.Briefs[i].Priority = tier
			segContent.Briefs[i].PriorityScore = totalScore
			segContent.Briefs[i].PrioritySignals = allSignals

			changelog.RecordUpdate(brief.ID, []string{"cves.epss", "priority"})
			segModified = true
		}
	}
	return segModified
}

// addCVEScores records the scores of every CVE the briefs carry. A CVE that
// appears in several briefs keeps the scores of the last one recorded.
func addCVEScores(scores map[string]CVEScore, briefs []BundleBrief) {
	for _, brief := range briefs {
		for _, cve := range brief.CVEs {
			scores[cve.ID] = CVEScore{
				EPSS:           cve.EPSS,
				EPSSPercentile: cve.EPSSPercentile,
				CVSS:           cve.CVSS,
				KEV:            cve.KEV,
			}
		}
	}
}
