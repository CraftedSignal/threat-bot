package pipeline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// kevCatalogURL is the public evidence page a KEV-derived exploitation state
// cites, the same URL CVE enrichment writes at publication.
const kevCatalogURL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

// ExploitationReconcileOptions bounds one reconciliation pass.
type ExploitationReconcileOptions struct {
	// Limit caps the briefs one pass updates; 0 means no cap.
	Limit int
	// NotifyWithin dispatches update notifications only for CVEs CISA added
	// this recently. Older listings are a backfill, not news.
	NotifyWithin time.Duration
	// Now is the reference time; zero means the current time.
	Now time.Time
}

// ExploitationReconcileResult reports one pass.
type ExploitationReconcileResult struct {
	Candidates int  // approved briefs mentioning a KEV CVE or citing an exploit listing
	Updated    int  // briefs this pass changed
	Corrected  int  // of those, briefs no longer exploited on a PoC listing alone
	Notified   int  // update notifications attempted
	Held       int  // updates refused by the publication contract, left unchanged
	More       bool // the limit stopped the pass with briefs still to update
}

// exploitationReconcileHolds remembers refused updates by draft and content, so one
// brief whose prose contradicts its KEV listing warns once, not every pass.
type exploitationReconcileHolds struct {
	mu   sync.Mutex
	seen map[string]string
}

func (h *exploitationReconcileHolds) firstSeen(draftID, briefYAML string) bool {
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(briefYAML)))
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen == nil {
		h.seen = map[string]string{}
	}
	if h.seen[draftID] == digest {
		return false
	}
	h.seen[draftID] = digest
	return true
}

// ReconcileExploitation keeps the exploitation state of approved briefs true
// to their evidence. It marks briefs whose CVEs the CISA KEV catalog lists as
// exploited, and flags those CVEs as KEV: publication only reads KEV when a
// brief is first enriched, and a later listing reached a brief only through a
// merge of the CISA KEV item, which any held merge blocked. By 2026-11-19, 199
// published briefs listed a KEV CVE without being marked exploited. It also
// unmarks briefs whose only exploitation evidence is an exploit-code listing,
// which shows code exists, not that attackers used it.
//
// The catalog is authoritative, so no model is involved. A brief whose
// updated form fails the publication contract (for example prose that says
// the CVE is not exploited) stays unchanged and is reported for review.
func (p *Pipeline) ReconcileExploitation(ctx context.Context, opts ExploitationReconcileOptions) (ExploitationReconcileResult, error) {
	var result ExploitationReconcileResult
	if p.cveVerifier == nil || p.db == nil {
		return result, nil
	}
	catalog := p.cveVerifier.kev.Entries()
	if len(catalog) == 0 {
		// KEV membership is unknown until the catalog loads, and unknown is not
		// "not listed": correcting exploitation now could undo a KEV listing.
		return result, nil
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Collect first, write after: updates must not run under an open cursor.
	type candidate struct{ id, briefYAML string }
	var candidates []candidate
	for draft, err := range p.db.DraftsWithStatus(storage.StatusApproved) {
		if err != nil {
			return result, err
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if citesExploitListing(draft.BriefYAML) {
			candidates = append(candidates, candidate{draft.ID, draft.BriefYAML})
			continue
		}
		for _, id := range sourceCVEPattern.FindAllString(draft.BriefYAML, -1) {
			if _, ok := catalog[strings.ToUpper(id)]; ok {
				candidates = append(candidates, candidate{draft.ID, draft.BriefYAML})
				break
			}
		}
	}
	result.Candidates = len(candidates)

	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		updated, listed, corrected, changed, err := reconcileExploitation(c.briefYAML, catalog)
		if err != nil || !changed {
			continue
		}
		if opts.Limit > 0 && result.Updated >= opts.Limit {
			result.More = true
			break
		}
		draft, err := p.db.GetDraft(c.id)
		if err != nil {
			return result, err
		}
		if draft.Status != storage.StatusApproved || draft.BriefYAML != c.briefYAML {
			continue // changed since the scan; the next pass re-reads it
		}
		var before, after map[string]any
		if yaml.Unmarshal([]byte(c.briefYAML), &before) != nil || yaml.Unmarshal([]byte(updated), &after) != nil {
			continue
		}
		level, summary := classifyUpdate(snapshotBriefSignals(before), snapshotBriefSignals(after), false, false, false, false, false, false)
		event := storage.UpdateEvent{At: now, Sources: []string{"cisa-kev"}, SourceURLs: []string{kevCatalogURL}}
		switch {
		case corrected && len(listed) == 0:
			level, summary = "L1", "exploitation evidence corrected: an exploit-code listing is not exploitation"
			event.Sources, event.SourceURLs = []string{"threat-bot"}, nil
		case level == "L0":
			level, summary = "L1", "KEV status refreshed"
		}
		event.Level, event.Summary = level, summary
		if err := injectUpdateMetadata(&updated, draft, event); err != nil {
			p.logger.Warn("exploitation reconciliation: update metadata not recorded", "draft_id", draft.ID, "error", err)
		}
		if err := p.validatePublication(updated); err != nil {
			result.Held++
			// Mostly briefs older than the current contract, which no update can
			// republish. The pass summary counts them; detail once per content.
			if p.kevHolds.firstSeen(draft.ID, c.briefYAML) {
				p.logger.Info("exploitation reconciliation needs editorial review", "draft_id", draft.ID, "kev_cves", listed, "error", err)
			}
			continue
		}
		publish := p.autoPublish && p.publisher != nil
		sourceID := "threat-bot:exploitation-evidence"
		if len(listed) > 0 {
			sourceID = "cisa-kev:" + listed[0]
		}
		if err := p.db.RecordDraftUpdateWithPublication(draft.ID, updated, event, sourceID, publish); err != nil {
			return result, err
		}
		if publish {
			if err := p.enqueuePublicationIntent(storage.PublicationIntent{DraftID: draft.ID, BriefYAML: updated}); err != nil {
				return result, err
			}
		}
		result.Updated++
		if corrected {
			result.Corrected++
		}
		p.logger.Info("exploitation reconciliation updated brief", "draft_id", draft.ID, "kev_cves", listed, "summary", summary)
		if level == "L3" && kevListedWithin(listed, catalog, now, opts.NotifyWithin) {
			p.maybeDispatchL3Update(ctx, draft.ID, summary, "cisa-kev", p.siteURL)
			result.Notified++
		}
	}
	return result, nil
}

// reconcileExploitation corrects one brief's exploitation state. A
// confirmed_active state whose only evidence is an exploit-code listing
// becomes unknown. Every catalog-listed CVE is then flagged as KEV and the
// brief recorded as exploited with the catalog as evidence; an existing
// confirmed_active state keeps its own evidence. It returns the listed CVEs,
// whether a listing-only claim was withdrawn, and whether the brief changed.
func reconcileExploitation(briefYAML string, catalog map[string]string) (out string, listed []string, corrected, changed bool, err error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML, nil, false, false, err
	}
	if doc == nil {
		return briefYAML, nil, false, false, nil
	}
	evidence, _ := asStringMap(doc["exploitation_evidence"])
	if confirmedEvidence(evidence) && ExploitCodeListingURL(fmt.Sprint(evidence["source_url"])) {
		evidence = map[string]any{"status": "unknown"}
		doc["exploitation_evidence"] = evidence
		doc["exploited"] = false
		doc["priority_signals"] = withoutSignal(doc["priority_signals"], "active_exploitation")
		corrected, changed = true, true
	}
	cves, _ := doc["cves"].([]any)
	for i, raw := range cves {
		entry, isMap := asStringMap(raw)
		if !isMap {
			id, isID := raw.(string)
			if !isID {
				continue
			}
			entry = map[string]any{"id": id}
		}
		id := strings.ToUpper(strings.TrimSpace(fmt.Sprint(entry["id"])))
		if _, inKEV := catalog[id]; !inKEV || slices.Contains(listed, id) {
			continue
		}
		listed = append(listed, id)
		// A bare ID entry becomes structured so it can carry its KEV flag.
		if kev, _ := entry["kev"].(bool); !isMap || !kev || fmt.Sprint(entry["kev_status"]) != "true" {
			entry["kev"] = true
			entry["kev_status"] = "true"
			cves[i] = entry
			changed = true
		}
	}
	if len(listed) > 0 {
		if !confirmedEvidence(evidence) {
			next := map[string]any{"status": "confirmed_active", "source_url": kevCatalogURL, "confidence": "high"}
			if observed := kevEarliestAdded(listed, catalog); observed != "" {
				next["observed_at"] = observed
			}
			doc["exploitation_evidence"] = next
			changed = true
		}
		if exploited, _ := doc["exploited"].(bool); !exploited {
			doc["exploited"] = true
			changed = true
		}
		doc["cves"] = cves
	}
	if !changed {
		return briefYAML, listed, false, false, nil
	}
	encoded, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML, nil, false, false, err
	}
	return string(encoded), listed, corrected, true, nil
}

func confirmedEvidence(evidence map[string]any) bool {
	return strings.EqualFold(strings.TrimSpace(fmt.Sprint(evidence["status"])), "confirmed_active")
}

// citesExploitListing is a cheap prefilter for briefs whose exploitation
// evidence may be an exploit-code listing; reconcileExploitation decides.
func citesExploitListing(briefYAML string) bool {
	if !strings.Contains(briefYAML, "confirmed_active") {
		return false
	}
	for host := range exploitCodeListingHosts {
		if strings.Contains(briefYAML, host) {
			return true
		}
	}
	return false
}

func withoutSignal(raw any, signal string) any {
	list, ok := raw.([]any)
	if !ok {
		return raw
	}
	out := make([]any, 0, len(list))
	for _, value := range list {
		if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(value)), signal) {
			out = append(out, value)
		}
	}
	return out
}

// kevEarliestAdded returns the earliest catalog date among ids as RFC3339,
// or "" when the catalog has no dates for them.
func kevEarliestAdded(ids []string, catalog map[string]string) string {
	earliest := ""
	for _, id := range ids {
		if date := catalog[id]; date != "" && (earliest == "" || date < earliest) {
			earliest = date
		}
	}
	if added, err := time.Parse("2006-01-02", earliest); err == nil {
		return added.UTC().Format(time.RFC3339)
	}
	return ""
}

// kevListedWithin reports whether CISA added any of ids within window of now.
// A missing date is not recent: a backfill must not notify.
func kevListedWithin(ids []string, catalog map[string]string, now time.Time, window time.Duration) bool {
	if window <= 0 {
		return false
	}
	for _, id := range ids {
		if added, err := time.Parse("2006-01-02", catalog[id]); err == nil && now.Sub(added) <= window {
			return true
		}
	}
	return false
}
