package pipeline

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"

	"gopkg.in/yaml.v3"
)

// injectUpdateMetadata mutates the merged brief YAML to carry the
// lastmod timestamp and the capped updates log inline so the publisher
// can read both from brief_yaml without a second DB round-trip.
func injectUpdateMetadata(merged *string, draft *storage.Draft, event storage.UpdateEvent) error {
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(*merged), &fm); err != nil {
		return err
	}
	fm["lastmod"] = event.At.Format(time.RFC3339)

	// Build the capped updates list = prior log + this event.
	var prior []storage.UpdateEvent
	if draft.UpdateLog != "" {
		_ = json.Unmarshal([]byte(draft.UpdateLog), &prior)
	}
	prior = append(prior, event)
	if len(prior) > 5 {
		prior = prior[len(prior)-5:]
	}
	// Collapse consecutive CVE-add events that share the same minute, level and
	// source so a source batch (e.g. NVD publishing several CVEs for one product
	// at the same timestamp) renders as one "What's new" line instead of many.
	prior = coalesceUpdateEvents(prior)
	out := make([]any, 0, len(prior))
	for _, e := range prior {
		out = append(out, map[string]any{
			"at":          e.At.Format(time.RFC3339),
			"level":       e.Level,
			"summary":     e.Summary,
			"sources":     e.Sources,
			"source_urls": e.SourceURLs,
		})
	}
	fm["updates"] = out

	encoded, err := yaml.Marshal(fm)
	if err != nil {
		return err
	}
	*merged = string(encoded)
	return nil
}

// injectSourceField adds `source: <name>` to a brief YAML if it isn't
// already present. Idempotent — re-running on a brief that already
// carries the field leaves the YAML untouched. Bare top-level prepend
// avoids the cost of a full parse + re-marshal on every brief.
// coalesceUpdateEvents merges consecutive update events that share the same
// minute-level timestamp, level, and source(s) and whose summaries each added
// CVE ids. This turns a batch of same-timestamp CVE additions (e.g. NVD
// dropping several CVEs for one product at once) into a single "What's new"
// line.
func coalesceUpdateEvents(events []storage.UpdateEvent) []storage.UpdateEvent {
	if len(events) < 2 {
		return events
	}
	var out []storage.UpdateEvent
	var pending *storage.UpdateEvent
	var pendingCVEs []string
	var pendingSourceURLs []string

	flush := func() {
		if pending == nil {
			return
		}
		if len(pendingCVEs) > 0 {
			pending.Summary = formatAddedCVEsSummary(pendingCVEs)
			pending.SourceURLs = dedupStrings(pendingSourceURLs)
		}
		out = append(out, *pending)
		pending = nil
		pendingCVEs = nil
		pendingSourceURLs = nil
	}

	for _, e := range events {
		cves := cvesFromAddedSummary(e.Summary)
		if cves == nil {
			flush()
			out = append(out, e)
			continue
		}
		minute := e.At.Truncate(time.Minute)
		if pending != nil &&
			pending.Level == e.Level &&
			pending.At.Truncate(time.Minute).Equal(minute) &&
			slicesEqual(pending.Sources, e.Sources) {
			pendingCVEs = append(pendingCVEs, cves...)
			pendingSourceURLs = append(pendingSourceURLs, e.SourceURLs...)
			continue
		}
		flush()
		pending = &e
		pendingCVEs = cves
		pendingSourceURLs = append([]string(nil), e.SourceURLs...)
	}
	flush()
	return out
}

// cvesFromAddedSummary parses "added CVE-YYYY-NNNN" summaries and returns the
// CVE ids. It returns nil for summaries that do not follow this pattern,
// including "added CVE-YYYY-NNNN +N" where the exact ids of the extra CVEs are
// not present.
func cvesFromAddedSummary(summary string) []string {
	const prefix = "added "
	if !strings.HasPrefix(summary, prefix) {
		return nil
	}
	rest := strings.TrimPrefix(summary, prefix)
	parts := strings.SplitN(rest, " ", 2)
	if len(parts) == 0 {
		return nil
	}
	first := strings.ToUpper(strings.TrimSpace(parts[0]))
	if !strings.HasPrefix(first, "CVE-") {
		return nil
	}
	// Cannot expand a "+N" suffix, so treat it as non-coalescable.
	if len(parts) == 2 && strings.HasPrefix(parts[1], "+") {
		return nil
	}
	return []string{first}
}

// formatAddedCVEsSummary produces a readable summary for a coalesced set of
// CVE additions. Up to three CVEs are listed explicitly; beyond that the
// existing "CVE-A +N" style is preserved.
func formatAddedCVEsSummary(cves []string) string {
	seen := make(map[string]bool)
	var uniq []string
	for _, c := range cves {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		uniq = append(uniq, c)
	}
	if len(uniq) == 0 {
		return "added CVEs"
	}
	sort.Strings(uniq)
	if len(uniq) <= 3 {
		return "added " + strings.Join(uniq, ", ")
	}
	return fmt.Sprintf("added %s +%d", uniq[0], len(uniq)-1)
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func injectSourceField(briefYAML, source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return briefYAML
	}
	if strings.Contains(briefYAML, "\nsource:") || strings.HasPrefix(briefYAML, "source:") {
		return briefYAML
	}
	// Prepend on its own line so the order in the assembled YAML
	// stays stable. Uses double quotes around the value to be safe
	// against future source names containing special characters.
	return "source: " + escapeYAMLString(source) + "\n" + briefYAML
}

// injectStringListField prepends a single-element YAML list to a brief YAML
// if the key is not already present. Idempotent — existing values are kept.
// Only used for the initial brief creation; subsequent URLs are merged via
// mergeStringList in mergeIntoDraft.
func injectStringListField(briefYAML, key, value string) string {
	marker := "\n" + key + ":"
	if strings.Contains(briefYAML, marker) || strings.HasPrefix(briefYAML, key+":") {
		return briefYAML
	}
	return key + ":\n- " + value + "\n" + briefYAML
}

// ensureInitialSourceReference preserves assembler references and adds the
// actual source item's URL, including when the assembler emitted references:
// []. It runs before validation so the stored brief and public page agree on
// provenance.
func ensureInitialSourceReference(briefYAML, sourceURL string) (string, error) {
	if !validSourceURL(sourceURL) {
		return briefYAML, nil
	}
	var fields map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &fields); err != nil {
		return briefYAML, fmt.Errorf("parse brief before source attribution: %w", err)
	}
	if !mergeStringList(fields, "references", []string{sourceURL}) {
		return briefYAML, nil
	}
	out, err := yaml.Marshal(fields)
	if err != nil {
		return briefYAML, fmt.Errorf("serialize attributed brief: %w", err)
	}
	return string(out), nil
}

// injectBoolField prepends `key: true` to a brief YAML if the key isn't
// already present. Idempotent — existing values are never overwritten.
func injectBoolField(briefYAML, key string, val bool) string {
	marker := "\n" + key + ":"
	if strings.Contains(briefYAML, marker) || strings.HasPrefix(briefYAML, key+":") {
		return briefYAML
	}
	v := "false"
	if val {
		v = "true"
	}
	return key + ": " + v + "\n" + briefYAML
}

func escapeYAMLString(s string) string {
	if !strings.ContainsAny(s, ":#'\"\n") {
		return s
	}
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}

// briefSignals captures the small set of fields that drive update-tier
// classification. Cheap to extract, cheap to diff.
type briefSignals struct {
	cveSet      map[string]bool
	kevSet      map[string]bool
	productVers map[string]string // product → version qualifier (or "" if none)
	osSet       map[string]bool
	iocCount    int
	severity    string
	exploited   bool
	hasPOC      bool
}

func snapshotBriefSignals(fm map[string]any) briefSignals {
	s := briefSignals{
		cveSet:      map[string]bool{},
		kevSet:      map[string]bool{},
		productVers: map[string]string{},
		osSet:       map[string]bool{},
	}
	if list, ok := fm["cves"].([]any); ok {
		for _, v := range list {
			switch t := v.(type) {
			case string:
				s.cveSet[strings.ToUpper(strings.TrimSpace(t))] = true
			case map[string]any:
				if id, _ := t["id"].(string); id != "" {
					id = strings.ToUpper(strings.TrimSpace(id))
					s.cveSet[id] = true
					if kev, _ := t["kev"].(bool); kev {
						s.kevSet[id] = true
					}
				}
			}
		}
	}
	if list, ok := fm["affected_products"].([]any); ok {
		for _, v := range list {
			str, _ := v.(string)
			str = strings.TrimSpace(str)
			if str == "" {
				continue
			}
			bare := strings.TrimSpace(strings.SplitN(str, "(", 2)[0])
			ver := ""
			if i := strings.Index(str, "("); i >= 0 {
				ver = strings.TrimSpace(strings.TrimSuffix(str[i+1:], ")"))
			}
			s.productVers[strings.ToLower(bare)] = ver
		}
	}
	if list, ok := fm["affected_os"].([]any); ok {
		for _, v := range list {
			if str, ok := v.(string); ok {
				s.osSet[strings.ToLower(strings.TrimSpace(str))] = true
			}
		}
	}
	if list, ok := fm["iocs"].([]any); ok {
		s.iocCount = len(list)
	}
	if str, ok := fm["severity"].(string); ok {
		s.severity = strings.ToLower(strings.TrimSpace(str))
	}
	if b, ok := fm["exploited"].(bool); ok {
		s.exploited = b
	}
	if b, ok := fm["has_poc"].(bool); ok {
		s.hasPOC = b
	}
	return s
}

// classifyUpdate diffs pre- and post-merge signal snapshots into a
// human-readable summary and an L1/L2/L3 tier label. Tier ordering is
// strict: L3 > L2 > L1; the highest fired wins. Returns "L0" with an
// empty summary when nothing user-relevant actually changed.
func classifyUpdate(pre, post briefSignals, addedVendors, addedProducts, addedOS, addedCVEs, addedIOCs, addedRef bool) (string, string) {
	level := "L0"
	bump := func(target string) {
		switch {
		case target == "L3":
			level = "L3"
		case target == "L2" && level != "L3":
			level = "L2"
		case target == "L1" && level == "L0":
			level = "L1"
		}
	}
	var parts []string

	// Severity escalation — pre/post.
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if r1, r2 := rank[pre.severity], rank[post.severity]; r2 > r1 && r1 > 0 {
		parts = append(parts, "severity → "+post.severity)
		if post.severity == "critical" {
			bump("L3")
		} else {
			bump("L2")
		}
	}

	// Exploitation flag flipped on.
	if post.exploited && !pre.exploited {
		parts = append(parts, "exploited:true")
		bump("L3")
	}

	// PoC became available.
	if post.hasPOC && !pre.hasPOC {
		parts = append(parts, "poc_available")
		bump("L2")
	}

	// New KEV-flagged CVEs (verifier filled this in).
	for cve := range post.kevSet {
		if !pre.kevSet[cve] {
			parts = append(parts, "KEV "+cve)
			bump("L3")
		}
	}

	// New CVE ids.
	newCVEs := make([]string, 0)
	for cve := range post.cveSet {
		if !pre.cveSet[cve] {
			newCVEs = append(newCVEs, cve)
		}
	}
	if len(newCVEs) > 0 {
		sort.Strings(newCVEs)
		summary := "added " + newCVEs[0]
		if len(newCVEs) > 1 {
			summary = fmt.Sprintf("added %s +%d", newCVEs[0], len(newCVEs)-1)
		}
		parts = append(parts, summary)
		bump("L2")
	}

	// New product version qualifier on a previously-bare product.
	for product, postVer := range post.productVers {
		preVer, existed := pre.productVers[product]
		if !existed {
			continue
		}
		if preVer == "" && postVer != "" {
			parts = append(parts, fmt.Sprintf("%s version %s", product, postVer))
			bump("L2")
		}
	}

	// New OS row.
	for os := range post.osSet {
		if !pre.osSet[os] {
			parts = append(parts, "OS "+os)
			bump("L1")
		}
	}

	// New vendors / products / IOCs surface as L1.
	if addedVendors {
		bump("L1")
	}
	if addedProducts {
		bump("L1")
	}
	if addedIOCs {
		bump("L1")
	}

	if level == "L0" {
		return "L0", ""
	}
	if len(parts) == 0 {
		// Defensive: bumped but no readable summary — e.g. pure tag/IOC adds.
		switch {
		case addedIOCs:
			parts = append(parts, "new IOCs")
		case addedProducts:
			parts = append(parts, "new product")
		case addedVendors:
			parts = append(parts, "new vendor")
		}
	}
	return level, strings.Join(parts, "; ")
}
