package pipeline

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// A CVE identifies one vulnerability, so a merge must never add a CVE to a
// brief unless the brief already lists it or a source documents it as part of
// one exploitation chain with a CVE the brief lists, and a report about only
// other CVEs never joins a brief. Every merge path checks that rule here.
// Roundups and campaign umbrellas collect many CVEs by design and are exempt.

// cveChainSet records which CVEs a source documents as one exploitation chain.
type cveChainSet map[string]string

// cveChains links the CVEs of each chain, joining chains that share a CVE.
func cveChains(chains [][]string) cveChainSet {
	parent := make(map[string]string)
	find := func(id string) string {
		for parent[id] != id {
			parent[id] = parent[parent[id]]
			id = parent[id]
		}
		return id
	}
	for _, chain := range chains {
		var first string
		for _, raw := range chain {
			id := normalizeCVEID(raw)
			if id == "" {
				continue
			}
			if _, ok := parent[id]; !ok {
				parent[id] = id
			}
			if first == "" {
				first = id
				continue
			}
			parent[find(id)] = find(first)
		}
	}
	set := make(cveChainSet, len(parent))
	for id := range parent {
		set[id] = find(id)
	}
	return set
}

// linked reports whether a and b are the same CVE or part of one chain.
func (s cveChainSet) linked(a, b string) bool {
	a, b = normalizeCVEID(a), normalizeCVEID(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	ra, okA := s[a]
	rb, okB := s[b]
	return okA && okB && ra == rb
}

func normalizeCVEID(raw string) string {
	id := strings.ToUpper(strings.TrimSpace(raw))
	if cveRegex.FindString(id) != id {
		return ""
	}
	return id
}

// briefCVEIDs returns the CVE IDs a brief lists. Briefs list CVEs as plain IDs
// or as objects with an id field.
func briefCVEIDs(fm map[string]any) map[string]bool {
	ids := make(map[string]bool)
	for _, entry := range yamlAnyList(fm["cves"]) {
		raw, _ := entry.(string)
		if m, ok := asStringMap(entry); ok {
			raw, _ = m["id"].(string)
		}
		if id := normalizeCVEID(raw); id != "" {
			ids[id] = true
		}
	}
	return ids
}

func parseBriefFrontmatter(briefYAML string) map[string]any {
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &fm); err != nil {
		return nil
	}
	return fm
}

// cvesAccepted reports whether a brief listing target may take a report about
// cves: each must be listed in target or chained with a listed CVE. A brief
// that lists no CVE has no vulnerability identity yet and accepts any report.
func cvesAccepted(target map[string]bool, cves []string, chains cveChainSet) bool {
	if len(target) == 0 {
		return true
	}
	for _, raw := range cves {
		id := normalizeCVEID(raw)
		if id == "" || target[id] {
			continue
		}
		accepted := false
		for listed := range target {
			if chains.linked(id, listed) {
				accepted = true
				break
			}
		}
		if !accepted {
			return false
		}
	}
	return true
}

// cvesOverlap reports whether a report naming cves may join a brief listing
// target: one of them must be listed or chained with a listed CVE. Either side
// naming no CVE leaves the decision to the other merge checks.
func cvesOverlap(target map[string]bool, cves []string, chains cveChainSet) bool {
	if len(target) == 0 {
		return true
	}
	named := false
	for _, raw := range cves {
		if normalizeCVEID(raw) == "" {
			continue
		}
		named = true
		if cvesAccepted(target, []string{raw}, chains) {
			return true
		}
	}
	return !named
}

// briefAcceptsBrief reports whether incoming may merge into target. A merge
// copies the incoming brief's severity, actions and TTPs along with its CVEs,
// so every incoming CVE must be accepted. chains are the exploitation chains
// the incoming item's source documents.
func briefAcceptsBrief(target, incoming map[string]any, chains [][]string) bool {
	return cvesAccepted(briefCVEIDs(target), sortedCVEIDs(briefCVEIDs(incoming)), cveChains(chains))
}

func sortedCVEIDs(ids map[string]bool) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
