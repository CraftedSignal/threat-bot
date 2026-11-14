package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"gopkg.in/yaml.v3"
)

// correlationBrief holds the fields needed for cross-brief correlation.
type correlationBrief struct {
	ID           string
	ThreatActor  string
	Tags         []string
	CVEs         []string
	TechniqueIDs []string
}

// tagCache abstracts the correlation tag persistence layer.
type tagCache interface {
	GetCorrelationTag(hash string) (string, error)
	SaveCorrelationTag(hash, tag string) error
}

// clusterNamer generates human-readable tags for TTP clusters using an LLM,
// falling back to deterministic tactic-based names.
type clusterNamer struct {
	db  tagCache
	llm llm.Client
}

// Name returns a short hyphenated tag for a set of MITRE technique IDs.
// It checks the cache first, then tries the LLM, then falls back to a
// deterministic name derived from the dominant tactic prefix.
func (cn *clusterNamer) Name(ctx context.Context, techniqueIDs []string) string {
	h := hashTechniques(techniqueIDs)
	tag, err := cn.db.GetCorrelationTag(h)
	if err == nil && tag != "" {
		return tag
	}

	tag = cn.llmName(ctx, techniqueIDs)
	if tag == "" {
		tag = fallbackTTPTag(techniqueIDs)
	}

	_ = cn.db.SaveCorrelationTag(h, tag)
	return tag
}

// llmName asks the LLM for a 2-3 word cluster name.
func (cn *clusterNamer) llmName(ctx context.Context, techniqueIDs []string) string {
	if cn.llm == nil {
		return ""
	}

	prompt := fmt.Sprintf(
		"Given these MITRE ATT&CK technique IDs: %s\n"+
			"Generate a short 2-3 word lowercase hyphenated tag that describes this cluster of techniques.\n"+
			"Reply with ONLY the tag, nothing else. Example: credential-harvesting",
		strings.Join(techniqueIDs, ", "),
	)

	resp, err := cn.llm.Generate(ctx, prompt, "You are a concise threat intelligence tagger.")
	if err != nil {
		return ""
	}

	tag := normalizeTag(strings.TrimSpace(resp))
	// Sanity check: must be short and look like a tag.
	if len(tag) > 40 || len(tag) < 3 || strings.Count(tag, " ") > 0 {
		return ""
	}
	return tag
}

// correlateBriefs finds shared attributes across briefs and returns new tags
// to add per brief ID (only tags the brief doesn't already have).
// An optional clusterNamer can be provided for LLM-assisted TTP cluster naming.
func correlateBriefs(ctx context.Context, briefs []correlationBrief, namer ...*clusterNamer) map[string][]string {
	newTags := make(map[string][]string)

	// 1. Actor match: briefs sharing the same normalized threat_actor.
	actorBriefs := make(map[string][]int) // normalized actor -> brief indices
	for i, b := range briefs {
		actor := normalizeTag(b.ThreatActor)
		if actor == "" {
			continue
		}
		actorBriefs[actor] = append(actorBriefs[actor], i)
	}
	for actor, indices := range actorBriefs {
		if len(indices) < 2 {
			continue
		}
		for _, i := range indices {
			if !briefHasTag(briefs[i], actor) {
				newTags[briefs[i].ID] = append(newTags[briefs[i].ID], actor)
			}
		}
	}

	// 2. CVE overlap: briefs sharing a CVE ID.
	cveBriefs := make(map[string][]int)
	for i, b := range briefs {
		for _, cve := range b.CVEs {
			c := strings.ToUpper(cve)
			cveBriefs[c] = append(cveBriefs[c], i)
		}
	}
	for cve, indices := range cveBriefs {
		if len(indices) < 2 {
			continue
		}
		tag := normalizeTag(cve)
		for _, i := range indices {
			if !briefHasTag(briefs[i], tag) {
				newTags[briefs[i].ID] = append(newTags[briefs[i].ID], tag)
			}
		}
	}

	// 3. TTP cluster: pairs of briefs sharing 3+ technique IDs. A technique →
	// briefs index finds each brief's partners, so only briefs that share a
	// technique are compared; pairs are still visited in (i, j) order.
	techniqueBriefs := make(map[string][]int)
	for i, b := range briefs {
		for _, tid := range b.TechniqueIDs {
			techniqueBriefs[tid] = append(techniqueBriefs[tid], i)
		}
	}
	overlap := make([]int, len(briefs))
	var partners []int
	for i := 0; i < len(briefs); i++ {
		partners = partners[:0]
		for _, tid := range briefs[i].TechniqueIDs {
			for _, j := range techniqueBriefs[tid] {
				if j <= i {
					continue
				}
				if overlap[j] == 0 {
					partners = append(partners, j)
				}
				overlap[j]++
			}
		}
		slices.Sort(partners)
		for _, j := range partners {
			// overlap counts repeated technique IDs too, so it never
			// undercounts the intersection; it only skips sure misses.
			enough := overlap[j] >= 3
			overlap[j] = 0
			if !enough {
				continue
			}
			shared := intersect(briefs[i].TechniqueIDs, briefs[j].TechniqueIDs)
			if len(shared) < 3 {
				continue
			}

			var tag string
			if len(namer) > 0 && namer[0] != nil {
				tag = namer[0].Name(ctx, shared)
			} else {
				tag = fallbackTTPTag(shared)
			}

			if tag == "" {
				continue
			}
			for _, idx := range []int{i, j} {
				if !briefHasTag(briefs[idx], tag) {
					newTags[briefs[idx].ID] = append(newTags[briefs[idx].ID], tag)
				}
			}
		}
	}

	return newTags
}

// normalizeTag lowercases and replaces spaces/underscores with hyphens.
func normalizeTag(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	return s
}

// briefHasTag checks if a brief already has a given tag (case-insensitive).
func briefHasTag(b correlationBrief, tag string) bool {
	tag = strings.ToLower(tag)
	for _, t := range b.Tags {
		if strings.ToLower(t) == tag {
			return true
		}
	}
	return false
}

// intersect returns the common elements between two string slices.
func intersect(a, b []string) []string {
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	var result []string
	for _, v := range b {
		if set[v] {
			result = append(result, v)
		}
	}
	return result
}

// hashTechniques returns a deterministic SHA-256 hex digest of sorted technique IDs.
func hashTechniques(ids []string) string {
	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, ",")))
	return fmt.Sprintf("%x", h)
}

// tacticPrefixes maps MITRE technique ID prefixes to tactic names.
var tacticPrefixes = map[string]string{
	"T1001": "command-and-control",
	"T1003": "credential-access",
	"T1005": "collection",
	"T1007": "discovery",
	"T1010": "discovery",
	"T1012": "discovery",
	"T1016": "discovery",
	"T1018": "discovery",
	"T1020": "exfiltration",
	"T1021": "lateral-movement",
	"T1027": "defense-evasion",
	"T1033": "discovery",
	"T1036": "defense-evasion",
	"T1037": "persistence",
	"T1039": "collection",
	"T1040": "credential-access",
	"T1041": "exfiltration",
	"T1046": "discovery",
	"T1047": "execution",
	"T1048": "exfiltration",
	"T1049": "discovery",
	"T1053": "execution",
	"T1055": "defense-evasion",
	"T1056": "collection",
	"T1057": "discovery",
	"T1059": "execution",
	"T1068": "privilege-escalation",
	"T1069": "discovery",
	"T1070": "defense-evasion",
	"T1071": "command-and-control",
	"T1074": "collection",
	"T1078": "defense-evasion",
	"T1082": "discovery",
	"T1083": "discovery",
	"T1087": "discovery",
	"T1090": "command-and-control",
	"T1098": "persistence",
	"T1102": "command-and-control",
	"T1105": "command-and-control",
	"T1106": "execution",
	"T1110": "credential-access",
	"T1112": "defense-evasion",
	"T1113": "collection",
	"T1114": "collection",
	"T1119": "collection",
	"T1132": "command-and-control",
	"T1133": "initial-access",
	"T1134": "defense-evasion",
	"T1135": "discovery",
	"T1140": "defense-evasion",
	"T1176": "persistence",
	"T1185": "collection",
	"T1189": "initial-access",
	"T1190": "initial-access",
	"T1195": "initial-access",
	"T1197": "defense-evasion",
	"T1199": "initial-access",
	"T1200": "initial-access",
	"T1201": "discovery",
	"T1202": "defense-evasion",
	"T1203": "execution",
	"T1204": "execution",
	"T1210": "lateral-movement",
	"T1218": "defense-evasion",
	"T1219": "command-and-control",
	"T1220": "defense-evasion",
	"T1222": "defense-evasion",
	"T1480": "defense-evasion",
	"T1486": "impact",
	"T1489": "impact",
	"T1490": "impact",
	"T1491": "impact",
	"T1497": "defense-evasion",
	"T1498": "impact",
	"T1499": "impact",
	"T1505": "persistence",
	"T1518": "discovery",
	"T1543": "persistence",
	"T1546": "persistence",
	"T1547": "persistence",
	"T1548": "privilege-escalation",
	"T1550": "lateral-movement",
	"T1553": "defense-evasion",
	"T1555": "credential-access",
	"T1556": "credential-access",
	"T1557": "credential-access",
	"T1558": "credential-access",
	"T1560": "collection",
	"T1562": "defense-evasion",
	"T1563": "lateral-movement",
	"T1564": "defense-evasion",
	"T1566": "initial-access",
	"T1567": "exfiltration",
	"T1568": "command-and-control",
	"T1569": "execution",
	"T1570": "lateral-movement",
	"T1571": "command-and-control",
	"T1572": "command-and-control",
	"T1573": "command-and-control",
	"T1574": "persistence",
	"T1583": "resource-development",
	"T1584": "resource-development",
	"T1585": "resource-development",
	"T1586": "resource-development",
	"T1587": "resource-development",
	"T1588": "resource-development",
	"T1589": "reconnaissance",
	"T1590": "reconnaissance",
	"T1591": "reconnaissance",
	"T1592": "reconnaissance",
	"T1593": "reconnaissance",
	"T1594": "reconnaissance",
	"T1595": "reconnaissance",
	"T1598": "reconnaissance",
	"T1608": "resource-development",
	"T1609": "execution",
	"T1610": "defense-evasion",
	"T1611": "privilege-escalation",
	"T1612": "defense-evasion",
	"T1613": "discovery",
	"T1614": "discovery",
}

// fallbackTTPTag derives a tag from the dominant tactic among the given technique IDs.
func fallbackTTPTag(techniqueIDs []string) string {
	counts := make(map[string]int)
	for _, tid := range techniqueIDs {
		// Extract the base technique (e.g. T1059 from T1059.001).
		base := tid
		if dot := strings.Index(tid, "."); dot > 0 {
			base = tid[:dot]
		}
		if tactic, ok := tacticPrefixes[base]; ok {
			counts[tactic]++
		}
	}
	if len(counts) == 0 {
		return "ttp-cluster"
	}

	// Find dominant tactic (alphabetical tie-break for determinism).
	var best string
	var bestCount int
	for tactic, count := range counts {
		if count > bestCount || (count == bestCount && tactic < best) {
			best = tactic
			bestCount = count
		}
	}
	return best
}

// Correlator integrates brief correlation into the pipeline.
type Correlator struct {
	db                  *storage.DB
	namer               *clusterNamer
	logger              *slog.Logger
	validatePublication func(string) error
	publishUpdates      bool
}

// NewCorrelator creates a new Correlator. If llmClient is nil, LLM naming is disabled.
func NewCorrelator(db *storage.DB, llmClient llm.Client, logger *slog.Logger) *Correlator {
	return &Correlator{
		db: db,
		namer: &clusterNamer{
			db:  db,
			llm: llmClient,
		},
		logger: logger,
	}
}

// correlationCVERe is a local copy to avoid import cycles with verify_cve.go.
var correlationCVERe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// parseBriefForCorrelation extracts correlation-relevant fields from raw YAML.
func parseBriefForCorrelation(id, rawYAML string) correlationBrief {
	var brief briefYAML
	if err := yaml.Unmarshal([]byte(rawYAML), &brief); err != nil {
		return correlationBrief{ID: id}
	}

	// Collect CVEs from references and content via regex.
	cveSet := make(map[string]bool)
	for _, ref := range brief.References {
		for _, m := range correlationCVERe.FindAllString(ref, -1) {
			cveSet[strings.ToUpper(m)] = true
		}
	}
	for _, m := range correlationCVERe.FindAllString(brief.Content, -1) {
		cveSet[strings.ToUpper(m)] = true
	}
	for _, m := range correlationCVERe.FindAllString(brief.Summary, -1) {
		cveSet[strings.ToUpper(m)] = true
	}
	var cves []string
	for c := range cveSet {
		cves = append(cves, c)
	}
	sort.Strings(cves)

	// Collect technique IDs from TTPs.
	var techniqueIDs []string
	seen := make(map[string]bool)
	for _, ttp := range brief.TTPs {
		tid := ttp.TechniqueID
		if ttp.SubtechniqueID != "" {
			tid = ttp.SubtechniqueID
		}
		if tid != "" && !seen[tid] {
			seen[tid] = true
			techniqueIDs = append(techniqueIDs, tid)
		}
	}

	return correlationBrief{
		ID:           id,
		ThreatActor:  brief.ThreatActor,
		Tags:         brief.Tags,
		CVEs:         cves,
		TechniqueIDs: techniqueIDs,
	}
}

// correlationSummaryVersion versions the correlation summaries stored per
// draft. Bump it whenever parseBriefForCorrelation changes what it extracts,
// so stored summaries are recomputed.
const correlationSummaryVersion = 1

// correlationSummary is the stored form of a draft's correlation fields.
type correlationSummary struct {
	Version      int      `json:"v"`
	ThreatActor  string   `json:"threat_actor,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	CVEs         []string `json:"cves,omitempty"`
	TechniqueIDs []string `json:"technique_ids,omitempty"`
}

func encodeCorrelationSummary(b correlationBrief) (string, error) {
	out, err := json.Marshal(correlationSummary{
		Version:      correlationSummaryVersion,
		ThreatActor:  b.ThreatActor,
		Tags:         b.Tags,
		CVEs:         b.CVEs,
		TechniqueIDs: b.TechniqueIDs,
	})
	return string(out), err
}

// decodeCorrelationSummary reports false when the stored summary is missing,
// unreadable, or from another summary version.
func decodeCorrelationSummary(id, stored string) (correlationBrief, bool) {
	var s correlationSummary
	if stored == "" || json.Unmarshal([]byte(stored), &s) != nil || s.Version != correlationSummaryVersion {
		return correlationBrief{ID: id}, false
	}
	return correlationBrief{ID: id, ThreatActor: s.ThreatActor, Tags: s.Tags, CVEs: s.CVEs, TechniqueIDs: s.TechniqueIDs}, true
}

// Run correlates the last 90 days of approved drafts and updates their YAML with new tags.
// It reads each draft's stored correlation summary; only drafts whose YAML
// changed since their summary was stored are parsed, and their new summaries
// are stored for the next run. Drafts that gain tags are loaded again in full.
// Returns updated brief YAMLs (for re-publishing) and the count of drafts updated.
func (c *Correlator) Run(ctx context.Context) ([]string, error) {
	var briefs []correlationBrief
	var unparsed []int
	for s, err := range c.db.ApprovedDraftCorrelationsSince(time.Now().AddDate(0, 0, -90)) {
		if err != nil {
			return nil, fmt.Errorf("listing recent drafts: %w", err)
		}
		b, ok := decodeCorrelationSummary(s.ID, s.Summary)
		if !ok {
			unparsed = append(unparsed, len(briefs))
		}
		briefs = append(briefs, b)
	}

	for _, i := range unparsed {
		d, err := c.db.GetDraft(briefs[i].ID)
		if err != nil || d == nil {
			c.logger.Warn("failed to load draft for correlation", "draft_id", briefs[i].ID, "error", err)
			continue
		}
		briefs[i] = parseBriefForCorrelation(d.ID, d.BriefYAML)
		summary, err := encodeCorrelationSummary(briefs[i])
		if err == nil {
			err = c.db.SaveDraftCorrelation(d.ID, d.BriefYAML, summary)
		}
		if err != nil {
			c.logger.Warn("failed to store correlation summary", "draft_id", d.ID, "error", err)
		}
	}

	if len(briefs) < 2 {
		return nil, nil
	}

	// Correlate.
	newTags := correlateBriefs(ctx, briefs, c.namer)

	// Apply new tags to drafts and collect updated YAML for re-publishing.
	var updatedYAMLs []string
	for _, b := range briefs {
		tags, ok := newTags[b.ID]
		if !ok || len(tags) == 0 {
			continue
		}

		d, err := c.db.GetDraft(b.ID)
		if err != nil || d == nil {
			c.logger.Warn("failed to load draft for tag update", "draft_id", b.ID, "error", err)
			continue
		}

		var brief map[string]any
		if err := yaml.Unmarshal([]byte(d.BriefYAML), &brief); err != nil {
			c.logger.Warn("failed to parse draft YAML for tag update", "draft_id", d.ID, "error", err)
			continue
		}

		brief["tags"] = append(yamlStringList(brief["tags"]), tags...)

		out, err := yaml.Marshal(&brief)
		if err != nil {
			c.logger.Warn("failed to marshal updated brief", "draft_id", d.ID, "error", err)
			continue
		}
		if c.validatePublication != nil {
			if err := c.validatePublication(string(out)); err != nil {
				c.logger.Warn("correlated brief held for editorial review", "draft_id", d.ID, "error", err)
				continue
			}
		}

		if err := c.db.UpdateDraftYAMLWithPublication(d.ID, string(out), c.publishUpdates, false); err != nil {
			c.logger.Warn("failed to update draft YAML", "draft_id", d.ID, "error", err)
			continue
		}

		c.logger.Info("correlated brief", "draft_id", d.ID, "new_tags", tags)
		updatedYAMLs = append(updatedYAMLs, string(out))
	}

	return updatedYAMLs, nil
}
