package pipeline

import (
	"strconv"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

var (
	sourceSeverityClampRank     = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	detectionMetadataRank       = map[string]int{"informational": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}
	sourceSeverityClampMaxLevel = "medium"
)

type detectionRuleMetadata struct {
	ruleType string
	level    string
	severity string
	score    *int
}

// normalizeDetectionSeverity applies deterministic severity from source
// metadata after LLM assembly but before normal validation/enrichment: GHSA and
// NVD items get the severity their own data states, other items the caps from
// detection-rule metadata. It only changes top-level brief severity and leaves
// the rest of the generated YAML intact.
func normalizeDetectionSeverity(briefYAML string, item scraper.RawItem) string {
	if severity := structuredAdvisorySeverity(item); severity != "" {
		return setBriefSeverity(briefYAML, severity)
	}
	maxSeverity := detectionSeverityCap(item)
	if maxSeverity == "" {
		return briefYAML
	}
	return clampBriefSeverity(briefYAML, maxSeverity)
}

func detectionSeverityCap(item scraper.RawItem) string {
	meta := extractDetectionRuleMetadata(item)

	sourceSeverity := firstNonPlaceholder([]string{meta.severity, meta.level})
	if rank := detectionMetadataRank[strings.ToLower(sourceSeverity)]; rank > 0 && rank <= detectionMetadataRank["medium"] {
		if rank <= detectionMetadataRank["low"] {
			return "low"
		}
		return "medium"
	}

	if strings.EqualFold(strings.TrimSpace(meta.ruleType), "anomaly") && meta.score != nil && *meta.score <= 40 {
		return sourceSeverityClampMaxLevel
	}

	return ""
}

func extractDetectionRuleMetadata(item scraper.RawItem) detectionRuleMetadata {
	var meta detectionRuleMetadata
	if item.SigmaRule != nil {
		meta.level = item.SigmaRule.Level
	}
	if item.Metadata != nil {
		if v := strings.TrimSpace(item.Metadata["type"]); v != "" {
			meta.ruleType = v
		}
		if v := strings.TrimSpace(item.Metadata["level"]); v != "" {
			meta.level = v
		}
		if v := strings.TrimSpace(item.Metadata["severity"]); v != "" {
			meta.severity = v
		}
		if v := strings.TrimSpace(item.Metadata["score"]); v != "" {
			if score, err := strconv.Atoi(v); err == nil {
				meta.score = &score
			}
		}
	}
	mergeYAMLDetectionMetadata(&meta, item.Content)
	return meta
}

func mergeYAMLDetectionMetadata(meta *detectionRuleMetadata, content string) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil || len(doc.Content) == 0 {
		return
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return
	}

	if meta.ruleType == "" {
		meta.ruleType = findYAMLScalar(root, "type")
	}
	if meta.level == "" {
		meta.level = findYAMLScalar(root, "level")
	}
	if meta.severity == "" {
		meta.severity = findYAMLScalar(root, "severity")
	}
	if meta.score == nil {
		if score, ok := findYAMLInt(root, "score"); ok {
			meta.score = &score
		}
	}
}

func findYAMLScalar(n *yaml.Node, key string) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			if strings.EqualFold(k.Value, key) && v.Kind == yaml.ScalarNode {
				return strings.TrimSpace(v.Value)
			}
		}
	}
	for _, child := range n.Content {
		if found := findYAMLScalar(child, key); found != "" {
			return found
		}
	}
	return ""
}

func findYAMLInt(n *yaml.Node, key string) (int, bool) {
	if n == nil {
		return 0, false
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			if strings.EqualFold(k.Value, key) && v.Kind == yaml.ScalarNode {
				score, err := strconv.Atoi(strings.TrimSpace(v.Value))
				if err == nil {
					return score, true
				}
			}
		}
	}
	for _, child := range n.Content {
		if score, ok := findYAMLInt(child, key); ok {
			return score, true
		}
	}
	return 0, false
}

func clampBriefSeverity(briefYAML, maxSeverity string) string {
	maxRank, ok := sourceSeverityClampRank[maxSeverity]
	if !ok {
		return briefYAML
	}

	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil || len(doc.Content) == 0 {
		return briefYAML
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return briefYAML
	}

	changed := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		val := root.Content[i+1]
		if key.Value != "severity" || val.Kind != yaml.ScalarNode {
			continue
		}
		current := strings.ToLower(strings.TrimSpace(val.Value))
		if sourceSeverityClampRank[current] > maxRank {
			val.Value = maxSeverity
			val.Tag = "!!str"
			val.Style = 0
			changed = true
		}
		break
	}
	if !changed {
		return briefYAML
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}

// structuredAdvisorySeverity returns the severity a ghsa or nvd item states in
// its own data: the advisory severity when present, otherwise the band of its
// CVSS base score (9.0+ critical, 7.0-8.9 high, 4.0-6.9 medium, below that
// low). Any other source, or an item without either, returns "".
func structuredAdvisorySeverity(item scraper.RawItem) string {
	if item.Source != "ghsa" && item.Source != "nvd" {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(item.Metadata["severity"])) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	}
	score, err := strconv.ParseFloat(strings.TrimSpace(item.Metadata["cvss"]), 64)
	if err != nil || score <= 0 {
		return ""
	}
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	}
	return "low"
}

// setBriefSeverity replaces the top-level severity label. A missing label and
// the pipeline-assigned "rumour" are left alone.
func setBriefSeverity(briefYAML, severity string) string {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil || len(doc.Content) == 0 {
		return briefYAML
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return briefYAML
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		val := root.Content[i+1]
		if root.Content[i].Value != "severity" || val.Kind != yaml.ScalarNode {
			continue
		}
		current := strings.ToLower(strings.TrimSpace(val.Value))
		if current == severity || current == "rumour" {
			return briefYAML
		}
		val.Value, val.Tag, val.Style = severity, "!!str", 0
		out, err := yaml.Marshal(&doc)
		if err != nil {
			return briefYAML
		}
		return string(out)
	}
	return briefYAML
}
