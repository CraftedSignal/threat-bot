package pipeline

import (
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestNormalizeDetectionSeverity_AnomalyScoreCapsHigh(t *testing.T) {
	brief := "title: Test\nseverity: high\ncontent: x\n"
	item := scraper.RawItem{
		Source: "any-detection-source",
		Content: `
name: Example anomaly
type: Anomaly
intermediate_findings:
  entities:
    score: 20
`,
	}
	got := normalizeDetectionSeverity(brief, item)
	if !strings.Contains(got, "severity: medium") {
		t.Fatalf("want high severity capped to medium, got:\n%s", got)
	}
}

func TestNormalizeDetectionSeverity_MetadataLevelCapsHigh(t *testing.T) {
	brief := "title: Test\nseverity: high\ncontent: x\n"
	item := scraper.RawItem{
		Source:   "any-detection-source",
		Metadata: map[string]string{"level": "low"},
	}
	got := normalizeDetectionSeverity(brief, item)
	if !strings.Contains(got, "severity: low") {
		t.Fatalf("want high severity capped to low, got:\n%s", got)
	}
}
