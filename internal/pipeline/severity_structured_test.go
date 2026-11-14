package pipeline

import (
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"gopkg.in/yaml.v3"
)

func TestNormalizeSeverityFromCVSSBand(t *testing.T) {
	cases := []struct {
		source, cvss, sevMeta, llm, want string
	}{
		{"nvd", "8.8", "", "medium", "high"},
		{"nvd", "9.0", "", "high", "critical"},
		{"nvd", "7.0", "", "critical", "high"},
		{"nvd", "4.0", "", "low", "medium"},
		{"nvd", "3.9", "", "high", "low"},
		{"ghsa", "8.8", "critical", "medium", "critical"}, // advisory severity wins
		{"ghsa", "", "moderate", "high", "medium"},
		{"ghsa", "5.5", "", "critical", "medium"},
		{"cisa-kev", "9.8", "", "medium", "medium"}, // other sources untouched
		{"nvd", "", "", "medium", "medium"},         // no data, no change
	}
	for _, c := range cases {
		meta := map[string]string{}
		if c.cvss != "" {
			meta["cvss"] = c.cvss
		}
		if c.sevMeta != "" {
			meta["severity"] = c.sevMeta
		}
		out := normalizeDetectionSeverity("title: x\nseverity: "+c.llm+"\n", scraper.RawItem{Source: c.source, Metadata: meta})
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		if doc["severity"] != c.want {
			t.Errorf("%+v: severity = %v, want %s", c, doc["severity"], c.want)
		}
	}
}
