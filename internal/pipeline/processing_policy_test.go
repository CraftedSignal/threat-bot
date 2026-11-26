package pipeline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func policyTestConfig() Config {
	return Config{
		ProcessingPolicy:       "vertexai/eu/model/fast/repair",
		QualityThreshold:       3.5,
		SourceSignalThresholds: map[string]int{"sploitus": 3},
		RoundupConsolidation:   true,
	}
}

// Adding a scraper or retuning its default confidence must not discard every
// pending candidate (and re-pay their grounding work) for all other sources.
func TestProcessingPolicyKeyIgnoresSourceDefaultTable(t *testing.T) {
	before := New(policyTestConfig()).processingPolicyKey()
	inputBefore := New(policyTestConfig()).processingInputKey(policyKeyItem())

	saved := make(map[string]float64, len(defaultSourceConfidence))
	for source, value := range defaultSourceConfidence {
		saved[source] = value
	}
	t.Cleanup(func() {
		clear(defaultSourceConfidence)
		for source, value := range saved {
			defaultSourceConfidence[source] = value
		}
	})
	defaultSourceConfidence["zz-new-scraper"] = 0.75
	defaultSourceConfidence["nvd"] = 0.42
	delete(defaultSourceConfidence, "sploitus")

	p := New(policyTestConfig())
	if got := p.processingPolicyKey(); got != before {
		t.Fatal("a source default change invalidated every pending checkpoint")
	}
	if got := p.processingInputKey(policyKeyItem()); got != inputBefore {
		t.Fatal("a source default change reset every retry identity")
	}
	if got := p.getSourceConfidence("zz-new-scraper"); got != 0.75 {
		t.Fatalf("new source default not applied to new items: %v", got)
	}
}

// Operator configuration remains a deliberate policy change.
func TestProcessingPolicyKeyFollowsConfiguredOverrides(t *testing.T) {
	base := New(policyTestConfig()).processingPolicyKey()
	for name, mutate := range map[string]func(*Config){
		"confidence override": func(c *Config) { c.SourceConfidence = map[string]float64{"nvd": 0.5} },
		"trusted source":      func(c *Config) { c.TrustedSources = []string{"bsi"} },
		"signal threshold":    func(c *Config) { c.SourceSignalThresholds = map[string]int{"sploitus": 4} },
		"quality threshold":   func(c *Config) { c.QualityThreshold = 4 },
		"models":              func(c *Config) { c.ProcessingPolicy = "vertexai/eu/other/fast/repair" },
	} {
		cfg := policyTestConfig()
		mutate(&cfg)
		if New(cfg).processingPolicyKey() == base {
			t.Errorf("%s did not change the processing policy", name)
		}
	}
}

// The baseline reproduces the policy that production checkpoints were written
// with; editing it re-processes every pending candidate at the next deploy.
func TestProcessingPolicyBaselineIsFrozen(t *testing.T) {
	encoded, err := json.Marshal(processingPolicySourceBaseline)
	if err != nil {
		t.Fatal(err)
	}
	const want = "03c476cdd06963a683e1e9fe7e92c891c09c1de0e38e3cbe27a584be0516c381"
	if got := fmt.Sprintf("%x", sha256.Sum256(encoded)); got != want {
		t.Fatalf("processingPolicySourceBaseline changed (digest %s): this discards every pending candidate at deploy. Change defaultSourceConfidence instead, or bump processingPolicyVersion deliberately", got)
	}
}

func policyKeyItem() scraper.RawItem {
	return scraper.RawItem{SourceID: "nvd:CVE-2026-0001", Source: "nvd", Title: "CVE-2026-0001", Content: "Vendor advisory."}
}
