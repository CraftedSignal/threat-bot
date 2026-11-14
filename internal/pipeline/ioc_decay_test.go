package pipeline

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestDecayIOCConfidence(t *testing.T) {
	cfg := DefaultIOCDecayConfig()

	tests := []struct {
		name     string
		iocType  string
		age      time.Duration
		expected float64
	}{
		{"IP at t=0", "ipv4", 0, 1.0},
		{"IP at half-life (72h)", "ipv4", 72 * time.Hour, 0.5},
		{"IP at 2x half-life (144h)", "ipv4", 144 * time.Hour, 0.25},
		{"Domain at half-life (168h)", "domain", 168 * time.Hour, 0.5},
		{"Hash at half-life (720h)", "hash_sha256", 720 * time.Hour, 0.5},
		{"URL at half-life (120h)", "url", 120 * time.Hour, 0.5},
		{"Email at half-life (336h)", "email", 336 * time.Hour, 0.5},
		{"Negative age", "ipv4", -1 * time.Hour, 1.0},
		{"Unknown type uses domain half-life", "unknown_type", 168 * time.Hour, 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecayIOCConfidence(tt.iocType, tt.age, cfg)
			if math.Abs(got-tt.expected) > 0.001 {
				t.Errorf("DecayIOCConfidence(%q, %v) = %f, want %f", tt.iocType, tt.age, got, tt.expected)
			}
		})
	}
}

func TestApplyDecay(t *testing.T) {
	cfg := DefaultIOCDecayConfig()
	now := time.Date(2026, 3, 22, 12, 0, 0, 0, time.UTC)

	briefYAML := `id: test-brief
title: Test Brief
summary: A test
severity: high
published_at: "2026-03-22T12:00:00Z"
iocs:
    - type: ipv4
      value: 1.2.3.4
    - type: domain
      value: evil.example.net
    - type: hash_sha256
      value: abc123def456
`

	result := ApplyDecay(briefYAML, now, cfg)

	// At age=0, all IOCs should have confidence ~1.0
	if !strings.Contains(result, "confidence") {
		t.Error("expected confidence field in output")
	}

	// Now test with age
	oldBrief := `id: old-brief
title: Old Brief
summary: Old
severity: medium
published_at: "2026-03-19T12:00:00Z"
iocs:
    - type: ipv4
      value: 1.2.3.4
`
	result = ApplyDecay(oldBrief, now, cfg)
	// 72 hours old IP should have confidence ~0.5
	if !strings.Contains(result, "confidence") {
		t.Error("expected confidence field in aged brief output")
	}
}

func TestApplyDecay_NoIOCs(t *testing.T) {
	briefYAML := `id: no-iocs
title: No IOCs
summary: Brief without IOCs
severity: low
published_at: "2026-03-22T12:00:00Z"
`
	now := time.Date(2026, 3, 22, 12, 0, 0, 0, time.UTC)
	result := ApplyDecay(briefYAML, now, DefaultIOCDecayConfig())

	// Should return unchanged (no IOCs to annotate)
	if strings.Contains(result, "confidence") {
		t.Error("did not expect confidence field when no IOCs present")
	}
}

func TestApplyDecay_InvalidYAML(t *testing.T) {
	result := ApplyDecay("{{invalid yaml", time.Now(), DefaultIOCDecayConfig())
	if result != "{{invalid yaml" {
		t.Error("expected original string returned for invalid YAML")
	}
}

func TestApplyDecay_MissingPublishedAt(t *testing.T) {
	briefYAML := `id: test
title: Test
iocs:
    - type: ipv4
      value: 1.2.3.4
`
	result := ApplyDecay(briefYAML, time.Now(), DefaultIOCDecayConfig())
	if strings.Contains(result, "confidence") {
		t.Error("should not add confidence when published_at is missing")
	}
}
