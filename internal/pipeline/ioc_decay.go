package pipeline

import (
	"math"
	"time"

	"gopkg.in/yaml.v3"
)

// IOCDecayConfig configures half-life durations for IOC confidence decay
// by IOC type. Confidence follows exponential decay: 0.5^(age/half_life).
type IOCDecayConfig struct {
	IPHalfLifeHours     float64 // default: 72 (3 days)
	DomainHalfLifeHours float64 // default: 168 (7 days)
	HashHalfLifeHours   float64 // default: 720 (30 days)
	URLHalfLifeHours    float64 // default: 120 (5 days)
	EmailHalfLifeHours  float64 // default: 336 (14 days)
}

// DefaultIOCDecayConfig returns an IOCDecayConfig with sensible defaults.
func DefaultIOCDecayConfig() IOCDecayConfig {
	return IOCDecayConfig{
		IPHalfLifeHours:     72,
		DomainHalfLifeHours: 168,
		HashHalfLifeHours:   720,
		URLHalfLifeHours:    120,
		EmailHalfLifeHours:  336,
	}
}

// halfLifeForType returns the half-life in hours for a given IOC type.
func halfLifeForType(iocType string, cfg IOCDecayConfig) float64 {
	switch iocType {
	case "ipv4", "ipv6", "ip":
		return cfg.IPHalfLifeHours
	case "domain":
		return cfg.DomainHalfLifeHours
	case "hash_md5", "hash_sha1", "hash_sha256", "hash":
		return cfg.HashHalfLifeHours
	case "url":
		return cfg.URLHalfLifeHours
	case "email":
		return cfg.EmailHalfLifeHours
	default:
		// For unknown types, use domain half-life as a reasonable middle ground.
		return cfg.DomainHalfLifeHours
	}
}

// DecayIOCConfidence calculates a confidence score (0.0-1.0) for an IOC
// based on its type and age since first observation.
// Formula: confidence = 0.5^(age_hours / half_life_hours)
func DecayIOCConfidence(iocType string, age time.Duration, cfg IOCDecayConfig) float64 {
	if age <= 0 {
		return 1.0
	}
	halfLife := halfLifeForType(iocType, cfg)
	if halfLife <= 0 {
		return 1.0
	}
	ageHours := age.Hours()
	confidence := math.Pow(0.5, ageHours/halfLife)
	// Clamp to [0, 1].
	if confidence > 1.0 {
		return 1.0
	}
	if confidence < 0.0 {
		return 0.0
	}
	return confidence
}

// ApplyDecay adds a "confidence" field to IOCs in a brief YAML based on
// the brief's published_at date and the current time.
func ApplyDecay(briefYAML string, now time.Time, cfg IOCDecayConfig) string {
	// Parse the full YAML into a generic map to preserve all fields.
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(briefYAML), &doc); err != nil {
		return briefYAML
	}

	// Extract published_at to compute age.
	pubStr, _ := doc["published_at"].(string)
	if pubStr == "" {
		return briefYAML
	}
	publishedAt, err := time.Parse(time.RFC3339, pubStr)
	if err != nil {
		return briefYAML
	}

	// Get IOCs slice.
	iocsRaw, ok := doc["iocs"]
	if !ok {
		return briefYAML
	}
	iocsList, ok := iocsRaw.([]any)
	if !ok || len(iocsList) == 0 {
		return briefYAML
	}

	age := now.Sub(publishedAt)

	// Annotate each IOC with confidence.
	for _, item := range iocsList {
		iocMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		iocType, _ := iocMap["type"].(string)
		confidence := DecayIOCConfidence(iocType, age, cfg)
		// Round to 4 decimal places.
		iocMap["confidence"] = math.Round(confidence*10000) / 10000
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return briefYAML
	}
	return string(out)
}
