package pipeline

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// MissingFieldError reports a brief without a field the feed compiler needs.
// The response schema marks such fields required, but cannot demand that a
// string is not blank, so the check stays in Go.
type MissingFieldError struct{ Field string }

func (e *MissingFieldError) Error() string {
	return fmt.Sprintf("brief missing required field %q", e.Field)
}

// ValidateBriefContract checks the internal fields the feed compiler needs
// before a brief can be stored, buffered, or converted to public Markdown.
// It is run both after LLM normalization and at the publisher boundary.
func ValidateBriefContract(rawYAML string) error {
	var brief briefYAML
	if err := yaml.Unmarshal([]byte(rawYAML), &brief); err != nil {
		return fmt.Errorf("parsing brief YAML: %w", err)
	}
	return validateBriefContractFields(brief)
}

func validateBriefContractFields(brief briefYAML) error {
	for _, field := range []struct{ name, value string }{
		{"id", brief.ID},
		{"slug", brief.Slug},
		{"title", brief.Title},
		{"summary", brief.Summary},
		{"severity", brief.Severity},
		{"published_at", brief.PublishedAt},
	} {
		if strings.TrimSpace(field.value) == "" {
			return &MissingFieldError{Field: field.name}
		}
	}
	if brief.ID == "brief-unknown" || brief.Slug == "unknown" {
		return fmt.Errorf("brief has placeholder id or slug")
	}
	switch strings.ToLower(brief.Severity) {
	case "critical", "high", "medium", "low", "rumour", "informational":
	default:
		return fmt.Errorf("brief has invalid severity %q", brief.Severity)
	}
	if _, err := time.Parse(time.RFC3339, brief.PublishedAt); err != nil {
		return fmt.Errorf("brief has invalid published_at %q: %w", brief.PublishedAt, err)
	}
	if err := normalizeExploitationEvidence(&brief); err != nil {
		return err
	}
	return nil
}
