package publisher

import (
	"bytes"
	"fmt"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// PublicNotificationFields returns the fields subscribers filter on (type,
// severity, actors, vendors, products, tags, exploitation, PoC) exactly as the
// brief's published front matter carries them, by rendering it the way
// publication does. Update notifications use these: the draft YAML has no
// public type and keeps vendors and products under affected_*, so update
// payloads built from it alone matched no type-filtered subscription.
//
// It uses no publisher state, so it is safe on a nil receiver.
func (*Publisher) PublicNotificationFields(briefYAML string) (pipeline.PublicNotificationFields, error) {
	var fields pipeline.PublicNotificationFields
	brief, err := ParseBriefYAML(briefYAML)
	if err != nil {
		return fields, err
	}
	content, err := briefToMarkdown(*brief)
	if err != nil {
		return fields, err
	}
	frontmatter, ok := renderedFrontmatter(content)
	if !ok {
		return fields, fmt.Errorf("rendered brief %q has no front matter", brief.ID)
	}
	if err := yaml.Unmarshal(frontmatter, &fields); err != nil {
		return fields, fmt.Errorf("decoding rendered front matter of %q: %w", brief.ID, err)
	}
	return fields, nil
}

// renderedFrontmatter returns the YAML between the opening and closing "---"
// lines that briefToMarkdown writes.
func renderedFrontmatter(content []byte) ([]byte, bool) {
	rest, ok := bytes.CutPrefix(content, []byte("---\n"))
	if !ok {
		return nil, false
	}
	end := bytes.Index(rest, []byte("\n---\n"))
	if end < 0 {
		return nil, false
	}
	return rest[:end+1], true
}
