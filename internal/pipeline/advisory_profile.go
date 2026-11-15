package pipeline

import (
	"strings"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// Keep all substantive guidance. Only the schema-shaped field examples and
// four lengthy sample Sigma rules are removed. The field guide's unique body
// instructions remain verbatim, along with Sigma syntax and structure. This
// does not assume that an advisory lacks detector-grade behavior.
var compactAdvisorySystemPrompt = func() string {
	prefix, fieldGuide, found := strings.Cut(briefSystemPrompt, "FIELD GUIDE (")
	if !found {
		panic("brief field guide boundary missing")
	}
	_, requirements, found := strings.Cut(fieldGuide, "QUALITY REQUIREMENTS:")
	if !found {
		panic("brief quality boundary missing")
	}
	_, body, found := strings.Cut(fieldGuide, "content: |\n")
	if !found {
		panic("brief content guide missing")
	}
	body, _, found = strings.Cut(body, "\ntags:")
	if !found {
		panic("brief content guide end missing")
	}
	before, examples, found := strings.Cut(requirements, "EXAMPLE SIGMA RULES (")
	if !found {
		panic("brief Sigma examples boundary missing")
	}
	_, after, found := strings.Cut(examples, "\nIOCs:\n")
	if !found {
		panic("brief Sigma examples end missing")
	}
	return prefix + "FIELD GUIDE: Use the attached response schema for all fields, types, allowed values, structured detections and test events. Supply its required identity, title, summary, severity and content fields; omit optional fields without evidence.\n\nContent body guide:\n" + body + "\n\nQUALITY REQUIREMENTS:" + before + "IOCs:\n" + after
}()

func assemblySystemPrompt(item scraper.RawItem) string {
	switch item.Source {
	case "nvd", "ghsa", "cisa-kev":
		return compactAdvisorySystemPrompt
	default:
		return briefSystemPrompt
	}
}
