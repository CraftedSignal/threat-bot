package scraper

import (
	"context"
	"strings"
	"time"
)

// Scraper polls a single TI source for new items.
type Scraper interface {
	Name() string
	Poll(ctx context.Context, since time.Time) ([]RawItem, error)
}

// ItemFetcher is implemented by scrapers that can fetch specific items by
// source ID. `threat-bot sources replay` uses it for sources whose polls are
// capped and so cannot replay an older window.
type ItemFetcher interface {
	FetchItems(ctx context.Context, sourceIDs []string) ([]RawItem, error)
}

// RawItem is a single item from a TI source.
type RawItem struct {
	SourceID    string
	Source      string
	Title       string
	URL         string
	Content     string
	PublishedAt time.Time
	Metadata    map[string]string
	Discovery   *DiscoveryContext
	SigmaRule   *SigmaRule
	// NeedsFullArticle tells the pipeline that the feed body is only an
	// excerpt even when it is long enough to look complete.
	NeedsFullArticle bool
	// BodyCVEsAreSubjects is reserved for authoritative advisory sources whose
	// article CVE references identify the disclosure itself. Generic news bodies
	// leave this false because they often mention unrelated historical CVEs.
	BodyCVEsAreSubjects bool
	// CorroborationOnly prevents a secondary aggregator from becoming the sole
	// source for a new brief. It may still enrich an incident already identified
	// by a primary or authoritative source.
	CorroborationOnly bool
	// Enriched is set once the pipeline has tried to fetch the item's full
	// article, so a second pass does not append the page again.
	Enriched bool
}

// DiscoveryContext records public-social provenance without assigning trust to
// the author. It is populated only for broad discovery candidates.
type DiscoveryContext struct {
	Platform        string
	OriginalURL     string
	DiscoveryURL    string
	Author          string
	ParentURLs      []string
	QuoteURLs       []string
	ContextComplete bool
}

// SigmaRule is a parsed Sigma detection rule.
type SigmaRule struct {
	ID             string         `yaml:"id"`
	Title          string         `yaml:"title"`
	Status         string         `yaml:"status"`
	Description    string         `yaml:"description"`
	Author         string         `yaml:"author"`
	Date           string         `yaml:"date"`
	Modified       string         `yaml:"modified"`
	Tags           []string       `yaml:"tags"`
	Level          string         `yaml:"level"`
	LogSource      SigmaLogSource `yaml:"logsource"`
	Detection      map[string]any `yaml:"detection"`
	References     []string       `yaml:"references"`
	FalsePositives []string       `yaml:"falsepositives"`
}

type SigmaLogSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// MITRETechniques extracts technique IDs from Sigma tags (e.g., attack.t1059.003).
func (s *SigmaRule) MITRETechniques() []string {
	var techniques []string
	for _, tag := range s.Tags {
		if len(tag) > 7 && tag[:7] == "attack." {
			rest := tag[7:]
			if len(rest) >= 2 && (rest[0] == 't' || rest[0] == 'T') {
				techniques = append(techniques, strings.ToUpper(rest[:1])+rest[1:])
			}
		}
	}
	return techniques
}

// MITRETactics extracts tactic names from Sigma tags (e.g., attack.execution).
func (s *SigmaRule) MITRETactics() []string {
	var tactics []string
	for _, tag := range s.Tags {
		if len(tag) > 7 && tag[:7] == "attack." {
			rest := tag[7:]
			if len(rest) == 0 || rest[0] == 't' || rest[0] == 'T' {
				continue
			}
			tactics = append(tactics, rest)
		}
	}
	return tactics
}
