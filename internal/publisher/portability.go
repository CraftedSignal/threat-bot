package publisher

import (
	"io"
	"strings"
)

// PublicationSettings selects the destination and attribution without changing
// feed object identities, key derivation, or the atomic publication protocol.
type PublicationSettings struct {
	SiteURL     string
	Branch      string
	AuthorName  string
	AuthorEmail string
}

func WithPublicationSettings(settings PublicationSettings) PublisherOption {
	return func(p *Publisher) { p.settings = settings }
}

func (p *Publisher) publicationBranch() string {
	if p.settings.Branch != "" {
		return p.settings.Branch
	}
	return "main"
}

func (p *Publisher) publicationSiteURL() string {
	if p.settings.SiteURL != "" {
		return strings.TrimRight(p.settings.SiteURL, "/")
	}
	// Standalone fixture/export callers still need an absolute canonical URL.
	// Configured publishers are required to supply their real site_url.
	return "https://example.invalid"
}

func (p *Publisher) publicationAuthor() commitAuthor {
	name, email := p.settings.AuthorName, p.settings.AuthorEmail
	if name == "" {
		name = "threat-bot"
	}
	if email == "" {
		email = "threat-bot@users.noreply.github.com"
	}
	return commitAuthor{Name: name, Email: email}
}

func (p *Publisher) contentsPayload(message, sha string, size int, writeFile func(io.Writer) error) ([]byte, error) {
	return contentsPayload(message, sha, size, writeFile, p.settings)
}
