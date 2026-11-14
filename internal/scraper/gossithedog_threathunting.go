package scraper

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	gossiTheDogThreatHuntingOwner = "GossiTheDog"
	gossiTheDogThreatHuntingRepo  = "ThreatHunting"
)

// gossiTheDogThreatHuntingDirs allowlists the repo's content directories.
// Many files inside them have no extension (e.g. "Hunt-PrintNightmare"), so
// unlike sigma-hq/elastic the filter is directory prefix, not file
// extension. This also excludes the root README.md, LICENSE, and meme
// image without naming them individually.
var gossiTheDogThreatHuntingDirs = []string{
	"AdvancedHuntingQueries/",
	"AzureSentinel/",
	"EDR-BlockRules/",
	"YARA/",
}

type GossiTheDogThreatHunting struct {
	client  *http.Client
	tokenFn func() string
}

func NewGossiTheDogThreatHunting(tokenFn func() string) *GossiTheDogThreatHunting {
	return &GossiTheDogThreatHunting{
		client:  &http.Client{Timeout: 30 * time.Second},
		tokenFn: tokenFn,
	}
}

func (g *GossiTheDogThreatHunting) Name() string { return "gossithedog-threathunting" }

func (g *GossiTheDogThreatHunting) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	return g.pollFrom(ctx, since, sigmaHQAPI, "https://raw.githubusercontent.com")
}

func (g *GossiTheDogThreatHunting) pollFrom(ctx context.Context, since time.Time, apiURL, rawURL string) ([]RawItem, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits?since=%s&per_page=100",
		apiURL, gossiTheDogThreatHuntingOwner, gossiTheDogThreatHuntingRepo, since.Format(time.RFC3339))

	var items []RawItem
	seen := make(map[string]bool)

	for url != "" {
		commits, nextURL, err := fetchGitHubPage[[]ghCommit](ctx, g.client, g.tokenFn(), url)
		if err != nil {
			return nil, fmt.Errorf("fetching commits: %w", err)
		}

		for _, commit := range commits {
			detailURL := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
				apiURL, gossiTheDogThreatHuntingOwner, gossiTheDogThreatHuntingRepo, commit.SHA)
			detail, err := fetchJSON[ghCommitDetail](ctx, g.client, g.tokenFn(), detailURL)
			if err != nil {
				continue
			}

			for _, f := range detail.Files {
				if !inGossiTheDogThreatHuntingDir(f.Filename) {
					continue
				}
				if f.Status != "added" && f.Status != "modified" {
					continue
				}
				if seen[f.Filename] {
					continue
				}
				seen[f.Filename] = true

				blobURL := fmt.Sprintf("https://github.com/%s/%s/blob/master/%s",
					gossiTheDogThreatHuntingOwner, gossiTheDogThreatHuntingRepo, f.Filename)
				rawFileURL := fmt.Sprintf("%s/%s/%s/%s/%s",
					rawURL, gossiTheDogThreatHuntingOwner, gossiTheDogThreatHuntingRepo, commit.SHA, f.Filename)
				content, _ := fetchRawContent(ctx, g.client, g.tokenFn(), rawFileURL)

				items = append(items, RawItem{
					SourceID:    fmt.Sprintf("gossithedog-threathunting:%s:%s", commit.SHA[:8], f.Filename),
					Source:      "gossithedog-threathunting",
					Title:       f.Filename,
					URL:         blobURL,
					Content:     content,
					PublishedAt: commit.Commit.Author.Date,
					Metadata: map[string]string{
						"commit": commit.SHA,
					},
				})
			}
		}

		url = nextURL
	}

	return items, nil
}

func inGossiTheDogThreatHuntingDir(filename string) bool {
	for _, dir := range gossiTheDogThreatHuntingDirs {
		if strings.HasPrefix(filename, dir) {
			return true
		}
	}
	return false
}
