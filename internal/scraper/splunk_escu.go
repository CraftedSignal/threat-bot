package scraper

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	splunkOwner = "splunk"
	splunkRepo  = "security_content"
)

type SplunkESCU struct {
	client  *http.Client
	tokenFn func() string
}

func NewSplunkESCU(tokenFn func() string) *SplunkESCU {
	return &SplunkESCU{
		client:  &http.Client{Timeout: 30 * time.Second},
		tokenFn: tokenFn,
	}
}

func (s *SplunkESCU) Name() string { return "splunk-escu" }

func (s *SplunkESCU) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	return s.pollFrom(ctx, since, sigmaHQAPI, "https://raw.githubusercontent.com")
}

func (s *SplunkESCU) pollFrom(ctx context.Context, since time.Time, apiURL, rawURL string) ([]RawItem, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits?path=detections&since=%s&per_page=100",
		apiURL, splunkOwner, splunkRepo, since.Format(time.RFC3339))

	var items []RawItem
	seen := make(map[string]bool)

	for url != "" {
		commits, nextURL, err := fetchGitHubPage[[]ghCommit](ctx, s.client, s.tokenFn(), url)
		if err != nil {
			return nil, fmt.Errorf("fetching commits: %w", err)
		}

		for _, commit := range commits {
			detailURL := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
				apiURL, splunkOwner, splunkRepo, commit.SHA)
			detail, err := fetchJSON[ghCommitDetail](ctx, s.client, s.tokenFn(), detailURL)
			if err != nil {
				continue
			}

			for _, f := range detail.Files {
				if !strings.HasPrefix(f.Filename, "detections/") {
					continue
				}
				if f.Status != "added" && f.Status != "modified" {
					continue
				}
				if !strings.HasSuffix(f.Filename, ".yml") && !strings.HasSuffix(f.Filename, ".yaml") {
					continue
				}
				if seen[f.Filename] {
					continue
				}
				seen[f.Filename] = true

				blobURL := fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", splunkOwner, splunkRepo, f.Filename)
				rawFileURL := fmt.Sprintf("%s/%s/%s/%s/%s", rawURL, splunkOwner, splunkRepo, commit.SHA, f.Filename)
				content, _ := fetchRawContent(ctx, s.client, s.tokenFn(), rawFileURL)

				items = append(items, RawItem{
					SourceID:    fmt.Sprintf("splunk-escu:%s:%s", commit.SHA[:8], f.Filename),
					Source:      "splunk-escu",
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
