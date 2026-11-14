package scraper

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	elasticOwner = "elastic"
	elasticRepo  = "detection-rules"
)

type Elastic struct {
	client  *http.Client
	tokenFn func() string
}

func NewElastic(tokenFn func() string) *Elastic {
	return &Elastic{
		client:  &http.Client{Timeout: 30 * time.Second},
		tokenFn: tokenFn,
	}
}

func (e *Elastic) Name() string { return "elastic" }

func (e *Elastic) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	return e.pollFrom(ctx, since, sigmaHQAPI, "https://raw.githubusercontent.com")
}

func (e *Elastic) pollFrom(ctx context.Context, since time.Time, apiURL, rawURL string) ([]RawItem, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits?path=rules&since=%s&per_page=100",
		apiURL, elasticOwner, elasticRepo, since.Format(time.RFC3339))

	var items []RawItem
	seen := make(map[string]bool)

	for url != "" {
		commits, nextURL, err := fetchGitHubPage[[]ghCommit](ctx, e.client, e.tokenFn(), url)
		if err != nil {
			return nil, fmt.Errorf("fetching commits: %w", err)
		}

		for _, commit := range commits {
			detailURL := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
				apiURL, elasticOwner, elasticRepo, commit.SHA)
			detail, err := fetchJSON[ghCommitDetail](ctx, e.client, e.tokenFn(), detailURL)
			if err != nil {
				continue
			}

			for _, f := range detail.Files {
				if !strings.HasPrefix(f.Filename, "rules/") {
					continue
				}
				if f.Status != "added" && f.Status != "modified" {
					continue
				}
				if !strings.HasSuffix(f.Filename, ".toml") {
					continue
				}
				if seen[f.Filename] {
					continue
				}
				seen[f.Filename] = true

				blobURL := fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", elasticOwner, elasticRepo, f.Filename)
				rawFileURL := fmt.Sprintf("%s/%s/%s/%s/%s", rawURL, elasticOwner, elasticRepo, commit.SHA, f.Filename)
				content, _ := fetchRawContent(ctx, e.client, e.tokenFn(), rawFileURL)

				items = append(items, RawItem{
					SourceID:    fmt.Sprintf("elastic:%s:%s", commit.SHA[:8], f.Filename),
					Source:      "elastic",
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

// fetchRawContent fetches the raw file content from a GitHub raw URL.
func fetchRawContent(ctx context.Context, client *http.Client, token, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", fmt.Errorf("GitHub raw HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
