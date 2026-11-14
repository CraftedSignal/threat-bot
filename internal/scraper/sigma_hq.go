package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	sigmaHQOwner = "SigmaHQ"
	sigmaHQRepo  = "sigma"
	sigmaHQAPI   = "https://api.github.com"
)

type SigmaHQ struct {
	client  *http.Client
	tokenFn func() string
}

func NewSigmaHQ(tokenFn func() string) *SigmaHQ {
	return &SigmaHQ{
		client:  &http.Client{Timeout: 30 * time.Second},
		tokenFn: tokenFn,
	}
}

func (s *SigmaHQ) Name() string { return "sigma-hq" }

func (s *SigmaHQ) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	return s.pollFrom(ctx, since, sigmaHQAPI, "https://raw.githubusercontent.com")
}

func (s *SigmaHQ) pollFrom(ctx context.Context, since time.Time, apiURL, rawURL string) ([]RawItem, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits?path=rules&since=%s&per_page=100",
		apiURL, sigmaHQOwner, sigmaHQRepo, since.Format(time.RFC3339))

	var items []RawItem
	seen := make(map[string]bool)

	for url != "" {
		commits, nextURL, err := fetchGitHubPage[[]ghCommit](ctx, s.client, s.tokenFn(), url)
		if err != nil {
			return nil, fmt.Errorf("fetching commits: %w", err)
		}

		for _, commit := range commits {
			detailURL := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
				apiURL, sigmaHQOwner, sigmaHQRepo, commit.SHA)
			detail, err := fetchJSON[ghCommitDetail](ctx, s.client, s.tokenFn(), detailURL)
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
				if !strings.HasSuffix(f.Filename, ".yml") && !strings.HasSuffix(f.Filename, ".yaml") {
					continue
				}
				if seen[f.Filename] {
					continue
				}
				seen[f.Filename] = true

				rule, content, err := fetchSigmaRuleFrom(ctx, s.client, f.Filename, commit.SHA, rawURL)
				if err != nil {
					continue
				}

				items = append(items, RawItem{
					SourceID:    fmt.Sprintf("sigma-hq:%s:%s", commit.SHA[:8], f.Filename),
					Source:      "sigma-hq",
					Title:       rule.Title,
					URL:         fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", sigmaHQOwner, sigmaHQRepo, f.Filename),
					Content:     content,
					PublishedAt: commit.Commit.Author.Date,
					Metadata: map[string]string{
						"sigma_id": rule.ID,
						"level":    rule.Level,
						"status":   rule.Status,
					},
					SigmaRule: rule,
				})
			}
		}
		url = nextURL
	}

	return items, nil
}

// maxSigmaRuleBytes bounds one fetched Sigma rule file.
const maxSigmaRuleBytes = 2 << 20

func fetchSigmaRuleFrom(ctx context.Context, client *http.Client, path, sha, rawBaseURL string) (*SigmaRule, string, error) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s",
		rawBaseURL, sigmaHQOwner, sigmaHQRepo, sha, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer discardClose(resp.Body)

	// Fail rather than truncate: a cut YAML rule can still parse, and would
	// publish with part of its detection missing. The largest SigmaHQ rule
	// (the vulnerable-driver hash list) is ~295KB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSigmaRuleBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > maxSigmaRuleBytes {
		return nil, "", fmt.Errorf("sigma rule %s exceeds %d bytes", path, maxSigmaRuleBytes)
	}

	var rule SigmaRule
	if err := yaml.Unmarshal(body, &rule); err != nil {
		return nil, "", fmt.Errorf("parsing sigma rule %s: %w", path, err)
	}

	return &rule, string(body), nil
}

func fetchJSON[T any](ctx context.Context, client *http.Client, token, url string) (T, error) {
	result, _, err := fetchGitHubPage[T](ctx, client, token, url)
	return result, err
}

// fetchGitHubPage performs a single GitHub API GET and returns the decoded
// body plus the URL of the next page from the Link header (empty if none).
func fetchGitHubPage[T any](ctx context.Context, client *http.Client, token, url string) (T, string, error) {
	var zero T
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return zero, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return zero, "", err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return zero, "", statusErrorf(resp.StatusCode, "HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return zero, "", err
	}
	return result, parseGitHubNextLink(resp.Header.Get("Link")), nil
}

// parseGitHubNextLink extracts the rel="next" URL from a GitHub Link header.
// It handles the common format: <url>; rel="next", <url>; rel="last".
func parseGitHubNextLink(link string) string {
	for _, part := range strings.Split(link, ",") {
		sections := strings.Split(part, ";")
		if len(sections) != 2 {
			continue
		}
		urlStr := strings.TrimSpace(sections[0])
		if !strings.HasPrefix(urlStr, "<") || !strings.HasSuffix(urlStr, ">") {
			continue
		}
		urlStr = urlStr[1 : len(urlStr)-1]
		rel := strings.TrimSpace(sections[1])
		if strings.HasPrefix(rel, `rel="`) && strings.HasSuffix(rel, `"`) && strings.Contains(rel, "next") {
			return urlStr
		}
	}
	return ""
}

type ghCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Author struct {
			Date time.Time `json:"date"`
		} `json:"author"`
		Message string `json:"message"`
	} `json:"commit"`
}

type ghCommitDetail struct {
	Files []struct {
		Filename string `json:"filename"`
		Status   string `json:"status"`
	} `json:"files"`
}
