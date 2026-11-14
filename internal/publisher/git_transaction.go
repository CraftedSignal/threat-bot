package publisher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

const publicationMaxAttempts = 3

// ErrPublicationConflict leaves the pending publication queued for a later
// flush, which can recompute it from the new branch contents.
var ErrPublicationConflict = errors.New("git publication conflict")

type stagedGitFile struct {
	sha     string
	size    int64
	deleted bool
}

func (p *Publisher) stageGitDelete(path string) error {
	if p.publication == nil {
		return fmt.Errorf("no active Git publication")
	}
	if staged, exists := p.publication.staged[path]; exists {
		if staged.deleted {
			return nil
		}
		return fmt.Errorf("cannot delete Git file %s: a write is already staged", path)
	}
	sha, err := p.getFileSHA(path)
	if err != nil {
		return fmt.Errorf("checking Git file before deletion: %w", err)
	}
	if sha == "" {
		return nil
	}
	p.publication.staged[path] = stagedGitFile{deleted: true}
	return nil
}

// gitPublication uploads blobs eagerly but exposes them through one final,
// non-forced branch ref update. It retains only blob metadata, so large feed
// releases do not accumulate every staged file body in memory.
type gitPublication struct {
	baseCommit  string
	baseTree    string
	message     string
	staged      map[string]stagedGitFile
	readPaths   map[string]struct{}
	afterCommit []func()
}

func (p *Publisher) withAtomicPublication(message string, publish func() error) error {
	if p.publication != nil {
		return publish()
	}

	tx, err := p.beginGitPublication(message)
	if err != nil {
		return fmt.Errorf("starting atomic publication: %w", err)
	}
	p.publication = tx
	defer func() { p.publication = nil }()

	if err := publish(); err != nil {
		return err
	}
	if err := p.commitGitPublication(tx); err != nil {
		return fmt.Errorf("committing atomic publication: %w", err)
	}
	for _, callback := range tx.afterCommit {
		callback()
	}
	return nil
}

func (p *Publisher) afterPublicationCommit(callback func()) {
	if p.publication == nil {
		callback()
		return
	}
	p.publication.afterCommit = append(p.publication.afterCommit, callback)
}

func (p *Publisher) beginGitPublication(message string) (*gitPublication, error) {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := p.gitJSON(context.Background(), http.MethodGet, "git/ref/heads/"+url.PathEscape(p.publicationBranch()), nil, &ref, nil); err != nil {
		return nil, err
	}
	if ref.Object.SHA == "" {
		return nil, fmt.Errorf("GitHub returned an empty %s ref", p.publicationBranch())
	}

	var commit struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := p.gitJSON(context.Background(), http.MethodGet, "git/commits/"+ref.Object.SHA, nil, &commit, nil); err != nil {
		return nil, err
	}
	if commit.Tree.SHA == "" {
		return nil, fmt.Errorf("GitHub returned an empty base tree")
	}
	return &gitPublication{
		baseCommit: ref.Object.SHA,
		baseTree:   commit.Tree.SHA,
		message:    message,
		staged:     make(map[string]stagedGitFile),
		readPaths:  make(map[string]struct{}),
	}, nil
}

func (p *Publisher) stageGitFile(path string, data []byte) (string, error) {
	if p.publication == nil {
		return "", fmt.Errorf("no active Git publication")
	}
	var blob struct {
		SHA string `json:"sha"`
	}
	headers := http.Header{"X-Threat-Bot-Path": []string{path}}
	if err := p.gitJSON(context.Background(), http.MethodPost, "git/blobs", map[string]string{
		"content":  base64.StdEncoding.EncodeToString(data),
		"encoding": "base64",
	}, &blob, headers); err != nil {
		return "", err
	}
	if blob.SHA == "" {
		return "", fmt.Errorf("GitHub returned an empty blob SHA for %s", path)
	}
	p.publication.staged[path] = stagedGitFile{sha: blob.SHA, size: int64(len(data))}
	return blob.SHA, nil
}

func (p *Publisher) commitGitPublication(tx *gitPublication) error {
	var baseEntries map[string]publicationTreeEntry
	for attempt := 1; attempt <= publicationMaxAttempts; attempt++ {
		err := p.commitGitPublicationAttempt(tx)
		if err == nil {
			return nil
		}
		var refErr *publicationRefError
		if !errors.As(err, &refErr) || !isNonFastForward(refErr.err) {
			return err
		}
		if attempt == publicationMaxAttempts {
			return fmt.Errorf("%w after %d attempts: %w", ErrPublicationConflict, attempt, err)
		}
		fresh, fetchErr := p.beginGitPublication(tx.message)
		if fetchErr != nil {
			return fmt.Errorf("refreshing publication head: %w", fetchErr)
		}
		if fresh.baseCommit == tx.baseCommit {
			return err
		}
		if baseEntries == nil {
			baseEntries, fetchErr = p.publicationTree(tx.baseTree)
			if fetchErr != nil {
				return fetchErr
			}
		}
		freshEntries, fetchErr := p.publicationTree(fresh.baseTree)
		if fetchErr != nil {
			return fetchErr
		}
		for path := range tx.staged {
			if baseEntries[normalizedPublicationPath(path)] != freshEntries[normalizedPublicationPath(path)] {
				return fmt.Errorf("%w: staged path %s changed; a new flush must recompute it", ErrPublicationConflict, path)
			}
		}
		for path := range tx.readPaths {
			if (path == "" && tx.baseTree != fresh.baseTree) || baseEntries[path] != freshEntries[path] {
				return fmt.Errorf("%w: read path %s changed; a new flush must recompute it", ErrPublicationConflict, path)
			}
		}
		// Only immutable blob identities are reused. The new tree retains every
		// unrelated concurrent change and its commit becomes our sole parent.
		tx.baseCommit, tx.baseTree = fresh.baseCommit, fresh.baseTree
		baseEntries = freshEntries
		p.logger.Info("retrying atomic publication after concurrent branch advance", "attempt", attempt+1)
	}
	return ErrPublicationConflict
}

type publicationTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

func (p *Publisher) publicationTree(sha string) (map[string]publicationTreeEntry, error) {
	var tree struct {
		SHA       string                 `json:"sha"`
		Tree      []publicationTreeEntry `json:"tree"`
		Truncated *bool                  `json:"truncated"`
	}
	if err := p.gitJSON(context.Background(), http.MethodGet, "git/trees/"+sha+"?recursive=1", nil, &tree, nil); err != nil {
		return nil, fmt.Errorf("checking publication tree: %w", err)
	}
	if tree.Truncated != nil && *tree.Truncated {
		return nil, fmt.Errorf("publication tree comparison is truncated; refusing to rebase")
	}
	if tree.Truncated == nil || tree.Tree == nil {
		return nil, fmt.Errorf("publication tree comparison returned incomplete metadata")
	}
	if tree.SHA != sha {
		return nil, fmt.Errorf("publication tree comparison returned an unexpected tree")
	}
	entries := make(map[string]publicationTreeEntry, len(tree.Tree))
	for _, entry := range tree.Tree {
		if entry.Path == "" || entry.SHA == "" || entry.Mode == "" || entry.Type == "" {
			return nil, fmt.Errorf("publication tree comparison returned an incomplete entry")
		}
		if _, exists := entries[entry.Path]; exists {
			return nil, fmt.Errorf("publication tree comparison returned a duplicate path")
		}
		entries[entry.Path] = entry
	}
	return entries, nil
}

func (p *Publisher) recordPublicationRead(path string) {
	if p.publication != nil {
		p.publication.readPaths[normalizedPublicationPath(path)] = struct{}{}
	}
}

func normalizedPublicationPath(value string) string {
	value = path.Clean(strings.Trim(value, "/"))
	if value == "." {
		return ""
	}
	return value
}

type publicationRefError struct{ err error }

func (e *publicationRefError) Error() string { return e.err.Error() }
func (e *publicationRefError) Unwrap() error { return e.err }

type githubAPIError struct {
	status int
	body   string
}

func (e *githubAPIError) Error() string {
	body := e.body
	if !json.Valid([]byte(body)) {
		body = "upstream returned a non-JSON error response"
	}
	return fmt.Sprintf("GitHub API HTTP %d: %s", e.status, body)
}

func isNonFastForward(err error) bool {
	var apiErr *githubAPIError
	if !errors.As(err, &apiErr) || (apiErr.status != http.StatusConflict && apiErr.status != http.StatusUnprocessableEntity) {
		return false
	}
	var body struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(apiErr.body), &body) != nil {
		return false
	}
	message := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(body.Message)), ".")
	return message == "update is not a fast forward" || message == "update is not a fast-forward"
}

func (p *Publisher) commitGitPublicationAttempt(tx *gitPublication) error {
	if len(tx.staged) == 0 {
		return nil
	}
	paths := make([]string, 0, len(tx.staged))
	for path := range tx.staged {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	type treeEntry struct {
		Path string  `json:"path"`
		Mode string  `json:"mode"`
		Type string  `json:"type"`
		SHA  *string `json:"sha"`
	}
	entries := make([]treeEntry, 0, len(paths))
	for _, path := range paths {
		staged := tx.staged[path]
		var sha *string
		if !staged.deleted {
			value := staged.sha
			sha = &value
		}
		entries = append(entries, treeEntry{Path: path, Mode: "100644", Type: "blob", SHA: sha})
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if err := p.gitJSON(context.Background(), http.MethodPost, "git/trees", map[string]any{
		"base_tree": tx.baseTree,
		"tree":      entries,
	}, &tree, nil); err != nil {
		return err
	}

	var commit struct {
		SHA string `json:"sha"`
	}
	if err := p.gitJSON(context.Background(), http.MethodPost, "git/commits", map[string]any{
		"message": tx.message,
		"tree":    tree.SHA,
		"parents": []string{tx.baseCommit},
		"author":  p.publicationAuthor(),
	}, &commit, nil); err != nil {
		return err
	}
	if commit.SHA == "" {
		return fmt.Errorf("GitHub returned an empty commit SHA")
	}
	if err := p.gitJSON(context.Background(), http.MethodPatch, "git/refs/heads/"+url.PathEscape(p.publicationBranch()), map[string]any{
		"sha": commit.SHA, "force": false,
	}, nil, nil); err != nil {
		return &publicationRefError{err: err}
	}
	return nil
}

func (p *Publisher) gitJSON(ctx context.Context, method, endpoint string, input, output any, headers http.Header) error {
	var payload []byte
	var err error
	if input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	url := fmt.Sprintf("%s/repos/%s/%s", p.apiURL, p.repoSlug, endpoint)
	var lastErr error
	for attempt := 1; attempt <= putFileMaxAttempts; attempt++ {
		if err := p.awaitRateLimit(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		p.setHeaders(req)
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			p.recordRateLimit(resp)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				defer discardClose(resp.Body)
				if output == nil || resp.StatusCode == http.StatusNoContent {
					return nil
				}
				if err := json.NewDecoder(resp.Body).Decode(output); err != nil {
					return err
				}
				return nil
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, githubErrorBodyBytes))
			_ = resp.Body.Close()
			lastErr = &githubAPIError{status: resp.StatusCode, body: string(body)}
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return lastErr
			}
		}
		if attempt < putFileMaxAttempts {
			if err := sleepWithContext(ctx, putFileRetryDelays[attempt-1]); err != nil {
				return err
			}
		}
	}
	return lastErr
}

func (p *Publisher) stagedGitFile(path string) (stagedGitFile, bool) {
	if p.publication == nil {
		return stagedGitFile{}, false
	}
	file, ok := p.publication.staged[path]
	return file, ok
}

func (p *Publisher) publicationBaseRef() string {
	if p.publication == nil {
		return p.publicationBranch()
	}
	return p.publication.baseCommit
}
