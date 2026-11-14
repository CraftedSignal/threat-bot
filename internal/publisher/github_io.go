package publisher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// fetchBundle gets the existing bundle from GitHub. Returns empty content on 404.
func (p *Publisher) fetchBundle() (*BundleContent, string, error) {
	raw, sha, err := p.fetchJSONFile(bundlePath)
	if err != nil {
		return nil, "", err
	}
	if raw == nil {
		return &BundleContent{}, "", nil
	}

	var manifest BundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, "", fmt.Errorf("parsing bundle manifest: %w", err)
	}

	content, err := Decrypt(&manifest, p.publicKey)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting bundle: %w", err)
	}

	return content, sha, nil
}

// putFile creates or updates a file holding json.Marshal(manifest) via the
// GitHub Contents API and returns the checksum of the uploaded bytes. The
// manifest JSON is streamed into the request body, so neither it nor its
// base64 is built as a separate copy of a multi-megabyte segment. On a
// transient 5xx/429 response, or GitHub's explicit repository-rule timeout,
// it retries the same request (same payload + SHA)
// up to putFileMaxAttempts times with a short backoff, returning the error
// only after the last attempt. Other 4xx responses (e.g. 409 stale SHA, 422
// validation failure) are returned immediately.
func (p *Publisher) putFile(path string, manifest *BundleManifest, sha, message string) (string, error) {
	// Marshal the small fields once; the content goes between them. Content
	// is base64, which JSON never escapes, so the streamed bytes equal
	// json.Marshal(manifest).
	head, err := json.Marshal(&BundleManifest{Version: manifest.Version, PublishedAt: manifest.PublishedAt, Checksum: manifest.Checksum})
	if err != nil {
		return "", err
	}
	if !bytes.HasSuffix(head, []byte(`"content":""}`)) {
		return "", fmt.Errorf("unexpected manifest encoding")
	}
	prefix, suffix := head[:len(head)-2], head[len(head)-2:]

	h := sha256.New()
	size := len(prefix) + len(manifest.Content) + len(suffix)
	if p.publication != nil {
		var raw bytes.Buffer
		raw.Grow(size)
		w := io.MultiWriter(&raw, h)
		if _, err := w.Write(prefix); err != nil {
			return "", err
		}
		if err := writeString(w, manifest.Content); err != nil {
			return "", err
		}
		if _, err := w.Write(suffix); err != nil {
			return "", err
		}
		if _, err := p.stageGitFile(path, raw.Bytes()); err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	payload, err := p.contentsPayload(message, sha, size, func(w io.Writer) error {
		w = io.MultiWriter(w, h)
		if _, err := w.Write(prefix); err != nil {
			return err
		}
		if err := writeString(w, manifest.Content); err != nil {
			return err
		}
		_, err := w.Write(suffix)
		return err
	})
	if err != nil {
		return "", err
	}
	if err := p.putContentsWithRetry(context.Background(), path, payload, "putFile"); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// contentsPayload builds the body of a GitHub Contents API PUT for a file of
// size bytes that writeFile streams. The file's base64 goes straight into one
// buffer sized for the whole body, with no separate copy of the file, of its
// base64, or of the body.
func contentsPayload(message, sha string, size int, writeFile func(io.Writer) error, settings ...PublicationSettings) ([]byte, error) {
	var p Publisher
	if len(settings) > 0 {
		p.settings = settings[0]
	}
	head, err := json.Marshal(contentsRequest{
		Message: message,
		SHA:     sha,
		Author:  p.publicationAuthor(),
		Branch:  p.publicationBranch(),
	})
	if err != nil {
		return nil, err
	}
	// The empty content value is where the file's base64 goes. The message
	// is encoded first and has its quotes escaped, so this is the first match.
	i := bytes.Index(head, []byte(`"content":""`))
	if i < 0 {
		return nil, fmt.Errorf("unexpected contents request encoding")
	}
	i += len(`"content":"`)

	var buf bytes.Buffer
	buf.Grow(len(head) + base64.StdEncoding.EncodedLen(size))
	buf.Write(head[:i])
	enc := base64.NewEncoder(base64.StdEncoding, &buf)
	if err := writeFile(enc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	buf.Write(head[i:])
	return buf.Bytes(), nil
}

// writeBytes returns a contentsPayload writer for data.
func writeBytes(data []byte) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}
}

// writeString writes s to w in chunks, so a large string is never copied
// into one []byte.
func writeString(w io.Writer, s string) error {
	buf := make([]byte, 32<<10)
	for len(s) > 0 {
		n := copy(buf, s)
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
		s = s[n:]
	}
	return nil
}

type repoDirEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

// listDir returns the names of files in a GitHub repo directory.
func (p *Publisher) listDir(dir string) ([]string, error) {
	items, err := p.readDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		if item.Type == "file" {
			names = append(names, item.Name)
		}
	}
	if p.publication != nil {
		seen := make(map[string]bool, len(names))
		for _, name := range names {
			seen[name] = true
		}
		prefix := strings.TrimSuffix(dir, "/") + "/"
		for path := range p.publication.staged {
			rest, ok := strings.CutPrefix(path, prefix)
			if ok && !strings.Contains(rest, "/") && !seen[rest] {
				names = append(names, rest)
				seen[rest] = true
			}
		}
	}
	sort.Strings(names)
	return names, nil
}

// readDir returns the entries of a GitHub repo directory at the publication's
// base commit, or nil when the directory does not exist. GitHub lists at most
// 1,000 entries.
func (p *Publisher) readDir(dir string) ([]repoDirEntry, error) {
	p.recordPublicationRead(dir)
	url := fmt.Sprintf("%s/repos/%s/contents/%s", p.apiURL, p.repoSlug, dir)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if ref := p.publicationBaseRef(); ref != "" {
		query := req.URL.Query()
		query.Set("ref", ref)
		req.URL.RawQuery = query.Encode()
	}
	p.setHeaders(req)
	resp, err := p.doGitHubRead(req, githubErrorBodyBytes)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, githubErrorBodyBytes))
		return nil, &githubAPIError{status: resp.StatusCode, body: string(body)}
	}
	var items []repoDirEntry
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding dir listing: %w", err)
	}
	return items, nil
}

// listGitTreeFiles returns the names of the files directly below the
// subdirectory name of parent at the publication's base commit. It reads the
// subdirectory's Git tree because the Contents API stops listing at 1,000
// entries.
func (p *Publisher) listGitTreeFiles(parent, name string) ([]string, error) {
	entries, err := p.readDir(parent)
	if err != nil {
		return nil, err
	}
	treeSHA := ""
	for _, entry := range entries {
		if entry.Name == name && entry.Type == "dir" {
			treeSHA = entry.SHA
		}
	}
	if treeSHA == "" {
		return nil, nil
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := p.gitJSON(context.Background(), http.MethodGet, "git/trees/"+treeSHA, nil, &tree, nil); err != nil {
		return nil, fmt.Errorf("reading Git tree of %s/%s: %w", parent, name, err)
	}
	if tree.Truncated {
		p.logger.Warn("git tree listing truncated", "dir", parent+"/"+name, "entries", len(tree.Tree))
	}
	names := make([]string, 0, len(tree.Tree))
	for _, entry := range tree.Tree {
		if entry.Type == "blob" {
			names = append(names, entry.Path)
		}
	}
	return names, nil
}

// fetchManifest fetches the segment manifest from GitHub. Returns new manifest on 404.
func (p *Publisher) fetchManifest() (*SegmentManifest, string, error) {
	raw, sha, err := p.fetchJSONFile(manifestPath)
	if err != nil {
		return nil, "", err
	}
	if raw == nil {
		return NewSegmentManifest(), "", nil
	}

	var m SegmentManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "", fmt.Errorf("parsing manifest: %w", err)
	}
	// Initialize the internal map from the deserialized segments.
	if m.briefsBySegment == nil {
		m.briefsBySegment = make(map[string][]BundleBrief)
	}
	return &m, sha, nil
}

// fetchChangelog fetches the changelog from GitHub. Returns new changelog on 404.
func (p *Publisher) fetchChangelog() (*Changelog, string, error) {
	raw, sha, err := p.fetchJSONFile(changelogPath)
	if err != nil {
		return nil, "", err
	}
	if raw == nil {
		return NewChangelog(), "", nil
	}

	var cl Changelog
	if err := json.Unmarshal(raw, &cl); err != nil {
		return nil, "", fmt.Errorf("parsing changelog: %w", err)
	}
	// A changelog.json with an empty entries array slips past unmarshal
	// but blows up the first time anything calls currentEntry(). Treat
	// it the same as a missing file.
	if len(cl.Entries) == 0 {
		return NewChangelog(), sha, nil
	}
	return &cl, sha, nil
}

// redistributeLegacySegments moves briefs (and digests) that only live in
// pre-migration yearly segments into their monthly segments, then prunes the
// yearly entries from the manifest. Consumers sync exactly the manifest-listed
// segments, so a brief must reach a monthly segment before its yearly listing
// disappears — pruning alone would delete it from the feed. Copies that
// already exist in a monthly segment are skipped so stale yearly versions
// never overwrite fresher monthly ones.
func (p *Publisher) redistributeLegacySegments(manifest *SegmentManifest, modifiedSegments map[string]bool, digestsBySegment map[string][]BundleDigest) error {
	var legacy []SegmentEntry
	for _, seg := range manifest.Segments {
		if !monthlySegmentPath.MatchString(seg.Path) {
			legacy = append(legacy, seg)
		}
	}
	if len(legacy) == 0 {
		return nil
	}

	// Brief/digest IDs already present per monthly segment, loaded lazily.
	monthlyIDs := make(map[string]map[string]bool)
	loadMonth := func(key string) (map[string]bool, error) {
		if ids, ok := monthlyIDs[key]; ok {
			return ids, nil
		}
		ids := make(map[string]bool)
		existing, _, err := p.fetchSegment("output/" + segmentPath(key))
		if err != nil {
			return nil, err
		}
		for _, b := range existing.Briefs {
			ids[b.ID] = true
		}
		for _, d := range existing.Digests {
			ids[d.ID] = true
		}
		for _, b := range manifest.GetSegmentBriefs(key) {
			ids[b.ID] = true
		}
		for _, d := range digestsBySegment[key] {
			ids[d.ID] = true
		}
		monthlyIDs[key] = ids
		return ids, nil
	}

	segmentKeyFor := func(publishedAt string) string {
		ts, err := time.Parse(time.RFC3339, publishedAt)
		if err != nil {
			ts = time.Now().UTC()
		}
		return SegmentKey(ts)
	}

	for _, seg := range legacy {
		content, _, err := p.fetchSegment("output/" + seg.Path)
		if err != nil {
			return fmt.Errorf("fetching legacy segment %s: %w", seg.Path, err)
		}
		moved := 0
		for _, b := range content.Briefs {
			key := segmentKeyFor(b.PublishedAt)
			ids, err := loadMonth(key)
			if err != nil {
				return fmt.Errorf("fetching segment %s: %w", key, err)
			}
			if ids[b.ID] {
				continue
			}
			manifest.AddBrief(b)
			ids[b.ID] = true
			modifiedSegments[key] = true
			moved++
		}
		for _, d := range content.Digests {
			key := segmentKeyFor(d.PublishedAt)
			ids, err := loadMonth(key)
			if err != nil {
				return fmt.Errorf("fetching segment %s: %w", key, err)
			}
			if ids[d.ID] {
				continue
			}
			digestsBySegment[key] = append(digestsBySegment[key], d)
			manifest.EnsureSegment(key)
			ids[d.ID] = true
			modifiedSegments[key] = true
			moved++
		}
		p.logger.Info("redistributed legacy segment", "path", seg.Path, "moved", moved)
	}

	if removed := manifest.PruneLegacySegments(); len(removed) > 0 {
		p.logger.Info("pruned legacy segment entries from manifest", "paths", removed)
	}
	return nil
}

// listUnlistedMonthlySegments adds a manifest entry for every monthly segment
// file present under output/briefs that the manifest does not list. Files are
// only listed, never rewritten.
func (p *Publisher) listUnlistedMonthlySegments(manifest *SegmentManifest) error {
	entries, err := p.listDir("output/briefs")
	if err != nil {
		return err
	}
	listed := make(map[string]bool, len(manifest.Segments))
	for _, seg := range manifest.Segments {
		listed[seg.Path] = true
	}
	added := 0
	for _, name := range entries {
		path := "briefs/" + name
		if !monthlySegmentPath.MatchString(path) || listed[path] {
			continue
		}
		raw, _, err := p.fetchJSONFile("output/" + path)
		if err != nil {
			return fmt.Errorf("fetching unlisted segment %s: %w", path, err)
		}
		if raw == nil {
			continue
		}
		var segManifest BundleManifest
		if err := json.Unmarshal(raw, &segManifest); err != nil {
			return fmt.Errorf("parsing unlisted segment %s: %w", path, err)
		}
		content, err := DecryptSegment(&segManifest, p.publicKey)
		if err != nil {
			return fmt.Errorf("decrypting unlisted segment %s: %w", path, err)
		}
		manifest.Segments = append(manifest.Segments, SegmentEntry{
			Path:         path,
			Checksum:     ComputeChecksum(raw),
			BriefCount:   len(content.Briefs),
			LastModified: bundleTimestamp(),
		})
		if manifest.BriefLocations != nil {
			key := strings.TrimSuffix(name, ".json")
			for _, brief := range content.Briefs {
				addBriefLocation(manifest.BriefLocations, brief.ID, key)
			}
		}
		p.logger.Info("listed unlisted monthly segment", "path", path, "briefs", len(content.Briefs))
		added++
	}
	if added > 0 {
		sort.Slice(manifest.Segments, func(i, j int) bool {
			return manifest.Segments[i].Path < manifest.Segments[j].Path
		})
	}
	return nil
}

// ensureBriefLocations backfills the manifest's ID index once from the
// encrypted monthly files. The index lets later flushes find old months
// without downloading the entire feed for every brief update.
func (p *Publisher) ensureBriefLocations(manifest *SegmentManifest, listedAtFetch, modifiedSegments map[string]bool) error {
	if manifest.BriefLocations != nil {
		return nil
	}
	locations := make(map[string][]string)
	for _, segment := range manifest.Segments {
		if !monthlySegmentPath.MatchString(segment.Path) {
			continue
		}
		content, sha, err := p.fetchSegment("output/" + segment.Path)
		if err != nil {
			return fmt.Errorf("fetching %s: %w", segment.Path, err)
		}
		key := strings.TrimPrefix(strings.TrimSuffix(segment.Path, ".json"), "briefs/")
		if sha == "" && (listedAtFetch[segment.Path] || !modifiedSegments[key]) {
			return fmt.Errorf("indexed segment %s is missing", segment.Path)
		}
		for _, brief := range content.Briefs {
			addBriefLocation(locations, brief.ID, key)
		}
	}
	manifest.BriefLocations = locations
	return nil
}

func addBriefLocation(locations map[string][]string, id, key string) {
	for _, existing := range locations[id] {
		if existing == key {
			return
		}
	}
	locations[id] = append(locations[id], key)
}

// fetchSegment fetches and decrypts a single segment file. Returns empty content on 404.
func (p *Publisher) fetchSegment(path string) (*SegmentContent, string, error) {
	raw, sha, err := p.fetchJSONFile(path)
	if err != nil {
		return nil, "", err
	}
	if raw == nil {
		return &SegmentContent{}, "", nil
	}

	content, err := decodeSegment(raw, p.publicKey)
	return content, sha, err
}

// fetchManifestSegment requires a manifest-listed segment to exist and match
// its exact byte checksum and decrypted brief count.
func (p *Publisher) fetchManifestSegment(entry SegmentEntry) (*SegmentContent, string, error) {
	path := "output/" + entry.Path
	raw, sha, err := p.fetchJSONFile(path)
	if err != nil {
		return nil, "", err
	}
	if raw == nil {
		return nil, "", fmt.Errorf("manifest-listed segment %s is missing", entry.Path)
	}
	if entry.Checksum != "" && ComputeChecksum(raw) != strings.TrimPrefix(entry.Checksum, "sha256:") {
		return nil, "", fmt.Errorf("manifest checksum mismatch for %s", entry.Path)
	}
	content, err := decodeSegment(raw, p.publicKey)
	if err != nil {
		return nil, "", err
	}
	if len(content.Briefs) != entry.BriefCount {
		return nil, "", fmt.Errorf("manifest brief_count for %s is %d, decrypted segment has %d", entry.Path, entry.BriefCount, len(content.Briefs))
	}
	return content, sha, nil
}

func decodeSegment(raw []byte, publicKey string) (*SegmentContent, error) {
	// Decode content as bytes: encoding/json base64-decodes it straight into
	// one buffer, which openSegment then decrypts in place.
	var file struct {
		Content []byte `json:"content"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parsing segment manifest: %w", err)
	}

	content, err := openSegment(file.Content, publicKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting segment: %w", err)
	}
	return content, nil
}

// fetchJSONFile fetches a file from GitHub and returns the raw bytes and SHA.
// Returns (nil, "", nil) on 404.
func (p *Publisher) fetchJSONFile(path string) ([]byte, string, error) {
	if staged, ok := p.stagedGitFile(path); ok {
		if staged.deleted {
			return nil, "", nil
		}
		raw, err := p.fetchBlob(staged.sha, staged.size)
		if err != nil {
			return nil, "", err
		}
		return raw, staged.sha, nil
	}
	p.recordPublicationRead(path)
	url := fmt.Sprintf("%s/repos/%s/contents/%s", p.apiURL, p.repoSlug, path)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}
	if ref := p.publicationBaseRef(); ref != "" {
		query := req.URL.Query()
		query.Set("ref", ref)
		req.URL.RawQuery = query.Encode()
	}
	p.setHeaders(req)

	resp, err := p.doGitHubRead(req, githubErrorBodyBytes)
	if err != nil {
		return nil, "", err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, githubErrorBodyBytes))
		return nil, "", &githubAPIError{status: resp.StatusCode, body: string(body)}
	}

	var ghFile struct {
		SHA     string `json:"sha"`
		Size    int64  `json:"size"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghFile); err != nil {
		return nil, "", fmt.Errorf("decoding GitHub response: %w", err)
	}

	var raw []byte
	if ghFile.Content != "" {
		cleaned := strings.ReplaceAll(ghFile.Content, "\n", "")
		raw, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, "", fmt.Errorf("decoding file content: %w", err)
		}
	} else if ghFile.SHA != "" {
		// Files over 1MB come without inline content. Read them as the blob
		// with this SHA, not from download_url: that URL names the branch and
		// is served by a CDN that caches for 5 minutes, so right after a flush
		// it returned the previous version while the SHA was already current,
		// and the next flush merged into that copy and overwrote the briefs
		// the previous flush had added.
		if ghFile.Size > maxFeedFileBytes {
			return nil, "", fmt.Errorf("%s is %d bytes, over the %d byte limit", path, ghFile.Size, maxFeedFileBytes)
		}
		raw, err = p.fetchBlob(ghFile.SHA, ghFile.Size)
		if err != nil {
			return nil, "", fmt.Errorf("downloading %s: %w", path, err)
		}
	} else {
		return nil, "", fmt.Errorf("GitHub returned no content or SHA")
	}

	return raw, ghFile.SHA, nil
}

// blobDeadline is how long a download of size bytes may take: a base plus
// size at a slow assumed rate, capped.
func (p *Publisher) blobDeadline(size int64) time.Duration {
	base, rate, limit := p.blobDeadlineBase, p.blobRate, p.blobDeadlineMax
	if base <= 0 {
		base = defaultBlobDeadlineBase
	}
	if rate <= 0 {
		rate = defaultBlobRate
	}
	if limit <= 0 {
		limit = defaultBlobDeadlineMax
	}
	d := base + time.Duration(max(size, 0))*time.Second/time.Duration(rate)
	return min(d, limit)
}

// blobError is a failed blob download; retryAfter is the server's hint.
type blobError struct {
	status     int
	retryAfter time.Duration
	err        error
}

// retryableBlobError reports whether a failed blob download is worth another
// attempt: timeouts, truncated or reset connections, 5xx and 429.
func retryableBlobError(err error) bool {
	var be *blobError
	if errors.As(err, &be) {
		return be.status == http.StatusTooManyRequests || be.status >= 500
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// fetchBlob reads the raw bytes of the git blob sha, which is size bytes. The
// download has a size-aware deadline instead of the API client's 30s total
// timeout, and transient failures are retried.
func (p *Publisher) fetchBlob(sha string, size int64) ([]byte, error) {
	backoff := p.blobBackoff
	if backoff == nil {
		backoff = defaultBlobBackoff
	}
	path := "git/blobs/" + sha
	for attempt := 1; ; attempt++ {
		raw, err := p.fetchBlobOnce(sha, size)
		if err == nil || attempt > len(backoff) || !retryableBlobError(err) {
			return raw, err
		}
		wait := backoff[attempt-1]
		var be *blobError
		if errors.As(err, &be) && be.retryAfter > 0 {
			wait = min(be.retryAfter, maxBlobRetryAfter)
		}
		p.logger.Info("retrying blob download", "path", path, "attempt", attempt, "error", err, "wait", wait)
		time.Sleep(wait)
	}
}

func (p *Publisher) fetchBlobOnce(sha string, size int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.blobDeadline(size))
	defer cancel()
	url := fmt.Sprintf("%s/repos/%s/git/blobs/%s", p.apiURL, p.repoSlug, sha)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	p.setHeaders(req)
	req.Header.Set("Accept", "application/vnd.github.raw+json")

	// Same transport, but no total timeout: the context bounds the download.
	client := *p.client
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer discardClose(resp.Body)
	p.recordRateLimit(resp)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, githubErrorBodyBytes))
		be := &blobError{status: resp.StatusCode, err: &githubAPIError{status: resp.StatusCode, body: string(body)}}
		if secs, convErr := strconv.Atoi(resp.Header.Get("Retry-After")); convErr == nil && secs > 0 {
			be.retryAfter = time.Duration(secs) * time.Second
		}
		return nil, be
	}
	return readFeedFile(resp.Body, size, maxFeedFileBytes)
}

// readFeedFile reads a download of the expected size into one buffer of that
// size, and fails rather than reading on past maxBytes.
func readFeedFile(r io.Reader, size, maxBytes int64) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, min(max(size, 0), maxBytes)+bytes.MinRead))
	if _, err := buf.ReadFrom(io.LimitReader(r, maxBytes+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > maxBytes {
		return nil, fmt.Errorf("download exceeds %d bytes", maxBytes)
	}
	return buf.Bytes(), nil
}

// putJSONFile marshals v to JSON and uploads it as a plain (unencrypted) file.
func (p *Publisher) putJSONFile(path string, v interface{}, sha, message string) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshalling JSON: %w", err)
	}
	if p.publication != nil {
		_, err := p.stageGitFile(path, data)
		return err
	}

	payload, err := p.contentsPayload(message, sha, len(data), writeBytes(data))
	if err != nil {
		return err
	}

	return p.putContentsWithRetry(context.Background(), path, payload, "putJSONFile")
}

// putContentsWithRetry uploads a base64-encoded contents request to the GitHub
// Contents API with retry. It retries on transient 5xx/429 responses and
// network errors, respects context cancellation, and observes the rate-limit
// floor between attempts.
func (p *Publisher) putContentsWithRetry(ctx context.Context, path string, payload []byte, description string) error {
	url := fmt.Sprintf("%s/repos/%s/contents/%s", p.apiURL, p.repoSlug, path)

	var lastErr error
	for attempt := 1; attempt <= putFileMaxAttempts; attempt++ {
		if err := p.awaitRateLimit(ctx); err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		p.setHeaders(req)

		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("GitHub request failed: %w", err)
			if !isRetryableGitHubError(err) {
				return lastErr
			}
			if attempt < putFileMaxAttempts {
				if sleepErr := sleepWithContext(ctx, putFileRetryDelays[attempt-1]); sleepErr != nil {
					return sleepErr
				}
			}
			continue
		}
		p.recordRateLimit(resp)

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			_ = resp.Body.Close()
			return nil
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, githubErrorBodyBytes))
		_ = resp.Body.Close()
		lastErr = &githubAPIError{status: resp.StatusCode, body: string(respBody)}

		if resp.StatusCode == http.StatusTooManyRequests {
			// Honor Retry-After if present, otherwise fall through to
			// standard backoff.
			if after := resp.Header.Get("Retry-After"); after != "" {
				if secs, parseErr := strconv.Atoi(after); parseErr == nil && secs > 0 {
					if sleepErr := sleepWithContext(ctx, time.Duration(secs)*time.Second); sleepErr != nil {
						return sleepErr
					}
					continue
				}
			}
		}
		retryableRuleTimeout := resp.StatusCode == http.StatusConflict &&
			bytes.Contains(bytes.ToLower(respBody), []byte("rule did not run because of a timeout"))
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests && !retryableRuleTimeout {
			return lastErr
		}
		if attempt < putFileMaxAttempts {
			if sleepErr := sleepWithContext(ctx, putFileRetryDelays[attempt-1]); sleepErr != nil {
				return sleepErr
			}
		}
	}
	return fmt.Errorf("putting %s (%s) after %d attempts: %w", path, description, putFileMaxAttempts, lastErr)
}

func isRetryableGitHubError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "temporary failure") ||
		strings.Contains(msg, "no such host")
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func (p *Publisher) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+p.tokenFn())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

// recordRateLimit reads the X-RateLimit-* headers from a GitHub API
// response and stores them on the Publisher. Called once per response
// across every API call site (fetch, get-SHA, put, put-markdown).
func (p *Publisher) recordRateLimit(resp *http.Response) {
	if resp == nil {
		return
	}
	remStr := resp.Header.Get("X-RateLimit-Remaining")
	resetStr := resp.Header.Get("X-RateLimit-Reset")
	if remStr == "" || resetStr == "" {
		return
	}
	rem, err := strconv.Atoi(remStr)
	if err != nil {
		return
	}
	resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
	if err != nil {
		return
	}
	p.rateLimitMu.Lock()
	p.rateLimitRemaining = rem
	p.rateLimitReset = time.Unix(resetUnix, 0)
	p.rateLimitMu.Unlock()
}

// awaitRateLimit blocks until the GitHub API budget recovers above the
// floor. Called before each write; cheap (no-op when remaining is
// healthy or no headers have been seen yet). Returns ctx.Err if the
// context is cancelled while waiting.
func (p *Publisher) awaitRateLimit(ctx context.Context) error {
	p.rateLimitMu.Lock()
	rem := p.rateLimitRemaining
	reset := p.rateLimitReset
	p.rateLimitMu.Unlock()
	if rem == 0 && reset.IsZero() {
		return nil // no measurement yet
	}
	if rem >= rateLimitFloor {
		return nil
	}
	wait := time.Until(reset) + 5*time.Second
	if wait <= 0 {
		return nil
	}
	if wait > 1*time.Hour {
		wait = 1 * time.Hour // belt: never sleep more than an hour on a single call
	}
	p.logger.Warn("github api rate limit near floor — backing off until reset",
		"remaining", rem, "reset", reset, "sleep", wait)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

type contentsRequest struct {
	Branch  string       `json:"branch"`
	Message string       `json:"message"`
	Content string       `json:"content"`
	SHA     string       `json:"sha,omitempty"`
	Author  commitAuthor `json:"author"`
}

type commitAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
