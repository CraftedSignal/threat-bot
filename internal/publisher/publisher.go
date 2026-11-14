package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/sigma"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

const bundlePath = "output/bundle.json"

const (
	manifestPath    = "output/manifest.json"
	changelogPath   = "output/changelog.json"
	cveMetadataPath = "output/cve-metadata.json"
)

// PublisherOption configures a Publisher.
type PublisherOption func(*Publisher)

// WithLLMClient attaches an LLM client for digest summary generation.
func WithLLMClient(c llm.Client) PublisherOption {
	return func(p *Publisher) {
		p.llmClient = c
	}
}

const retirementOutboxPrefix = "retire:"

// Publisher accumulates briefs and atomically publishes feed releases to Git.
// Mutating methods require serial calls, as provided by the service main loop;
// NewestPublicBrief separately synchronizes concurrent health-monitor reads.
type Publisher struct {
	settings  PublicationSettings
	repoSlug  string        // "owner/repo"
	publicKey string        // hex-encoded public key for bundle encryption
	tokenFn   func() string // GitHub App installation token
	apiURL    string        // GitHub API base URL (for testing)
	client    *http.Client
	logger    *slog.Logger
	// Blob download tuning; zero values mean the defaults below.
	blobDeadlineBase time.Duration   // fixed part of a blob download's deadline
	blobRate         int64           // assumed worst-case bytes per second
	blobDeadlineMax  time.Duration   // cap on a blob download's deadline
	blobBackoff      []time.Duration // waits between attempts; len+1 attempts
	// GitHub API rate-limit state. Updated from every response's
	// X-RateLimit-* headers; consulted before the next request so
	// long backfill runs back off automatically when the remaining
	// budget drops below the safety threshold.
	rateLimitMu        sync.Mutex
	rateLimitRemaining int
	rateLimitReset     time.Time
	llmClient          llm.Client        // optional LLM client for digest summaries
	pending            []BundleBrief     // briefs buffered since last Flush
	pendingDigests     []BundleDigest    // digests buffered since last Flush
	pendingRetirements map[string]string // canonical brief ID -> public slug to remove
	UseSegmented       bool              // when true, Flush uses FlushSegmented instead
	retiredInFavourOf  map[string]string // retired brief ID -> canonical brief ID it is retired in favour of
	rejectedIDs        []string          // brief IDs the latest segmented flush rejected
	publication        *gitPublication
	outbox             OutboxStore      // optional durable copy of pending briefs and digests
	outboxSeq          map[string]int64 // outbox ID -> seq of the snapshot currently buffered
	// Retirements restored from the outbox after a restart, by retired brief
	// ID. Once a flush applies one, retirementApplied lets the caller finish
	// the draft-side consolidation the crashed process never reached.
	restoredRetirements map[string]Retirement
	retirementApplied   func(Retirement) error
	draftPublished      func(DraftPublication) error
	draftPublishable    func(DraftPublication) (bool, error)
	pendingDrafts       map[string]draftOutboxPayload

	// The newest publish date among the briefs whose public Markdown this
	// process pushed, and when it pushed that brief. The public site lists
	// briefs by publish date, so its feed should reach that date once the
	// site has been rebuilt.
	newestPublicMu     sync.Mutex
	newestPublicBrief  time.Time
	newestPublicPushed time.Time
}

func (e *RetirementRejectedError) Error() string { return e.Err.Error() }
func (e *RetirementRejectedError) Unwrap() error { return e.Err }

// PublishedBriefExists reports whether id belongs to the canonical identity
// of a brief currently listed in the segmented feed.
func (p *Publisher) PublishedBriefExists(id string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, fmt.Errorf("published brief ID is required")
	}
	manifest, _, err := p.fetchManifest()
	if err != nil {
		return false, fmt.Errorf("fetching manifest: %w", err)
	}
	identity, err := p.loadCanonicalIdentity(manifest, nil)
	if err != nil {
		return false, fmt.Errorf("loading canonical brief identity: %w", err)
	}
	_, exists := identity.byID[id]
	return exists, nil
}

// NewestPublicBrief returns the publish date of the newest brief whose public
// Markdown this process pushed, and when it pushed it. Both are zero until
// the first push.
func (p *Publisher) NewestPublicBrief() (published, pushed time.Time) {
	p.newestPublicMu.Lock()
	defer p.newestPublicMu.Unlock()
	return p.newestPublicBrief, p.newestPublicPushed
}

func (p *Publisher) notePublicBriefPushed(b BundleBrief, pushed time.Time) {
	published, err := time.Parse(time.RFC3339, b.PublishedAt)
	if err != nil {
		p.logger.Warn("public brief has an unparseable publish date", "brief", b.ID, "published_at", b.PublishedAt)
		return
	}
	p.newestPublicMu.Lock()
	defer p.newestPublicMu.Unlock()
	if published.After(p.newestPublicBrief) {
		p.newestPublicBrief = published
		p.newestPublicPushed = pushed
	}
}

func New(repoSlug, publicKey string, tokenFn func() string, logger *slog.Logger, opts ...PublisherOption) *Publisher {
	p := &Publisher{
		repoSlug:  repoSlug,
		publicKey: publicKey,
		tokenFn:   tokenFn,
		apiURL:    "https://api.github.com",
		client:    &http.Client{Timeout: 30 * time.Second},
		logger:    logger,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Publish parses briefYAML, drops its rules that are not valid Sigma, applies
// IOC confidence decay, and buffers it for the next Flush. No GitHub calls are
// made.
func (p *Publisher) Publish(briefYAML string) error {
	return p.queueDraftPublication(briefYAML, DraftPublication{})
}

// bufferBrief keeps only the newest prepared snapshot for each canonical
// brief identity. A scrape run may approve multiple source items that resolve
// to the same brief; publishing both snapshots would make slug repair on the
// first snapshot look like an immutable identity change on the second.
// Replacing in place preserves deterministic first-seen ordering.
func (p *Publisher) bufferBrief(brief BundleBrief) {
	for i := range p.pending {
		if p.pending[i].ID == brief.ID {
			p.pending[i] = brief
			return
		}
	}
	p.pending = append(p.pending, brief)
}

// ValidatePublication runs the full local publication contract without
// buffering. Merge paths use it before changing an approved draft.
func (p *Publisher) ValidatePublication(briefYAML string) error {
	_, err := p.prepareBrief(briefYAML)
	return err
}

func (p *Publisher) prepareBrief(briefYAML string) (*BundleBrief, error) {
	if issues := pipeline.ValidatePublicationConsistency(briefYAML); len(issues) > 0 {
		return nil, fmt.Errorf("brief requires editorial review: %s", strings.Join(issues, "; "))
	}
	// Apply IOC confidence decay before parsing into the bundle brief.
	decayedYAML := pipeline.ApplyDecay(briefYAML, time.Now(), pipeline.DefaultIOCDecayConfig())
	if err := pipeline.ValidateBriefContract(decayedYAML); err != nil {
		return nil, fmt.Errorf("publication contract: %w", err)
	}

	brief, err := ParseBriefYAML(decayedYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing brief: %w", err)
	}
	if err := validatePublicSourceReferences(*brief); err != nil {
		return nil, fmt.Errorf("publication contract: %w", err)
	}
	brief.Rules = p.validRules(brief)
	if _, _, _, _, err := RenderPublicBriefMarkdown(*brief, nil); err != nil {
		return nil, fmt.Errorf("publication contract: %w", err)
	}
	return brief, nil
}

// validRules returns the brief's rules that are valid Sigma, dropping the
// rest: the feed never carries a rule its consumers cannot compile.
func (p *Publisher) validRules(brief *BundleBrief) []BundleRule {
	valid := brief.Rules[:0]
	for _, rule := range brief.Rules {
		if problems := sigma.Problems(rule.Title, sigma.LogSource(rule.LogSource), rule.Detection); len(problems) > 0 {
			p.logger.Warn("dropping invalid Sigma rule", "brief", brief.ID, "rule", rule.Title, "problems", problems)
			continue
		}
		valid = append(valid, rule)
	}
	return valid
}

// Flush encrypts all pending briefs into the bundle and pushes a single commit.
// When UseSegmented is true, it delegates to FlushSegmented instead.
func (p *Publisher) Flush() error {
	if p.UseSegmented {
		return p.FlushSegmented()
	}
	if err := p.retryDraftCompletions(); err != nil {
		return err
	}
	p.rejectedIDs = nil
	if err := p.checkDraftPublications(); err != nil {
		return err
	}

	if len(p.pending) == 0 {
		return nil
	}

	count := len(p.pending)
	flushed := p.outboxSnapshotExcludingRetirements()
	p.logger.Info("flushing bundle", "new_briefs", count)

	// Fetch existing bundle (404 = empty bundle).
	existing, sha, err := p.fetchBundle()
	if err != nil {
		return fmt.Errorf("fetching existing bundle: %w", err)
	}

	// Merge pending briefs and digests into existing using one revision time for
	// the whole publication run.
	runTime := time.Now().UTC()
	merged, err := MergeBriefs(existing.Briefs, p.pending, runTime)
	if err != nil {
		return fmt.Errorf("merging pending briefs: %w", err)
	}
	existing.Briefs = merged
	existing.Digests = mergeDigests(existing.Digests, p.pendingDigests)

	// Encrypt.
	manifest, err := Encrypt(existing, bundleVersion(), runTime.Format(time.RFC3339), p.publicKey)
	if err != nil {
		return fmt.Errorf("encrypting bundle: %w", err)
	}

	// Push.
	commitMsg := fmt.Sprintf("chore: update threat feed bundle (%d new briefs)", count)
	if _, err := p.putFile(bundlePath, manifest, sha, commitMsg); err != nil {
		return fmt.Errorf("pushing bundle: %w", err)
	}

	p.logger.Info("bundle flushed", "total_briefs", len(merged), "new_briefs", count, "digests", len(existing.Digests))
	completionErr := p.finishDraftPublications(flushed)
	p.pending = nil
	p.pendingDigests = nil
	p.clearOutbox(flushed)
	return completionErr
}

// putFileMaxAttempts bounds putFile's internal retry on transient GitHub
// 5xx responses. Large (~40MB) segment pushes during the vendor/product
// backfill intermittently hit a GitHub 500; a short bounded retry of the
// same payload clears it without failing the whole run.
const putFileMaxAttempts = 3

// putFileRetryDelays are the backoff sleeps between putFile attempts
// (index 0 = wait after attempt 1 fails, index 1 = wait after attempt 2).
var putFileRetryDelays = []time.Duration{2 * time.Second, 4 * time.Second}

// PublishDigest generates a digest and pushes it as an encrypted JSON file to the feed repo.
func (p *Publisher) PublishDigest(ctx context.Context, db *storage.DB, cfg DigestConfig) error {
	cfg.LLMClient = p.llmClient
	digest, err := GenerateDigest(ctx, db, cfg)
	if err != nil {
		return fmt.Errorf("generating digest: %w", err)
	}
	if digest.TotalBriefs == 0 {
		p.logger.Info("no briefs for digest, skipping publish")
		return nil
	}

	md := digest.RenderMarkdown()

	kind := "daily"
	if cfg.LookbackHours > 24 {
		kind = "weekly"
	}
	yearMonth := digest.Period[:7] // "YYYY-MM" from "YYYY-MM-DD"
	path := fmt.Sprintf("output/digests/%s/%s-%s.json", yearMonth, kind, digest.Period)

	digestType := "daily_digest"
	if cfg.LookbackHours > 24 {
		digestType = "weekly_digest"
	}
	bundleDigest := BundleDigest{
		ID:            fmt.Sprintf("%s-%s", kind, digest.Period),
		Type:          digestType,
		Title:         fmt.Sprintf("%s Threat Intelligence Digest - %s", strings.ToUpper(kind[:1])+kind[1:], digest.Period),
		Summary:       digest.Summary(),
		Content:       md,
		Period:        digest.Period,
		LookbackHours: cfg.LookbackHours,
		TotalBriefs:   digest.TotalBriefs,
		PublishedAt:   digest.GeneratedAt.Format(time.RFC3339),
	}

	manifest, err := EncryptDigest(&bundleDigest, bundleDigest.PublishedAt, p.publicKey)
	if err != nil {
		return fmt.Errorf("encrypting digest: %w", err)
	}

	// Check if digest already exists (get SHA for update).
	sha, err := p.getFileSHA(path)
	if err != nil {
		return fmt.Errorf("checking existing digest: %w", err)
	}

	// A successful acknowledgement requires the recoverable bundle work to be
	// durable before any remote publication. Retrying uses the same digest ID.
	payload, err := json.Marshal(bundleDigest)
	if err != nil {
		return fmt.Errorf("encoding digest for publish outbox: %w", err)
	}
	if err := p.persistOutbox(bundleDigest.ID, storage.OutboxKindDigest, string(payload)); err != nil {
		return fmt.Errorf("persisting digest publication: %w", err)
	}
	p.bufferDigest(bundleDigest)

	commitMsg := fmt.Sprintf("chore: publish threat intel digest for %s (%d briefs)", digest.Period, digest.TotalBriefs)
	if _, err := p.putFile(path, manifest, sha, commitMsg); err != nil {
		return fmt.Errorf("pushing digest: %w", err)
	}

	p.logger.Info("digest published", "path", path, "briefs", digest.TotalBriefs)

	return nil
}

// getFileSHA retrieves the SHA of an existing file, or "" if not found.
func (p *Publisher) getFileSHA(path string) (string, error) {
	if staged, ok := p.stagedGitFile(path); ok {
		return staged.sha, nil
	}
	p.recordPublicationRead(path)
	url := fmt.Sprintf("%s/repos/%s/contents/%s", p.apiURL, p.repoSlug, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	if ref := p.publicationBaseRef(); ref != "" {
		query := req.URL.Query()
		query.Set("ref", ref)
		req.URL.RawQuery = query.Encode()
	}
	p.setHeaders(req)

	resp, err := p.doGitHubRead(req, 512)
	if err != nil {
		return "", err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", &githubAPIError{status: resp.StatusCode, body: string(body)}
	}

	var ghFile struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghFile); err != nil {
		return "", err
	}
	return ghFile.SHA, nil
}

const (
	stixDir         = "site/static/stix"
	stixReleasesDir = stixDir + "/releases"
)

var stixReleaseName = regexp.MustCompile(`^(?:[0-9]{4}-(?:0[1-9]|1[0-2])-)?sha256-[0-9a-f]{64}\.json$`)

// MigrateBundle converts a legacy bundle.json into yearly segment files without
// buffering all briefs in memory simultaneously. It processes one year at a time:
// decrypt bundle → group by year → push each year segment → push manifest.
// This is idempotent: re-running after a partial failure is safe.
func (p *Publisher) MigrateBundle() error {
	return p.withAtomicPublication("chore: migrate legacy feed bundle", p.migrateBundleRelease)
}

func (p *Publisher) migrateBundleRelease() error {
	// Check for existing manifest — skip if already migrated.
	_, manifestSHA, err := p.fetchManifest()
	if err == nil && manifestSHA != "" {
		p.logger.Info("manifest already exists, skipping migration")
		return nil
	}

	// Fetch and decrypt legacy bundle (this is the peak memory moment: ~2× bundle size).
	legacy, _, err := p.fetchBundle()
	if err != nil {
		return fmt.Errorf("fetching legacy bundle: %w", err)
	}
	if len(legacy.Briefs) == 0 {
		p.logger.Info("legacy bundle empty, nothing to migrate")
		return nil
	}
	p.logger.Info("migrating legacy bundle", "briefs", len(legacy.Briefs), "digests", len(legacy.Digests))

	// Group briefs and digests by year key. Use index-based loops to allow GC
	// to reclaim bundle slices once we've consumed each element.
	byYear := make(map[string][]BundleBrief)
	for i := range legacy.Briefs {
		brief := legacy.Briefs[i]
		ts, _ := time.Parse(time.RFC3339, brief.PublishedAt)
		byYear[SegmentKey(ts)] = append(byYear[SegmentKey(ts)], brief)
	}
	digestsByYear := make(map[string][]BundleDigest)
	for i := range legacy.Digests {
		d := legacy.Digests[i]
		ts, _ := time.Parse(time.RFC3339, d.PublishedAt)
		digestsByYear[SegmentKey(ts)] = append(digestsByYear[SegmentKey(ts)], d)
	}
	// Allow the legacy bundle to be GC'd before we start pushing.
	legacy = nil

	now := bundleTimestamp()
	manifest := NewSegmentManifest()
	manifest.Version = "v" + now

	// Process one year at a time: build, encrypt, push, then discard.
	for year, briefs := range byYear {
		segPath := "output/briefs/" + year + ".json"
		sha, shaErr := p.getFileSHA(segPath)
		if shaErr != nil {
			return fmt.Errorf("checking existing segment %s: %w", year, shaErr)
		}

		segContent := &SegmentContent{
			Briefs:  briefs,
			Digests: digestsByYear[year],
		}
		encrypted, encErr := EncryptSegment(segContent, bundleVersion(), now, p.publicKey)
		if encErr != nil {
			return fmt.Errorf("encrypting segment %s: %w", year, encErr)
		}

		commitMsg := fmt.Sprintf("chore: migrate segment %s (%d briefs)", year, len(briefs))
		checksum, err := p.putFile(segPath, encrypted, sha, commitMsg)
		if err != nil {
			return fmt.Errorf("pushing segment %s: %w", year, err)
		}

		manifest.Segments = append(manifest.Segments, SegmentEntry{
			Path:         "briefs/" + year + ".json",
			Checksum:     checksum,
			BriefCount:   len(briefs),
			LastModified: now,
		})

		p.logger.Info("segment migrated", "year", year, "briefs", len(briefs), "digests", len(digestsByYear[year]))

		// Explicitly nil out so GC can reclaim before next iteration.
		byYear[year] = nil
		digestsByYear[year] = nil
	}

	// Push empty changelog and manifest so clients can discover segments.
	cl := NewChangelog()
	clSHA, shaErr := p.getFileSHA(changelogPath)
	if shaErr != nil {
		return fmt.Errorf("checking existing changelog: %w", shaErr)
	}
	if err := p.putJSONFile(changelogPath, cl, clSHA, "chore: init changelog"); err != nil {
		return fmt.Errorf("pushing changelog: %w", err)
	}

	manifestSHA2, shaErr := p.getFileSHA(manifestPath)
	if shaErr != nil {
		return fmt.Errorf("checking existing manifest: %w", shaErr)
	}
	if err := p.putJSONFile(manifestPath, manifest, manifestSHA2, "chore: publish segment manifest"); err != nil {
		return fmt.Errorf("pushing manifest: %w", err)
	}

	p.logger.Info("migration complete", "segments", len(manifest.Segments))
	return nil
}

// RepairManifest scans output/briefs/*.json files in the repo, fetches each
// one to compute the correct checksum and brief_count, then writes a corrected
// manifest. Safe to run at any time; no segment files are modified.
func (p *Publisher) RepairManifest() error {
	entries, err := p.listDir("output/briefs")
	if err != nil {
		return fmt.Errorf("listing briefs dir: %w", err)
	}

	_, manifestSHA, _ := p.fetchManifest()
	now := bundleTimestamp()
	manifest := NewSegmentManifest()
	manifest.Version = "v" + now

	for _, name := range entries {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		segPath := "output/briefs/" + name
		raw, _, fetchErr := p.fetchJSONFile(segPath)
		if fetchErr != nil || raw == nil {
			p.logger.Warn("skipping unreadable segment", "file", name, "err", fetchErr)
			continue
		}

		var enc BundleManifest
		if jsonErr := json.Unmarshal(raw, &enc); jsonErr != nil {
			p.logger.Warn("skipping non-manifest segment", "file", name)
			continue
		}

		checksum := ComputeChecksum(raw)
		key := strings.TrimSuffix(name, ".json")
		// Decrypt to count briefs accurately.
		seg, decErr := DecryptSegment(&enc, p.publicKey)
		briefCount := 0
		if decErr == nil {
			briefCount = len(seg.Briefs)
		} else {
			p.logger.Warn("could not decrypt segment for brief count", "file", name)
		}

		manifest.Segments = append(manifest.Segments, SegmentEntry{
			Path:         "briefs/" + key + ".json",
			Checksum:     checksum,
			BriefCount:   briefCount,
			LastModified: now,
		})
		p.logger.Info("segment scanned", "key", key, "briefs", briefCount, "checksum", checksum[:12])
	}

	sort.Slice(manifest.Segments, func(i, j int) bool {
		return manifest.Segments[i].Path < manifest.Segments[j].Path
	})

	if err := p.putJSONFile(manifestPath, manifest, manifestSHA, "chore: repair segment manifest"); err != nil {
		return fmt.Errorf("pushing manifest: %w", err)
	}
	p.logger.Info("manifest repaired", "segments", len(manifest.Segments))
	return nil
}

const (
	defaultBlobDeadlineBase = 60 * time.Second
	defaultBlobRate         = 256 << 10
	defaultBlobDeadlineMax  = 10 * time.Minute
	maxBlobRetryAfter       = 60 * time.Second
)

var defaultBlobBackoff = []time.Duration{2 * time.Second, 5 * time.Second}

func (e *blobError) Error() string { return e.err.Error() }
func (e *blobError) Unwrap() error { return e.err }

// maxFeedFileBytes bounds one downloaded feed file: the GitHub Contents API
// serves files up to 100MB.
const maxFeedFileBytes = 100 << 20

// githubErrorBodyBytes bounds how much of a GitHub error response is read
// into an error message.
const githubErrorBodyBytes = 4 << 10

// rateLimitFloor is the threshold below which we pause until reset
// rather than hammer the remaining budget. 200 leaves headroom for
// other concurrent threat-bot writes (scraper + backfill can run together).
const rateLimitFloor = 200
