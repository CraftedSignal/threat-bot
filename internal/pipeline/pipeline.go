package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/sigma"
	"github.com/craftedsignal/threat-bot/internal/storage"

	"gopkg.in/yaml.v3"
)

// BriefPublisher publishes approved briefs to the threat-feed repo.
type BriefPublisher interface {
	Publish(briefYAML string) error
	Flush() error
}

// DraftPublisher preserves a pending draft's completion identity until the
// publisher commits the batch. A successful enqueue is not draft approval.
type DraftPublisher interface {
	PublishDraft(briefYAML, draftID, claimKey string) error
}

func (p *Pipeline) queueDraftPublication(briefYAML, draftID, claimKey string) error {
	pub, ok := p.publisher.(DraftPublisher)
	if !ok {
		return fmt.Errorf("publisher does not support committed draft completion")
	}
	if err := pub.PublishDraft(briefYAML, draftID, claimKey); err != nil {
		return err
	}
	return p.db.DeletePublicationIntent(draftID, briefYAML)
}

// BriefRetirementPublisher atomically removes superseded public identities
// when several approved drafts are found to describe one incident.
type BriefRetirementPublisher interface {
	BriefPublisher
	RetireBrief(id, slug string) error
}

type Pipeline struct {
	db                     *storage.DB
	dedup                  *Deduplicator
	quality                *QualityGate
	extractor              *ThreatExtractor
	llmClient              llm.Client
	assembler              *BriefAssembler
	validator              *BriefValidator
	iocVerifier            *IOCVerifier
	cveVerifier            *CVEVerifier
	cveEnricher            *CVEEnricher
	grounding              *GroundingChecker
	maxGroundingAttempts   int
	processingPolicy       string
	retryBackoff           time.Duration
	enricher               *ContentEnricher
	watchlistMu            sync.RWMutex
	watchlist              *Watchlist
	correlator             *Correlator
	publisher              BriefPublisher
	sigmaIdx               *sigma.Index
	logger                 *slog.Logger
	sourceConfidence       map[string]float64
	sourceSignalThresholds map[string]int
	autoPublish            bool
	roundupConsolidation   bool
	campaignConsolidation  bool
	kev                    *scraper.KEVCatalog
	notifierURL            string
	notifierToken          string
	notifierCooldown       time.Duration
	siteURL                string
	decisions              decisionLog
	socialProvider         scraper.StatusProvider
	socialThreadDepth      int
}

type Config struct {
	DB               *storage.DB
	LLMClient        llm.Client // main model for brief assembly
	RepairLLMClient  llm.Client // optional dedicated grounding repair model
	FastLLMClient    llm.Client // fast model for quality gate (nil = use main)
	SigmaIdx         *sigma.Index
	QualityThreshold float64
	// MaxGroundingAttempts quarantines an item after this many failed
	// grounding passes. <= 0 uses defaultMaxGroundingAttempts.
	MaxGroundingAttempts   int
	ProcessingPolicy       string             // configured model identities; invalidates durable candidates
	RetryBackoff           time.Duration      // zero defaults to 15m; negative disables delays for deterministic tests
	TrustedSources         []string           // deprecated: use SourceConfidence instead
	SourceConfidence       map[string]float64 // per-source confidence multiplier (0.0-1.0)
	SourceSignalThresholds map[string]int     // opt-in deterministic pre-LLM gate by source
	Publisher              BriefPublisher     // nil = no auto-publish
	AutoPublish            bool
	RoundupConsolidation   bool // fold patch-cycle vendor CVEs into one monthly roundup brief (default off)
	CampaignConsolidation  bool // fold known campaign/technique families (ClickFix, Shai-Hulud) into one umbrella brief (default off)
	EnableCorrelation      bool
	Logger                 *slog.Logger
	EPSSCache              *scraper.EPSSCache
	KEV                    *scraper.KEVCatalog // filled by the CISA KEV source; nil leaves KEV status unknown
	Watchlist              *Watchlist

	// Notifier wiring for L3 update dispatches (KEV flip, active
	// exploitation, severity → critical). All optional — empty URL or
	// token disables direct emails; the visual "What's new" bar still
	// renders regardless.
	NotifierURL       string
	NotifierToken     string
	NotifierCooldown  time.Duration
	SiteURL           string
	SocialProvider    scraper.StatusProvider
	SocialThreadDepth int
}

// defaultSourceConfidence provides baseline confidence multipliers for known sources.
var defaultSourceConfidence = map[string]float64{
	"cisa":                   0.95,
	"cisa-kev":               0.95,
	"dfir-report":            0.90,
	"ccb-belgium":            0.85,
	"sigma-hq":               0.90,
	"elastic":                0.85,
	"splunk-escu":            0.85,
	"abuse-ch":               0.80,
	"nvd":                    0.90,
	"ghsa":                   0.85,
	"isc-stormcast":          0.70,
	"circl-misp":             0.75,
	"risky-biz":              0.80,
	"risky-biz-bulletin":     0.80,
	"pwn-watch":              0.55,
	"reddit-netsec":          0.30,
	"reddit-blueteamsec":     0.35,
	"reddit-cybersecurity":   0.25,
	"talos":                  0.85,
	"mandiant":               0.90,
	"unit42":                 0.85,
	"microsoft-threat-intel": 0.85,
	"sophos-xops":            0.80,
	"huntress":               0.80,
	"arctic-wolf":            0.80,
	"checkpoint":             0.85,
	"crowdstrike":            0.90,
	"eset":                   0.85,
	"volexity":               0.90,
	"securelist":             0.90,
	"wiz":                    0.80,
	"ncsc-uk":                0.90,
	"ncsc-nl":                0.90,
	"anssi":                  0.85,
	"bsi":                    0.85,
	"cert-eu":                0.85,
	"jpcert":                 0.80,
	"bleepingcomputer":       0.70,
	"therecord":              0.75,
	"securityweek":           0.70,
	"msrc":                   0.95,
	"cisco-psirt":            0.90,
	"palo-alto-networks":     0.90,
	"sonatype":               0.85,
	"google-project-zero":    0.95,
	"watchtowr":              0.85,
	"mozilla-security":       0.95,
	"ars-security":           0.85,
	// Tier 1 commercial
	"sentinelone-labs": 0.85,
	// Tier 2 commercial
	"bitdefender":              0.80,
	"fortiguard":               0.80,
	"proofpoint":               0.85,
	"rapid7":                   0.80,
	"red-canary":               0.80,
	"recorded-future":          0.80,
	"flashpoint":               0.75,
	"intel471":                 0.80,
	"greynoise":                0.75,
	"cofense":                  0.75,
	"any-run":                  0.70,
	"qualys-threat-research":   0.75,
	"malware-traffic-analysis": 0.75,
	"objective-see":            0.85,
	"attackiq":                 0.70,
	// Government / CERT
	"fbi-cyber": 0.90,
	"cccs":      0.85,
	"acsc":      0.85,
	"ms-isac":   0.80,
	// Independent research
	"google-tag": 0.90,
	// Ransomware victim tracking (observational — group claims, not independently verified)
	"ransomware-live": 0.70,
	// Exploit tracking
	"exploit-db": 0.80,
	"sploitus":   0.75,
	// Detection-focused research
	"socprime": 0.75,
	// Curator, not author: the content is whatever they linked to. Above the
	// reddit tier (a research company's curation, not crowd submissions), well
	// below vendor research. When the destination is already a threat-bot source
	// its own item wins on authority, so this only governs links to publishers
	// threat-bot does not follow — whose rigour is therefore unvetted.
	"ronin66": 0.60,
	// GossiTheDog (Kevin Beaumont): original detection-engineering content he
	// authored himself, same tier as elastic/splunk-escu rather than a curator
	// citing someone else's work.
	"gossithedog-threathunting": 0.80,
	// Mastodon commentary: structurally a curator+link like ronin66, but a
	// named researcher with a strong personal track record of first breaking
	// stories he then verifies himself — set above the generic curator tier.
	"gossithedog-mastodon": 0.75,
}

var sourceThreatTerms = []string{
	"ransomware", "malware", "threat actor", "campaign",
	"command and control", "c2", "data breach",
}

// sourceSignalScore assigns deterministic evidence points before any LLM call.
// The score is deliberately coarse: configured thresholds select for concrete
// vulnerability, exploitation, detection, or threat-campaign evidence.
func sourceSignalScore(item scraper.RawItem) int {
	score := 0
	if item.SigmaRule != nil {
		score += 4
	}
	if len(ExtractCVEsFromText(item.Title, item.Content)) > 0 {
		score += 3
	}
	text := strings.ToLower(item.Title + " " + item.Content)
	if containsAny(text, activeExploitTerms) {
		score += 2
	}
	if informationalHashRe.MatchString(text) || informationalIPRe.MatchString(text) {
		score += 2
	}
	if containsAny(text, sourceThreatTerms) {
		score++
	}
	return score
}

func meetsSourceSignalThreshold(item scraper.RawItem, thresholds map[string]int) (int, bool) {
	score := sourceSignalScore(item)
	threshold, configured := thresholds[item.Source]
	if !configured || threshold <= 0 {
		return score, true
	}
	return score, score >= threshold
}

func New(cfg Config) *Pipeline {
	qualityClient := cfg.FastLLMClient
	var qualityFallback llm.Client
	if qualityClient == nil {
		qualityClient = cfg.LLMClient
	} else {
		qualityFallback = cfg.LLMClient
	}

	// Build source confidence map: start with defaults, then apply config overrides.
	confidence := make(map[string]float64)
	for k, v := range defaultSourceConfidence {
		confidence[k] = v
	}
	// Legacy support: treat TrustedSources as confidence 1.0.
	for _, s := range cfg.TrustedSources {
		confidence[s] = 1.0
	}
	// Explicit config overrides take priority.
	for k, v := range cfg.SourceConfidence {
		confidence[k] = v
	}

	cveVerifier := NewCVEVerifier(cfg.EPSSCache, cfg.KEV)
	cveEnricher := NewCVEEnricher(cveVerifier)

	var correlator *Correlator
	if cfg.EnableCorrelation && cfg.DB != nil {
		correlator = NewCorrelator(cfg.DB, cfg.LLMClient, cfg.Logger)
		if cfg.AutoPublish && cfg.Publisher != nil {
			correlator.publishUpdates = true
			if validator, ok := cfg.Publisher.(interface{ ValidatePublication(string) error }); ok {
				correlator.validatePublication = validator.ValidatePublication
			}
		}
	}

	policyConfig, _ := json.Marshal(struct {
		Models            string
		Threshold         float64
		Confidence        map[string]float64
		Signals           map[string]int
		Roundup, Campaign bool
	}{cfg.ProcessingPolicy, cfg.QualityThreshold, confidence, cfg.SourceSignalThresholds, cfg.RoundupConsolidation, cfg.CampaignConsolidation})
	return &Pipeline{
		db:                     cfg.DB,
		dedup:                  NewDeduplicator(cfg.DB, cfg.Logger),
		quality:                NewQualityGateWithFallback(qualityClient, qualityFallback, cfg.QualityThreshold, cfg.Logger),
		extractor:              NewThreatExtractor(cfg.LLMClient),
		llmClient:              cfg.LLMClient,
		assembler:              NewBriefAssembler(cfg.LLMClient),
		validator:              NewBriefValidator(),
		iocVerifier:            NewIOCVerifier(),
		cveVerifier:            cveVerifier,
		cveEnricher:            cveEnricher,
		grounding:              NewGroundingChecker(cfg.LLMClient).WithLogger(cfg.Logger).WithRepairClient(cfg.RepairLLMClient),
		maxGroundingAttempts:   groundingAttemptLimit(cfg.MaxGroundingAttempts),
		processingPolicy:       string(policyConfig),
		retryBackoff:           configuredRetryBackoff(cfg.RetryBackoff),
		enricher:               NewContentEnricher(),
		correlator:             correlator,
		watchlist:              cfg.Watchlist,
		publisher:              cfg.Publisher,
		sigmaIdx:               cfg.SigmaIdx,
		logger:                 cfg.Logger,
		sourceConfidence:       confidence,
		sourceSignalThresholds: cfg.SourceSignalThresholds,
		autoPublish:            cfg.AutoPublish,
		roundupConsolidation:   cfg.RoundupConsolidation,
		campaignConsolidation:  cfg.CampaignConsolidation,
		kev:                    cfg.KEV,
		notifierURL:            cfg.NotifierURL,
		notifierToken:          cfg.NotifierToken,
		notifierCooldown:       cfg.NotifierCooldown,
		siteURL:                cfg.SiteURL,
		socialProvider:         cfg.SocialProvider,
		socialThreadDepth:      cfg.SocialThreadDepth,
	}
}

// flushBatchSize is the maximum number of briefs to buffer before flushing
// to the feed repo. Keeps data loss bounded on spot node evictions.
const flushBatchSize = 25

func (p *Pipeline) Process(ctx context.Context, items []scraper.RawItem) error {
	intents, _ := p.db.ListPublicationIntents()
	recoveryErr := p.recoverPublicationIntents()
	if recoveryErr != nil {
		p.logger.Error("publication recovery deferred", "error", recoveryErr)
	}
	// Publisher enqueue can already have acknowledged the DB intent while
	// its own durable outbox still awaits a successful flush.
	if (p.hasPrefetcher() || len(intents) > 0) && p.autoPublish && p.publisher != nil {
		if err := p.publisher.Flush(); err != nil {
			p.logger.Error("recovered bundle flush failed", "error", err)
		}
	}
	published := 0
	for start := 0; start < len(items); start += prefetchChunkSize {
		chunk := append([]scraper.RawItem(nil), items[start:min(start+prefetchChunkSize, len(items))]...)
		if err := p.processBatchChunk(ctx, chunk, &published); err != nil {
			return p.finishShutdown(err)
		}
		p.releasePrefetch()
	}

	// Run correlation across recent briefs and re-publish updated ones.
	if p.correlator != nil {
		updatedYAMLs, err := p.correlator.Run(ctx)
		if err != nil {
			p.logger.Error("correlation failed", "error", err)
		} else if len(updatedYAMLs) > 0 {
			p.logger.Info("correlation complete", "briefs_updated", len(updatedYAMLs))
			if p.autoPublish && p.publisher != nil {
				if pubErr := p.recoverPublicationIntents(); pubErr != nil {
					p.logger.Error("failed to queue durable correlated publications", "error", pubErr)
				}
			}
		}
	}

	// Flush any remaining briefs.
	if p.autoPublish && p.publisher != nil {
		if err := p.publisher.Flush(); err != nil {
			p.logger.Error("bundle flush failed", "error", err)
		}
	}

	return recoveryErr
}

// processBatchChunk owns one optional provider worker. Only this parent
// processes, deduplicates, assembles and publishes. Joining precedes every
// return, including shutdown, so answers cannot be released under the worker.
func (p *Pipeline) processBatchChunk(ctx context.Context, chunk []scraper.RawItem, published *int) error {
	chunkCtx := context.WithValue(ctx, sourceRefreshMemoKey{}, sourceRefreshMemo{})
	var ready []scraper.RawItem
	if p.hasPrefetcher() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.retainBatchItems(chunk); err != nil {
			if !errors.Is(err, storage.ErrIngestionBackpressure) {
				return fmt.Errorf("retaining batch source payloads: %w", err)
			}
			retained, readErr := p.retainedBatchItems(chunk)
			if readErr != nil {
				return fmt.Errorf("reading retained batch source payloads: %w", readErr)
			}
			p.logger.Warn("intake full; draining retained sources before new inference", "deferred", len(chunk)-len(retained), "retained", len(retained))
			chunk = retained
		}
		ready, chunk = p.readyBatchItems(chunkCtx, chunk)
	}
	plan := p.planPrefetch(chunkCtx, chunk)
	if err := ctx.Err(); err != nil {
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	if len(plan.qualityRequests) > 0 || len(plan.extractionRequests) > 0 || len(plan.candidates) > 0 {
		go func() { defer close(done); plan.run(workerCtx) }()
	} else {
		close(done)
	}
	defer func() { cancel(); <-done }()
	for phase, work := range [][]scraper.RawItem{ready, chunk} {
		if phase == 1 {
			<-done
			// Pending social evidence refreshes at consumption after provider
			// waiting. Article bodies already remain enriched in chunk.
			clear(chunkCtx.Value(sourceRefreshMemoKey{}).(sourceRefreshMemo))
		}
		for _, item := range work {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := p.processItem(chunkCtx, item); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
					return ctxErr
				}
				// Waiting for a paid remote batch prevents duplicate inference.
				// The item stays unconsumed and resumes once the answer exists.
				var pending *llm.PendingBatchError
				if errors.As(err, &pending) {
					p.logger.Warn("item deferred while paid batch work is pending", "source_id", item.SourceID,
						"source", item.Source, "error_class", "batch_pending", "error", err)
				} else {
					p.decisions.record(outcomeFailed)
					p.logger.Error("pipeline error", "source_id", item.SourceID,
						"source", item.Source, "error_class", llm.ErrorStatus(err), "error", err)
				}
			}
			if p.autoPublish && p.publisher != nil {
				*published++
				if *published%flushBatchSize == 0 {
					if err := p.publisher.Flush(); err != nil {
						p.logger.Error("bundle flush failed", "error", err)
					}
				}
			}
		}
		if phase == 0 && len(ready) > 0 && len(chunk) > 0 && p.autoPublish && p.publisher != nil {
			if err := p.publisher.Flush(); err != nil {
				p.logger.Error("ready bundle flush failed", "error", err)
			}
		}
	}
	return ctx.Err()
}

// finishShutdown releases batch state and publishes work completed before the
// service context was canceled. Cancellation itself is not an operational
// failure; a flush failure still is.
func (p *Pipeline) finishShutdown(err error) error {
	p.releasePrefetch()
	if p.autoPublish && p.publisher != nil {
		if flushErr := p.publisher.Flush(); flushErr != nil {
			p.logger.Error("bundle flush failed during shutdown", "error", flushErr)
		}
	}
	return err
}

// Decisions reports what the pipeline decided over the trailing window. Counts
// start at zero with the process and are accurate to within five minutes.
func (p *Pipeline) Decisions(window time.Duration) DecisionCounts {
	return p.decisions.since(window)
}

// createDraft stores a new draft and counts it, so every path that produces a
// brief is visible to the starvation check.
func (p *Pipeline) createDraft(draft *storage.Draft) error {
	if err := p.db.CreateDraft(draft); err != nil {
		return err
	}
	p.decisions.record(outcomeDraft)
	return nil
}

var patchCycleVendorDisplay = map[string]string{
	"microsoft": "Microsoft",
	"adobe":     "Adobe",
	"apple":     "Apple",
	"oracle":    "Oracle",
	"sap":       "SAP",
	"qualcomm":  "Qualcomm",
	"google":    "Google",
	"android":   "Android",
	"cisco":     "Cisco",
	"siemens":   "Siemens",
	"mozilla":   "Mozilla",
	"atlassian": "Atlassian",
}

// getSourceConfidence returns the confidence multiplier for a source.
// Returns 0.5 if the source is not configured.
func (p *Pipeline) getSourceConfidence(source string) float64 {
	if c, ok := p.sourceConfidence[source]; ok {
		return c
	}
	return 0.5
}

// SetWatchlist updates the pipeline's watchlist (e.g. after a platform sync).
func (p *Pipeline) SetWatchlist(wl *Watchlist) {
	p.watchlistMu.Lock()
	defer p.watchlistMu.Unlock()
	p.watchlist = wl
}

// getWatchlist returns the current watchlist, safe for concurrent access.
func (p *Pipeline) getWatchlist() *Watchlist {
	p.watchlistMu.RLock()
	defer p.watchlistMu.RUnlock()
	return p.watchlist
}

// isActionableBrief checks whether a brief YAML contains at least one rule,
// IOC, or TTP. Briefs with none of these are news summaries that provide no
// actionable intelligence for detection engineers.
func isActionableBrief(briefYAML string) bool {
	var brief struct {
		Rules            []any           `yaml:"rules"`
		IOCs             []any           `yaml:"iocs"`
		TTPs             []any           `yaml:"ttps"`
		ThreatActor      string          `yaml:"threat_actor"`
		AffectedVendors  []string        `yaml:"affected_vendors"`
		AffectedProducts []string        `yaml:"affected_products"`
		ActionPlan       briefActionPlan `yaml:"action_plan"`
	}
	if err := yaml.Unmarshal([]byte(briefYAML), &brief); err != nil {
		return true // err on the side of inclusion
	}
	if len(brief.Rules) > 0 || len(brief.IOCs) > 0 || len(brief.TTPs) > 0 {
		return true
	}
	// A CVE-NNNN pattern in the brief or a named threat actor is enough on
	// its own. Otherwise sources like CISA KEV, NVD, or vendor advisories
	// (which carry vendor + product + CVE but no Sigma rule, no IOC, no
	// TTP) drop out of the feed even though they describe actively
	// exploited issues that defenders need to patch.
	if cveRe.MatchString(briefYAML) {
		return true
	}
	if strings.TrimSpace(brief.ThreatActor) != "" {
		return true
	}
	// A grounded vendor/CERT notice can require a concrete response before
	// any detector, CVE, or IOC exists. Require both an affected asset and an
	// evidence-backed action; product announcements do not meet this bar.
	if hasMeaningfulEntry(brief.AffectedProducts) || hasMeaningfulEntry(brief.AffectedVendors) {
		for _, action := range brief.ActionPlan.ImmediateActions {
			if strings.TrimSpace(action.Action) != "" && strings.TrimSpace(action.Evidence) != "" {
				return true
			}
		}
		for _, action := range brief.ActionPlan.MitigationPlan {
			if strings.TrimSpace(action.Action) != "" && strings.TrimSpace(action.Evidence) != "" {
				return true
			}
		}
	}
	return false
}

func (p *Pipeline) refreshSourceEvidence(ctx context.Context, item scraper.RawItem) (scraper.RawItem, error) {
	if err := ctx.Err(); err != nil {
		return item, err
	}
	key := item.SourceID + "\x00" + item.ContentRevision()
	memo, _ := ctx.Value(sourceRefreshMemoKey{}).(sourceRefreshMemo)
	if result, ok := memo[key]; ok {
		return result.item, result.err
	}
	refreshed, articleBase, err := p.refreshSourceEvidenceUncached(ctx, item)
	if memo != nil {
		memo[key] = sourceRefreshResult{item: refreshed, articleBase: articleBase, err: err}
	}
	return refreshed, err
}

func (p *Pipeline) refreshSourceEvidenceUncached(ctx context.Context, item scraper.RawItem) (scraper.RawItem, scraper.RawItem, error) {
	articleBase := item
	// Social enrichment mutates provenance as well as text. Preserve the
	// fetched source payload for a new current-context reconstruction.
	if item.Metadata != nil {
		metadata := make(map[string]string, len(item.Metadata))
		for key, value := range item.Metadata {
			metadata[key] = value
		}
		item.Metadata = metadata
	}
	if item.Discovery != nil {
		discovery := *item.Discovery
		discovery.ParentURLs = append([]string(nil), discovery.ParentURLs...)
		discovery.QuoteURLs = append([]string(nil), discovery.QuoteURLs...)
		item.Discovery = &discovery
	}
	var refreshErrors []error
	if p.socialProvider != nil && (item.Discovery != nil || containsXStatusReference(item.URL+" "+item.Content)) {
		item = scraper.EnrichSocialContext(ctx, p.socialProvider, item, p.socialThreadDepth)
		if item.Discovery != nil && !item.Discovery.ContextComplete {
			refreshErrors = append(refreshErrors, fmt.Errorf("social context refresh incomplete"))
			p.logger.Warn("social context provider failed or returned incomplete thread", "source_id", item.SourceID, "url", item.URL)
		}
		if item.Discovery != nil {
			if item.Metadata == nil {
				item.Metadata = map[string]string{}
			}
			provenance := []string{item.Discovery.OriginalURL, item.Discovery.DiscoveryURL}
			provenance = append(provenance, item.Discovery.ParentURLs...)
			provenance = append(provenance, item.Discovery.QuoteURLs...)
			for i, raw := range provenance {
				if strings.TrimSpace(raw) == "" {
					continue
				}
				item.Metadata[fmt.Sprintf("reference_url_social_%03d", i)] = raw
			}
		}
	}

	// Enrich thin content before quality gate so scoring sees full article.
	beforeArticle := item.Content
	origLen := len(item.Content)
	for _, enrichmentErr := range p.enricher.Enrich(ctx, &item) {
		refreshErrors = append(refreshErrors, enrichmentErr)
		p.logger.Warn("source enrichment unavailable", "source_id", item.SourceID, "source", item.Source, "error", enrichmentErr)
	}
	if len(item.Content) > origLen {
		p.logger.Debug("content enriched", "source_id", item.SourceID, "before", origLen, "after", len(item.Content))
	}

	articleBase.Content += strings.TrimPrefix(item.Content, beforeArticle)
	articleBase.Enriched = item.Enriched
	articleBase.NeedsFullArticle = item.NeedsFullArticle
	return item, articleBase, errors.Join(refreshErrors...)
}
