package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/sigma"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func runScraper() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel()}))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// GitHub token source: either GitHub App or static GITHUB_TOKEN env var.
	ghTokenFn, err := newGitHubTokenFn(cfg.GitHub, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error setting up GitHub auth: %v\n", err)
		os.Exit(1)
	}

	// Open database
	if err := os.MkdirAll(filepath.Dir(cfg.DB.Path), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "error creating database directory: %v\n", err)
		os.Exit(1)
	}
	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	if err := db.PruneProcessingArtifacts(time.Now().UTC()); err != nil {
		logger.Warn("pruning completed processing artifacts", "error", err)
	}

	// LLM clients
	llmClients, err := buildLLMClients(cfg.LLM, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating LLM clients: %v\n", err)
		os.Exit(1)
	}
	llmHealth := llm.NewHealthMonitor()
	llmClient := llmHealth.Wrap("primary", llmClients.PrimaryModel, llmClients.Primary)
	llmChecks := []llmCheck{{Role: "primary", Model: llmClients.PrimaryModel, Client: llmClient}}
	var fastLLMClient llm.Client
	if llmClients.Fast != nil {
		fastLLMClient = llmHealth.Wrap("fast", llmClients.FastModel, llmClients.Fast)
		llmChecks = append(llmChecks, llmCheck{Role: "fast", Model: llmClients.FastModel, Client: fastLLMClient})
	}
	var repairLLMClient llm.Client
	if llmClients.Repair != nil {
		repairLLMClient = llmHealth.Wrap("repair", llmClients.RepairModel, llmClients.Repair)
		llmChecks = append(llmChecks, llmCheck{Role: "repair", Model: llmClients.RepairModel, Client: repairLLMClient})
	}
	if err := smokeCheckLLMs(ctx, llmChecks, logger); err != nil {
		fmt.Fprintf(os.Stderr, "error checking LLM models: %v\n", err)
		os.Exit(1)
	}
	// Keep readiness checks live, then cache only successful runtime structured
	// calls. Plain-text generation (including brief assembly) is never cached.
	llmClient = llm.NewCachedClient(llmClient, llmClients.PrimaryModel, db, logger)
	if fastLLMClient != nil {
		fastLLMClient = llm.NewCachedClient(fastLLMClient, llmClients.FastModel, db, logger)
	}

	// Put batch caches outside health monitoring: only actual online requests
	// should affect the model health counters. Smoke checks above stay online.
	if cfg.LLM.Batch.Enabled {
		llmClient, err = withBatchPrefetch(cfg.LLM, llmClients.PrimaryModel, llmClient, logger)
		if err != nil {
			logger.Error("creating batch client", "error", err)
			os.Exit(1)
		}
		if fastLLMClient != nil {
			fastLLMClient, err = withBatchPrefetch(cfg.LLM, llmClients.FastModel, fastLLMClient, logger)
			if err != nil {
				logger.Error("creating fast batch client", "error", err)
				os.Exit(1)
			}
		}
		logger.Info("batch prefetch enabled", "location", cfg.LLM.Location, "bucket", cfg.LLM.Batch.Bucket, "max_wait", cfg.LLM.Batch.MaxWait)
	}

	// Sigma index (optional — clone SigmaHQ/sigma locally)
	var sigmaIdx *sigma.Index
	sigmaDir := filepath.Join(filepath.Dir(cfg.DB.Path), "sigma-rules")
	if _, err := os.Stat(sigmaDir); err == nil {
		logger.Info("building sigma index", "dir", sigmaDir)
		idx, buildErr := sigma.BuildIndex(sigmaDir)
		if buildErr != nil {
			logger.Error("failed to build sigma index", "error", buildErr)
		} else {
			sigmaIdx = idx
			logger.Info("sigma index ready", "rules", sigmaIdx.Count())
		}
	}

	// CISA KEV catalog for CVE enrichment. The KEV source refreshes it on
	// every poll; it is first loaded just before the poll loop starts.
	kevCatalog := scraper.NewKEVCatalog()
	kevSource := scraper.NewCISAKEV(kevCatalog)

	// Register scrapers
	runner := scraper.NewRunner(db, logger, cfg.Pipeline.InitialLookback)

	registerScrapers(runner, cfg, ghTokenFn, kevSource, logger)
	for source, maxInterval := range cfg.Pipeline.AdaptivePolling {
		if !runner.SetAdaptivePolling(source, maxInterval) {
			logger.Warn("adaptive polling configured for unknown or disabled source", "source", source)
		}
	}
	// Items queued by `threat-bot sources replay` re-enter the pipeline here.
	runner.RegisterWithInterval(scraper.NewReplay(db), replayPollInterval)

	// EPSS cache for CVE enrichment.
	epssCache := scraper.NewEPSSCache(&http.Client{Timeout: 60 * time.Second}, db)
	if err := epssCache.Refresh(); err != nil {
		logger.Warn("initial EPSS refresh failed, will retry", "error", err)
	}

	// Watchlist from config.
	var watchlist *pipeline.Watchlist
	if len(cfg.Watchlist.Vendors) > 0 || len(cfg.Watchlist.Products) > 0 || len(cfg.Watchlist.Keywords) > 0 {
		watchlist = &pipeline.Watchlist{
			Vendors:  cfg.Watchlist.Vendors,
			Products: cfg.Watchlist.Products,
			Keywords: cfg.Watchlist.Keywords,
		}
		logger.Info("watchlist configured", "vendors", len(watchlist.Vendors), "products", len(watchlist.Products), "keywords", len(watchlist.Keywords))
	}

	// Publisher (for auto-publish)
	var pub *publisher.Publisher
	if cfg.Pipeline.AutoPublish && cfg.Publish.RepoSlug != "" && ghTokenFn != nil {
		pub = newServicePublisher(cfg, ghTokenFn, logger, llmClient, db)
		pub.UseSegmented = true
		flushRestored(pub, logger)
		logger.Info("auto-publish enabled", "repo", cfg.Publish.RepoSlug)
	}

	// Pipeline
	var statusProviders []scraper.StatusProvider
	for _, resolverURL := range cfg.Sources.SocialContext.ResolverURLs {
		statusProviders = append(statusProviders, &scraper.HTTPStatusProvider{BaseURL: resolverURL, MaxBytes: cfg.Sources.SocialContext.ResponseLimit})
	}
	if cfg.Sources.SocialContext.ThreadResolverURL != "" {
		statusProviders = append(statusProviders, scraper.NewThreadStatusProvider(cfg.Sources.SocialContext.ThreadResolverURL, cfg.Sources.SocialContext.ResponseLimit, scraper.StatusProviderOptions{
			DailyBudget: cfg.Sources.SocialContext.ThreadDailyBudget, RequestInterval: cfg.Sources.SocialContext.RequestInterval, CacheEntries: cfg.Sources.SocialContext.ThreadCacheEntries,
		}))
	}
	if cfg.Sources.SocialContext.OEmbedEnabled {
		statusProviders = append(statusProviders, scraper.NewOEmbedStatusProvider(cfg.Sources.SocialContext.OEmbedURL, cfg.Sources.SocialContext.ResponseLimit, scraper.StatusProviderOptions{
			DailyBudget: cfg.Sources.SocialContext.LeafDailyBudget, RequestInterval: cfg.Sources.SocialContext.RequestInterval,
		}))
	}
	var socialProvider scraper.StatusProvider
	if len(statusProviders) > 0 {
		socialProvider = scraper.NewProviderChain(statusProviders)
	}
	pipe := pipeline.New(pipeline.Config{
		DB:                     db,
		LLMClient:              llmClient,
		FastLLMClient:          fastLLMClient,
		RepairLLMClient:        repairLLMClient,
		ProcessingPolicy:       fmt.Sprintf("%s/%s/%s/%s/%s", cfg.LLM.Provider, cfg.LLM.Location, cfg.LLM.Model, cfg.LLM.FastModel, cfg.LLM.RepairModel),
		RetryBackoff:           cfg.Pipeline.RetryBackoff,
		SigmaIdx:               sigmaIdx,
		QualityThreshold:       cfg.Pipeline.QualityThreshold,
		MaxGroundingAttempts:   cfg.Pipeline.MaxGroundingAttempts,
		SourceConfidence:       cfg.Pipeline.SourceConfidence,
		SourceSignalThresholds: cfg.Pipeline.SourceSignalThresholds,
		Publisher:              briefPublisherOrNil(pub),
		AutoPublish:            cfg.Pipeline.AutoPublish,
		RoundupConsolidation:   cfg.Pipeline.RoundupConsolidation,
		CampaignConsolidation:  cfg.Pipeline.CampaignConsolidation,
		Logger:                 logger,
		EPSSCache:              epssCache,
		KEV:                    kevCatalog,
		Watchlist:              watchlist,
		NotifierURL:            cfg.Notifier.URL,
		NotifierToken:          cfg.Notifier.DispatchToken,
		NotifierCooldown:       cfg.Notifier.Cooldown,
		SiteURL:                cfg.Publish.SiteURL,
		SocialProvider:         socialProvider,
		SocialThreadDepth:      cfg.Sources.SocialContext.ThreadDepth,
	})

	// Main loop and probe server share the shutdown lifetime.

	var lastPollOK atomic.Bool
	lastPollOK.Store(true)
	srv := newHealthServer(&lastPollOK, llmHealth)
	go func() {
		logger.Info("health server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server failed", "error", err)
			cancel()
		}
	}()
	defer func() {
		if err := shutdownHealthServer(srv); err != nil {
			logger.Warn("health server shutdown failed", "error", err)
		}
	}()

	logger.Info("threat-bot starting", "sources", countEnabledSources(cfg))

	// Restore digest timestamps from SQLite so we survive restarts.
	lastDailyDigest := loadDigestTime(db, "daily", logger)
	lastWeeklyDigest := loadDigestTime(db, "weekly", logger)
	lastEPSSRefresh := time.Time{}
	lastWatchlistSync := time.Time{}
	var kevReconcile kevReconcileSchedule

	// Track prior observed health per source so we log only on transitions
	// (healthy <-> unhealthy) rather than every poll cycle.
	prevHealthy := make(map[string]bool)
	prevLLMHealthy := true
	startedAt := time.Now()
	lastNewItems := time.Time{}
	var starvation starvationThrottle
	var newestPublic func() (time.Time, time.Time)
	if pub != nil {
		newestPublic = pub.NewestPublicBrief
	}
	feedFreshness := newFeedFreshnessMonitor(cfg.Monitoring, newestPublic, logger)

	// Until this load succeeds every CVE's kev_status stays unknown, never
	// false. A failure is logged here once; a later KEV poll retries it.
	if err := kevSource.LoadCatalog(ctx); err != nil {
		logger.Warn("loading CISA KEV catalog failed; kev_status stays unknown until a KEV poll succeeds", "error", err)
	} else {
		logger.Info("CISA KEV catalog loaded", "cves", kevCatalog.Len())
	}
	if !cfg.Sources.CISAKEV.Enabled {
		logger.Info("cisa_kev source disabled; the KEV catalog is not refreshed until restart")
	}

	// Catch up any missed digests before entering the main loop.
	if pub != nil {
		catchUpDigests(ctx, db, pub, &lastDailyDigest, &lastWeeklyDigest, logger)
	}

	lastArtifactPrune := time.Now()
	for {
		if time.Since(lastArtifactPrune) >= 24*time.Hour {
			if err := db.PruneProcessingArtifacts(time.Now().UTC()); err != nil {
				logger.Warn("pruning completed processing artifacts", "error", err)
			} else {
				lastArtifactPrune = time.Now()
			}
		}
		items, err := runner.PollAll(ctx)
		if err != nil {
			if handleLoopError(ctx, logger, "poll error", err) {
				logger.Info("shutting down")
				return
			}
		}
		lastPollOK.Store(err == nil)
		runner.LogAnomalies(logger)

		if len(items) > 0 {
			lastNewItems = time.Now()
			logger.Info("processing new items", "count", len(items))
		}
		var flush func() error
		if pub != nil {
			flush = pub.Flush
		}
		if err := processPolledItems(ctx, items, pipe.Process, flush); err != nil {
			if handleLoopError(ctx, logger, "pipeline error", err) {
				logger.Info("shutting down")
				return
			}
		}

		llmStatus := llmHealth.Status()
		if llmStatus.OK != prevLLMHealthy {
			if llmStatus.OK {
				logger.Info("llm dependency recovered")
			} else {
				logger.Error("llm dependency unhealthy", "error", llmStatus.Message)
			}
			prevLLMHealthy = llmStatus.OK
		}

		checkBriefStarvation(pipe.Decisions, startedAt, lastNewItems, &starvation, logger)
		feedFreshness.Check(ctx)

		// Auto-publish digests if publisher is configured.
		if pub != nil {
			if time.Since(lastDailyDigest) >= 24*time.Hour {
				if err := pub.PublishDigest(ctx, db, publisher.DigestConfig{LookbackHours: 24}); err != nil {
					logger.Error("daily digest publish failed", "error", err)
				} else {
					lastDailyDigest = time.Now()
					period := time.Now().UTC().Format("2006-01-02")
					if err := db.SaveDigestState("daily", lastDailyDigest, period); err != nil {
						logger.Error("failed to persist daily digest state", "error", err)
					}
				}
			}
			if time.Since(lastWeeklyDigest) >= 7*24*time.Hour {
				if err := pub.PublishDigest(ctx, db, publisher.DigestConfig{LookbackHours: 7 * 24}); err != nil {
					logger.Error("weekly digest publish failed", "error", err)
				} else {
					lastWeeklyDigest = time.Now()
					period := time.Now().UTC().Format("2006-01-02")
					if err := db.SaveDigestState("weekly", lastWeeklyDigest, period); err != nil {
						logger.Error("failed to persist weekly digest state", "error", err)
					}
				}
			}

			// Warn if digests are overdue.
			if age := time.Since(lastDailyDigest); age > 36*time.Hour {
				logger.Warn("daily digest overdue", "last_published", lastDailyDigest, "age", age.Round(time.Hour))
			}
			if age := time.Since(lastWeeklyDigest); age > 8*24*time.Hour {
				logger.Warn("weekly digest overdue", "last_published", lastWeeklyDigest, "age", age.Round(time.Hour))
			}

			// EPSS refresh: periodically re-score CVEs across all segments.
			if time.Since(lastEPSSRefresh) >= cfg.EPSS.RefreshInterval {
				if err := pub.RefreshEPSS(epssCache, kevCatalog, publisher.EPSSRefreshConfig{
					Interval:      cfg.EPSS.RefreshInterval,
					MinScoreDelta: cfg.EPSS.MinScoreDelta,
				}, logger); err != nil {
					logger.Error("EPSS refresh failed", "error", err)
				} else {
					lastEPSSRefresh = time.Now()
				}
			}
		}

		// Exploitation reconciliation: mark briefs whose CVEs CISA has since
		// listed, unmark briefs exploited only on an exploit-code listing.
		if kevReconcile.due(time.Now()) {
			result, err := pipe.ReconcileExploitation(ctx, pipeline.ExploitationReconcileOptions{Limit: kevReconcileLimit, NotifyWithin: kevReconcileNotifyWithin})
			if handleLoopError(ctx, logger, "exploitation reconciliation failed", err) {
				logger.Info("shutting down")
				return
			}
			if err != nil {
				kevReconcile.failed(time.Now())
			} else {
				kevReconcile.completed(time.Now(), result, logger)
				if result.Updated > 0 && pub != nil {
					if err := pub.Flush(); err != nil {
						logger.Error("publishing exploitation reconciliation failed", "error", err)
					}
				}
			}
		}

		// Platform watchlist sync: periodically merge platform-managed watchlist entries.
		if cfg.Watchlist.PlatformSync != nil && cfg.Watchlist.PlatformSync.Enabled &&
			time.Since(lastWatchlistSync) >= cfg.Watchlist.PlatformSync.Interval {
			wlClient := scraper.NewWatchlistSyncClient(
				cfg.Watchlist.PlatformSync.Endpoint,
				cfg.Watchlist.PlatformSync.APIKey,
				&http.Client{Timeout: 30 * time.Second},
			)
			if resp, err := wlClient.Fetch(); err == nil {
				platformWL := &pipeline.Watchlist{
					Vendors:  resp.Vendors,
					Products: resp.Products,
					Keywords: resp.Keywords,
				}
				baseWL := &pipeline.Watchlist{
					Vendors:  cfg.Watchlist.Vendors,
					Products: cfg.Watchlist.Products,
					Keywords: cfg.Watchlist.Keywords,
				}
				pipe.SetWatchlist(pipeline.MergeWatchlists(baseWL, platformWL))
				lastWatchlistSync = time.Now()
				logger.Info("watchlist synced from platform", "vendors", len(resp.Vendors), "products", len(resp.Products))
			} else {
				logger.Warn("watchlist sync failed", "error", err)
			}
		}

		logSourceHealthTransitions(logger, runner.HealthSummary(), prevHealthy)

		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return
		case <-time.After(1 * time.Minute):
		}
	}
}

// briefPublisherOrNil keeps a nil publisher a nil interface. A typed nil
// stored in pipeline.Config.Publisher looks configured: the reconciliation
// then validates through it and panics on the nil receiver.
func briefPublisherOrNil(pub *publisher.Publisher) pipeline.BriefPublisher {
	if pub == nil {
		return nil
	}
	return pub
}

// Exploitation reconciliation runs hourly, every 10 minutes while a backlog
// remains.
// Only listings added within a week notify subscribers; older ones are a
// backfill, not news.
const (
	kevReconcileInterval        = time.Hour
	kevReconcileBacklogInterval = 10 * time.Minute
	kevReconcileLimit           = 50
	kevReconcileNotifyWithin    = pipeline.KEVNotifyWithin
)

type kevReconcileSchedule struct {
	next     time.Time
	lastHeld int
}

func (s *kevReconcileSchedule) due(now time.Time) bool { return !now.Before(s.next) }

// failed retries after the backlog interval, not on the next loop: a failing
// pass must not rescan every draft and log an error every minute.
func (s *kevReconcileSchedule) failed(now time.Time) { s.next = now.Add(kevReconcileBacklogInterval) }

// completed schedules the next pass and logs a pass that changed anything or
// whose count of briefs needing editorial review moved.
func (s *kevReconcileSchedule) completed(now time.Time, result pipeline.ExploitationReconcileResult, logger *slog.Logger) {
	s.next = now.Add(kevReconcileInterval)
	if result.More {
		s.next = now.Add(kevReconcileBacklogInterval)
	}
	if result.Updated > 0 || result.Held != s.lastHeld {
		logger.Info("exploitation reconciliation pass", "candidates", result.Candidates, "updated", result.Updated,
			"corrected", result.Corrected, "notified", result.Notified, "needs_review", result.Held, "more", result.More)
	}
	s.lastHeld = result.Held
}

// handleLoopError reports operational failures and tells the caller to stop
// when the operation was interrupted by shutdown of the service context.
func handleLoopError(ctx context.Context, logger *slog.Logger, message string, err error) bool {
	if err == nil {
		return false
	}
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return true
	}
	logger.Error(message, "error", err)
	return false
}

// loadDigestTime restores the last-published timestamp for a digest type from
// the database. Returns zero time if no prior state exists.
func loadDigestTime(db *storage.DB, digestType string, logger *slog.Logger) time.Time {
	state, err := db.GetDigestState(digestType)
	if err != nil {
		logger.Error("failed to load digest state", "type", digestType, "error", err)
		return time.Time{}
	}
	if state == nil {
		return time.Time{}
	}
	logger.Info("restored digest state", "type", digestType, "last_published", state.LastPublished, "period", state.Period)
	return state.LastPublished
}

// catchUpDigests generates digests for any days/weeks missed while threat-bot was
// down. Daily digests are generated for each missed day; weekly digests are
// generated if more than 7 days have elapsed since the last one.
func catchUpDigests(ctx context.Context, db *storage.DB, pub *publisher.Publisher, lastDaily, lastWeekly *time.Time, logger *slog.Logger) {
	now := time.Now()

	// Catch up missed daily digests (one per missed day, up to 7).
	if !lastDaily.IsZero() {
		missedDays := int(now.Sub(*lastDaily).Hours()) / 24
		if missedDays > 7 {
			missedDays = 7 // cap to avoid flooding
		}
		if missedDays > 1 {
			logger.Warn("catching up missed daily digests", "missed_days", missedDays-1)
			for i := missedDays - 1; i >= 1; i-- {
				lookback := 24
				target := now.AddDate(0, 0, -i)
				if err := pub.PublishDigest(ctx, db, publisher.DigestConfig{LookbackHours: lookback, Now: target}); err != nil {
					logger.Error("catch-up daily digest failed", "days_ago", i, "error", err)
					continue
				}
				*lastDaily = target
				period := target.UTC().Format("2006-01-02")
				if err := db.SaveDigestState("daily", *lastDaily, period); err != nil {
					logger.Error("failed to persist daily digest state", "error", err)
				}
				logger.Info("catch-up daily digest published", "days_ago", i)
			}
		}
	}

	// Catch up missed weekly digest.
	if !lastWeekly.IsZero() && now.Sub(*lastWeekly) > 8*24*time.Hour {
		logger.Warn("catching up missed weekly digest", "last_published", *lastWeekly)
		if err := pub.PublishDigest(ctx, db, publisher.DigestConfig{LookbackHours: 7 * 24, Now: now}); err != nil {
			logger.Error("catch-up weekly digest failed", "error", err)
		} else {
			*lastWeekly = now
			period := now.UTC().Format("2006-01-02")
			if err := db.SaveDigestState("weekly", *lastWeekly, period); err != nil {
				logger.Error("failed to persist weekly digest state", "error", err)
			}
			logger.Info("catch-up weekly digest published")
		}
	}
}

// starvationThrottle remembers when checkBriefStarvation last spoke, per
// severity, so each is logged at most once per briefStarvationWindow. A quiet
// period must not hold back an error that follows it.
type starvationThrottle struct {
	lastError time.Time
	lastQuiet time.Time
}

// due reports whether a line last logged at *last may be logged again. When it
// may, *last is stamped with the current time.
func due(last *time.Time) bool {
	if !last.IsZero() && time.Since(*last) < briefStarvationWindow {
		return false
	}
	*last = time.Now()
	return true
}

// checkBriefStarvation looks at what the pipeline decided over the last
// briefStarvationWindow when new items arrived but no draft was created. Items
// that clear the quality gate yet produce neither a draft nor a merge into an
// existing one mean the pipeline is broken: that is an error. Anything else is
// a quiet period, where nothing worth briefing arrived or all of it was already
// covered, and is only logged at info level.
func checkBriefStarvation(decisions func(window time.Duration) pipeline.DecisionCounts, startedAt, lastNewItems time.Time, throttle *starvationThrottle, logger *slog.Logger) {
	// Counts start with the process, so judge only once they span a full window.
	if lastNewItems.IsZero() || time.Since(startedAt) < briefStarvationWindow {
		return
	}
	if time.Since(lastNewItems) > briefStarvationWindow {
		return
	}

	d := decisions(briefStarvationWindow)
	if d.Drafts > 0 {
		return
	}

	attrs := []any{
		"window", briefStarvationWindow,
		"last_new_items", lastNewItems,
		"processed", d.Processed,
		"passed_quality", d.PassedQuality,
		"drafts", d.Drafts,
		"merged", d.Merged,
		"rejected_ungrounded", d.RejectedUngrounded,
		"failed", d.Failed,
	}
	if d.PassedQuality > 0 && d.Merged == 0 {
		if due(&throttle.lastError) {
			logger.Error("brief production starvation", attrs...)
		}
		return
	}
	if due(&throttle.lastQuiet) {
		logger.Info("quiet period", attrs...)
	}
}
