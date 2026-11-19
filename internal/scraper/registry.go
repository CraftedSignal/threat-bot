package scraper

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

// scraperEntry wraps a Scraper with per-source poll interval tracking.
type scraperEntry struct {
	scraper          Scraper
	basePollInterval time.Duration
	pollInterval     time.Duration
	adaptiveMax      time.Duration
	consecutiveEmpty int
	lastPoll         time.Time
}

// runnerStore is the durable state required to acknowledge a source poll.
type runnerStore interface {
	GetScraperState(string) (*storage.ScraperState, error)
	HasSeenRevision(string, string) (bool, error)
	MarkSeenRevision(string, string, string, string, ...string) error
	SaveScraperState(string, time.Time, string) error
	HasIngestionCandidate(string, string) (bool, error)
	CommitIngestion(string, time.Time, []storage.IngestionCandidate) error
	NextIngestionCandidates(int) ([]storage.IngestionCandidate, error)
}

// Runner manages and polls all registered scrapers.
type Runner struct {
	entries         []scraperEntry
	db              runnerStore
	logger          *slog.Logger
	initialLookback time.Duration
	health          map[string]SourceHealth
	healthMu        sync.RWMutex
}

type discoveryAnchorObserver interface {
	ObserveDiscoveryItems([]RawItem)
}

func NewRunner(db *storage.DB, logger *slog.Logger, initialLookback time.Duration) *Runner {
	if initialLookback <= 0 {
		initialLookback = 3 * 24 * time.Hour // default 3 days
	}
	return &Runner{
		db:              db,
		logger:          logger,
		initialLookback: initialLookback,
		health:          make(map[string]SourceHealth),
	}
}

// RegisterWithInterval adds a scraper with a custom poll interval. An unset
// interval falls back to hourly: external feeds must never be polled at
// loop-tick cadence — that hammering got the egress IP bot-blocked.
func (r *Runner) RegisterWithInterval(s Scraper, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	// Stagger first polls: ~50 sources firing in the same second on every
	// boot trips rate limits (Reddit 429'd each cold start). Source i
	// becomes eligible after i*7s, capped at half its interval.
	stagger := time.Duration(len(r.entries)) * 7 * time.Second
	if stagger > interval/2 {
		stagger = interval / 2
	}
	r.entries = append(r.entries, scraperEntry{
		scraper:          s,
		basePollInterval: interval,
		pollInterval:     interval,
		lastPoll:         time.Now().Add(-interval + stagger),
	})
}

// SetAdaptivePolling opts one registered source into interval backoff. Values
// at or below the base interval leave adaptive polling disabled.
func (r *Runner) SetAdaptivePolling(source string, max time.Duration) bool {
	for i := range r.entries {
		entry := &r.entries[i]
		if entry.scraper.Name() != source {
			continue
		}
		entry.adaptiveMax = 0
		entry.consecutiveEmpty = 0
		entry.pollInterval = entry.basePollInterval
		if max > entry.basePollInterval {
			entry.adaptiveMax = max
		}
		return true
	}
	return false
}

func updateAdaptivePolling(entry *scraperEntry, newItemCount int) {
	if entry.adaptiveMax <= entry.basePollInterval {
		return
	}
	if newItemCount > 0 {
		entry.pollInterval = entry.basePollInterval
		entry.consecutiveEmpty = 0
		return
	}
	entry.consecutiveEmpty++
	if entry.consecutiveEmpty < 2 {
		return
	}
	entry.consecutiveEmpty = 0
	next := entry.pollInterval * 2
	if next > entry.adaptiveMax {
		next = entry.adaptiveMax
	}
	entry.pollInterval = next
}

// Lookback returns how far back the runner accepts items. It skips items
// published before then and marks them seen.
func (r *Runner) Lookback() time.Duration { return r.initialLookback }

// Scraper returns the registered scraper with the given name.
func (r *Runner) Scraper(name string) (Scraper, bool) {
	for _, entry := range r.entries {
		if entry.scraper.Name() == name {
			return entry.scraper, true
		}
	}
	return nil, false
}

// PollIntervals returns the effective poll interval per registered source.
func (r *Runner) PollIntervals() map[string]time.Duration {
	intervals := make(map[string]time.Duration, len(r.entries))
	for _, entry := range r.entries {
		intervals[entry.scraper.Name()] = entry.pollInterval
	}
	return intervals
}

// PollAll runs all scrapers concurrently and returns new (unseen) items.
// Scrapers whose poll interval has not elapsed since their last poll are skipped.
func (r *Runner) PollAll(ctx context.Context) ([]RawItem, error) {
	var mu sync.Mutex
	var allItems []RawItem
	var errs []error
	var durableErrs []error
	var wg sync.WaitGroup

	now := time.Now()

	for i := range r.entries {
		entry := &r.entries[i]
		s := entry.scraper

		// Skip if this source was polled recently (per-source interval).
		if !entry.lastPoll.IsZero() && now.Sub(entry.lastPoll) < entry.pollInterval {
			r.logger.Debug("skipping source (poll interval not elapsed)", "source", s.Name(), "interval", entry.pollInterval, "last_poll", entry.lastPoll)
			continue
		}

		wg.Add(1)
		go func(entry *scraperEntry, s Scraper) {
			defer wg.Done()
			failState := func(operation string, err error) {
				failure := fmt.Errorf("%s: %s: %w", s.Name(), operation, err)
				r.recordError(s.Name(), failure)
				mu.Lock()
				errs = append(errs, failure)
				durableErrs = append(durableErrs, failure)
				mu.Unlock()
			}

			state, err := r.db.GetScraperState(s.Name())
			if err != nil {
				failState("getting state", err)
				return
			}
			since := time.Now().Add(-r.initialLookback)
			if state != nil {
				if state.LastPoll.After(time.Now()) {
					r.logger.Warn("source checkpoint is ahead of the clock; replaying lookback", "source", s.Name())
				} else {
					since = state.LastPoll
				}
			}

			r.logger.Info("polling source", "source", s.Name(), "since", since)
			var items []RawItem
			var window streamWindow
			stream, durable := s.(streamPoller)
			if durable {
				window, err = stream.PollWindow(ctx, since, func(item RawItem) (bool, error) {
					known, err := r.db.HasIngestionCandidate(item.SourceID, item.Revision)
					return !known, err
				})
				items = window.Items
				var queued []storage.IngestionCandidate
				var persistErr error
				for _, item := range items {
					payload, e := json.Marshal(item)
					if e != nil {
						persistErr = e
						break
					}
					queued = append(queued, storage.IngestionCandidate{SourceID: item.SourceID, Source: item.Source, Revision: item.Revision, Payload: string(payload)})
				}
				if persistErr == nil && (len(queued) > 0 || !window.Watermark.IsZero()) {
					persistErr = r.db.CommitIngestion(s.Name(), window.Watermark, queued)
				}
				if persistErr != nil {
					failState("durable handoff", persistErr)
					return
				}
			} else {
				items, err = s.Poll(ctx, since)
			}

			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
					return
				}
				if errors.Is(err, ErrPollSkipped) {
					// The source asked us to stay away: not a poll, so no
					// health success or failure. Check again next cycle.
					r.logger.Debug("poll skipped; source is backing off", "source", s.Name())
					return
				}
				// Don't advance lastPoll on failure — retry next cycle
				// but use a short backoff (half the poll interval) to avoid
				// hammering a failing source every loop iteration.
				entry.lastPoll = time.Now().Add(-entry.pollInterval / 2)
				health, logFailure := r.recordError(s.Name(), err)
				if logFailure {
					mu.Lock()
					errs = append(errs, scraperPollError{
						source:            s.Name(),
						err:               err,
						expectedUpstream:  health.LastErrorExpectedUpstream,
						errorClass:        health.LastErrorClass,
						consecutiveErrors: health.ConsecutiveErrors,
					})
					mu.Unlock()
				}
				return
			}

			if durable {
				entry.lastPoll = time.Now()
				r.recordSuccess(s.Name(), len(items))
				updateAdaptivePolling(entry, len(items))
				r.logger.Info("poll complete", "source", s.Name(), "total", len(items), "new", len(items), "stream_watermark", window.Watermark)
				return
			}

			pollNow := time.Now()
			cutoff := pollNow.Add(-r.initialLookback)
			var newItems []RawItem
			for index, item := range items {
				// Clamp future dates to now (scheduled/pre-published posts).
				if !item.PublishedAt.IsZero() && item.PublishedAt.After(pollNow) {
					r.logger.Debug("clamping future date to now", "source_id", item.SourceID, "published_at", item.PublishedAt)
					item.PublishedAt = pollNow
					items[index] = item
				}
				freshness := itemFreshness(item)
				item.Revision = item.ContentRevision()
				if !freshness.IsZero() && freshness.Before(cutoff) {
					// Paid work may outlive the feed lookback. Its durable queue
					// payload must survive until actual processing completes.
					retained, err := r.db.HasIngestionCandidate(item.SourceID, item.Revision)
					if err != nil {
						failState("checking retained ingestion before age filter", err)
						return
					}
					if retained {
						continue
					}
					r.logger.Debug("skipping old item", "source_id", item.SourceID, "published_at", item.PublishedAt, "cutoff", cutoff)
					if err := r.db.MarkSeenRevision(item.SourceID, item.Source, item.Title, item.Revision); err != nil {
						failState("recording old item", err)
						return
					}
					continue
				}
				seen, err := r.db.HasSeenRevision(item.SourceID, item.Revision)
				if err != nil {
					failState("checking seen state", err)
					return
				}
				if !seen {
					newItems = append(newItems, item)
				}
			}

			// Only advance the poll timestamp if every fetched item has been
			// seen (processed) before.  When there are new/unseen items we
			// keep the old timestamp so that a subsequent poll re-fetches them
			// if processing fails downstream. Equally important: a poll that
			// returned zero items at all (network glitch, transient parse
			// failure, source reformat, etc.) must NOT advance the state for
			// a brand-new source — otherwise the initial-lookback window is
			// burned and the source skips its entire backlog forever. Only
			// advance when we actually fetched something AND nothing was new.
			if len(items) > 0 && len(newItems) == 0 {
				boundary := itemFreshness(items[0])
				cursor := items[0].SourceID
				for _, item := range items[1:] {
					if fresh := itemFreshness(item); fresh.After(boundary) {
						boundary = fresh
						cursor = item.SourceID
					}
				}
				if boundary.IsZero() || boundary.After(pollNow) {
					boundary = pollNow
				}
				// Replaying a cached representation cannot move a checkpoint
				// backwards. Repair legacy future state to the current poll.
				if state != nil && !state.LastPoll.After(pollNow) && boundary.Before(state.LastPoll) {
					boundary, cursor = state.LastPoll, state.Cursor
				}
				if err := r.db.SaveScraperState(s.Name(), boundary, cursor); err != nil {
					failState("saving checkpoint", err)
					return
				}
			}
			entry.lastPoll = time.Now()

			r.recordSuccess(s.Name(), len(newItems))
			previousInterval := entry.pollInterval
			updateAdaptivePolling(entry, len(newItems))
			if entry.pollInterval != previousInterval {
				r.logger.Info("adapted source poll interval", "source", s.Name(), "previous", previousInterval, "interval", entry.pollInterval, "new", len(newItems))
			}

			r.logger.Info("poll complete", "source", s.Name(), "total", len(items), "new", len(newItems))

			mu.Lock()
			allItems = append(allItems, newItems...)
			mu.Unlock()

		}(entry, s)
	}

	wg.Wait()
	queued, queueErr := r.db.NextIngestionCandidates(200)
	if queueErr != nil {
		durableErrs = append(durableErrs, fmt.Errorf("loading ingestion queue: %w", queueErr))
	}
	// This cycle's observation is the current state of its source. A queued
	// revision of the same source is either the same input or an older one;
	// processing it too would repeat or overwrite the current candidate. The
	// queue drops it once the current observation is retained.
	observed := make(map[string]bool, len(allItems))
	for _, item := range allItems {
		observed[item.SourceID] = true
	}
	for _, candidate := range queued {
		if observed[candidate.SourceID] {
			continue
		}
		var item RawItem
		if err := json.Unmarshal([]byte(candidate.Payload), &item); err != nil {
			durableErrs = append(durableErrs, fmt.Errorf("decoding queued candidate %s: %w", candidate.SourceID, err))
			continue
		}
		allItems = append(allItems, item)
	}
	if err := ctx.Err(); err != nil {
		return allItems, err
	}
	for i := range r.entries {
		if observer, ok := r.entries[i].scraper.(discoveryAnchorObserver); ok {
			observer.ObserveDiscoveryItems(allItems)
		}
	}

	for _, err := range errs {
		safeErr := boundedScraperError(err)
		args := []any{"error", safeErr}
		var pollErr scraperPollError
		if errors.As(err, &pollErr) {
			args = append(args, "source", pollErr.source, "error_class", pollErr.errorClass, "consecutive_errors", pollErr.consecutiveErrors)
		}
		if isExpectedUpstreamScraperError(err) {
			r.logger.Warn("scraper upstream unavailable", args...)
			continue
		}
		r.logger.Error("scraper error", args...)
	}

	return allItems, errors.Join(durableErrs...)
}

type scraperPollError struct {
	source            string
	err               error
	expectedUpstream  bool
	errorClass        string
	consecutiveErrors int
}

func (e scraperPollError) Error() string {
	return fmt.Sprintf("%s: poll: %v", e.source, e.err)
}

func (e scraperPollError) Unwrap() error {
	return e.err
}

func isExpectedUpstreamScraperError(err error) bool {
	if err == nil {
		return false
	}
	if pollErr, ok := err.(scraperPollError); ok {
		return pollErr.expectedUpstream
	}

	if code, ok := upstreamStatus(err); ok {
		return expectedUpstreamStatuses[code]
	}
	if scraperErrorClass(err) == "tls_certificate" {
		// Verification still fails closed. A source certificate failure is
		// an upstream availability problem; sustained errors remain unhealthy.
		return true
	}
	// Dropped connections and timeouts are upstream hiccups, not bot faults.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "parsing feed ") &&
		strings.Contains(msg, "Failed to detect feed type")
}

func scraperErrorClass(err error) string {
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	if errors.As(err, &invalid) || errors.As(err, &unknown) || errors.As(err, &hostname) {
		return "tls_certificate"
	}
	if code, ok := upstreamStatus(err); ok {
		return fmt.Sprintf("http_%d", code)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "network_eof"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "network_timeout"
	}
	if err != nil && strings.Contains(err.Error(), "parsing feed ") && strings.Contains(err.Error(), "Failed to detect feed type") {
		return "feed_format"
	}
	return "unexpected"
}

// Never log arbitrary upstream response text or credential-bearing request
// URLs. Operation/source context is logged separately from these finite states.
func boundedScraperError(err error) string {
	if err == nil {
		return ""
	}
	if scraperErrorClass(err) == "tls_certificate" {
		return "upstream TLS certificate verification failed"
	}
	if code, ok := upstreamStatus(err); ok {
		return fmt.Sprintf("upstream HTTP %d (details redacted)", code)
	}
	if errors.Is(err, context.Canceled) {
		return "operation canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "operation timed out"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "upstream timeout"
	}
	return "source operation failed (details redacted)"
}
