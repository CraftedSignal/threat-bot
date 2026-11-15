package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// newServicePublisher builds the long-running service's publisher. It alone
// keeps a durable outbox and restores briefs a previous process buffered but
// never flushed; CLI publishers flush synchronously and stay in memory.
func newServicePublisher(cfg *config.Config, ghTokenFn func() string, logger *slog.Logger, llmClient llm.Client, db *storage.DB) *publisher.Publisher {
	pub := publisher.New(cfg.Publish.RepoSlug, cfg.Publish.FeedPublicKey, ghTokenFn, logger, publicationSettings(cfg),
		publisher.WithLLMClient(llmClient), publisher.WithOutbox(db),
		publisher.WithBlobCache(cfg.Publish.CacheDir),
		publisher.WithDraftPublishable(func(draft publisher.DraftPublication) (bool, error) {
			return draftMayPublish(db, draft)
		}),
		publisher.WithDraftPublished(func(draft publisher.DraftPublication) error {
			return finishCommittedDraft(db, draft)
		}),
		publisher.WithRetirementApplied(func(r publisher.Retirement) error {
			return finishRestoredRetirement(db, r)
		}))
	return pub
}

type draftPublicationStore interface {
	GetDraft(string) (*storage.Draft, error)
	UpdateDraftStatus(string, string, string) error
	MarkRumourCandidatePublished(string) error
}

func draftMayPublish(db draftPublicationStore, draft publisher.DraftPublication) (bool, error) {
	// This pre-flush snapshot never holds a database lock across Git work.
	// Rejection during an active Git transaction remains a cross-system
	// window; post-commit completion still refuses to approve rejected state.
	stored, err := db.GetDraft(draft.DraftID)
	if err != nil {
		return false, fmt.Errorf("checking queued draft: %w", err)
	}
	switch stored.Status {
	case storage.StatusPending, storage.StatusApproved:
		return true, nil
	case storage.StatusRejected:
		return false, nil
	default:
		return false, fmt.Errorf("queued draft %q has unexpected status %q", draft.DraftID, stored.Status)
	}
}

func processPolledItems(ctx context.Context, items []scraper.RawItem, process func(context.Context, []scraper.RawItem) error, flush func() error) error {
	// Idle cycles also recover durable publication intents.
	if err := process(ctx, items); err != nil {
		return err
	}
	if len(items) > 0 {
		return nil
	}
	if flush != nil {
		if err := flush(); err != nil {
			return fmt.Errorf("flushing retained publication on idle poll: %w", err)
		}
	}
	return nil
}

func finishCommittedDraft(db draftPublicationStore, draft publisher.DraftPublication) error {
	stored, err := db.GetDraft(draft.DraftID)
	if err != nil {
		return fmt.Errorf("loading committed draft: %w", err)
	}
	switch stored.Status {
	case storage.StatusPending:
		if err := db.UpdateDraftStatus(draft.DraftID, storage.StatusApproved, ""); err != nil {
			return fmt.Errorf("approving committed draft: %w", err)
		}
	case storage.StatusApproved:
		// A crash or a later claim-state failure can replay this callback.
		// Preserve the original review timestamp while finishing the claim.
	default:
		return fmt.Errorf("committed draft %q has unexpected status %q", draft.DraftID, stored.Status)
	}
	if draft.ClaimKey != "" {
		if err := db.MarkRumourCandidatePublished(draft.ClaimKey); err != nil {
			return fmt.Errorf("completing committed rumour candidate: %w", err)
		}
	}
	return nil
}

// draftConsolidator is the part of storage that finishes a retirement.
type draftConsolidator interface {
	GetDraft(id string) (*storage.Draft, error)
	ConsolidateApprovedDrafts(canonicalID string, duplicateIDs []string, reason string) error
}

// finishRestoredRetirement rejects the duplicate draft of a retirement that a
// restart carried over, after the flush has removed the public duplicate. It
// is idempotent: a duplicate that is no longer approved was already
// consolidated.
func finishRestoredRetirement(db draftConsolidator, r publisher.Retirement) error {
	if r.DraftID == "" || r.CanonicalDraftID == "" {
		return nil
	}
	duplicate, err := db.GetDraft(r.DraftID)
	if err != nil {
		return err
	}
	if duplicate.Status != storage.StatusApproved {
		return nil
	}
	return db.ConsolidateApprovedDrafts(r.CanonicalDraftID, []string{r.DraftID},
		fmt.Sprintf("consolidated into %s after restart", r.CanonicalBriefID))
}

// outboxRestorer is the part of the publisher flushRestored drives.
type outboxRestorer interface {
	RestoreOutbox() (int, error)
	Flush() error
}

// flushRestored restores the outbox and, if anything came back, flushes once
// before the main loop so restored work does not wait for new approvals. Any
// failure is logged; the normal loop retries the flush.
func flushRestored(pub outboxRestorer, logger *slog.Logger) {
	n, err := pub.RestoreOutbox()
	if err != nil {
		logger.Error("restoring publish outbox failed", "error", err)
		return
	}
	if n == 0 {
		return
	}
	if err := pub.Flush(); err != nil {
		logger.Error("flushing restored publish outbox failed; the main loop will retry", "count", n, "error", err)
	}
}
