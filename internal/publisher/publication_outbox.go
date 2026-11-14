package publisher

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

// OutboxStore durably records buffered publications so they survive a restart.
// *storage.DB implements it.
type OutboxStore interface {
	UpsertPublishOutbox(id, kind, payload string) (int64, error)
	ListPublishOutbox() ([]storage.OutboxRow, error)
	DeletePublishOutboxIfSeq(id string, seq int64) error
}

// WithOutbox persists every buffered brief and digest in store until a flush
// commits it. Only the long-running service uses it; CLI publishers flush
// synchronously and keep their buffers in memory.
func WithOutbox(store OutboxStore) PublisherOption {
	return func(p *Publisher) {
		p.outbox = store
	}
}

// Retirement is a duplicate public brief queued for removal, with the draft
// IDs needed to finish consolidating the drafts in SQLite after the removal is
// published. Draft IDs are optional.
type Retirement struct {
	BriefID          string
	Slug             string
	CanonicalBriefID string
	CanonicalDraftID string
	DraftID          string
}

// retirementOutboxPayload is the JSON stored for an OutboxKindRetirement row.
type retirementOutboxPayload struct {
	BriefID          string `json:"brief_id"`
	Slug             string `json:"slug"`
	CanonicalID      string `json:"canonical_id,omitempty"`
	CanonicalDraftID string `json:"canonical_draft_id,omitempty"`
	DraftID          string `json:"draft_id,omitempty"`
}

// retirementOutboxID is the outbox key of a retirement. It is namespaced so a
// retirement can never overwrite the row of a brief that shares the retired ID.
func retirementOutboxID(briefID string) string {
	return retirementOutboxPrefix + briefID
}

// WithRetirementApplied registers a callback run after a flush published a
// retirement that was restored from the outbox, i.e. one whose originating
// process crashed before it could consolidate the duplicate drafts. The
// callback must be idempotent. Its failure is logged and does not fail the
// flush, which has already been committed; the retirement's outbox row is kept
// until the callback succeeds, so the next start runs it again.
func WithRetirementApplied(fn func(Retirement) error) PublisherOption {
	return func(p *Publisher) {
		p.retirementApplied = fn
	}
}

// RetireBrief queues a published duplicate for removal from encrypted
// segments, public Markdown, indexes, and regenerated STIX artifacts. The
// caller is responsible for ensuring the surviving canonical brief remains
// published.
func (p *Publisher) RetireBrief(id, slug string) error {
	return p.RetireBriefInFavourOf(id, slug, "")
}

// RetireBriefInFavourOf is RetireBrief for a duplicate whose removal is only
// valid while canonicalID stays published: if the flush rejects the revision
// of canonicalID, this retirement is dropped without being applied.
func (p *Publisher) RetireBriefInFavourOf(id, slug, canonicalID string) error {
	return p.RetireBriefForDrafts(id, slug, canonicalID, "", "")
}

// RetireBriefForDrafts is RetireBriefInFavourOf that also records the draft
// IDs of the duplicate and its canonical brief. The retirement is persisted
// in the outbox so a restart between publishing the canonical brief and
// flushing the retirement cannot leave the duplicate public.
func (p *Publisher) RetireBriefForDrafts(id, slug, canonicalID, draftID, canonicalDraftID string) error {
	id = strings.TrimSpace(id)
	slug = strings.TrimSpace(slug)
	if id == "" || slug == "" {
		return fmt.Errorf("retiring a brief requires both canonical ID and slug")
	}
	canonicalID = strings.TrimSpace(canonicalID)
	payload, err := json.Marshal(retirementOutboxPayload{
		BriefID: id, Slug: slug, CanonicalID: canonicalID,
		CanonicalDraftID: strings.TrimSpace(canonicalDraftID), DraftID: strings.TrimSpace(draftID),
	})
	if err != nil {
		return fmt.Errorf("encoding retirement for publish outbox: %w", err)
	}
	if err := p.persistOutbox(retirementOutboxID(id), storage.OutboxKindRetirement, string(payload)); err != nil {
		return fmt.Errorf("persisting retirement: %w", err)
	}
	if p.pendingRetirements == nil {
		p.pendingRetirements = make(map[string]string)
	}
	p.pendingRetirements[id] = slug
	if canonicalID != "" {
		if p.retiredInFavourOf == nil {
			p.retiredInFavourOf = make(map[string]string)
		}
		p.retiredInFavourOf[id] = canonicalID
	} else {
		delete(p.retiredInFavourOf, id)
	}
	delete(p.restoredRetirements, id)
	return nil
}

// errRestartFlush aborts a release attempt (nothing is committed) so that
// FlushSegmented can rerun it after retirements were dropped.
var errRestartFlush = errors.New("restart segmented flush")

// RetirementRejectedError reports a queued retirement that can never be
// applied (or must not be, because it would delete public content). The flush
// isolates it: the retirement and its outbox row are dropped, everything else
// still publishes.
type RetirementRejectedError struct {
	BriefID     string
	Slug        string
	CanonicalID string
	Err         error
}

// dropRetirement forgets one pending retirement and its outbox row.
func (p *Publisher) dropRetirement(id string) {
	delete(p.pendingRetirements, id)
	delete(p.retiredInFavourOf, id)
	delete(p.restoredRetirements, id)
	p.dropOutboxRow(retirementOutboxID(id))
}

// rejectRetirement logs a rejected retirement once at ERROR and drops it.
func (p *Publisher) rejectRetirement(rejected *RetirementRejectedError) {
	p.logger.Error("retirement rejected and dropped",
		"brief_id", rejected.BriefID, "slug", rejected.Slug, "canonical_id", rejected.CanonicalID, "error", rejected.Error())
	p.dropRetirement(rejected.BriefID)
}

// dropRetirementsFavouring removes pending retirements tied to canonicalID.
func (p *Publisher) dropRetirementsFavouring(canonicalID string) bool {
	dropped := false
	for id, canonical := range p.retiredInFavourOf {
		if canonical == canonicalID {
			p.dropRetirement(id)
			dropped = true
		}
	}
	return dropped
}

// persistOutbox records a buffered item in the outbox. Brief enqueueing must
// succeed here before acknowledging a configured durable publication.
func (p *Publisher) persistOutbox(id, kind, payload string) error {
	if p.outbox == nil {
		return nil
	}
	seq, err := p.outbox.UpsertPublishOutbox(id, kind, payload)
	if err != nil {
		// Keep any earlier seq: the older row is acked by the next successful
		// flush instead of being orphaned and restored over newer content.
		p.logger.Error("persisting publish outbox failed", "id", id, "kind", kind, "error", err)
		return err
	}
	if p.outboxSeq == nil {
		p.outboxSeq = make(map[string]int64)
	}
	p.outboxSeq[id] = seq
	return nil
}

// outboxSnapshot captures the outbox sequence of every buffered item, to be
// handed to clearOutbox once the flush that publishes them succeeds.
func (p *Publisher) outboxSnapshot() map[string]int64 {
	return maps.Clone(p.outboxSeq)
}

// outboxSnapshotExcludingRetirements is outboxSnapshot for the non-segmented
// Flush, which publishes briefs and digests only: retirement rows stay until
// a segmented flush applies them.
func (p *Publisher) outboxSnapshotExcludingRetirements() map[string]int64 {
	snapshot := maps.Clone(p.outboxSeq)
	maps.DeleteFunc(snapshot, func(id string, _ int64) bool {
		return strings.HasPrefix(id, retirementOutboxPrefix)
	})
	return snapshot
}

// dropOutboxRow removes the outbox row currently buffered for id, if any. It
// compares the seq, so a newer snapshot written meanwhile survives.
func (p *Publisher) dropOutboxRow(id string) {
	if seq, ok := p.outboxSeq[id]; ok {
		p.clearOutbox(map[string]int64{id: seq})
	}
}

// clearOutbox removes the rows a successful flush published. A row whose item
// was re-buffered with a newer snapshot meanwhile has a higher seq and stays.
func (p *Publisher) clearOutbox(flushed map[string]int64) {
	if p.outbox == nil {
		return
	}
	for id, seq := range flushed {
		if err := p.outbox.DeletePublishOutboxIfSeq(id, seq); err != nil {
			p.logger.Warn("removing published item from outbox failed", "id", id, "error", err)
			continue
		}
		if p.outboxSeq[id] == seq {
			delete(p.outboxSeq, id)
		}
	}
}

// RestoreOutbox loads rows left by a previous process into the pending buffer
// through the normal buffering path, without writing them back. Rows that no
// longer pass publication validation are logged once and deleted.
func (p *Publisher) RestoreOutbox() (int, error) {
	if p.outbox == nil {
		return 0, nil
	}
	rows, err := p.outbox.ListPublishOutbox()
	if err != nil {
		return 0, fmt.Errorf("listing publish outbox: %w", err)
	}
	restored := 0
	// Restore briefs and digests first so the canonical check below sees every
	// restored canonical regardless of outbox order.
	slices.SortStableFunc(rows, func(a, b storage.OutboxRow) int {
		return cmp.Compare(boolToInt(a.Kind == storage.OutboxKindRetirement), boolToInt(b.Kind == storage.OutboxKindRetirement))
	})
	// Briefs whose rows could not be restored: a retirement made in favour of
	// one of them must not be applied either.
	unrestorable := map[string]bool{}
	for _, row := range rows {
		switch row.Kind {
		case storage.OutboxKindRetirement:
			var payload retirementOutboxPayload
			if err := json.Unmarshal([]byte(row.Payload), &payload); err != nil {
				p.dropUnrestorable(row, err)
				continue
			}
			if strings.TrimSpace(payload.BriefID) == "" || strings.TrimSpace(payload.Slug) == "" {
				p.dropUnrestorable(row, fmt.Errorf("retirement row lacks brief ID or slug"))
				continue
			}
			if unrestorable[payload.CanonicalID] {
				p.dropUnrestorable(row, fmt.Errorf("canonical brief %q was not restored", payload.CanonicalID))
				continue
			}
			p.restoreRetirement(Retirement{
				BriefID: payload.BriefID, Slug: payload.Slug, CanonicalBriefID: payload.CanonicalID,
				CanonicalDraftID: payload.CanonicalDraftID, DraftID: payload.DraftID,
			})
		case storage.OutboxKindDigest:
			var digest BundleDigest
			if err := json.Unmarshal([]byte(row.Payload), &digest); err != nil {
				unrestorable[row.ID] = true
				p.dropUnrestorable(row, err)
				continue
			}
			p.bufferDigest(digest)
		default:
			payload, err := decodeDraftOutboxPayload(row.Payload)
			if err != nil {
				unrestorable[row.ID] = true
				p.dropUnrestorable(row, err)
				continue
			}
			if payload.Committed {
				if p.pendingDrafts == nil {
					p.pendingDrafts = make(map[string]draftOutboxPayload)
				}
				p.pendingDrafts[row.ID] = payload
				break
			}
			brief, err := p.prepareBrief(payload.BriefYAML)
			if err != nil {
				unrestorable[row.ID] = true
				p.dropUnrestorable(row, err)
				continue
			}
			p.bufferBrief(*brief)
			if len(payload.Drafts) > 0 {
				if p.pendingDrafts == nil {
					p.pendingDrafts = make(map[string]draftOutboxPayload)
				}
				p.pendingDrafts[brief.ID] = payload
			}
		}
		if p.outboxSeq == nil {
			p.outboxSeq = make(map[string]int64)
		}
		p.outboxSeq[row.ID] = row.Seq
		restored++
	}
	p.logger.Info("restored pending briefs outbox", "count", restored)
	return restored, nil
}

// restoreRetirement re-queues a retirement read back from the outbox without
// writing it again.
func (p *Publisher) restoreRetirement(r Retirement) {
	if p.pendingRetirements == nil {
		p.pendingRetirements = make(map[string]string)
	}
	p.pendingRetirements[r.BriefID] = r.Slug
	if r.CanonicalBriefID != "" {
		if p.retiredInFavourOf == nil {
			p.retiredInFavourOf = make(map[string]string)
		}
		p.retiredInFavourOf[r.BriefID] = r.CanonicalBriefID
	}
	if p.restoredRetirements == nil {
		p.restoredRetirements = make(map[string]Retirement)
	}
	p.restoredRetirements[r.BriefID] = r
}

// dropUnrestorable logs a row that can never be published and deletes it, so it
// does not fail again on every restart. The draft stays approved in SQLite and
// can be republished later with `drafts republish`.
func (p *Publisher) dropUnrestorable(row storage.OutboxRow, cause error) {
	p.logger.Error("dropping unrestorable outbox row", "brief_id", row.ID, "error", cause)
	if err := p.outbox.DeletePublishOutboxIfSeq(row.ID, row.Seq); err != nil {
		p.logger.Warn("removing unrestorable outbox row failed", "brief_id", row.ID, "error", err)
	}
}

// bufferDigest keeps only the newest buffered digest for each digest ID.
func (p *Publisher) bufferDigest(digest BundleDigest) {
	for i := range p.pendingDigests {
		if p.pendingDigests[i].ID == digest.ID {
			p.pendingDigests[i] = digest
			return
		}
	}
	p.pendingDigests = append(p.pendingDigests, digest)
}
