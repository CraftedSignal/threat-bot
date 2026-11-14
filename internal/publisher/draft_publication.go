package publisher

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

// DraftPublication identifies SQLite state to finish after a brief commits.
type DraftPublication struct {
	DraftID  string `json:"draft_id"`
	ClaimKey string `json:"claim_key,omitempty"`
}

// WithDraftPublished registers an idempotent completion callback. A failure
// retains a durable completion-only receipt; it never republishes old content.
func WithDraftPublished(fn func(DraftPublication) error) PublisherOption {
	return func(p *Publisher) { p.draftPublished = fn }
}

// WithDraftPublishable checks draft state before beginning a Git publication.
// No database lock is held while Git requests run. A rejection during those
// requests cannot atomically undo a Git commit; completion refuses to approve it.
func WithDraftPublishable(fn func(DraftPublication) (bool, error)) PublisherOption {
	return func(p *Publisher) { p.draftPublishable = fn }
}

func (p *Publisher) PublishDraft(briefYAML, draftID, claimKey string) error {
	if strings.TrimSpace(draftID) == "" {
		return fmt.Errorf("draft publication requires a draft ID")
	}
	return p.queueDraftPublication(briefYAML, DraftPublication{DraftID: draftID, ClaimKey: claimKey})
}

// Queued payloads stay valid brief YAML for older parsers. The private comment
// is ignored by publication parsers and is never emitted in public artifacts.
// This persisted wire marker predates the product rename. Keeping it unchanged
// lets the previous deployed version recover receipts during an image rollback.
const draftOutboxPrefix = "# ti-bot-draft-publication-v1 "

type draftOutboxPayload struct {
	BriefYAML string             `json:"-"`
	Drafts    []DraftPublication `json:"drafts"`
	Committed bool               `json:"committed,omitempty"`
}

func encodeDraftOutboxPayload(payload draftOutboxPayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return draftOutboxPrefix + base64.StdEncoding.EncodeToString(raw) + "\n" + payload.BriefYAML, nil
}

func decodeDraftOutboxPayload(raw string) (draftOutboxPayload, error) {
	if !strings.HasPrefix(raw, draftOutboxPrefix) {
		return draftOutboxPayload{BriefYAML: raw}, nil
	}
	line, body, ok := strings.Cut(raw, "\n")
	if !ok {
		return draftOutboxPayload{}, fmt.Errorf("draft outbox payload lacks metadata terminator")
	}
	encoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, draftOutboxPrefix))
	if err != nil {
		return draftOutboxPayload{}, fmt.Errorf("decoding draft outbox metadata: %w", err)
	}
	var payload draftOutboxPayload
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return payload, err
	}
	payload.BriefYAML = body
	if (!payload.Committed && body == "") || len(payload.Drafts) == 0 {
		return payload, fmt.Errorf("draft outbox payload lacks brief or completion metadata")
	}
	for _, draft := range payload.Drafts {
		if strings.TrimSpace(draft.DraftID) == "" {
			return payload, fmt.Errorf("draft outbox payload lacks draft ID")
		}
	}
	return payload, nil
}

func (p *Publisher) queueDraftPublication(briefYAML string, draft DraftPublication) error {
	if err := p.retryDraftCompletions(); err != nil {
		return err
	}
	brief, err := p.prepareBrief(briefYAML)
	if err != nil {
		return err
	}
	payload := p.pendingDrafts[brief.ID]
	payload.BriefYAML = briefYAML
	if draft.DraftID != "" {
		found := false
		for _, existing := range payload.Drafts {
			if existing.DraftID == draft.DraftID {
				found = true
				break
			}
		}
		if !found {
			payload.Drafts = append(payload.Drafts, draft)
		}
	}
	stored := briefYAML
	if len(payload.Drafts) > 0 {
		stored, err = encodeDraftOutboxPayload(payload)
		if err != nil {
			return err
		}
	} else if strings.HasPrefix(stored, draftOutboxPrefix) {
		// A raw caller's comment is not trusted completion metadata.
		stored = "# threat-bot raw brief\n" + stored
	}
	if err := p.persistOutbox(brief.ID, storage.OutboxKindBrief, stored); err != nil {
		return fmt.Errorf("persisting brief publication: %w", err)
	}
	if len(payload.Drafts) > 0 {
		if p.pendingDrafts == nil {
			p.pendingDrafts = make(map[string]draftOutboxPayload)
		}
		p.pendingDrafts[brief.ID] = payload
	}
	p.bufferBrief(*brief)
	p.logger.Info("brief buffered", "id", brief.ID, "title", brief.Title, "pending", len(p.pending))
	return nil
}

func (p *Publisher) checkDraftPublications() error {
	if p.draftPublishable == nil {
		return nil
	}
	var rejected []string
	for _, brief := range p.pending {
		payload, ok := p.pendingDrafts[brief.ID]
		if !ok {
			continue
		}
		reject := false
		for _, draft := range payload.Drafts {
			allowed, err := p.draftPublishable(draft)
			if err != nil {
				return fmt.Errorf("checking queued draft %s: %w", draft.DraftID, err)
			}
			reject = reject || !allowed
		}
		// One latest YAML snapshot may represent several drafts. Without per-draft
		// provenance, evict the entire snapshot if any associated draft is rejected.
		if reject {
			rejected = append(rejected, brief.ID)
		}
	}
	for _, id := range rejected {
		p.logger.Info("evicting rejected queued draft publication", "brief_id", id)
		p.dropRejected(id)
	}
	return nil
}

// finishDraftPublications runs after a known successful Git update. Mark each
// receipt completion-only before callbacks, then let the caller clear pending
// content even if local bookkeeping fails. Git and SQLite cannot share one
// transaction: a crash after Git succeeds but before the receipt is durable can
// still restore the original queued input. Failures are surfaced, not hidden.
func (p *Publisher) finishDraftPublications(flushed map[string]int64) error {
	for _, brief := range p.pending {
		payload, ok := p.pendingDrafts[brief.ID]
		if !ok {
			continue
		}
		payload.Committed, payload.BriefYAML = true, ""
		p.pendingDrafts[brief.ID] = payload
		delete(flushed, brief.ID)
	}
	return p.retryDraftCompletions()
}

func (p *Publisher) retryDraftCompletions() error {
	var failures []error
	for id, payload := range p.pendingDrafts {
		if !payload.Committed {
			continue
		}
		stored, err := encodeDraftOutboxPayload(payload)
		if err == nil {
			err = p.persistOutbox(id, storage.OutboxKindBrief, stored)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("persisting committed draft receipt: %w", err))
			continue
		}
		remaining := make([]DraftPublication, 0, len(payload.Drafts))
		for _, draft := range payload.Drafts {
			var err error
			if p.draftPublished == nil {
				err = fmt.Errorf("draft completion callback is not configured")
			} else {
				err = p.draftPublished(draft)
			}
			if err != nil {
				remaining = append(remaining, draft)
				failures = append(failures, fmt.Errorf("finishing committed draft %s: %w", draft.DraftID, err))
			}
		}
		if len(remaining) == 0 {
			p.dropOutboxRow(id)
			delete(p.pendingDrafts, id)
			continue
		}
		payload.Drafts = remaining
		p.pendingDrafts[id] = payload
		stored, err = encodeDraftOutboxPayload(payload)
		if err == nil {
			err = p.persistOutbox(id, storage.OutboxKindBrief, stored)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("persisting remaining draft completions: %w", err))
		}
	}
	return errors.Join(failures...)
}
