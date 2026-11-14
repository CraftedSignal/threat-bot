package pipeline

import (
	"errors"
	"fmt"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// The DB commits this intent alongside the draft. Publisher enqueue persists its
// own outbox before acknowledgement; a crash between them only replays the same
// canonical snapshot, never loses an update or creates a second brief.
func (p *Pipeline) enqueuePublicationIntent(intent storage.PublicationIntent) error {
	var err error
	if intent.CompleteDraft {
		err = p.queueDraftPublication(intent.BriefYAML, intent.DraftID, intent.ClaimKey)
	} else {
		err = p.publisher.Publish(intent.BriefYAML)
	}
	if err != nil {
		return err
	}
	return p.db.DeletePublicationIntent(intent.DraftID, intent.BriefYAML)
}
func (p *Pipeline) recoverPublicationIntents() error {
	if !p.autoPublish || p.publisher == nil {
		return nil
	}
	intents, err := p.db.ListPublicationIntents()
	if err != nil {
		return err
	}
	var recoveryErrors []error
	for _, intent := range intents {
		draft, err := p.db.GetDraft(intent.DraftID)
		if err != nil {
			return err
		}
		if draft == nil || draft.Status == storage.StatusRejected || draft.BriefYAML != intent.BriefYAML {
			p.logger.Warn("discarding superseded publication intent", "draft_id", intent.DraftID)
			if err := p.db.DeletePublicationIntent(intent.DraftID, intent.BriefYAML); err != nil {
				return err
			}
			continue
		}
		if validator, ok := p.publisher.(interface{ ValidatePublication(string) error }); ok {
			if gateErr := validator.ValidatePublication(intent.BriefYAML); gateErr != nil {
				if err := p.db.HoldPublicationIntent(intent.DraftID, intent.BriefYAML, gateErr.Error()); err != nil {
					recoveryErrors = append(recoveryErrors, err)
				}
				p.logger.Warn("retained publication requires editorial review", "draft_id", intent.DraftID, "error", gateErr)
				continue
			}
		}
		if err := p.enqueuePublicationIntent(intent); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("recovering publication for %s: %w", intent.DraftID, err))
		}
	}
	return errors.Join(recoveryErrors...)
}
