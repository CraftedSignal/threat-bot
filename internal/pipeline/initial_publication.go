package pipeline

import (
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

func annotateRoundupYAML(raw string, extraction *ExtractionResult) (string, error) {
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(raw), &fm); err != nil {
		return "", err
	}
	if extraction != nil {
		annotateCVEProducts(fm, extraction.CVEs, firstNonPlaceholder(extraction.AffectedProducts))
	}
	out, err := yaml.Marshal(fm)
	return string(out), err
}

// Template routes must save the exact releasable snapshot and its recovery
// intent together, before attempting the external publisher queue.
func (p *Pipeline) createTemplateDraft(draft *storage.Draft) (bool, error) {
	if !p.autoPublish || p.publisher == nil {
		return false, p.createDraft(draft)
	}
	if err := p.validatePublication(draft.BriefYAML); err != nil {
		p.logger.Warn("template brief held for editorial review", "draft_id", draft.ID, "error", err)
		return false, p.createDraft(draft)
	}
	if err := p.db.CreateDraftWithPublication(draft, ""); err != nil {
		return false, err
	}
	p.decisions.record(outcomeDraft)
	return true, nil
}
