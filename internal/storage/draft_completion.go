package storage

import (
	"database/sql"
	"fmt"
)

// DraftProcessingResult is the durable outcome of one validated candidate.
// Content associations and any publication intent must survive with the draft
// before terminal seen state can prevent the candidate from being resumed.
type DraftProcessingResult struct {
	Draft                                        *Draft
	SourceID, SourceTitle, Revision, EvidenceKey string
	ExpectedInputKey                             string
	ContentIndex                                 []ContentIndexEntry
	Publish                                      bool
	ClaimKey                                     string
}

// CompleteDraftProcessing commits the saved result and terminal processing
// state together, so a checkpoint rollback cannot recreate a saved draft.
// The expected input key proves ownership of the checkpoint being completed;
// interpreting policy and evidence compatibility remains the caller's job.
func (d *DB) CompleteDraftProcessing(result DraftProcessingResult) error {
	if result.Draft == nil || result.Draft.ID == "" || result.SourceID == "" || result.ExpectedInputKey == "" || len(result.ContentIndex) == 0 {
		return fmt.Errorf("draft completion requires a draft, source, expected checkpoint and content associations")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var inputKey string
	if err := tx.QueryRow("SELECT input_key FROM processing_checkpoints WHERE source_id=?", result.SourceID).Scan(&inputKey); err != nil {
		return fmt.Errorf("reading draft completion checkpoint: %w", err)
	}
	if inputKey != result.ExpectedInputKey {
		return fmt.Errorf("draft completion checkpoint does not match expected input")
	}
	if err := insertDraft(tx, result.Draft); err != nil {
		return err
	}
	for _, entry := range result.ContentIndex {
		if entry.DraftID != result.Draft.ID || entry.SourceID != result.SourceID || entry.Source != result.Draft.Source {
			return fmt.Errorf("draft completion content association does not match source and draft")
		}
		if err := insertContentIndex(tx, &entry); err != nil {
			return err
		}
	}
	if result.Publish {
		if err := insertPublicationIntent(tx, result.Draft.ID, result.Draft.BriefYAML, result.ClaimKey, true); err != nil {
			return err
		}
	}
	if err := completeSeenRevision(tx, result.SourceID, result.Draft.Source, result.SourceTitle, result.Revision, result.EvidenceKey); err != nil {
		return err
	}
	return tx.Commit()
}

type sqlExecutor interface {
	Exec(string, ...any) (sql.Result, error)
}

func insertDraft(executor sqlExecutor, draft *Draft) error {
	_, err := executor.Exec(`INSERT INTO drafts(id,status,score,source,source_ids,brief_yaml,validation_notes,created_at) VALUES(?,?,?,?,?,?,?,?)`, draft.ID, draft.Status, draft.Score, draft.Source, draft.SourceIDs, draft.BriefYAML, draft.ValidationNotes, draft.CreatedAt)
	return err
}

func insertContentIndex(executor sqlExecutor, entry *ContentIndexEntry) error {
	_, err := executor.Exec(`INSERT INTO content_index(cve_id,title_hash,fingerprint_hash,product_fingerprint_hash,title_norm,content_hash,vendor_cycle_key,source_url_hash,source_published_day,claim_key,draft_id,source_id,source,cve_context,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, entry.CVEID, entry.TitleHash, entry.FingerprintHash, entry.ProductFingerprintHash, entry.TitleNorm, entry.ContentHash, entry.VendorCycleKey, entry.SourceURLHash, entry.SourcePublishedDay, entry.ClaimKey, entry.DraftID, entry.SourceID, entry.Source, entry.CVEContext, entry.CreatedAt)
	return err
}
