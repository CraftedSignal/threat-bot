package storage

import "time"

// MergeReviewHold identifies the durable evidence and one completed review.
// AttemptID retains the assessment identity across restarts. InputKey records
// delivery attribution; its timestamp may change without a new assessment.
type MergeReviewHold struct {
	SourceID, Source, Title string
	RawOutput, Reason       string
	InputKey, AttemptID     string
}

// EnsureMergeReviewHold repairs review visibility without duplicate history.
// Quarantine and history commit together; the caller retains its checkpoint
// until this succeeds and can retry without repeating a model assessment.
func (d *DB) EnsureMergeReviewHold(hold MergeReviewHold) (bool, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	result, err := tx.Exec(`INSERT INTO processing_history(source_id,input_key,attempt_id,stage,outcome,created_at)
		SELECT ?,?,?,'merge_editorial','held',? WHERE NOT EXISTS (
			SELECT 1 FROM processing_history WHERE source_id=? AND attempt_id=? AND stage='merge_editorial' AND outcome='held'
		)`, hold.SourceID, hold.InputKey, hold.AttemptID, now.Format(time.RFC3339Nano), hold.SourceID, hold.AttemptID)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	// A distinct assessment replaces the operator-visible evidence. A repeated
	// assessment only repairs a missing row, so it cannot overwrite a later hold.
	if _, err := tx.Exec(`INSERT INTO pipeline_quarantine
		(source_id,source,title,raw_output,error_message,created_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(source_id) DO UPDATE SET
			source=excluded.source,title=excluded.title,raw_output=excluded.raw_output,
			error_message=excluded.error_message,created_at=excluded.created_at
		WHERE ?`, hold.SourceID, hold.Source, hold.Title, hold.RawOutput, hold.Reason, now, n != 0); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n != 0, nil
}
