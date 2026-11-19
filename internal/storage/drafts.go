package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Draft struct {
	ID              string
	Status          string
	Score           float64
	Source          string
	SourceIDs       string // JSON array
	BriefYAML       string
	RejectReason    string
	ValidationNotes string // JSON array of validation messages
	CreatedAt       time.Time
	ReviewedAt      *time.Time
	Lastmod         *time.Time
	UpdateCount     int
	UpdateLog       string // JSON array of UpdateEvent
	LastL3Dispatch  *time.Time
}

// UpdateEvent records a single merge that enriched a draft. Stored as
// a capped JSON array on Draft.UpdateLog. Rendered by the publisher
// into the brief frontmatter under `updates:` for the "What's new"
// section on detail pages.
type UpdateEvent struct {
	At         time.Time `json:"at"`
	Level      string    `json:"level"`   // "L1" | "L2" | "L3"
	Summary    string    `json:"summary"` // "added CVE-2026-1234, KEV"
	Sources    []string  `json:"sources"` // ["nvd", "bleepingcomputer"]
	SourceURLs []string  `json:"source_urls,omitempty"`
}

// CreateDraft inserts a new draft brief.
func (d *DB) CreateDraft(draft *Draft) error {
	return insertDraft(d.db, draft)
}

// scanDraft scans a draft row handling nullable columns.
func scanDraft(scanner interface{ Scan(...any) error }) (*Draft, error) {
	var draft Draft
	var sourceIDs, rejectReason, validationNotes, updateLog sql.NullString
	var reviewedAt, lastmod, lastL3 sql.NullTime
	var updateCount sql.NullInt64

	err := scanner.Scan(
		&draft.ID, &draft.Status, &draft.Score, &draft.Source,
		&sourceIDs, &draft.BriefYAML, &rejectReason, &validationNotes,
		&draft.CreatedAt, &reviewedAt, &lastmod, &updateCount, &updateLog, &lastL3,
	)
	if err != nil {
		return nil, err
	}

	draft.SourceIDs = sourceIDs.String
	draft.RejectReason = rejectReason.String
	draft.ValidationNotes = validationNotes.String
	if reviewedAt.Valid {
		draft.ReviewedAt = &reviewedAt.Time
	}
	if lastmod.Valid {
		draft.Lastmod = &lastmod.Time
	}
	draft.UpdateCount = int(updateCount.Int64)
	draft.UpdateLog = updateLog.String
	if lastL3.Valid {
		draft.LastL3Dispatch = &lastL3.Time
	}
	return &draft, nil
}

// GetDraft retrieves a draft by ID.
func (d *DB) GetDraft(id string) (*Draft, error) {
	row := d.db.QueryRow(
		"SELECT id, status, score, source, source_ids, brief_yaml, reject_reason, validation_notes, created_at, reviewed_at, lastmod, update_count, update_log, last_l3_dispatch FROM drafts WHERE id = ?", id,
	)
	draft, err := scanDraft(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("draft %q not found", id)
	}
	if err != nil {
		return nil, err
	}
	return draft, nil
}

// DraftsWithStatus yields drafts with the given status, newest first, one row
// at a time.
func (d *DB) DraftsWithStatus(status string) iter.Seq2[*Draft, error] {
	return d.draftRows(
		"SELECT id, status, score, source, source_ids, brief_yaml, reject_reason, validation_notes, created_at, reviewed_at, lastmod, update_count, update_log, last_l3_dispatch FROM drafts WHERE status = ? ORDER BY created_at DESC", status,
	)
}

// ApprovedDraftsSince yields approved drafts created at or after since,
// newest first, one row at a time.
func (d *DB) ApprovedDraftsSince(since time.Time) iter.Seq2[*Draft, error] {
	return d.draftRows(
		`SELECT id, status, score, source, source_ids, brief_yaml, reject_reason, validation_notes, created_at, reviewed_at, lastmod, update_count, update_log, last_l3_dispatch
		 FROM drafts WHERE status = ? AND created_at >= ? ORDER BY created_at DESC`,
		StatusApproved, since,
	)
}

// ActiveDraftsSince yields pending and approved drafts created at or after
// since. Callers use it for bounded public-identity collision checks; rejected
// drafts never reached the feed and do not reserve an identity.
func (d *DB) ActiveDraftsSince(since time.Time) iter.Seq2[*Draft, error] {
	return d.draftRows(
		`SELECT id, status, score, source, source_ids, brief_yaml, reject_reason, validation_notes, created_at, reviewed_at, lastmod, update_count, update_log, last_l3_dispatch
		 FROM drafts WHERE status IN (?, ?) AND created_at >= ? ORDER BY created_at DESC`,
		StatusPending, StatusApproved, since,
	)
}

// DraftCorrelation is an approved draft's stored correlation summary. Summary
// is empty when the draft's YAML changed since the summary was saved.
type DraftCorrelation struct {
	ID      string
	Summary string
}

// ApprovedDraftCorrelationsSince yields the correlation summaries of approved
// drafts created at or after since, newest first, without reading their YAML.
func (d *DB) ApprovedDraftCorrelationsSince(since time.Time) iter.Seq2[DraftCorrelation, error] {
	return func(yield func(DraftCorrelation, error) bool) {
		rows, err := d.db.Query(
			`SELECT id, COALESCE(correlation, '') FROM drafts
			 WHERE status = ? AND created_at >= ? ORDER BY created_at DESC`,
			StatusApproved, since,
		)
		if err != nil {
			yield(DraftCorrelation{}, err)
			return
		}
		defer discardClose(rows)
		for rows.Next() {
			var c DraftCorrelation
			if err := rows.Scan(&c.ID, &c.Summary); err != nil {
				yield(DraftCorrelation{}, err)
				return
			}
			if !yield(c, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(DraftCorrelation{}, err)
		}
	}
}

// SaveDraftCorrelation stores the correlation summary computed from
// briefYAML. It is a no-op when the draft's YAML has changed since.
func (d *DB) SaveDraftCorrelation(id, briefYAML, summary string) error {
	_, err := d.db.Exec("UPDATE drafts SET correlation = ? WHERE id = ? AND brief_yaml = ?", summary, id, briefYAML)
	return err
}

// draftRows streams the drafts a query selects so callers never hold a whole
// result set. Stopping the range early closes the rows.
func (d *DB) draftRows(query string, args ...any) iter.Seq2[*Draft, error] {
	return func(yield func(*Draft, error) bool) {
		rows, err := d.db.Query(query, args...)
		if err != nil {
			yield(nil, err)
			return
		}
		defer discardClose(rows)
		for rows.Next() {
			draft, err := scanDraft(rows)
			if err != nil {
				yield(nil, err)
				return
			}
			if !yield(draft, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(nil, err)
		}
	}
}

// UpdateDraftStatus changes the status of a draft and records the review time.
func (d *DB) UpdateDraftStatus(id, status, reason string) error {
	now := time.Now()
	result, err := d.db.Exec(
		"UPDATE drafts SET status = ?, reject_reason = ?, reviewed_at = ? WHERE id = ?",
		status, reason, now, id,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("draft %q not found", id)
	}
	return nil
}

// ConsolidateApprovedDrafts makes canonicalID the sole active draft for an
// incident. It preserves all source provenance and repoints dedup index rows
// before rejecting the superseded drafts in one transaction.
func (d *DB) ConsolidateApprovedDrafts(canonicalID string, duplicateIDs []string, reason string) error {
	canonicalID = strings.TrimSpace(canonicalID)
	if canonicalID == "" || len(duplicateIDs) == 0 {
		return fmt.Errorf("consolidating drafts requires a canonical draft and duplicates")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var canonicalStatus string
	var canonicalSources sql.NullString
	if err := tx.QueryRow("SELECT status, source_ids FROM drafts WHERE id = ?", canonicalID).Scan(&canonicalStatus, &canonicalSources); err != nil {
		return err
	}
	if canonicalStatus != StatusApproved {
		return fmt.Errorf("canonical draft %q is %s, want approved", canonicalID, canonicalStatus)
	}
	var sourceIDs []string
	if canonicalSources.Valid && strings.TrimSpace(canonicalSources.String) != "" {
		if err := json.Unmarshal([]byte(canonicalSources.String), &sourceIDs); err != nil {
			return fmt.Errorf("decoding canonical source IDs: %w", err)
		}
	}
	seenSources := make(map[string]bool, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		seenSources[sourceID] = true
	}
	seenDrafts := map[string]bool{canonicalID: true}
	now := time.Now().UTC()
	for _, duplicateID := range duplicateIDs {
		duplicateID = strings.TrimSpace(duplicateID)
		if duplicateID == "" || seenDrafts[duplicateID] {
			return fmt.Errorf("duplicate draft IDs must be non-empty and unique")
		}
		seenDrafts[duplicateID] = true
		var status string
		var sources sql.NullString
		if err := tx.QueryRow("SELECT status, source_ids FROM drafts WHERE id = ?", duplicateID).Scan(&status, &sources); err != nil {
			return err
		}
		if status != StatusApproved {
			return fmt.Errorf("duplicate draft %q is %s, want approved", duplicateID, status)
		}
		if sources.Valid && strings.TrimSpace(sources.String) != "" {
			var decoded []string
			if err := json.Unmarshal([]byte(sources.String), &decoded); err != nil {
				return fmt.Errorf("decoding duplicate source IDs for %q: %w", duplicateID, err)
			}
			for _, sourceID := range decoded {
				if sourceID = strings.TrimSpace(sourceID); sourceID != "" && !seenSources[sourceID] {
					seenSources[sourceID] = true
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
		if _, err := tx.Exec("UPDATE content_index SET draft_id = ? WHERE draft_id = ?", canonicalID, duplicateID); err != nil {
			return err
		}
		result, err := tx.Exec(
			"UPDATE drafts SET status = ?, reject_reason = ?, reviewed_at = ? WHERE id = ? AND status = ?",
			StatusRejected, reason, now, duplicateID, StatusApproved,
		)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			if err != nil {
				return err
			}
			return fmt.Errorf("duplicate draft %q changed during consolidation", duplicateID)
		}
	}
	encodedSources, err := json.Marshal(sourceIDs)
	if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE drafts SET source_ids = ? WHERE id = ?", string(encodedSources), canonicalID); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateDraftYAML replaces the brief_yaml for a draft.
func (d *DB) UpdateDraftYAML(id, briefYAML string) error {
	_, err := d.db.Exec("UPDATE drafts SET brief_yaml = ?, correlation = NULL WHERE id = ?", briefYAML, id)
	return err
}

// EditorialCorrection is an operator-reviewed replacement for one approved
// draft. The caller derives revised metadata from the exact YAML it publishes.
type EditorialCorrection struct {
	DraftID            string
	BriefID            string
	PreviousYAML       string
	RevisedYAML        string
	RevisedLastmod     *time.Time
	RevisedUpdateLog   string
	RevisedUpdateCount int
	Operator           string
	Reason             string
	BackupPath         string
}

// ApplyEditorialCorrection atomically updates YAML and matching update
// metadata, and appends an audit record preserving the exact previous YAML and
// SQL update log. A stale YAML/status comparison leaves both tables unchanged.
func (d *DB) ApplyEditorialCorrection(c EditorialCorrection) error {
	if c.DraftID == "" || c.BriefID == "" || strings.TrimSpace(c.Operator) == "" || strings.TrimSpace(c.Reason) == "" || c.BackupPath == "" {
		return fmt.Errorf("editorial correction requires draft ID, brief ID, operator, reason, and backup path")
	}
	var events []UpdateEvent
	if c.RevisedUpdateLog != "" {
		if err := json.Unmarshal([]byte(c.RevisedUpdateLog), &events); err != nil {
			return fmt.Errorf("decoding revised update log: %w", err)
		}
	}
	if c.RevisedUpdateCount != len(events) {
		return fmt.Errorf("revised update count %d does not match %d update log entries", c.RevisedUpdateCount, len(events))
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var oldYAML, status string
	var oldLastmod sql.NullTime
	var oldCount sql.NullInt64
	var oldLog sql.NullString
	if err := tx.QueryRow(`SELECT brief_yaml, status, lastmod, update_count, update_log FROM drafts WHERE id = ?`, c.DraftID).Scan(&oldYAML, &status, &oldLastmod, &oldCount, &oldLog); err != nil {
		return fmt.Errorf("reading draft before editorial correction: %w", err)
	}
	if status != StatusApproved || oldYAML != c.PreviousYAML {
		return fmt.Errorf("approved draft %q changed since preview; stored YAML was not replaced", c.DraftID)
	}
	result, err := tx.Exec(
		`UPDATE drafts SET brief_yaml = ?, correlation = NULL, lastmod = ?, update_count = ?, update_log = NULLIF(?, '')
		 WHERE id = ? AND status = ? AND brief_yaml = ?`,
		c.RevisedYAML, c.RevisedLastmod, c.RevisedUpdateCount, c.RevisedUpdateLog,
		c.DraftID, StatusApproved, c.PreviousYAML,
	)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("approved draft %q changed since preview; stored YAML was not replaced", c.DraftID)
	}
	_, err = tx.Exec(
		`INSERT INTO draft_editorial_corrections
		 (draft_id, brief_id, operator, reason, previous_yaml, revised_yaml,
		  previous_lastmod, revised_lastmod, previous_update_count, revised_update_count,
		  previous_update_log, revised_update_log, backup_path, corrected_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)`,
		c.DraftID, c.BriefID, strings.TrimSpace(c.Operator), strings.TrimSpace(c.Reason), oldYAML, c.RevisedYAML,
		oldLastmod, c.RevisedLastmod, oldCount.Int64, c.RevisedUpdateCount,
		oldLog, c.RevisedUpdateLog, c.BackupPath, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("recording editorial correction audit: %w", err)
	}
	return tx.Commit()
}

func (d *DB) RecordDraftUpdate(id, briefYAML string, event UpdateEvent) error {
	return d.RecordDraftUpdateWithSource(id, briefYAML, event, "")
}

// RecordDraftUpdateWithSource performs the same atomic update as
// RecordDraftUpdate and also appends sourceID to the draft's provenance. The
// source is committed in the same transaction as the merged YAML so a retry
// can never observe the intelligence without knowing which item supplied it.
func (d *DB) RecordDraftUpdateWithSource(id, briefYAML string, event UpdateEvent, sourceID string) error {
	return d.RecordDraftUpdateWithPublication(id, briefYAML, event, sourceID, false)
}

// RecordDraftUpdateWithPublication commits update and publication recovery together.
func (d *DB) RecordDraftUpdateWithPublication(id, briefYAML string, event UpdateEvent, sourceID string, publish bool) error {
	return d.recordDraftUpdate(id, nil, briefYAML, event, sourceID, publish)
}

// ErrDraftChanged reports a conditional update whose draft no longer holds the
// expected brief YAML; nothing was written.
var ErrDraftChanged = errors.New("draft changed since it was read")

// RecordDraftUpdateIfUnchanged is RecordDraftUpdateWithPublication for a
// writer outside the processing loop: it applies only while the draft still
// holds expectedYAML and returns ErrDraftChanged otherwise, so an operator
// edit or concurrent merge is never overwritten.
func (d *DB) RecordDraftUpdateIfUnchanged(id, expectedYAML, briefYAML string, event UpdateEvent, sourceID string, publish bool) error {
	return d.recordDraftUpdate(id, &expectedYAML, briefYAML, event, sourceID, publish)
}

func (d *DB) recordDraftUpdate(id string, expectedYAML *string, briefYAML string, event UpdateEvent, sourceID string, publish bool) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var existingLog sql.NullString
	var existingSourceIDs sql.NullString
	if err := tx.QueryRow("SELECT update_log, source_ids FROM drafts WHERE id = ?", id).Scan(&existingLog, &existingSourceIDs); err != nil {
		return err
	}
	var events []UpdateEvent
	if existingLog.Valid && existingLog.String != "" {
		_ = json.Unmarshal([]byte(existingLog.String), &events)
	}
	events = append(events, event)
	if len(events) > maxUpdateLogEntries {
		events = events[len(events)-maxUpdateLogEntries:]
	}
	logJSON, err := json.Marshal(events)
	if err != nil {
		return err
	}
	sourceIDsJSON, err := appendSourceIDJSON(existingSourceIDs, sourceID)
	if err != nil {
		return fmt.Errorf("updating source IDs for draft %q: %w", id, err)
	}

	query := `UPDATE drafts
		 SET brief_yaml = ?, correlation = NULL, lastmod = ?, update_count = COALESCE(update_count, 0) + 1, update_log = ?, source_ids = ?
		 WHERE id = ?`
	args := []any{briefYAML, event.At, string(logJSON), sourceIDsJSON, id}
	if expectedYAML != nil {
		query += " AND brief_yaml = ?"
		args = append(args, *expectedYAML)
	}
	result, err := tx.Exec(query, args...)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		if expectedYAML != nil {
			return fmt.Errorf("draft %q: %w", id, ErrDraftChanged)
		}
		return fmt.Errorf("draft %q not found", id)
	}
	if publish {
		if err := insertPublicationIntent(tx, id, briefYAML, "", false); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func appendSourceIDJSON(existing sql.NullString, sourceID string) (string, error) {
	var sourceIDs []string
	if existing.Valid && strings.TrimSpace(existing.String) != "" {
		if err := json.Unmarshal([]byte(existing.String), &sourceIDs); err != nil {
			return "", err
		}
	}
	if sourceID = strings.TrimSpace(sourceID); sourceID != "" {
		for _, current := range sourceIDs {
			if current == sourceID {
				encoded, err := json.Marshal(sourceIDs)
				return string(encoded), err
			}
		}
		sourceIDs = append(sourceIDs, sourceID)
	}
	encoded, err := json.Marshal(sourceIDs)
	return string(encoded), err
}

// RecordL3Dispatch stamps when a draft's L3 update was dispatched to
// subscribers. The pipeline reads this to enforce the per-brief
// cooldown that prevents repeated KEV-flag flips from spamming.
func (d *DB) RecordL3Dispatch(id string, at time.Time) error {
	_, err := d.db.Exec("UPDATE drafts SET last_l3_dispatch = ? WHERE id = ?", at, id)
	return err
}

// BoostDraftScore increases a draft's score by boost, capping at maxScore.
func (d *DB) BoostDraftScore(draftID string, boost float64, maxScore float64) error {
	_, err := d.db.Exec(
		"UPDATE drafts SET score = MIN(score + ?, ?) WHERE id = ?",
		boost, maxScore, draftID,
	)
	return err
}

// AppendDraftReference appends a one-line note to a draft's
// validation_notes field, used to record that a cross-source
// duplicate was observed (so the original brief carries the
// corroborating source URLs even when the duplicate item is
// otherwise dropped).
func (d *DB) AppendDraftReference(draftID, note string) error {
	if note == "" || draftID == "" {
		return nil
	}
	_, err := d.db.Exec(
		`UPDATE drafts SET validation_notes = COALESCE(validation_notes, '') || ? WHERE id = ?`,
		"\n"+note, draftID,
	)
	return err
}

// AppendDraftReferenceWithSource records corroboration and its source
// provenance atomically when a merge adds no new structured intelligence.
func (d *DB) AppendDraftReferenceWithSource(draftID, note, sourceID string) error {
	if draftID == "" {
		return nil
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existingSourceIDs sql.NullString
	if err := tx.QueryRow("SELECT source_ids FROM drafts WHERE id = ?", draftID).Scan(&existingSourceIDs); err != nil {
		return err
	}
	sourceIDsJSON, err := appendSourceIDJSON(existingSourceIDs, sourceID)
	if err != nil {
		return fmt.Errorf("updating source IDs for draft %q: %w", draftID, err)
	}
	result, err := tx.Exec(
		`UPDATE drafts
		 SET validation_notes = COALESCE(validation_notes, '') || ?, source_ids = ?
		 WHERE id = ?`,
		"\n"+note, sourceIDsJSON, draftID,
	)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("draft %q not found", draftID)
	}
	return tx.Commit()
}
