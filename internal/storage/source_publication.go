package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// UpdateDraftYAMLWithPublication commits a source-derived snapshot and its
// publication intent together. Existing draft-completion receipts survive
// later metadata updates to the same still-pending publication.
func (d *DB) UpdateDraftYAMLWithPublication(id, briefYAML string, publish, complete bool) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.Exec("UPDATE drafts SET brief_yaml=?, correlation=NULL WHERE id=?", briefYAML, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("draft %q not found", id)
	}
	if publish {
		if err := insertPublicationIntent(tx, id, briefYAML, "", complete); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// HoldPublicationIntent removes only the exact failed queue snapshot and keeps
// its evidence visible to editorial review. Unrelated publications can proceed.
func (d *DB) HoldPublicationIntent(id, payload, reason string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var source, title string
	err = tx.QueryRow(`SELECT d.source,d.id FROM drafts d JOIN publication_intents p ON p.draft_id=d.id WHERE d.id=? AND d.brief_yaml=? AND p.brief_yaml=?`, id, payload, payload).Scan(&source, &title)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO pipeline_quarantine(source_id,source,title,raw_output,error_message,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET raw_output=excluded.raw_output,error_message=excluded.error_message,created_at=excluded.created_at`, "publication:"+id, source, title, payload, "publication requires editorial review: "+reason, time.Now().UTC()); err != nil {
		return err
	}
	notes, _ := json.Marshal([]string{"editorial review: " + reason})
	if _, err = tx.Exec("UPDATE drafts SET status=?,validation_notes=? WHERE id=? AND brief_yaml=?", StatusPending, string(notes), id, payload); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM publication_intents WHERE draft_id=? AND brief_yaml=?", id, payload); err != nil {
		return err
	}
	return tx.Commit()
}
