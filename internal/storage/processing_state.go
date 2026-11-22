package storage

import (
	"database/sql"
	"time"
)

func migrateProcessingState(db *sql.DB) error {
	_, err := db.Exec(`
 CREATE TABLE IF NOT EXISTS llm_batch_jobs (request_key TEXT PRIMARY KEY, job_name TEXT NOT NULL, created_at DATETIME NOT NULL);
 CREATE TABLE IF NOT EXISTS processing_checkpoints (source_id TEXT PRIMARY KEY, input_key TEXT NOT NULL, payload TEXT NOT NULL, retry_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS processing_history (id INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL, input_key TEXT NOT NULL, attempt_id TEXT NOT NULL, stage TEXT NOT NULL, outcome TEXT NOT NULL, created_at TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS processing_history_source ON processing_history(source_id,created_at);
 CREATE TABLE IF NOT EXISTS seen_evidence (source_id TEXT PRIMARY KEY, evidence_key TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS seen_revisions (source_id TEXT PRIMARY KEY, revision TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS publication_intents (draft_id TEXT PRIMARY KEY REFERENCES drafts(id), brief_yaml TEXT NOT NULL, claim_key TEXT NOT NULL DEFAULT '', complete_draft INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
 `)
	return err
}

func (d *DB) GetBatchJob(key string) (string, bool, error) {
	var job string
	err := d.db.QueryRow("SELECT job_name FROM llm_batch_jobs WHERE request_key = ?", key).Scan(&job)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return job, err == nil, err
}
func (d *DB) PutBatchJob(keys []string, job string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, key := range keys {
		if _, err = tx.Exec(`INSERT INTO llm_batch_jobs(request_key,job_name,created_at) VALUES(?,?,?) ON CONFLICT(request_key) DO UPDATE SET job_name=excluded.job_name,created_at=excluded.created_at`, key, job, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (d *DB) DeleteBatchJob(keys []string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, key := range keys {
		if _, err = tx.Exec("DELETE FROM llm_batch_jobs WHERE request_key = ?", key); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type ProcessingCheckpoint struct {
	SourceID, InputKey, Payload string
	RetryAt                     time.Time
}

// GetProcessingCheckpoint returns the saved work for a source, including the
// stored InputKey. Policy and evidence compatibility are decided by the caller.
func (d *DB) GetProcessingCheckpoint(id string) (*ProcessingCheckpoint, error) {
	cp := &ProcessingCheckpoint{SourceID: id}
	var retry string
	err := d.db.QueryRow("SELECT payload,retry_at,input_key FROM processing_checkpoints WHERE source_id=?", id).Scan(&cp.Payload, &retry, &cp.InputKey)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cp.RetryAt, err = time.Parse(time.RFC3339Nano, retry)
	return cp, err
}
func (d *DB) PutProcessingCheckpoint(cp ProcessingCheckpoint) error {
	_, err := d.db.Exec(`INSERT INTO processing_checkpoints(source_id,input_key,payload,retry_at) VALUES(?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET input_key=excluded.input_key,payload=excluded.payload,retry_at=excluded.retry_at`, cp.SourceID, cp.InputKey, cp.Payload, cp.RetryAt.UTC().Format(time.RFC3339Nano))
	return err
}
func (d *DB) DeleteProcessingCheckpoint(id string) error {
	_, err := d.db.Exec("DELETE FROM processing_checkpoints WHERE source_id=?", id)
	return err
}

// DeleteProcessingCheckpointIfUnchanged removes only the exact snapshot read
// by the caller. A replacement can share the same source and input key.
func (d *DB) DeleteProcessingCheckpointIfUnchanged(cp ProcessingCheckpoint) error {
	_, err := d.db.Exec("DELETE FROM processing_checkpoints WHERE source_id=? AND input_key=? AND payload=? AND retry_at=?", cp.SourceID, cp.InputKey, cp.Payload, cp.RetryAt.UTC().Format(time.RFC3339Nano))
	return err
}
func (d *DB) RecordProcessingEvent(id, key, attempt, stage, outcome string) error {
	_, err := d.db.Exec("INSERT INTO processing_history(source_id,input_key,attempt_id,stage,outcome,created_at) VALUES(?,?,?,?,?,?)", id, key, attempt, stage, outcome, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// HasSeenRevision bootstraps legacy seen rows without replaying the entire feed.
// Once a baseline is stored, changed evidence is eligible under the same ID.
func (d *DB) HasSeenRevision(id, revision string) (bool, error) {
	if revision == "" {
		return d.HasSeen(id)
	}
	var old sql.NullString
	err := d.db.QueryRow("SELECT r.revision FROM seen_items s LEFT JOIN seen_revisions r USING(source_id) WHERE s.source_id=?", id).Scan(&old)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !old.Valid {
		_, err = d.db.Exec("INSERT INTO seen_revisions(source_id,revision) VALUES(?,?) ON CONFLICT(source_id) DO NOTHING", id, revision)
		return true, err
	}
	return old.String == revision, nil
}

// MarkSeenRevision completes a source revision and removes its saved candidate
// in one transaction. A cleanup failure leaves the revision eligible for retry.
func (d *DB) MarkSeenRevision(id, source, title, revision string, evidenceKeys ...string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := completeSeenRevision(tx, id, source, title, revision, evidenceKeys...); err != nil {
		return err
	}
	return tx.Commit()
}

func completeSeenRevision(tx *sql.Tx, id, source, title, revision string, evidenceKeys ...string) error {
	if _, err := tx.Exec(`INSERT INTO seen_items(source_id,source,title,seen_at) VALUES(?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET source=excluded.source,title=excluded.title,seen_at=excluded.seen_at`, id, source, title, time.Now().UTC()); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO seen_revisions(source_id,revision) VALUES(?,?) ON CONFLICT(source_id) DO UPDATE SET revision=excluded.revision`, id, revision); err != nil {
		return err
	}
	if len(evidenceKeys) > 0 {
		if _, err := tx.Exec(`INSERT INTO seen_evidence(source_id,evidence_key) VALUES(?,?) ON CONFLICT(source_id) DO UPDATE SET evidence_key=excluded.evidence_key`, id, evidenceKeys[0]); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("DELETE FROM processing_checkpoints WHERE source_id=?", id); err != nil {
		return err
	}
	return nil
}

type PublicationIntent struct {
	DraftID, BriefYAML, ClaimKey string
	CompleteDraft                bool
}

func (d *DB) ListPublicationIntents() ([]PublicationIntent, error) {
	rows, err := d.db.Query("SELECT draft_id,brief_yaml,claim_key,complete_draft FROM publication_intents ORDER BY created_at,draft_id")
	if err != nil {
		return nil, err
	}
	defer discardClose(rows)
	var out []PublicationIntent
	for rows.Next() {
		var p PublicationIntent
		if err := rows.Scan(&p.DraftID, &p.BriefYAML, &p.ClaimKey, &p.CompleteDraft); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (d *DB) DeletePublicationIntent(id, payload string) error {
	_, err := d.db.Exec("DELETE FROM publication_intents WHERE draft_id=? AND brief_yaml=?", id, payload)
	return err
}
func insertPublicationIntent(tx *sql.Tx, id, payload, claim string, complete bool) error {
	_, err := tx.Exec(`INSERT INTO publication_intents(draft_id,brief_yaml,claim_key,complete_draft,created_at) VALUES(?,?,?,?,?) ON CONFLICT(draft_id) DO UPDATE SET brief_yaml=excluded.brief_yaml,claim_key=CASE WHEN excluded.claim_key<>'' THEN excluded.claim_key ELSE publication_intents.claim_key END,complete_draft=MAX(publication_intents.complete_draft,excluded.complete_draft),created_at=excluded.created_at`, id, payload, claim, complete, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (d *DB) CreateDraftWithPublication(draft *Draft, claim string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err = insertDraft(tx, draft); err != nil {
		return err
	}
	if err = insertPublicationIntent(tx, draft.ID, draft.BriefYAML, claim, true); err != nil {
		return err
	}
	return tx.Commit()
}

// ClaimBatchJob prevents overlapping service instances from submitting paid
// work twice. Every key is reserved together, or none are changed.
func (d *DB) ClaimBatchJob(keys []string, intent string) (bool, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, key := range keys {
		var n int
		if err := tx.QueryRow("SELECT COUNT(*) FROM llm_batch_jobs WHERE request_key=?", key).Scan(&n); err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	for _, key := range keys {
		if _, err := tx.Exec("INSERT INTO llm_batch_jobs(request_key,job_name,created_at) VALUES(?,?,?)", key, intent, time.Now().UTC()); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// PruneProcessingArtifacts bounds completed local artifacts. Unresolved remote
// jobs and candidate checkpoints remain recoverable and are never age-pruned.
func (d *DB) PruneProcessingArtifacts(now time.Time) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("DELETE FROM llm_cache WHERE created_at < ?", now.Add(-30*24*time.Hour)); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM llm_cache WHERE cache_key IN (SELECT cache_key FROM llm_cache ORDER BY created_at DESC,cache_key LIMIT -1 OFFSET 50000)"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM processing_history WHERE created_at < ?", now.Add(-90*24*time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) CompareAndSwapBatchJob(keys []string, expected, replacement string) (bool, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, key := range keys {
		var current string
		if err := tx.QueryRow("SELECT job_name FROM llm_batch_jobs WHERE request_key=?", key).Scan(&current); err == sql.ErrNoRows {
			return false, nil
		} else if err != nil {
			return false, err
		}
		if current != expected {
			return false, nil
		}
	}
	for _, key := range keys {
		if replacement == "" {
			_, err = tx.Exec("DELETE FROM llm_batch_jobs WHERE request_key=? AND job_name=?", key, expected)
		} else {
			_, err = tx.Exec("UPDATE llm_batch_jobs SET job_name=? WHERE request_key=? AND job_name=?", replacement, key, expected)
		}
		if err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

func (d *DB) SeenEvidenceMatches(id, key string) (bool, error) {
	var n int
	err := d.db.QueryRow("SELECT COUNT(*) FROM seen_items s JOIN seen_evidence e USING(source_id) WHERE s.source_id=? AND e.evidence_key=?", id, key).Scan(&n)
	return n > 0, err
}
