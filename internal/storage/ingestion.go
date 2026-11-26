package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Bound only unresolved ingestion payloads. Reaching this bound rejects the
// entire handoff, leaving the source cursor unchanged for replay after drain.
// This reserves most of the 1 GiB volume for the rest of the database and WAL.
const MaxIngestionQueueBytes = 128 << 20

const maxIngestionDeliveryBytes = 4 << 20

var ErrIngestionBackpressure = errors.New("ingestion queue is full; retaining source cursor")

type IngestionCandidate struct{ SourceID, Source, Revision, Payload string }

func migrateIngestion(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ingestion_candidates (
 source_id TEXT NOT NULL, revision TEXT NOT NULL, source TEXT NOT NULL,
 payload TEXT NOT NULL, payload_bytes INTEGER NOT NULL, queued_at TEXT NOT NULL,
 delivered_at TEXT NOT NULL DEFAULT '', PRIMARY KEY(source_id,revision));
 DROP INDEX IF EXISTS ingestion_delivery;
 CREATE INDEX IF NOT EXISTS ingestion_delivery_fair ON ingestion_candidates(COALESCE(NULLIF(delivered_at,''),queued_at),queued_at,source_id,revision);`)
	return err
}

// HasIngestionCandidate keeps replay overlap from consuming the candidate cap.
// Callers check this only after relevance filtering, never per firehose event.
func (d *DB) HasIngestionCandidate(id, revision string) (bool, error) {
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM ingestion_candidates WHERE source_id=? AND revision=?`, id, revision).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	return d.HasSeenRevision(id, revision)
}

// CommitIngestion atomically stores every selected candidate and the consumed
// stream watermark. A crash, full disk, queue bound or failed checkpoint writes
// neither part. Candidates are immutable and retry insertion is idempotent.
func (d *DB) CommitIngestion(source string, watermark time.Time, candidates []IngestionCandidate) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err = queueIngestionCandidates(tx, candidates); err != nil {
		return err
	}
	if !watermark.IsZero() {
		var old scraperLastPoll
		err = tx.QueryRow(`SELECT last_poll FROM scraper_state WHERE source=?`, source).Scan(&old)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == sql.ErrNoRows || watermark.After(time.Time(old)) {
			if _, err = tx.Exec(`INSERT INTO scraper_state(source,last_poll,cursor) VALUES(?,?,?) ON CONFLICT(source) DO UPDATE SET last_poll=excluded.last_poll,cursor=excluded.cursor`, source, watermark.UTC(), fmt.Sprint(watermark.UnixMicro())); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// CommitPolledIngestion queues a polled source's unprocessed items and records
// how far the source was read, in one transaction. The queue keeps each item
// until it is processed or superseded, so the cursor can move past work that is
// still held without losing it. The state is written exactly as
// SaveScraperState writes it; callers keep their cursor from moving backwards.
func (d *DB) CommitPolledIngestion(source string, lastPoll time.Time, cursor string, candidates []IngestionCandidate) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err = queueIngestionCandidates(tx, candidates); err != nil {
		return err
	}
	if _, err = tx.Exec(
		`INSERT INTO scraper_state (source, last_poll, cursor) VALUES (?, ?, ?)
		 ON CONFLICT(source) DO UPDATE SET last_poll = excluded.last_poll, cursor = excluded.cursor`,
		source, lastPoll, cursor,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// queueIngestionCandidates inserts candidates not yet queued. Candidates are
// immutable, so a retried insertion is idempotent.
func queueIngestionCandidates(tx *sql.Tx, candidates []IngestionCandidate) error {
	var size int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(payload_bytes),0) FROM ingestion_candidates`).Scan(&size); err != nil {
		return err
	}
	for _, c := range candidates {
		var exists int
		err := tx.QueryRow(`SELECT 1 FROM ingestion_candidates WHERE source_id=? AND revision=?`, c.SourceID, c.Revision).Scan(&exists)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		// Check before writing, so a rejected batch cannot transiently grow
		// the WAL beyond the unresolved payload budget.
		if int64(len(c.Payload)) > int64(MaxIngestionQueueBytes)-size {
			return ErrIngestionBackpressure
		}
		if _, err = tx.Exec(`INSERT INTO ingestion_candidates(source_id,revision,source,payload,payload_bytes,queued_at) VALUES(?,?,?,?,?,?)`, c.SourceID, c.Revision, c.Source, c.Payload, len(c.Payload), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		size += int64(len(c.Payload))
	}
	return nil
}

// NextIngestionCandidates rotates bounded delivery by the last service time,
// using enqueue time for candidates that have not yet been delivered. Held
// retries and fresh work share one oldest-first order: serving a candidate
// moves it behind all currently waiting work, even under continuous arrivals.
// Byte-limited batches retain the same order and single-candidate escape hatch.
func (d *DB) NextIngestionCandidates(limit int) ([]IngestionCandidate, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("ingestion delivery limit must be positive")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	// A source has one current state: its most recently observed revision.
	// Older queued observations are superseded. Delivering them after the
	// current one would rebuild the candidate from stale evidence, and held
	// candidates would rebuild on every rotation between their revisions.
	// julianday has millisecond precision; insertion order breaks ties. This
	// runs before completed revisions leave the queue, so completing the
	// current revision cannot resurrect an older one.
	if _, err = tx.Exec(`DELETE FROM ingestion_candidates WHERE EXISTS (SELECT 1 FROM ingestion_candidates newer WHERE newer.source_id=ingestion_candidates.source_id AND (julianday(newer.queued_at)>julianday(ingestion_candidates.queued_at) OR (julianday(newer.queued_at)=julianday(ingestion_candidates.queued_at) AND newer.rowid>ingestion_candidates.rowid)))`); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`DELETE FROM ingestion_candidates WHERE EXISTS (SELECT 1 FROM seen_items s JOIN seen_revisions r USING(source_id) WHERE s.source_id=ingestion_candidates.source_id AND r.revision=ingestion_candidates.revision)`); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT source_id,source,revision,payload FROM ingestion_candidates ORDER BY COALESCE(NULLIF(delivered_at,''),queued_at),queued_at,source_id,revision LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	var out []IngestionCandidate
	payloadBytes := 0
	for rows.Next() {
		var c IngestionCandidate
		if err = rows.Scan(&c.SourceID, &c.Source, &c.Revision, &c.Payload); err != nil {
			_ = rows.Close()
			return nil, err
		}
		// Deliver at least one candidate, even if it alone exceeds the soft
		// byte budget. It remains bounded by the ingestion/event read limits.
		if len(out) > 0 && payloadBytes+len(c.Payload) > maxIngestionDeliveryBytes {
			break
		}
		out = append(out, c)
		payloadBytes += len(c.Payload)
	}
	err = rows.Err()
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	for _, c := range out {
		if _, err = tx.Exec(`UPDATE ingestion_candidates SET delivered_at=? WHERE source_id=? AND revision=?`, time.Now().UTC().Format(time.RFC3339Nano), c.SourceID, c.Revision); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
