package storage

import (
	"time"

	_ "modernc.org/sqlite"
)

// Publish outbox entry kinds.
const (
	OutboxKindBrief  = "brief"
	OutboxKindDigest = "digest"
	// OutboxKindRetirement is a duplicate brief queued for removal. Its row ID
	// is "retire:<retired brief ID>" and its payload is JSON.
	OutboxKindRetirement = "retirement"
)

// OutboxRow is one buffered publication awaiting a feed flush. For briefs
// Payload is the brief YAML; for digests it is the digest JSON.
type OutboxRow struct {
	ID         string
	Kind       string
	Payload    string
	Seq        int64
	EnqueuedAt time.Time
}

// UpsertPublishOutbox stores payload as the latest snapshot for id and returns
// its new sequence number, which is greater than every sequence in the table.
func (d *DB) UpsertPublishOutbox(id, kind, payload string) (int64, error) {
	var seq int64
	err := d.db.QueryRow(
		`INSERT INTO publish_outbox (brief_id, kind, brief_yaml, seq, enqueued_at)
		 VALUES (?, ?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM publish_outbox), ?)
		 ON CONFLICT(brief_id) DO UPDATE SET kind = excluded.kind, brief_yaml = excluded.brief_yaml,
		   seq = excluded.seq, enqueued_at = excluded.enqueued_at
		 RETURNING seq`,
		id, kind, payload, time.Now().UTC().Format(time.RFC3339Nano),
	).Scan(&seq)
	return seq, err
}

// ListPublishOutbox returns every outbox row, oldest first.
func (d *DB) ListPublishOutbox() ([]OutboxRow, error) {
	rows, err := d.db.Query(`SELECT brief_id, kind, seq, enqueued_at, brief_yaml FROM publish_outbox ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer discardClose(rows)
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		var enqueued string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Seq, &enqueued, &r.Payload); err != nil {
			return nil, err
		}
		r.EnqueuedAt, _ = time.Parse(time.RFC3339Nano, enqueued)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeletePublishOutboxIfSeq removes the row for id only while it still carries
// seq. A newer snapshot buffered meanwhile has a higher seq and is kept.
func (d *DB) DeletePublishOutboxIfSeq(id string, seq int64) error {
	_, err := d.db.Exec(`DELETE FROM publish_outbox WHERE brief_id = ? AND seq = ?`, id, seq)
	return err
}
