package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type ScraperState struct {
	Source   string
	LastPoll time.Time
	Cursor   string
}

// scraperLastPoll accepts the native time.Time returned by SQLite and the
// textual timestamp representation returned by PostgreSQL-compatible drivers
// for the DATETIME compatibility column.
type scraperLastPoll time.Time

func (t *scraperLastPoll) Scan(value any) error {
	if native, ok := value.(time.Time); ok {
		*t = scraperLastPoll(native)
		return nil
	}
	var raw string
	switch value := value.(type) {
	case string:
		raw = value
	case []byte:
		raw = string(value)
	default:
		return fmt.Errorf("scan scraper last_poll: unsupported %T", value)
	}
	raw = strings.TrimSpace(raw)
	fields := strings.Fields(raw)
	if len(fields) >= 2 && isNumericUTCOffset(fields[len(fields)-2]) && isNumericUTCOffset(fields[len(fields)-1]) {
		if fields[len(fields)-2] != fields[len(fields)-1] {
			return fmt.Errorf("scan scraper last_poll: conflicting timezone offsets in %q", raw)
		}
		raw = strings.Join(fields[:len(fields)-1], " ")
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999 -0700",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02 15:04:05.999999999",
	} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			*t = scraperLastPoll(parsed)
			return nil
		}
	}
	return fmt.Errorf("scan scraper last_poll: invalid timestamp %q", raw)
}

func isNumericUTCOffset(value string) bool {
	if len(value) != 5 || (value[0] != '+' && value[0] != '-') {
		return false
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// HasSeen checks if a source_id has already been processed.
func (d *DB) HasSeen(sourceID string) (bool, error) {
	var count int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM seen_items WHERE source_id = ?", sourceID).Scan(&count); err != nil {
		return false, fmt.Errorf("checking seen_items: %w", err)
	}
	return count > 0, nil
}

// MarkSeen records that a source_id has been processed.
func (d *DB) MarkSeen(sourceID, source, title string) error {
	_, err := d.db.Exec(
		"INSERT OR IGNORE INTO seen_items (source_id, source, title, seen_at) VALUES (?, ?, ?, ?)",
		sourceID, source, title, time.Now(),
	)
	return err
}

// ReseedSource requeues either one source item or all items seen since the
// cutoff. It also rewinds the scraper cursor in the same transaction; clearing
// seen state alone cannot replay items older than the source's last poll.
func (d *DB) ReseedSource(source string, since time.Time, sourceID string) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var res sql.Result
	if sourceID != "" {
		res, err = tx.Exec("DELETE FROM seen_items WHERE source = ? AND source_id = ?", source, sourceID)
		if err == nil {
			_, err = tx.Exec("DELETE FROM grounding_attempts WHERE source_id = ?", sourceID)
		}
	} else {
		_, err = tx.Exec("DELETE FROM grounding_attempts WHERE source_id IN (SELECT source_id FROM seen_items WHERE source = ? AND seen_at >= ?)", source, since)
		if err == nil {
			res, err = tx.Exec("DELETE FROM seen_items WHERE source = ? AND seen_at >= ?", source, since)
		}
	}
	if err != nil {
		return 0, err
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if removed > 0 {
		if _, err := tx.Exec("UPDATE scraper_state SET last_poll = ?, cursor = '' WHERE source = ? AND last_poll > ?", since, source, since); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return removed, nil
}

// QueueReplay stores a source item for the replay source to re-emit and clears
// its seen state, so the pipeline processes it again.
func (d *DB) QueueReplay(source, sourceID, itemJSON string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("DELETE FROM seen_items WHERE source = ? AND source_id = ?", source, sourceID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM grounding_attempts WHERE source_id = ?", sourceID); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO replay_items (source_id, source, item_json, queued_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(source_id) DO UPDATE SET source = excluded.source, item_json = excluded.item_json, queued_at = excluded.queued_at`,
		sourceID, source, itemJSON, time.Now().UTC(),
	); err != nil {
		return err
	}
	return tx.Commit()
}

// PendingReplays returns the queued replay items, oldest first. It first
// drops items that were seen again since they were queued, and items queued
// before the cutoff.
func (d *DB) PendingReplays(queuedAfter time.Time) ([]string, error) {
	if _, err := d.db.Exec(
		"DELETE FROM replay_items WHERE queued_at < ? OR source_id IN (SELECT source_id FROM seen_items)",
		queuedAfter.UTC(),
	); err != nil {
		return nil, fmt.Errorf("pruning replay items: %w", err)
	}
	rows, err := d.db.Query("SELECT item_json FROM replay_items ORDER BY queued_at, source_id")
	if err != nil {
		return nil, fmt.Errorf("listing replay items: %w", err)
	}
	defer discardClose(rows)
	var items []string
	for rows.Next() {
		var itemJSON string
		if err := rows.Scan(&itemJSON); err != nil {
			return nil, err
		}
		items = append(items, itemJSON)
	}
	return items, rows.Err()
}

// GetScraperState retrieves the last poll state for a source.
func (d *DB) GetScraperState(source string) (*ScraperState, error) {
	row := d.db.QueryRow("SELECT source, last_poll, cursor FROM scraper_state WHERE source = ?", source)
	var state ScraperState
	var lastPoll scraperLastPoll
	err := row.Scan(&state.Source, &lastPoll, &state.Cursor)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	state.LastPoll = time.Time(lastPoll)
	return &state, nil
}

// SaveScraperState upserts the poll state for a source.
func (d *DB) SaveScraperState(source string, lastPoll time.Time, cursor string) error {
	_, err := d.db.Exec(
		`INSERT INTO scraper_state (source, last_poll, cursor) VALUES (?, ?, ?)
		 ON CONFLICT(source) DO UPDATE SET last_poll = excluded.last_poll, cursor = excluded.cursor`,
		source, lastPoll, cursor,
	)
	return err
}
