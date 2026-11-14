package storage

import (
	"database/sql"
	"fmt"
	"iter"

	_ "modernc.org/sqlite"
)

// EPSSRow is one CVE's EPSS probability and percentile.
type EPSSRow struct {
	CVEID      string
	EPSS       float64
	Percentile float64
}

// epssScoresTableSQL creates an EPSS score table with the given name.
func epssScoresTableSQL(name string) string {
	return `CREATE TABLE IF NOT EXISTS ` + name + ` (
		cve_id     TEXT PRIMARY KEY,
		epss       REAL NOT NULL,
		percentile REAL NOT NULL
	) WITHOUT ROWID`
}

// ReplaceEPSSScores replaces the stored EPSS scores with rows. The new set is
// loaded into a staging table in short transactions and then swapped in with
// one rename, so lookups see either the old or the new set. On error the
// staging table is dropped and the old set stays in place.
func (d *DB) ReplaceEPSSScores(rows iter.Seq2[EPSSRow, error]) (int, error) {
	// A crash mid-reload can leave a staging table behind.
	if _, err := d.db.Exec("DROP TABLE IF EXISTS epss_scores_next"); err != nil {
		return 0, err
	}
	if _, err := d.db.Exec(epssScoresTableSQL("epss_scores_next")); err != nil {
		return 0, err
	}
	n, err := d.loadEPSSStaging(rows)
	if err != nil {
		_, _ = d.db.Exec("DROP TABLE IF EXISTS epss_scores_next")
		return 0, err
	}

	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("DROP TABLE IF EXISTS epss_scores"); err != nil {
		return 0, err
	}
	if _, err := tx.Exec("ALTER TABLE epss_scores_next RENAME TO epss_scores"); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// loadEPSSStaging inserts rows into the staging table, committing every
// epssLoadBatchRows rows.
func (d *DB) loadEPSSStaging(rows iter.Seq2[EPSSRow, error]) (int, error) {
	var tx *sql.Tx
	var stmt *sql.Stmt
	defer func() {
		if tx != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
		}
	}()
	commit := func() error {
		if err := stmt.Close(); err != nil {
			return fmt.Errorf("closing EPSS staging insert: %w", err)
		}
		err := tx.Commit()
		tx, stmt = nil, nil
		return err
	}

	n := 0
	for row, err := range rows {
		if err != nil {
			return 0, err
		}
		if tx == nil {
			if tx, err = d.db.Begin(); err != nil {
				return 0, err
			}
			if stmt, err = tx.Prepare("INSERT OR REPLACE INTO epss_scores_next (cve_id, epss, percentile) VALUES (?, ?, ?)"); err != nil {
				_ = tx.Rollback()
				tx = nil
				return 0, err
			}
		}
		if _, err := stmt.Exec(row.CVEID, row.EPSS, row.Percentile); err != nil {
			return 0, err
		}
		n++
		if n%epssLoadBatchRows == 0 {
			if err := commit(); err != nil {
				return 0, err
			}
		}
	}
	if tx != nil {
		if err := commit(); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// EPSSScore returns the stored EPSS score for a CVE and whether one exists.
func (d *DB) EPSSScore(cveID string) (EPSSRow, bool, error) {
	var row EPSSRow
	err := d.db.QueryRow("SELECT cve_id, epss, percentile FROM epss_scores WHERE cve_id = ?", cveID).
		Scan(&row.CVEID, &row.EPSS, &row.Percentile)
	if err == sql.ErrNoRows {
		return EPSSRow{}, false, nil
	}
	if err != nil {
		return EPSSRow{}, false, err
	}
	return row, true, nil
}
