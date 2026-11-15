package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

func migrate(db *sql.DB) error {
	if err := migrateIngestion(db); err != nil {
		return err
	}
	if err := migrateProcessingState(db); err != nil {
		return err
	}
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS seen_items (
			source_id   TEXT PRIMARY KEY,
			source      TEXT NOT NULL,
			title       TEXT,
			seen_at     DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS drafts (
			id               TEXT PRIMARY KEY,
			status           TEXT NOT NULL DEFAULT 'pending',
			score            REAL,
			source           TEXT NOT NULL,
			source_ids       TEXT,
			brief_yaml       TEXT NOT NULL,
			reject_reason    TEXT,
			validation_notes TEXT,
			created_at       DATETIME NOT NULL,
			reviewed_at      DATETIME
		);

		CREATE TABLE IF NOT EXISTS scraper_state (
			source    TEXT PRIMARY KEY,
			last_poll DATETIME NOT NULL,
			cursor    TEXT
		);

		CREATE TABLE IF NOT EXISTS replay_items (
			source_id TEXT PRIMARY KEY,
			source    TEXT NOT NULL,
			item_json TEXT NOT NULL,
			queued_at DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS llm_cache (
			cache_key     TEXT PRIMARY KEY,
			response_json TEXT NOT NULL,
			created_at    DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS pipeline_quarantine (
			source_id     TEXT PRIMARY KEY,
			source        TEXT NOT NULL,
			title         TEXT,
			raw_output    TEXT NOT NULL,
			error_message TEXT NOT NULL,
			created_at    DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS grounding_attempts (
			source_id  TEXT PRIMARY KEY,
			attempts   INTEGER NOT NULL,
			updated_at DATETIME NOT NULL
		);
	`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rumour_candidates (
		claim_key TEXT PRIMARY KEY,
		source_ids TEXT NOT NULL,
		source_urls TEXT NOT NULL,
		assessment_json TEXT NOT NULL,
		status TEXT NOT NULL,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL
	)`)
	if err != nil {
		return err
	}

	// Human editorial corrections keep a durable before/after record in the
	// same database transaction as the draft update. Triggers make records
	// append-only even when SQL is run outside this package.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS draft_editorial_corrections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			draft_id TEXT NOT NULL,
			brief_id TEXT NOT NULL,
			operator TEXT NOT NULL,
			reason TEXT NOT NULL,
			previous_yaml TEXT NOT NULL,
			revised_yaml TEXT NOT NULL,
			previous_lastmod DATETIME,
			revised_lastmod DATETIME,
			previous_update_count INTEGER NOT NULL,
			revised_update_count INTEGER NOT NULL,
			previous_update_log TEXT,
			revised_update_log TEXT,
			backup_path TEXT NOT NULL,
			corrected_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_draft_editorial_corrections_draft ON draft_editorial_corrections(draft_id, id);
		CREATE TRIGGER IF NOT EXISTS draft_editorial_corrections_no_update
		BEFORE UPDATE ON draft_editorial_corrections BEGIN SELECT RAISE(ABORT, 'editorial corrections are append-only'); END;
		CREATE TRIGGER IF NOT EXISTS draft_editorial_corrections_no_delete
		BEFORE DELETE ON draft_editorial_corrections BEGIN SELECT RAISE(ABORT, 'editorial corrections are append-only'); END;
	`)
	if err != nil {
		return fmt.Errorf("creating editorial correction audit: %w", err)
	}

	// Add validation_notes column to existing databases. SQLite does not
	// support ADD COLUMN IF NOT EXISTS, so this fails with "duplicate column"
	// on new databases where the column already exists — that error is expected.
	_, _ = db.Exec("ALTER TABLE drafts ADD COLUMN validation_notes TEXT")

	// Update tracking columns: lastmod is set when a merge enriches a thin
	// draft with new structured fields; update_count caps how many times
	// the "Updated" pill renders before we go silent; update_log is a JSON
	// array of {at, level, summary, sources} events powering the
	// "What's new" detail-page bar and the L3 dispatch decision.
	_, _ = db.Exec("ALTER TABLE drafts ADD COLUMN lastmod DATETIME")
	_, _ = db.Exec("ALTER TABLE drafts ADD COLUMN update_count INTEGER DEFAULT 0")
	_, _ = db.Exec("ALTER TABLE drafts ADD COLUMN update_log TEXT")
	_, _ = db.Exec("ALTER TABLE drafts ADD COLUMN last_l3_dispatch DATETIME")

	// Digest tracking: persists last-published timestamps so we can detect
	// gaps and generate catch-up digests after restarts.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS digest_state (
			digest_type TEXT PRIMARY KEY,
			last_published DATETIME NOT NULL,
			period TEXT NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Cross-source dedup index: tracks CVEs and title hashes across sources.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS content_index (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			cve_id      TEXT,
			title_hash  TEXT,
			draft_id    TEXT NOT NULL,
			source_id   TEXT NOT NULL,
			source      TEXT NOT NULL,
			cve_context TEXT,
			created_at  DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_content_index_cve ON content_index(cve_id);
		CREATE INDEX IF NOT EXISTS idx_content_index_title ON content_index(title_hash);
	`)
	if err != nil {
		return err
	}

	// fingerprint_hash: SHA-256 of "vendor|product|vuln_class" for the
	// vendor+product+class fallback dedup axis. Catches near-duplicate
	// briefs like "Sourcecodester Pharmacy Sales SQL Injection" vs
	// "Sourcecodester Pharmacy Inventory SQL Injection" that share a
	// vendor+product+class but get distinct CVE ids and slightly
	// different titles. Errors expected on existing DBs where the
	// column already exists; ignore.
	_, _ = db.Exec("ALTER TABLE content_index ADD COLUMN fingerprint_hash TEXT")
	_, _ = db.Exec("ALTER TABLE content_index ADD COLUMN title_norm TEXT")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_content_index_fp ON content_index(fingerprint_hash)")

	// product_fingerprint_hash: SHA-256 of "vendor|product" (no class).
	// Used as a tertiary dedup axis: when one source describes a mechanism
	// ("oob-write") and another describes the effect ("rce") for the same
	// product without a shared CVE id, the class-keyed fingerprint misses.
	// This column lets CheckPostExtraction find those no-CVE briefs and
	// merge the incoming CVE into the existing draft.
	_, _ = db.Exec("ALTER TABLE content_index ADD COLUMN product_fingerprint_hash TEXT")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_content_index_pfp ON content_index(product_fingerprint_hash)")

	// content_hash: SHA-256 of normalized title+content, for the literal /
	// near-literal duplicate axis (syndicated republications that share no
	// CVE and whose titles differ only by a source tag).
	_, _ = db.Exec("ALTER TABLE content_index ADD COLUMN content_hash TEXT")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_content_index_content_hash ON content_index(content_hash)")

	// vendor_cycle_key: normalize(vendor)|YYYY-MM, for folding a vendor's
	// monthly advisory CVEs (Patch Tuesday, Apple, Adobe, Qualcomm) into one
	// roundup brief.
	_, _ = db.Exec("ALTER TABLE content_index ADD COLUMN vendor_cycle_key TEXT")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_content_index_vendor_cycle ON content_index(vendor_cycle_key)")
	// source_url_hash normalizes article/reference URLs so feed GUID churn
	// and tracking parameters don't create parallel briefs for same source.
	_, _ = db.Exec("ALTER TABLE content_index ADD COLUMN source_url_hash TEXT")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_content_index_source_url ON content_index(source_url_hash)")
	// source_published_day enables same-day product dedupe without treating
	// recurring products as permanent merge buckets.
	_, _ = db.Exec("ALTER TABLE content_index ADD COLUMN source_published_day TEXT")
	_, _ = db.Exec("ALTER TABLE content_index ADD COLUMN claim_key TEXT")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_content_index_claim_key ON content_index(claim_key)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_content_index_product_day ON content_index(product_fingerprint_hash, source_published_day)")
	// correlation caches the correlator's summary of brief_yaml; every write
	// to brief_yaml clears it.
	_, _ = db.Exec("ALTER TABLE drafts ADD COLUMN correlation TEXT")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_drafts_status_created_at ON drafts(status, created_at)")

	// One-shot reset for sources whose stored last_poll is too recent
	// (within the last hour) AND last_poll is on the same UTC day as
	// the migration runs. This catches the case where a previous pod
	// advanced the state to "now" on a poll that returned zero items
	// for a newly-added source, burning its initial-lookback window.
	// Idempotent: gated on a marker in the digest_state table so it
	// only runs once per upgrade.
	var marker string
	row := db.QueryRow("SELECT period FROM digest_state WHERE digest_type = ?", "scraper-state-reset-v1")
	if err := row.Scan(&marker); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("reading scraper-state-reset marker: %w", err)
	}
	if marker == "" {
		_, _ = db.Exec(`DELETE FROM scraper_state WHERE source IN ('the-hacker-news', 'dark-reading', 'cisa-kev')`)
		_, _ = db.Exec(
			`INSERT INTO digest_state (digest_type, last_published, period) VALUES (?, ?, ?)
			 ON CONFLICT(digest_type) DO UPDATE SET period = excluded.period`,
			"scraper-state-reset-v1", time.Now(), "applied",
		)
	}

	// Correlation tags: caches LLM-generated cluster names for TTP groups.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS correlation_tags (
			technique_hash TEXT PRIMARY KEY,
			tag            TEXT NOT NULL,
			created_at     DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Digest clusters: tracks cluster state across digest runs.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS digest_clusters (
			digest_id   TEXT NOT NULL,
			cluster_key TEXT NOT NULL,
			brief_ids   TEXT NOT NULL,
			summary     TEXT NOT NULL,
			created_at  DATETIME NOT NULL,
			PRIMARY KEY (digest_id, cluster_key)
		)
	`)
	if err != nil {
		return err
	}

	// Golden examples: approved (technique, evidence) pairs harvested from
	// human-approved briefs. Grow threat-bot's own labelled corpus alongside
	// the vendored TRAM dataset and serve as a few-shot pool.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS golden_examples (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			technique   TEXT NOT NULL,
			evidence    TEXT NOT NULL,
			source      TEXT,
			approved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(technique, evidence)
		)
	`)
	if err != nil {
		return err
	}

	// EPSS scores: the daily bulk score set, kept on disk instead of in memory.
	if _, err := db.Exec(epssScoresTableSQL("epss_scores")); err != nil {
		return err
	}

	// Publish outbox: briefs and digests buffered by the publisher but not yet
	// committed to the feed repo, so a restart cannot lose them. seq grows with
	// every upsert so a flush only removes the snapshot it actually published.
	// The large payload is the last column so MAX(seq) never reads past it.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS publish_outbox (
			brief_id    TEXT PRIMARY KEY,
			kind        TEXT NOT NULL DEFAULT 'brief',
			seq         INTEGER NOT NULL,
			enqueued_at TEXT NOT NULL,
			brief_yaml  TEXT NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_content_index_source_id ON content_index(source_id); CREATE INDEX IF NOT EXISTS idx_llm_cache_created_at ON llm_cache(created_at); CREATE INDEX IF NOT EXISTS idx_processing_history_created_at ON processing_history(created_at);`)
	if err != nil {
		return err
	}

	return nil
}
