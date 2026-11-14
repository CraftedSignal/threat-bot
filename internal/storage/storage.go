package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

type RumourCandidate struct {
	ClaimKey       string
	SourceIDs      []string
	SourceURLs     []string
	AssessmentJSON string
	Status         string
	FirstSeen      time.Time
	LastSeen       time.Time
}

type DB struct {
	db *sql.DB
}

const sqliteBusyTimeout = 5 * time.Second

func Open(path string) (*DB, error) {
	// SQLite permits one writer at a time. Apply the busy timeout, immediate
	// transaction locking, and foreign key enforcement through the DSN so
	// modernc configures every physical connection opened by database/sql,
	// including replacements created later. Immediate transactions avoid a
	// read-then-write transaction losing an otherwise unresolvable snapshot race.
	dsn, err := sqliteDSN(path)
	if err != nil {
		return nil, fmt.Errorf("configuring database: %w", err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return &DB{db: db}, nil
}

func sqliteDSN(path string) (string, error) {
	filename, rawQuery, _ := strings.Cut(path, "?")
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("parsing SQLite options: %w", err)
	}
	for key, values := range query {
		switch strings.ToLower(key) {
		case "_txlock", "_busy_timeout", "_timeout", "_foreign_keys", "_fk":
			return "", fmt.Errorf("sqlite option %q is managed by the application", key)
		case "_pragma":
			for _, value := range values {
				if containsSQLiteIdentifier(value, "busy_timeout") || containsSQLiteIdentifier(value, "foreign_keys") {
					return "", fmt.Errorf("sqlite pragma %q is managed by the application", value)
				}
			}
		}
	}

	busyTimeout := fmt.Sprintf("busy_timeout(%d)", sqliteBusyTimeout/time.Millisecond)
	query.Add("_pragma", busyTimeout)
	query.Add("_pragma", "foreign_keys(ON)")
	query.Set("_txlock", "immediate")
	return filename + "?" + query.Encode(), nil
}

func containsSQLiteIdentifier(value, identifier string) bool {
	normalized := strings.ToLower(value)
	for searchFrom := 0; searchFrom < len(normalized); {
		offset := strings.Index(normalized[searchFrom:], identifier)
		if offset < 0 {
			return false
		}
		start := searchFrom + offset
		end := start + len(identifier)
		beforeBoundary := start == 0 || !isSQLiteIdentifierByte(normalized[start-1])
		afterBoundary := end == len(normalized) || !isSQLiteIdentifierByte(normalized[end])
		if beforeBoundary && afterBoundary {
			return true
		}
		searchFrom = start + 1
	}
	return false
}

func isSQLiteIdentifierByte(b byte) bool {
	return b == '_' || b >= 0x80 || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

func (d *DB) Close() error {
	return d.db.Close()
}

const maxRumourLineage = 32

func (d *DB) UpsertRumourCandidate(in *RumourCandidate) error {
	if in == nil || strings.TrimSpace(in.ClaimKey) == "" {
		return fmt.Errorf("rumour candidate claim_key is required")
	}
	now := time.Now().UTC()
	if in.FirstSeen.IsZero() {
		in.FirstSeen = now
	}
	if in.LastSeen.IsZero() {
		in.LastSeen = now
	}
	if in.Status == "" {
		in.Status = "below_gate"
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var idsJSON, urlsJSON, status string
	var first time.Time
	err = tx.QueryRow(`SELECT source_ids,source_urls,status,first_seen FROM rumour_candidates WHERE claim_key=?`, in.ClaimKey).Scan(&idsJSON, &urlsJSON, &status, &first)
	ids := in.SourceIDs
	urls := in.SourceURLs
	if err == nil {
		var oldIDs, oldURLs []string
		_ = json.Unmarshal([]byte(idsJSON), &oldIDs)
		_ = json.Unmarshal([]byte(urlsJSON), &oldURLs)
		ids = boundedUnique(append(oldIDs, ids...), maxRumourLineage)
		urls = boundedUnique(append(oldURLs, urls...), maxRumourLineage)
		in.FirstSeen = first
		if status == "published" {
			in.Status = status
		}
	} else if err != sql.ErrNoRows {
		return err
	}
	idsJSONBytes, _ := json.Marshal(boundedUnique(ids, maxRumourLineage))
	urlsJSONBytes, _ := json.Marshal(boundedUnique(urls, maxRumourLineage))
	_, err = tx.Exec(`INSERT INTO rumour_candidates(claim_key,source_ids,source_urls,assessment_json,status,first_seen,last_seen) VALUES(?,?,?,?,?,?,?) ON CONFLICT(claim_key) DO UPDATE SET source_ids=excluded.source_ids,source_urls=excluded.source_urls,assessment_json=excluded.assessment_json,status=excluded.status,last_seen=excluded.last_seen`, in.ClaimKey, string(idsJSONBytes), string(urlsJSONBytes), in.AssessmentJSON, in.Status, in.FirstSeen, in.LastSeen)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) GetRumourCandidate(key string) (*RumourCandidate, error) {
	var c RumourCandidate
	var ids, urls string
	err := d.db.QueryRow(`SELECT claim_key,source_ids,source_urls,assessment_json,status,first_seen,last_seen FROM rumour_candidates WHERE claim_key=?`, key).Scan(&c.ClaimKey, &ids, &urls, &c.AssessmentJSON, &c.Status, &c.FirstSeen, &c.LastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(ids), &c.SourceIDs)
	_ = json.Unmarshal([]byte(urls), &c.SourceURLs)
	return &c, nil
}
func (d *DB) MarkRumourCandidatePublished(key string) error {
	_, err := d.db.Exec(`UPDATE rumour_candidates SET status='published',last_seen=? WHERE claim_key=?`, time.Now().UTC(), key)
	return err
}
func boundedUnique(values []string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// GoldenExample is an approved (technique, evidence) pair harvested from a
// human-approved brief. It grows threat-bot's own labelled corpus alongside the
// vendored TRAM dataset and is available as a few-shot pool.
type GoldenExample struct {
	Technique string
	Evidence  string
	Source    string
}

// AddGoldenExample upserts an approved (technique, evidence) pair. Idempotent
// on (technique, evidence) so re-approving a brief does not duplicate rows.
func (d *DB) AddGoldenExample(technique, evidence, source string) error {
	if technique == "" || evidence == "" {
		return nil
	}
	_, err := d.db.Exec(
		`INSERT OR IGNORE INTO golden_examples (technique, evidence, source) VALUES (?, ?, ?)`,
		technique, evidence, source,
	)
	return err
}

// GoldenExamples returns all harvested examples, newest first.
func (d *DB) GoldenExamples() ([]GoldenExample, error) {
	rows, err := d.db.Query(`SELECT technique, evidence, COALESCE(source, '') FROM golden_examples ORDER BY approved_at DESC`)
	if err != nil {
		return nil, err
	}
	defer discardClose(rows)
	var out []GoldenExample
	for rows.Next() {
		var e GoldenExample
		if err := rows.Scan(&e.Technique, &e.Evidence, &e.Source); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetLLMCache returns a previously decoded structured LLM response.
func (d *DB) GetLLMCache(key string) (string, bool, error) {
	var response string
	err := d.db.QueryRow(`SELECT response_json FROM llm_cache WHERE cache_key = ?`, key).Scan(&response)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading LLM cache: %w", err)
	}
	return response, true, nil
}

// PutLLMCache records a successfully decoded structured LLM response.
func (d *DB) PutLLMCache(key, response string) error {
	_, err := d.db.Exec(`
		INSERT INTO llm_cache (cache_key, response_json, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(cache_key) DO UPDATE SET
			response_json = excluded.response_json,
			created_at = excluded.created_at
	`, key, response, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("writing LLM cache: %w", err)
	}
	return nil
}

// QuarantinePipelineItem durably records a terminal malformed brief. The
// source ID is unique so retries or restarts cannot create alerting loops.
func (d *DB) QuarantinePipelineItem(sourceID, source, title, rawOutput, errorMessage string) error {
	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO pipeline_quarantine
			(source_id, source, title, raw_output, error_message, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, sourceID, source, title, rawOutput, errorMessage, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("quarantining pipeline item: %w", err)
	}
	return nil
}

// RecordGroundingAttempt counts one failed grounding pass for an item and
// returns the new total, so the pipeline can stop retrying a brief that never
// becomes grounded.
func (d *DB) RecordGroundingAttempt(sourceID string) (int, error) {
	var attempts int
	err := d.db.QueryRow(`
		INSERT INTO grounding_attempts (source_id, attempts, updated_at)
		VALUES (?, 1, ?)
		ON CONFLICT(source_id) DO UPDATE SET
			attempts = attempts + 1,
			updated_at = excluded.updated_at
		RETURNING attempts
	`, sourceID, time.Now().UTC()).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("recording grounding attempt: %w", err)
	}
	return attempts, nil
}

// ClearGroundingAttempts forgets an item's failed grounding passes.
func (d *DB) ClearGroundingAttempts(sourceID string) error {
	if _, err := d.db.Exec(`DELETE FROM grounding_attempts WHERE source_id = ?`, sourceID); err != nil {
		return fmt.Errorf("clearing grounding attempts: %w", err)
	}
	return nil
}

// PipelineQuarantineReason returns the recorded reason for a quarantined item.
func (d *DB) PipelineQuarantineReason(sourceID string) (string, bool, error) {
	var reason string
	err := d.db.QueryRow(`SELECT error_message FROM pipeline_quarantine WHERE source_id = ?`, sourceID).Scan(&reason)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading pipeline quarantine: %w", err)
	}
	return reason, true, nil
}

// RecordDraftUpdate atomically updates a draft's brief YAML, bumps the
// lastmod timestamp, increments the update counter, and appends an
// event to the update log (capped at 5 entries — the publisher only
// renders the last 5 in the "What's new" section). The combination
// runs inside a single transaction so a partial failure can't leave
// the lastmod metadata inconsistent with the YAML.
const maxUpdateLogEntries = 5

// DigestState holds the last-published state for a digest type.
type DigestState struct {
	DigestType    string // "daily" or "weekly"
	LastPublished time.Time
	Period        string // e.g. "2026-03-25"
}

// DigestCluster tracks cluster state across digest runs.
type DigestCluster struct {
	DigestID   string
	ClusterKey string
	BriefIDs   string // JSON array
	Summary    string
	CreatedAt  time.Time
}

// GetDigestState retrieves the last-published state for a digest type.
func (d *DB) GetDigestState(digestType string) (*DigestState, error) {
	row := d.db.QueryRow(
		"SELECT digest_type, last_published, period FROM digest_state WHERE digest_type = ?",
		digestType,
	)
	var state DigestState
	err := row.Scan(&state.DigestType, &state.LastPublished, &state.Period)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &state, nil
}

// SaveDigestState upserts the last-published state for a digest type.
func (d *DB) SaveDigestState(digestType string, lastPublished time.Time, period string) error {
	_, err := d.db.Exec(
		`INSERT INTO digest_state (digest_type, last_published, period) VALUES (?, ?, ?)
		 ON CONFLICT(digest_type) DO UPDATE SET last_published = excluded.last_published, period = excluded.period`,
		digestType, lastPublished, period,
	)
	return err
}

// SaveDigestCluster upserts a digest cluster.
func (d *DB) SaveDigestCluster(c DigestCluster) error {
	_, err := d.db.Exec(
		`INSERT INTO digest_clusters (digest_id, cluster_key, brief_ids, summary, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(digest_id, cluster_key) DO UPDATE SET brief_ids = excluded.brief_ids, summary = excluded.summary`,
		c.DigestID, c.ClusterKey, c.BriefIDs, c.Summary, time.Now(),
	)
	return err
}

// ListDigestClusters returns all clusters for a given digest ID.
func (d *DB) ListDigestClusters(digestID string) ([]DigestCluster, error) {
	rows, err := d.db.Query(
		"SELECT digest_id, cluster_key, brief_ids, summary, created_at FROM digest_clusters WHERE digest_id = ? ORDER BY cluster_key",
		digestID,
	)
	if err != nil {
		return nil, err
	}
	defer discardClose(rows)

	var clusters []DigestCluster
	for rows.Next() {
		var c DigestCluster
		if err := rows.Scan(&c.DigestID, &c.ClusterKey, &c.BriefIDs, &c.Summary, &c.CreatedAt); err != nil {
			return nil, err
		}
		clusters = append(clusters, c)
	}
	return clusters, rows.Err()
}

// epssLoadBatchRows bounds each write transaction of an EPSS reload, so the
// reload never holds SQLite's single write lock for long and the WAL can be
// checkpointed between batches.
const epssLoadBatchRows = 5000
