package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// GetCorrelationTag returns the cached tag for a technique hash, or "" if not found.
func (d *DB) GetCorrelationTag(techniqueHash string) (string, error) {
	var tag string
	if err := d.db.QueryRow("SELECT tag FROM correlation_tags WHERE technique_hash = ?", techniqueHash).Scan(&tag); err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("reading correlation tag: %w", err)
	}
	return tag, nil
}

// SaveCorrelationTag upserts a correlation tag for a technique hash.
func (d *DB) SaveCorrelationTag(techniqueHash, tag string) error {
	_, err := d.db.Exec(
		`INSERT INTO correlation_tags (technique_hash, tag, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(technique_hash) DO UPDATE SET tag = excluded.tag`,
		techniqueHash, tag, time.Now(),
	)
	return err
}

// ContentIndexEntry represents a row in the content_index table.
type ContentIndexEntry struct {
	ID                     int64
	CVEID                  string
	TitleHash              string
	FingerprintHash        string // SHA-256 of vendor|product|vuln_class — D1 fallback axis
	ProductFingerprintHash string // SHA-256 of vendor|product (no class) — tertiary axis
	TitleNorm              string // normalized lowercase title for token-Jaccard sim — D3
	DraftID                string
	SourceID               string
	Source                 string
	CVEContext             string // JSON-encoded CVEContext
	ContentHash            string // SHA-256 of normalized title+content — literal-duplicate axis
	VendorCycleKey         string // normalize(vendor)|YYYY-MM — vendor patch-cycle roundup axis
	SourceURLHash          string // SHA-256 normalized source URL
	SourcePublishedDay     string // YYYY-MM-DD UTC source published day
	ClaimKey               string
	CreatedAt              time.Time
}

func (d *DB) FindByClaimKey(key string) ([]ContentIndexEntry, error) {
	if key == "" {
		return nil, nil
	}
	rows, err := d.db.Query(`SELECT id,cve_id,title_hash,IFNULL(fingerprint_hash,''),IFNULL(product_fingerprint_hash,''),IFNULL(title_norm,''),IFNULL(content_hash,''),IFNULL(vendor_cycle_key,''),IFNULL(source_url_hash,''),IFNULL(source_published_day,''),IFNULL(claim_key,''),draft_id,source_id,source,cve_context,created_at FROM content_index WHERE claim_key=?`, key)
	if err != nil {
		return nil, err
	}
	defer discardClose(rows)
	var out []ContentIndexEntry
	for rows.Next() {
		var e ContentIndexEntry
		var ctx sql.NullString
		if err := rows.Scan(&e.ID, &e.CVEID, &e.TitleHash, &e.FingerprintHash, &e.ProductFingerprintHash, &e.TitleNorm, &e.ContentHash, &e.VendorCycleKey, &e.SourceURLHash, &e.SourcePublishedDay, &e.ClaimKey, &e.DraftID, &e.SourceID, &e.Source, &ctx, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.CVEContext = ctx.String
		out = append(out, e)
	}
	return out, rows.Err()
}

// FindByCVE returns all content index entries for a given CVE ID.
func (d *DB) FindByCVE(cveID string) ([]ContentIndexEntry, error) {
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE cve_id = ?`,
		cveID,
	)
}

// FindByTitleHash returns all content index entries for a given title hash.
func (d *DB) FindByTitleHash(hash string) ([]ContentIndexEntry, error) {
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE title_hash = ?`,
		hash,
	)
}

// FindByVendorCycle returns index entries sharing a vendor patch-cycle key
// (normalize(vendor)|YYYY-MM) — used to fold a vendor's monthly advisory CVEs
// into one roundup brief. The YYYY-MM in the key already bounds recency.
func (d *DB) FindByVendorCycle(key string) ([]ContentIndexEntry, error) {
	if key == "" {
		return nil, nil
	}
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE vendor_cycle_key = ?`,
		key,
	)
}

// FindByContentHash returns index entries whose normalized content hash
// matches — used to drop literal / near-literal cross-source republications
// (syndicated content) that carry no CVE and only source-tag title diffs.
func (d *DB) FindByContentHash(hash string) ([]ContentIndexEntry, error) {
	if hash == "" {
		return nil, nil
	}
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE content_hash = ?`,
		hash,
	)
}

// FindBySourceURLHash returns content index entries sharing normalized source URL.
func (d *DB) FindBySourceURLHash(hash string) ([]ContentIndexEntry, error) {
	if hash == "" {
		return nil, nil
	}
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE source_url_hash = ?`,
		hash,
	)
}

// FindByFingerprint returns content index entries that share the
// vendor+product+class fingerprint and were created within the
// rolling window. Window of 0 means no time bound (all history).
func (d *DB) FindByFingerprint(hash string, window time.Duration) ([]ContentIndexEntry, error) {
	if hash == "" {
		return nil, nil
	}
	if window <= 0 {
		return d.scanContentIndex(
			`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
			 FROM content_index WHERE fingerprint_hash = ?`,
			hash,
		)
	}
	since := time.Now().Add(-window)
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE fingerprint_hash = ? AND created_at >= ?`,
		hash, since,
	)
}

func (d *DB) scanContentIndex(q string, args ...any) ([]ContentIndexEntry, error) {
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer discardClose(rows)

	var entries []ContentIndexEntry
	for rows.Next() {
		var e ContentIndexEntry
		var cveCtx sql.NullString
		if err := rows.Scan(&e.ID, &e.CVEID, &e.TitleHash, &e.FingerprintHash, &e.ProductFingerprintHash, &e.TitleNorm, &e.ContentHash, &e.VendorCycleKey, &e.SourceURLHash, &e.SourcePublishedDay, &e.DraftID, &e.SourceID, &e.Source, &cveCtx, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.CVEContext = cveCtx.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// FindByProductAndNoCVE returns content index entries that share the
// product-only fingerprint (vendor|product), have no CVE indexed, and were
// created within the rolling window. Used as a tertiary dedup axis for the
// "new CVE report vs. earlier no-CVE advisory for the same product" pattern.
func (d *DB) FindByProductAndNoCVE(productFP string, window time.Duration) ([]ContentIndexEntry, error) {
	if productFP == "" {
		return nil, nil
	}
	since := time.Now().Add(-window)
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE product_fingerprint_hash = ? AND (cve_id IS NULL OR cve_id = '') AND created_at >= ?`,
		productFP, since,
	)
}

// FindByProduct returns content index entries that share the product-only
// fingerprint (vendor|product) created within the rolling window, regardless
// of whether they already carry a CVE. Used to merge distinct CVEs affecting
// the same specific product disclosed close together (e.g. cap-go).
func (d *DB) FindByProduct(productFP string, window time.Duration) ([]ContentIndexEntry, error) {
	if productFP == "" {
		return nil, nil
	}
	since := time.Now().Add(-window)
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE product_fingerprint_hash = ? AND created_at >= ?`,
		productFP, since,
	)
}

// FindByProductAndDay returns entries for same specific product and UTC source-published day.
func (d *DB) FindByProductAndDay(productFP, day string) ([]ContentIndexEntry, error) {
	if productFP == "" || day == "" {
		return nil, nil
	}
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE product_fingerprint_hash = ? AND source_published_day = ?`,
		productFP, day,
	)
}

// CountDistinctSourcesForCVE returns the number of distinct sources that have
// reported a given CVE ID in the content index.
func (d *DB) CountDistinctSourcesForCVE(cveID string) (int, error) {
	var count int
	err := d.db.QueryRow(
		"SELECT COUNT(DISTINCT source) FROM content_index WHERE cve_id = ?",
		cveID,
	).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// IndexContent inserts a new content index entry.
func (d *DB) IndexContent(entry *ContentIndexEntry) error {
	return insertContentIndex(d.db, entry)
}
