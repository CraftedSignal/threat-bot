package storage

// FindBySourceID preserves the canonical draft association when a later source
// revision changes its URL, title, or subject identifiers.
func (d *DB) FindBySourceID(sourceID string) ([]ContentIndexEntry, error) {
	if sourceID == "" {
		return nil, nil
	}
	return d.scanContentIndex(
		`SELECT id, cve_id, title_hash, IFNULL(fingerprint_hash, ''), IFNULL(product_fingerprint_hash, ''), IFNULL(title_norm, ''), IFNULL(content_hash, ''), IFNULL(vendor_cycle_key, ''), IFNULL(source_url_hash, ''), IFNULL(source_published_day, ''), draft_id, source_id, source, cve_context, created_at
		 FROM content_index WHERE source_id = ? ORDER BY id ASC`, sourceID,
	)
}
