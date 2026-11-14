package storage

import "time"

type ProcessingSummary struct {
	Since                     time.Time `json:"since"`
	ProcessPasses             int       `json:"process_passes"`
	DistinctSources           int       `json:"distinct_sources"`
	DistinctInputs            int       `json:"distinct_inputs"`
	RepeatedInputPasses       int       `json:"repeated_input_passes"`
	CompletedPasses           int       `json:"completed_passes"`
	ErrorPasses               int       `json:"error_passes"`
	GroundingAccepted         int       `json:"grounding_accepted"`
	GroundingRejected         int       `json:"grounding_rejected"`
	GroundingUnavailable      int       `json:"grounding_unavailable"`
	PendingCandidates         int       `json:"pending_candidates"`
	PendingPublicationIntents int       `json:"pending_publication_intents"`
}

func (d *DB) ProcessingSummary(since time.Time) (ProcessingSummary, error) {
	s := ProcessingSummary{Since: since.UTC()}
	stamp := since.UTC().Format(time.RFC3339Nano)
	err := d.db.QueryRow(`SELECT COUNT(*),COUNT(DISTINCT source_id),COALESCE(SUM(outcome='completed'),0),COALESCE(SUM(outcome='error'),0) FROM processing_history WHERE stage='process' AND created_at>=?`, stamp).Scan(&s.ProcessPasses, &s.DistinctSources, &s.CompletedPasses, &s.ErrorPasses)
	if err != nil {
		return s, err
	}
	err = d.db.QueryRow(`SELECT COUNT(*) FROM (SELECT DISTINCT source_id,input_key FROM processing_history WHERE stage='process' AND created_at>=?)`, stamp).Scan(&s.DistinctInputs)
	if err != nil {
		return s, err
	}
	s.RepeatedInputPasses = s.ProcessPasses - s.DistinctInputs
	err = d.db.QueryRow(`SELECT COALESCE(SUM(outcome='accepted'),0),COALESCE(SUM(outcome='rejected'),0),COALESCE(SUM(outcome='unavailable'),0) FROM processing_history WHERE stage='grounding' AND created_at>=?`, stamp).Scan(&s.GroundingAccepted, &s.GroundingRejected, &s.GroundingUnavailable)
	if err != nil {
		return s, err
	}
	err = d.db.QueryRow("SELECT (SELECT COUNT(*) FROM processing_checkpoints),(SELECT COUNT(*) FROM publication_intents)").Scan(&s.PendingCandidates, &s.PendingPublicationIntents)
	return s, err
}

type BatchJobReference struct {
	RequestKey string `json:"request_key"`
	Reference  string `json:"reference"`
}

func (d *DB) ListBatchJobReferences() ([]BatchJobReference, error) {
	rows, err := d.db.Query("SELECT request_key,job_name FROM llm_batch_jobs ORDER BY created_at,request_key")
	if err != nil {
		return nil, err
	}
	defer discardClose(rows)
	out := []BatchJobReference{}
	for rows.Next() {
		var r BatchJobReference
		if err := rows.Scan(&r.RequestKey, &r.Reference); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
