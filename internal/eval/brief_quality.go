package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BriefQualityCase is an independently labelled synthetic source/candidate pair.
// These are publication contract tests, not captured production snapshots,
// recorded model predictions or model-accuracy claims.
type BriefQualityCase struct {
	ID                  string `json:"id"`
	SourcePath          string `json:"source_path"`
	CandidatePath       string `json:"candidate_path"`
	SourceProvenance    string `json:"source_provenance"`
	CandidateProvenance string `json:"candidate_provenance"`
	Expected            string `json:"expected"`
	Category            string `json:"category"`
	RejectContains      string `json:"reject_contains"`
	Source              []byte `json:"-"`
	Candidate           []byte `json:"-"`
}

type BriefQualityBaseline struct {
	Version                 int      `json:"version"`
	Kind                    string   `json:"kind"`
	MinimumCases            int      `json:"minimum_cases"`
	RequiredCaseIDs         []string `json:"required_case_ids"`
	RequiredRoutes          []string `json:"required_routes"`
	MinimumRejectionRecall  float64  `json:"minimum_rejection_recall"`
	MinimumAcceptanceRecall float64  `json:"minimum_acceptance_recall"`
}

type BriefQualityCorpus struct {
	Version  int                  `json:"version"`
	Cases    []BriefQualityCase   `json:"cases"`
	Baseline BriefQualityBaseline `json:"-"`
}

// LoadBriefQualityCorpus requires every committed input. Missing fixtures,
// baselines, labels or provenance are errors rather than a disabled evaluation.
func LoadBriefQualityCorpus(dir string) (*BriefQualityCorpus, error) {
	read := func(name string, out any) error {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("required quality input %s: %w", name, err)
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("quality input %s: %w", name, err)
		}
		return nil
	}
	var corpus BriefQualityCorpus
	if err := read("corpus.json", &corpus); err != nil {
		return nil, err
	}
	if err := read("baseline.json", &corpus.Baseline); err != nil {
		return nil, err
	}
	b := corpus.Baseline
	if corpus.Version != 1 || b.Version != 1 || b.Kind != "deterministic-publication-contract" || b.MinimumCases < 1 || len(b.RequiredCaseIDs) < 1 || len(b.RequiredRoutes) < 1 || b.MinimumAcceptanceRecall <= 0 || b.MinimumAcceptanceRecall > 1 || b.MinimumRejectionRecall <= 0 || b.MinimumRejectionRecall > 1 {
		return nil, fmt.Errorf("invalid or empty required quality baseline")
	}
	if len(corpus.Cases) < b.MinimumCases {
		return nil, fmt.Errorf("quality corpus has %d cases, baseline requires %d", len(corpus.Cases), b.MinimumCases)
	}
	seen := map[string]bool{}
	for i := range corpus.Cases {
		c := &corpus.Cases[i]
		if c.ID == "" || seen[c.ID] || c.SourceProvenance == "" || c.CandidateProvenance == "" || c.Category == "" || (c.Expected != "accept" && c.Expected != "reject") {
			return nil, fmt.Errorf("invalid quality case %q: unique ID, provenance, category and explicit accept/reject label required", c.ID)
		}
		seen[c.ID] = true
		for _, entry := range []struct {
			path string
			dst  *[]byte
		}{{c.SourcePath, &c.Source}, {c.CandidatePath, &c.Candidate}} {
			clean := filepath.Clean(entry.path)
			if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("quality case %s has invalid fixture path %q", c.ID, entry.path)
			}
			data, err := os.ReadFile(filepath.Join(dir, clean))
			if err != nil {
				return nil, fmt.Errorf("quality case %s input %s: %w", c.ID, entry.path, err)
			}
			if len(strings.TrimSpace(string(data))) == 0 {
				return nil, fmt.Errorf("quality case %s input %s is empty", c.ID, entry.path)
			}
			*entry.dst = data
		}
	}
	for _, id := range b.RequiredCaseIDs {
		if !seen[id] {
			return nil, fmt.Errorf("required quality case %s is missing", id)
		}
	}
	return &corpus, nil
}
