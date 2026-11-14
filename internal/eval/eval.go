package eval

import (
	"context"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// PredictFunc returns the predicted technique IDs for one document.
type PredictFunc func(ctx context.Context, doc EvalDoc) ([]string, error)

// ExtractorPredict builds a PredictFunc backed by threat-bot's real extractor.
func ExtractorPredict(client llm.Client) PredictFunc {
	ex := pipeline.NewThreatExtractor(client)
	return func(ctx context.Context, doc EvalDoc) ([]string, error) {
		res, err := ex.Extract(ctx, scraper.RawItem{Title: doc.Title, Content: doc.Text})
		if err != nil {
			return nil, err
		}
		return res.Techniques, nil
	}
}

// Run extracts predictions for every doc and scores them at the given
// normalisation granularity. A per-doc extraction error yields an empty
// prediction (counted as all-false-negatives) rather than aborting the run.
func Run(ctx context.Context, docs []EvalDoc, predict PredictFunc, norm func(string) string) Report {
	results := make([]DocResult, 0, len(docs))
	for _, d := range docs {
		pred, err := predict(ctx, d)
		if err != nil {
			pred = nil
		}
		results = append(results, DocResult{Gold: d.GoldTechniques, Pred: pred})
	}
	return Score(results, norm)
}
