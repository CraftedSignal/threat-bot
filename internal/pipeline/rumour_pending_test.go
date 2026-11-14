package pipeline

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

type pendingRumourLLM struct{}

func (pendingRumourLLM) Generate(context.Context, string, string) (string, error) { return "", nil }
func (pendingRumourLLM) GenerateJSON(_ context.Context, _, _ string, out any) error {
	switch value := out.(type) {
	case *QualityScore:
		*value = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5, Summary: "concrete report"}
	case *ExtractionResult:
		*value = ExtractionResult{
			CVEs: []string{"CVE-2026-111497"}, AffectedProducts: []string{"Brotli"}, VulnClass: "oob",
			ClaimAssessment: &ClaimAssessment{Claim: "Brotli decompression can disclose heap memory", Status: "unverified", Likelihood: "unlikely", Evidence: []ClaimEvidence{{Type: "mechanism", Detail: "malformed stream", SourceURL: "https://x.com/a/status/3"}}, Gaps: []string{"not reproduced"}, EstablishedFacts: []string{"post is public"}},
		}
	}
	return nil
}

type mutableStatusProvider struct{ incomplete bool }

func (p *mutableStatusProvider) FetchStatus(context.Context, string) (scraper.SocialStatus, error) {
	return scraper.SocialStatus{ID: "3", URL: "https://x.com/a/status/3", Text: "CVE-2026-111497 Brotli decompression can disclose heap memory. " + strings.Repeat("Technical evidence. ", 8), Incomplete: p.incomplete}, nil
}

func TestIncompleteRumourResolutionRemainsPendingThenReassesses(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	provider := &mutableStatusProvider{incomplete: true}
	model := pendingRumourLLM{}
	pipe := New(Config{
		DB: db, LLMClient: model, FastLLMClient: model, QualityThreshold: 3,
		SourceConfidence: map[string]float64{"public-web-social-search": 1},
		SocialProvider:   provider, SocialThreadDepth: 6,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	item := scraper.RawItem{
		SourceID: "public-web-social-search:3", Source: "public-web-social-search", Title: "Brotli heap disclosure",
		URL: "https://x.com/a/status/3", Content: strings.Repeat("Indexed security snippet. ", 8), Enriched: true,
		Discovery: &scraper.DiscoveryContext{Platform: "x", OriginalURL: "https://x.com/a/status/3"},
	}

	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil || seen {
		t.Fatalf("incomplete candidate seen=%v err=%v", seen, err)
	}
	claimKey := ClaimKey(&ExtractionResult{CVEs: []string{"CVE-2026-111497"}, AffectedProducts: []string{"Brotli"}, VulnClass: "oob", ClaimAssessment: &ClaimAssessment{Claim: "Brotli decompression can disclose heap memory"}})
	candidate, err := db.GetRumourCandidate(claimKey)
	if err != nil || candidate == nil || candidate.Status != "resolve_pending" {
		t.Fatalf("candidate=%+v err=%v", candidate, err)
	}

	provider.incomplete = false
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	seen, err = db.HasSeen(item.SourceID)
	if err != nil || !seen {
		t.Fatalf("resolved below-gate candidate seen=%v err=%v", seen, err)
	}
	candidate, err = db.GetRumourCandidate(candidate.ClaimKey)
	if err != nil || candidate.Status != "below_gate" {
		t.Fatalf("reassessed candidate=%+v err=%v", candidate, err)
	}
}
