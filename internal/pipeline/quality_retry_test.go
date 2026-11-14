package pipeline

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestPipelineRetainsRecentCriticalDisclosureRejectedByQualityModel(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	model := &qualityMockLLM{score: QualityScore{Credibility: 4, Actionability: 1, Novelty: 3}}
	pipe := New(Config{DB: db, LLMClient: model, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{
		SourceID: "oss-security:php-notice", Source: "oss-security",
		Title: "Upcoming Critical PHP Security Release", URL: "https://seclists.org/oss-sec/2026/q4/266",
		Content:     strings.Repeat("The vendor reports two critical vulnerabilities and an upcoming security release. ", 10),
		PublishedAt: time.Now(),
	}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Fatal("recent critical disclosure was permanently marked seen after one low model score")
	}
}
