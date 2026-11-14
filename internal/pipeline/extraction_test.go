package pipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestThreatExtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": `{
				"tactics": ["initial-access", "execution"],
				"techniques": ["T1566.001", "T1059.003"],
				"iocs": [
					{"type": "domain", "value": "evil.example.com", "context": "C2 server"},
					{"type": "hash_sha256", "value": "abcdef1234567890", "context": "Malware payload"}
				],
				"cves": ["CVE-2026-1234"],
				"platforms": ["windows"],
				"summary": "Spearphishing campaign delivering malware"
			}`,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	extractor := NewThreatExtractor(client)

	item := scraper.RawItem{
		Title:   "New APT Campaign Targeting Finance",
		Content: "Researchers discovered a spearphishing campaign...",
		Source:  "cisa",
	}

	result, err := extractor.Extract(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Tactics) != 2 {
		t.Errorf("expected 2 tactics, got %d", len(result.Tactics))
	}
	if len(result.IOCs) != 2 {
		t.Errorf("expected 2 IOCs, got %d", len(result.IOCs))
	}
	if len(result.CVEs) != 1 {
		t.Errorf("expected 1 CVE, got %d", len(result.CVEs))
	}
}
