package scraper

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func collectEPSSRows(t *testing.T, csv string) map[string]storage.EPSSRow {
	t.Helper()
	scores := map[string]storage.EPSSRow{}
	for row, err := range EPSSRows(strings.NewReader(csv)) {
		if err != nil {
			t.Fatal(err)
		}
		scores[row.CVEID] = row
	}
	return scores
}

func TestEPSSRows(t *testing.T) {
	scores := collectEPSSRows(t, `#model_version:v2024.01.01,score_date:2026-03-30
cve,epss,percentile
CVE-2026-1234,0.87,0.99
CVE-2026-5678,0.02,0.15
CVE-2025-0001,0.45,0.82
`)
	if len(scores) != 3 {
		t.Fatalf("expected 3 scores, got %d", len(scores))
	}
	s := scores["CVE-2026-1234"]
	if s.EPSS != 0.87 || s.Percentile != 0.99 {
		t.Errorf("CVE-2026-1234: got epss=%f percentile=%f", s.EPSS, s.Percentile)
	}
	s2 := scores["CVE-2026-5678"]
	if s2.EPSS != 0.02 {
		t.Errorf("CVE-2026-5678: got epss=%f", s2.EPSS)
	}
}

func TestEPSSRows_Empty(t *testing.T) {
	scores := collectEPSSRows(t, `#model_version:v2024.01.01,score_date:2026-03-30
cve,epss,percentile
`)
	if len(scores) != 0 {
		t.Fatalf("expected 0 scores, got %d", len(scores))
	}
}

type epssTransport struct{ csv *string }

func (tr epssTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(*tr.csv)); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(&gz), Header: http.Header{}, Request: req}, nil
}

// Each refresh replaces the stored score set, so a CVE that drops out of the
// upstream file stops resolving.
func TestEPSSCacheRefreshReplacesStoredScores(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	csv := "cve,epss,percentile\nCVE-2026-0001,0.5,0.9\nCVE-2026-0002,0.1,0.4\n"
	cache := NewEPSSCache(&http.Client{Transport: epssTransport{&csv}}, db)
	if err := cache.Refresh(); err != nil {
		t.Fatal(err)
	}
	if s, ok := cache.Lookup("CVE-2026-0001"); !ok || s.EPSS != 0.5 || s.Percentile != 0.9 {
		t.Errorf("CVE-2026-0001 after first refresh = %+v, %v", s, ok)
	}

	csv = "cve,epss,percentile\nCVE-2026-0001,0.8,0.97\n"
	if err := cache.Refresh(); err != nil {
		t.Fatal(err)
	}
	if s, ok := cache.Lookup("CVE-2026-0001"); !ok || s.EPSS != 0.8 {
		t.Errorf("CVE-2026-0001 after second refresh = %+v, %v", s, ok)
	}
	if _, ok := cache.Lookup("CVE-2026-0002"); ok {
		t.Error("CVE-2026-0002 is no longer in the EPSS file but still resolves")
	}
}

// A download that breaks mid-file keeps the previous scores.
func TestEPSSCacheRefreshKeepsScoresOnBadFile(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	csv := "cve,epss,percentile\nCVE-2026-0001,0.5,0.9\n"
	cache := NewEPSSCache(&http.Client{Transport: epssTransport{&csv}}, db)
	if err := cache.Refresh(); err != nil {
		t.Fatal(err)
	}
	csv = "cve,epss,percentile\nCVE-2026-0001,0.6,0.91\nCVE-2026-0003,\"unterminated\n"
	if err := cache.Refresh(); err == nil {
		t.Fatal("expected the malformed file to fail the refresh")
	}
	if s, ok := cache.Lookup("CVE-2026-0001"); !ok || s.EPSS != 0.5 {
		t.Errorf("CVE-2026-0001 after failed refresh = %+v, %v, want the previous 0.5", s, ok)
	}
}
