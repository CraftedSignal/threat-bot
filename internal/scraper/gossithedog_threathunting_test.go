package scraper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGossiTheDogThreatHunting_Poll(t *testing.T) {
	now := time.Now().UTC()

	commits := []ghCommit{
		{
			SHA: "aaa12345bbb67890aaa12345bbb67890aaa12345",
			Commit: struct {
				Author struct {
					Date time.Time `json:"date"`
				} `json:"author"`
				Message string `json:"message"`
			}{
				Author: struct {
					Date time.Time `json:"date"`
				}{Date: now},
				Message: "Add ShieldBreak hunting query",
			},
		},
	}

	detail := ghCommitDetail{
		Files: []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		}{
			{Filename: "AdvancedHuntingQueries/ShieldBreak.kql", Status: "added"},
			{Filename: "AdvancedHuntingQueries/Hunt-PrintNightmare", Status: "added"}, // no extension
			{Filename: "YARA/BazaLoaderBackdoor.yar", Status: "modified"},
			{Filename: "README.md", Status: "modified"},                  // repo root, must be excluded
			{Filename: "porg.jpg", Status: "added"},                      // repo root, must be excluded
			{Filename: "EDR-BlockRules/old-rule.xml", Status: "removed"}, // removed, must be excluded
		},
	}

	const ruleContent = "let ShieldBreak = SecurityEvent | where ..."

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/GossiTheDog/ThreatHunting/commits", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(commits)
	})
	mux.HandleFunc("/repos/GossiTheDog/ThreatHunting/commits/aaa12345bbb67890aaa12345bbb67890aaa12345", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(detail)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ruleContent))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g := &GossiTheDogThreatHunting{
		client:  srv.Client(),
		tokenFn: func() string { return "" },
	}

	items, err := g.pollFrom(context.Background(), now.Add(-24*time.Hour), srv.URL, srv.URL)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items (dir-allowlisted, non-removed files only), got %d: %+v", len(items), items)
	}

	byPath := make(map[string]RawItem)
	for _, it := range items {
		byPath[it.Title] = it
	}

	if _, ok := byPath["README.md"]; ok {
		t.Error("README.md at repo root should have been excluded")
	}
	if _, ok := byPath["porg.jpg"]; ok {
		t.Error("porg.jpg at repo root should have been excluded")
	}
	if _, ok := byPath["EDR-BlockRules/old-rule.xml"]; ok {
		t.Error("removed file should have been excluded")
	}

	kql, ok := byPath["AdvancedHuntingQueries/Hunt-PrintNightmare"]
	if !ok {
		t.Fatal("extensionless file under an allowed directory should have been included")
	}
	if kql.Source != "gossithedog-threathunting" {
		t.Errorf("Source = %q, want gossithedog-threathunting", kql.Source)
	}
	if want := "https://github.com/GossiTheDog/ThreatHunting/blob/master/AdvancedHuntingQueries/Hunt-PrintNightmare"; kql.URL != want {
		t.Errorf("URL = %q, want %q", kql.URL, want)
	}
	if kql.SigmaRule != nil {
		t.Error("SigmaRule should be nil for non-Sigma content")
	}
	if kql.Content != ruleContent {
		t.Errorf("Content = %q, want raw file body %q", kql.Content, ruleContent)
	}
}
