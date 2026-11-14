package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sigmaRuleWithHashes renders a Sigma rule whose detection lists n hashes,
// like SigmaHQ's vulnerable-driver rule.
func sigmaRuleWithHashes(n int) string {
	var b strings.Builder
	b.WriteString("title: Vulnerable Driver Load\nid: 7aaaf4b9-1111-4f8c-9a3e-000000000000\nlogsource:\n  category: driver_load\n  product: windows\ndetection:\n  selection:\n    Hashes|contains:\n")
	for i := range n {
		fmt.Fprintf(&b, "      - 'SHA256=%064x'\n", i)
	}
	b.WriteString("  condition: selection\nlevel: high\n")
	return b.String()
}

// An oversized rule fails the fetch instead of arriving truncated: a cut
// hash list still parses, and would publish with part of its detection.
func TestFetchSigmaRuleRejectsOversizedRules(t *testing.T) {
	rules := map[string]string{
		"/SigmaHQ/sigma/abc/rules/today.yml":     sigmaRuleWithHashes(3500),  // ~300KB, today's largest rule
		"/SigmaHQ/sigma/abc/rules/oversized.yml": sigmaRuleWithHashes(30000), // past maxSigmaRuleBytes
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(rules[r.URL.Path]))
	}))
	defer srv.Close()

	rule, content, err := fetchSigmaRuleFrom(context.Background(), srv.Client(), "rules/today.yml", "abc", srv.URL)
	if err != nil {
		t.Fatalf("rule the size of today's largest failed: %v", err)
	}
	if rule.Title != "Vulnerable Driver Load" || len(content) != len(rules["/SigmaHQ/sigma/abc/rules/today.yml"]) {
		t.Errorf("got title %q and %d bytes, want the whole rule", rule.Title, len(content))
	}

	if len(rules["/SigmaHQ/sigma/abc/rules/oversized.yml"]) <= maxSigmaRuleBytes {
		t.Fatal("oversized fixture is within the cap")
	}
	if _, _, err := fetchSigmaRuleFrom(context.Background(), srv.Client(), "rules/oversized.yml", "abc", srv.URL); err == nil {
		t.Error("oversized rule was accepted")
	}
}
