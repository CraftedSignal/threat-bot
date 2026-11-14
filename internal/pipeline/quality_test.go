package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestQualityGate_Pass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": `{"credibility": 4, "actionability": 5, "novelty": 4, "summary": "real threat"}`,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	gate := NewQualityGate(client, 3.0)

	item := scraper.RawItem{
		Title:   "Critical RCE in Apache Struts",
		Content: "A new remote code execution vulnerability...",
		Source:  "cisa",
	}

	score, pass, err := gate.Evaluate(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	if !pass {
		t.Errorf("expected pass, score: %f", score)
	}
}

func TestQualityGate_Fail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": `{"credibility": 1, "actionability": 2, "novelty": 1, "summary": "AI hype article"}`,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	gate := NewQualityGate(client, 3.0)

	item := scraper.RawItem{
		Title:   "AI Will Revolutionize Cybersecurity",
		Content: "Artificial intelligence is changing everything...",
		Source:  "reddit-netsec",
	}

	score, pass, err := gate.Evaluate(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	if pass {
		t.Errorf("expected fail, score: %f", score)
	}
}

func TestQualityGate_BypassForCISAKEV(t *testing.T) {
	// LLM server should never be called for bypass sources.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("LLM should not be called for bypass source")
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	gate := NewQualityGate(client, 3.0)

	item := scraper.RawItem{
		Title:   "CVE-2026-34197 - Apache ActiveMQ RCE",
		Content: "CVE: CVE-2026-34197\nVendor: Apache\nProduct: ActiveMQ\nAction: Apply updates\nDue Date: 2026-04-30",
		Source:  "cisa-kev",
	}

	score, pass, err := gate.Evaluate(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	if !pass {
		t.Errorf("cisa-kev items must bypass quality gate, score: %f", score)
	}
	if score != 5.0 {
		t.Errorf("bypass score should be 5.0 (max): got %f", score)
	}
}

func TestQualityGatePreservesAuthoritativeSecurityNotices(t *testing.T) {
	model := &qualityMockLLM{score: QualityScore{Credibility: 2, Actionability: 1, Novelty: 2}}
	gate := NewQualityGate(model, 3)
	for _, item := range []scraper.RawItem{
		{Source: "cert-eu", URL: "https://cert.europa.eu/publications/security-advisories/2026-018/", Title: "Critical Vulnerabilities in PHP", Content: "Two critical vulnerabilities will be fixed tomorrow."},
		{Source: "cisa", URL: "https://www.cisa.gov/news-events/alerts/example", Title: "Compromised certificates require action", Content: "Eight intermediate keys were compromised."},
		{Source: "mozilla-security", URL: "https://blog.mozilla.org/security/example", Title: "eMudhra intermediate certificates compromised", Content: "Eight intermediate keys were compromised."},
	} {
		score, pass, err := gate.Evaluate(context.Background(), item)
		if err != nil || !pass || score != 5 {
			t.Fatalf("primary notice %q: score=%v pass=%v err=%v", item.Title, score, pass, err)
		}
	}
	if model.calls != 0 {
		t.Fatalf("primary notices sent to detail-biased quality model: %d calls", model.calls)
	}
}

func TestQualityGateDoesNotBypassOrdinaryReleaseOrNewsNotice(t *testing.T) {
	model := &qualityMockLLM{score: QualityScore{Credibility: 2, Actionability: 1, Novelty: 2}}
	gate := NewQualityGate(model, 3)
	for _, item := range []scraper.RawItem{
		{Source: "cert-eu", URL: "https://cert.europa.eu/publications/example/", Title: "Monthly technology digest"},
		{Source: "watchtowr", URL: "https://watchtowr.com/intelligence/critical-php", Title: "Upcoming Critical PHP Security Release"},
	} {
		_, pass, err := gate.Evaluate(context.Background(), item)
		if err != nil || pass {
			t.Fatalf("untrusted or ordinary notice %q: pass=%v err=%v", item.Title, pass, err)
		}
	}
	if model.calls != 2 {
		t.Fatalf("quality model calls = %d, want 2", model.calls)
	}
}

// TestQualityGate_SupplyChainLowNoveltyPass ensures a supply chain campaign
// with confirmed IOCs (credibility=4, actionability=4) still passes even when
// novelty=1 because a similar campaign ran two weeks prior.
// Old equal-weight: (4+4+1)/3 = 3.0. Pipeline multiplies by 0.85 confidence
// → 2.775, below the 3.0 threshold — rejected. New 40/40/20: 3.4 * 0.85 =
// 3.145 — passes. The raw gate score is what matters here.
func TestQualityGate_SupplyChainLowNoveltyPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": `{"credibility": 4, "actionability": 4, "novelty": 1, "summary": "known TTP reuse in npm supply chain"}`,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	gate := NewQualityGate(client, 3.0)

	item := scraper.RawItem{
		Title:   "Malicious npm Package Targets Axios Users",
		Content: "Threat actors published a typosquatted package targeting axios consumers with a post-install credential harvester.",
		Source:  "sonatype",
	}

	score, pass, err := gate.Evaluate(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	// 0.4*4 + 0.4*4 + 0.2*1 = 3.4 >= 3.0 → pass
	// Under old equal-weight: (4+4+1)/3 = 3.0 → marginal and confidence-adjusted below threshold
	if !pass {
		t.Errorf("supply chain item with low novelty should pass, score: %f", score)
	}
	if score < 3.0 {
		t.Errorf("score should be above 3.0, got: %f", score)
	}
}

func TestQualityGate_ActionabilityFloor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": `{"credibility": 5, "actionability": 1, "novelty": 3, "summary": "product announcement, no detection value"}`,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOllamaClient(srv.URL, "test")
	gate := NewQualityGate(client, 3.0)

	item := scraper.RawItem{
		Title:   "CrowdStrike Falcon Flex for Services Expansion",
		Content: "CrowdStrike is expanding its Falcon Flex model to include its services, offering flexible consumption of expert-led cybersecurity services.",
		Source:  "crowdstrike",
	}

	score, pass, err := gate.Evaluate(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	if pass {
		t.Errorf("expected actionability floor rejection, score: %f", score)
	}
}

func TestSourceSignalGateRejectsConfiguredJunk(t *testing.T) {
	item := scraper.RawItem{
		Source:  "reddit-cybersecurity",
		Title:   "What certification should I take next?",
		Content: "A general career discussion without concrete threat intelligence.",
	}
	score, pass := meetsSourceSignalThreshold(item, map[string]int{"reddit-cybersecurity": 2})
	if pass || score != 0 {
		t.Fatalf("score=%d pass=%v, want score 0 and rejection", score, pass)
	}
}

func TestSourceSignalGateAcceptsCVEEvidence(t *testing.T) {
	item := scraper.RawItem{
		Source:  "reddit-cybersecurity",
		Title:   "CVE-2026-12345 affects Example Gateway",
		Content: "The advisory documents affected versions and remediation guidance.",
	}
	score, pass := meetsSourceSignalThreshold(item, map[string]int{"reddit-cybersecurity": 2})
	if !pass || score < 3 {
		t.Fatalf("score=%d pass=%v, want CVE evidence to pass", score, pass)
	}
}

func TestSourceSignalGateAcceptsIOCEvidence(t *testing.T) {
	item := scraper.RawItem{
		Source:  "hackread",
		Title:   "Observed payload infrastructure",
		Content: "Analysts observed SHA-256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef in the incident.",
	}
	score, pass := meetsSourceSignalThreshold(item, map[string]int{"hackread": 2})
	if !pass || score < 2 {
		t.Fatalf("score=%d pass=%v, want IOC evidence to pass", score, pass)
	}
}

func TestSourceSignalGateLeavesUnconfiguredSourcesAlone(t *testing.T) {
	item := scraper.RawItem{Source: "cisa", Title: "Routine advisory"}
	if score, pass := meetsSourceSignalThreshold(item, map[string]int{"reddit-cybersecurity": 2}); !pass || score != 0 {
		t.Fatalf("score=%d pass=%v, want unconfigured source to bypass", score, pass)
	}
}

type qualityMockLLM struct {
	score QualityScore
	err   error
	calls int
}

func (m *qualityMockLLM) Generate(context.Context, string, string) (string, error) {
	m.calls++
	if m.err != nil {
		return "", m.err
	}
	b, err := json.Marshal(m.score)
	return string(b), err
}

func (m *qualityMockLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	resp, err := m.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(resp), out)
}

func TestQualityGate_FallbackClient(t *testing.T) {
	fast := &qualityMockLLM{err: errors.New("fast model unavailable")}
	primary := &qualityMockLLM{score: QualityScore{
		Credibility:   4,
		Actionability: 4,
		Novelty:       4,
		Summary:       "specific actionable threat",
	}}
	gate := NewQualityGateWithFallback(fast, primary, 3.0, nil)

	score, pass, err := gate.Evaluate(context.Background(), scraper.RawItem{
		Title:   "Exploit observed in attacks",
		Content: "Attackers are exploiting a Windows vulnerability with concrete commands and detections.",
		Source:  "huntress",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pass || score < 3 {
		t.Fatalf("expected fallback score to pass, score=%f pass=%v", score, pass)
	}
	if fast.calls != 1 || primary.calls != 1 {
		t.Fatalf("expected one fast call and one primary fallback call, got fast=%d primary=%d", fast.calls, primary.calls)
	}
}
