package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestPublishableRumourRequiresLikelyTypedEvidenceAndGaps(t *testing.T) {
	item := scraper.RawItem{URL: "https://x.com/a/status/1", Discovery: &scraper.DiscoveryContext{Platform: "x", OriginalURL: "https://x.com/a/status/1", ContextComplete: true}}
	good := &ClaimAssessment{Claim: "Brotli stream can disclose heap bytes", Status: "unverified", Likelihood: "likely", Evidence: []ClaimEvidence{{Type: "first_party_observation", Detail: "Researcher reproduced heap disclosure", SourceURL: item.URL}, {Type: "mechanism", Detail: "uninitialized output bytes", SourceURL: item.URL}}, Gaps: []string{"No vendor confirmation"}, EstablishedFacts: []string{"A public reproducer report exists"}}
	if ok, reason := PublishableRumour(item, good); !ok {
		t.Fatalf("rejected: %s", reason)
	}
	for name, mutate := range map[string]func(*ClaimAssessment){"roughly-even": func(a *ClaimAssessment) { a.Likelihood = "roughly even chance" }, "no-evidence": func(a *ClaimAssessment) { a.Evidence = nil }, "engagement": func(a *ClaimAssessment) {
		a.Evidence = []ClaimEvidence{{Type: "engagement", Detail: "viral", SourceURL: item.URL}}
	}, "no-gaps": func(a *ClaimAssessment) { a.Gaps = nil }} {
		t.Run(name, func(t *testing.T) {
			copy := *good
			copy.Evidence = append([]ClaimEvidence(nil), good.Evidence...)
			copy.Gaps = append([]string(nil), good.Gaps...)
			mutate(&copy)
			if ok, _ := PublishableRumour(item, &copy); ok {
				t.Fatal("unexpectedly publishable")
			}
		})
	}
}

func TestPublishableRumourDoesNotWhitelistAuthor(t *testing.T) {
	a := &ClaimAssessment{Claim: "claim", Status: "unverified", Likelihood: "likely", Evidence: []ClaimEvidence{{Type: "first_party_observation", Detail: "we reproduced crash", SourceURL: "https://x.com/unknown/status/1"}, {Type: "artifact", Detail: "reproducer", SourceURL: "https://example.test/poc"}}, Gaps: []string{"vendor confirmation pending"}, EstablishedFacts: []string{"post is public"}}
	item := scraper.RawItem{URL: "https://x.com/unknown/status/1", Discovery: &scraper.DiscoveryContext{Platform: "x", OriginalURL: "https://x.com/unknown/status/1", ContextComplete: true}}
	if ok, reason := PublishableRumour(item, a); !ok {
		t.Fatalf("author-agnostic evidence rejected: %s", reason)
	}
}

func TestPublishableRumourRejectsIncompleteSocialContext(t *testing.T) {
	a := &ClaimAssessment{Claim: "claim", Status: "unverified", Likelihood: "likely", Evidence: []ClaimEvidence{{Type: "first_party_observation", Detail: "we reproduced crash", SourceURL: "https://x.com/unknown/status/1"}, {Type: "artifact", Detail: "reproducer", SourceURL: "https://example.test/poc"}}, Gaps: []string{"vendor confirmation pending"}, EstablishedFacts: []string{"post is public"}}
	item := scraper.RawItem{URL: "https://x.com/unknown/status/1", Discovery: &scraper.DiscoveryContext{Platform: "x", OriginalURL: "https://x.com/unknown/status/1", ContextComplete: false}}
	if ok, reason := PublishableRumour(item, a); ok || !strings.Contains(reason, "incomplete") {
		t.Fatalf("ok=%v reason=%q", ok, reason)
	}
}

func TestClaimAssessmentPromptSeparatesFactsAndRejectsSocialProof(t *testing.T) {
	p := extractionRequest(scraper.RawItem{Title: "rumour", Content: "viral claim"}).System
	for _, want := range []string{"established_facts", "first_party_observation", "engagement", "likely"} {
		if !strings.Contains(p, want) {
			t.Fatalf("prompt missing %q", want)
		}
	}
}

func TestPipelineHoldsPlainRumourWithoutBriefOrQuarantine(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	var logs bytes.Buffer
	groundedBrief := strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1)
	client := shutdownStageLLM{
		generate: func(context.Context, string, string) (string, error) { return groundedBrief, nil },
		generateJSON: func(_ context.Context, _, system string, out any) error {
			switch out := out.(type) {
			case *QualityScore:
				*out = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
			case *GroundingResult:
				out.Grounded = true
			default:
				return fmt.Errorf("unexpected JSON system: %s", system)
			}
			return nil
		},
	}
	pipe := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	item := scraper.RawItem{SourceID: "reddit:rumour1", Source: "reddit-netsec", URL: "https://www.reddit.com/r/netsec/comments/abc", Title: "Someone says a loader abuses scheduled tasks", Content: strings.Repeat("A user claims a loader abuses scheduled tasks. ", 30)}
	if err := pipe.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	if _, quarantined, err := db.PipelineQuarantineReason(item.SourceID); err != nil || quarantined {
		t.Fatalf("quarantined=%v err=%v; a rumour must not become a malformed brief\n%s", quarantined, err, logs.String())
	}
	if seen, err := db.HasSeen(item.SourceID); err != nil || !seen {
		t.Fatalf("seen=%v err=%v; the held rumour must be marked seen\n%s", seen, err, logs.String())
	}
	for _, status := range []string{storage.StatusPending, storage.StatusApproved} {
		for draft, err := range db.DraftsWithStatus(status) {
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("unexpected %s draft %s", status, draft.ID)
		}
	}
	if strings.Contains(logs.String(), "quarantined malformed brief") || !strings.Contains(logs.String(), "holding rumour") {
		t.Fatalf("want an Info hold line and no quarantine warning:\n%s", logs.String())
	}
}
