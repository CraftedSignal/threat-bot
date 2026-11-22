package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

type draftStatePublisher struct {
	drafts    []string
	claims    []string
	flushes   int
	queueErr  error
	reviewErr error
}

func (p *draftStatePublisher) Publish(string) error             { return p.queueErr }
func (p *draftStatePublisher) Flush() error                     { p.flushes++; return errors.New("ref not committed") }
func (p *draftStatePublisher) ValidatePublication(string) error { return p.reviewErr }
func (p *draftStatePublisher) PublishDraft(_ string, id, claim string) error {
	if p.queueErr != nil {
		return p.queueErr
	}
	p.drafts = append(p.drafts, id)
	p.claims = append(p.claims, claim)
	return nil
}

func TestNewConsolidatedDraftStaysPendingWhileBuffered(t *testing.T) {
	for _, kind := range []string{"campaign", "roundup"} {
		t.Run(kind, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			p := newDedupTestPipeline(t, db)
			pub := &draftStatePublisher{}
			p.publisher, p.autoPublish = pub, true
			p.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
			if kind == "campaign" {
				p.campaignConsolidation = true
				if !p.routeToCampaign(context.Background(), scraper.RawItem{SourceID: "campaign-one", Source: "bleepingcomputer", Title: "ClickFix delivers malware", URL: "https://example.com/clickfix"}, &ExtractionResult{}) {
					t.Fatal("campaign not routed")
				}
			} else {
				p.roundupConsolidation = true
				if !p.routeToRoundup(context.Background(), scraper.RawItem{SourceID: "msrc-one", Source: "msrc", Title: "Microsoft security updates CVE-2026-10001", URL: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10001"}, &ExtractionResult{CVEs: []string{"CVE-2026-10001"}, AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Windows"}}) {
					t.Fatal("roundup not routed")
				}
			}
			var drafts []*storage.Draft
			for _, status := range []string{storage.StatusPending, storage.StatusApproved} {
				for draft, err := range db.DraftsWithStatus(status) {
					if err != nil {
						t.Fatal(err)
					}
					drafts = append(drafts, draft)
				}
			}
			if len(drafts) != 1 || drafts[0].Status != storage.StatusPending {
				t.Fatalf("buffering approved draft before commit: %+v", drafts)
			}
			if len(pub.drafts) != 1 || pub.drafts[0] != drafts[0].ID {
				t.Fatalf("draft completion identity not queued: %+v", pub.drafts)
			}
			if pub.flushes != 0 {
				t.Fatalf("per-brief flushes=%d", pub.flushes)
			}
		})
	}
}

func TestNewDraftPublicationPreservesPendingAndModeration(t *testing.T) {
	for _, mode := range []string{"buffered", "queue failure", "editorial rejection", "manual review"} {
		t.Run(mode, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			pub := &draftStatePublisher{}
			if mode == "queue failure" {
				pub.queueErr = errors.New("outbox unavailable")
			}
			if mode == "editorial rejection" {
				pub.reviewErr = errors.New("editorial review required")
			}
			brief := strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1)
			var logs strings.Builder
			client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) { return brief, nil }, generateJSON: func(_ context.Context, _, _ string, out any) error {
				switch r := out.(type) {
				case *GroundingResult:
					r.Grounded = true
				case *QualityScore:
					*r = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
				}
				return nil
			}}
			p := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Publisher: pub, AutoPublish: mode != "manual review", Logger: slog.New(slog.NewTextHandler(&logs, nil))})
			item := scraper.RawItem{SourceID: "sigma-state", Source: "sigma-hq", URL: "https://example.com/rule", Title: "Windows Path Detection", Content: strings.Repeat("Observed Windows process creation detection. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Detect Windows Binary"}}
			if err := p.Process(context.Background(), []scraper.RawItem{item}); err != nil {
				t.Fatal(err)
			}
			var pending int
			for _, err := range db.DraftsWithStatus(storage.StatusApproved) {
				if err != nil {
					t.Fatal(err)
				}
				t.Fatal("draft approved before committed publication")
			}
			for _, err := range db.DraftsWithStatus(storage.StatusPending) {
				if err != nil {
					t.Fatal(err)
				}
				pending++
			}
			if pending != 1 {
				t.Fatalf("pending=%d, want saved draft; %s", pending, logs.String())
			}
			wantQueued := 0
			if mode == "buffered" {
				wantQueued = 1
			}
			if len(pub.drafts) != wantQueued {
				t.Fatalf("queued=%d,want%d", len(pub.drafts), wantQueued)
			}
			wantFlush := 1
			if mode == "manual review" {
				wantFlush = 0
			}
			if pub.flushes != wantFlush {
				t.Fatalf("flushes=%d,want one batch flush=%d", pub.flushes, wantFlush)
			}
		})
	}
}

func TestRumourDraftQueuesClaimWithoutMarkingPublished(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	pub := &draftStatePublisher{}
	url := "https://x.com/researcher/status/123"
	assessment := &ClaimAssessment{Claim: "Windows process monitoring can reveal this loader", Status: "unverified", Likelihood: "likely", Evidence: []ClaimEvidence{{Type: "first_party_observation", Detail: "Researcher reports direct process observation", SourceURL: url}, {Type: "mechanism", Detail: "Process image matches the supplied rule", SourceURL: url}}, Gaps: []string{"Independent confirmation pending"}, EstablishedFacts: []string{"Public research report exists"}}
	extraction := &ExtractionResult{AffectedProducts: []string{"Windows"}, VulnClass: "loader", ClaimAssessment: assessment}
	brief := strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1)
	client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) { return brief, nil }, generateJSON: func(_ context.Context, _, _ string, out any) error {
		switch r := out.(type) {
		case *QualityScore:
			*r = QualityScore{Credibility: 5, Actionability: 5, Novelty: 5}
		case *GroundingResult:
			r.Grounded = true
		case *ExtractionResult:
			*r = *extraction
		}
		return nil
	}}
	var logs strings.Builder
	p := New(Config{DB: db, LLMClient: client, QualityThreshold: 3, Publisher: pub, AutoPublish: true, SourceConfidence: map[string]float64{"public-web-social-search": 1}, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	item := scraper.RawItem{SourceID: "social-state", Source: "public-web-social-search", URL: url, Title: "Windows loader process observations", Content: strings.Repeat("Researcher observed loader process image and supplied detection evidence. ", 25), Enriched: true, Discovery: &scraper.DiscoveryContext{Platform: "x", OriginalURL: url, ContextComplete: true}}
	if err := p.Process(context.Background(), []scraper.RawItem{item}); err != nil {
		t.Fatal(err)
	}
	key := ClaimKey(extraction)
	candidate, err := db.GetRumourCandidate(key)
	if err != nil || candidate == nil {
		t.Fatalf("candidate=%+v err=%v logs=%s", candidate, err, logs.String())
	}
	if candidate.Status == "published" {
		t.Fatal("buffering marked rumour published")
	}
	if len(pub.claims) != 1 || pub.claims[0] != key {
		t.Fatalf("claim completion identity not queued: %v; logs=%s", pub.claims, logs.String())
	}
	queued, err := db.GetDraft(pub.drafts[0])
	if err != nil {
		t.Fatal(err)
	}
	if queued.Status != storage.StatusPending {
		t.Fatal("buffered rumour draft approved")
	}
}
