package pipeline

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// rejectingRetirementPublisher reports a nil flush that silently dropped briefs.
type rejectingRetirementPublisher struct {
	sameIncidentRetirementPublisher
	rejected []string
}

func (p *rejectingRetirementPublisher) RejectedBriefIDs() []string { return p.rejected }

func TestConvergeSameIncidentFailsWhenCanonicalRevisionRejected(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	now := time.Now().UTC()
	drafts := []*storage.Draft{
		{
			ID: "connectwise-original", Status: storage.StatusApproved, Source: "the-hacker-news",
			SourceIDs: `["thn:connectwise"]`, CreatedAt: now.Add(-6 * 24 * time.Hour),
			BriefYAML: `id: brief-2026-10-connectwise-m365-compromise
slug: 2026-10-connectwise-m365-compromise
title: Unauthorized Access to Microsoft 365 Tenants via Compromised ConnectWise Credentials
summary: Compromised ConnectWise Cloud Backup credentials enabled access to Microsoft 365 tenants.
severity: high
published_at: "2026-10-17T06:39:00Z"
content: ConnectWise disclosed unauthorized Microsoft 365 tenant access.
affected_vendors: [ConnectWise, Microsoft]
affected_products: [Microsoft 365, ConnectWise Cloud Backup]
references: [https://status.connectwise.com/original]
action_plan:
  hunt_leads:
    - lead: Review anomalous ConnectWise service principal use
      evidence: Compromised credentials enabled unauthorized access
`,
		},
		{
			ID: "connectwise-huntress", Status: storage.StatusApproved, Source: "huntress",
			SourceIDs: `["huntress:connectwise"]`, CreatedAt: now.Add(-5 * 24 * time.Hour),
			BriefYAML: `id: brief-2026-10-connectwise-m365-abuse
slug: 2026-10-connectwise-m365-abuse
title: Unauthorized Access via Compromised ConnectWise M365 Vendor Credentials
summary: Compromised ConnectWise Cloud Backup credentials enabled unauthorized Microsoft 365 access.
severity: high
published_at: "2026-10-17T10:28:00Z"
content: Huntress observed Microsoft 365 access through compromised vendor credentials.
affected_vendors: [ConnectWise, Microsoft]
affected_products: [Microsoft 365, ConnectWise Cloud Backup]
references: [https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access]
iocs:
  - type: ip
    value: 144.172.64.128
action_plan:
  hunt_leads:
    - lead: Review sign-ins from reported infrastructure
      evidence: Huntress observed token use from 144.172.64.128
`,
		},
		{
			ID: "connectwise-microsoft", Status: storage.StatusApproved, Source: "microsoft-threat-intel",
			SourceIDs: `["microsoft:storm-0940"]`, CreatedAt: now.Add(-24 * time.Hour),
			BriefYAML: `id: brief-2026-10-21-storm-0940-artex
slug: 2026-10-storm-0940-artex
title: Storm-0940 exploitation of ConnectWise Cloud Backup
summary: Storm-0940 exploited compromised ConnectWise Cloud Backup credentials to access Microsoft 365 tenants.
severity: critical
threat_actor: Storm-0940
published_at: "2026-10-21T19:54:00Z"
content: Microsoft observed Storm-0940 using ARTEX in the ConnectWise compromise.
affected_vendors: [ConnectWise, Microsoft]
affected_products: [ConnectWise Automate, ConnectWise Cloud Backup, Microsoft 365]
references: [https://www.microsoft.com/security/blog/storm-0940]
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.microsoft.com/security/blog/storm-0940
action_plan:
  hunt_leads:
    - lead: Review ARTEX use of the affected service principal
      evidence: Microsoft observed active exploitation
`,
		},
	}
	for _, draft := range drafts {
		if err := db.CreateDraft(draft); err != nil {
			t.Fatal(err)
		}
		if err := db.IndexContent(&storage.ContentIndexEntry{DraftID: draft.ID, SourceID: draft.ID + ":source", Source: draft.Source, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}

	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{
		{Merge: boolPtr(true), PreferIncomingNarrative: boolPtr(false), Reason: "same ConnectWise incident"},
		{Merge: boolPtr(true), PreferIncomingNarrative: boolPtr(true), Reason: "same ConnectWise incident"},
	}}
	pub := &rejectingRetirementPublisher{rejected: []string{"brief-2026-10-connectwise-m365-compromise"}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm, Publisher: pub, AutoPublish: true})
	incoming := drafts[2].BriefYAML
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{
		SourceID: "microsoft:storm-0940", Source: "microsoft-threat-intel",
		Title: "Storm-0940 exploitation of ConnectWise Cloud Backup", URL: "https://www.microsoft.com/security/blog/storm-0940",
	}, nil, &ExtractionResult{AffectedVendors: []string{"ConnectWise", "Microsoft"}, AffectedProducts: []string{"ConnectWise Cloud Backup", "Microsoft 365"}})
	if err == nil {
		t.Fatalf("expected an error when the canonical revision was rejected (handled=%v)", handled)
	}
	for _, id := range []string{"connectwise-huntress", "connectwise-microsoft"} {
		draft, err := db.GetDraft(id)
		if err != nil {
			t.Fatal(err)
		}
		if draft.Status != storage.StatusApproved {
			t.Fatalf("duplicate %s status=%s, must stay approved", id, draft.Status)
		}
	}
}
