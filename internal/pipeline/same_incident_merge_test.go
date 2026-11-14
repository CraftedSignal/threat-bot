package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

func TestMergeSameIncidentAssembledProductBrief_PromotesConnectWiseIncidentWithoutLosingSignals(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{{
		Merge: boolPtr(true), PreferIncomingNarrative: boolPtr(true), Reason: "same ConnectWise Cloud Backup compromise",
	}}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	base := `id: brief-connectwise-original
slug: 2026-10-connectwise-m365-compromise
title: "Unauthorized Access to Microsoft 365 Tenants via Compromised ConnectWise Credentials"
summary: "Threat actors abused compromised ConnectWise Cloud Backup credentials to access Microsoft 365 tenants."
severity: high
published_at: "2026-10-17T06:39:00Z"
content: "ConnectWise disclosed unauthorized tenant access through compromised Cloud Backup credentials."
affected_vendors: [ConnectWise, Microsoft]
affected_products: [Microsoft 365, ConnectWise Cloud Backup]
references: [https://status.connectwise.com/original]
tags: [credential-access]
exploitation_evidence:
  status: unknown
action_plan:
  immediate_actions:
    - action: Rotate ConnectWise integration credentials
      owner: Identity
`
	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-connectwise", Status: storage.StatusApproved, Source: "connectwise",
		SourceIDs: `["connectwise:original"]`, BriefYAML: base, CreatedAt: time.Now().Add(-4 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}

	incoming := `id: brief-storm-0940
slug: 2026-10-storm-0940-artex
title: "Storm-0940 exploitation of ConnectWise Cloud Backup"
summary: "Storm-0940 used ARTEX to abuse compromised ConnectWise Cloud Backup credentials in attacks on Microsoft 365 tenants."
severity: critical
threat_actor: Storm-0940
published_at: "2026-10-21T21:33:00Z"
content: "Microsoft observed Storm-0940 exploiting the ConnectWise Cloud Backup compromise with ARTEX."
affected_vendors: [ConnectWise, Microsoft]
affected_products: [ConnectWise Automate, ConnectWise Cloud Backup, Microsoft 365]
affected_os: [Windows]
references: [https://www.microsoft.com/security/blog/storm-0940]
tags: [supply-chain, active-exploitation]
cpes: [cpe:2.3:a:connectwise:cloud_backup:*:*:*:*:*:*:*:*]
cves:
  - id: CVE-2026-99999
    kev_status: unknown
iocs:
  - type: ip
    value: 198.18.0.42
    context: ARTEX infrastructure reported by Microsoft
ttps:
  - tactic_id: TA0001
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: compromised credentials were abused
rules:
  - id: rule-connectwise-artex
    title: ConnectWise service principal abuse
    description: Detect suspicious use of the affected service principal.
    logsource: {product: azure, service: signinlogs}
    detection: {selection: {AppDisplayName: ConnectWise}, condition: selection}
    level: high
has_poc: true
poc_references: [https://research.example.test/connectwise-poc]
priority_signals: [active_exploitation, high_confidence_source]
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.microsoft.com/security/blog/storm-0940
  observed_at: "2026-10-21T21:33:00Z"
  confidence: high
action_plan:
  hunt_leads:
    - lead: Review anomalous use of the ConnectWise service principal across tenants
      technique_id: T1078
      data_needed: [Microsoft Entra sign-in logs]
      priority: critical
      evidence: compromised credentials were abused
  mitigation_plan:
    - action: Revoke affected service principal credentials
      owner: Identity
      addresses: Compromised ConnectWise credentials
`
	item := scraper.RawItem{
		SourceID: "microsoft:storm-0940", Source: "microsoft-threat-intel",
		Title: "Storm-0940 exploitation of ConnectWise Cloud Backup",
		URL:   "https://www.microsoft.com/security/blog/storm-0940",
	}
	var baseDoc, incomingDoc map[string]any
	_ = yaml.Unmarshal([]byte(base), &baseDoc)
	_ = yaml.Unmarshal([]byte(incoming), &incomingDoc)
	if got := sharedIncidentTokenCount(
		briefIncidentTokens(baseDoc, []string{"ConnectWise", "Microsoft"}),
		briefIncidentTokens(incomingDoc, []string{"ConnectWise", "Microsoft"}),
	); got < 2 {
		t.Fatalf("ConnectWise fixture shared incident tokens = %d, want at least 2", got)
	}
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, item, nil, &ExtractionResult{
		AffectedVendors: []string{"ConnectWise", "Microsoft"}, AffectedProducts: []string{"ConnectWise Cloud Backup"},
	})
	if err != nil {
		t.Fatalf("merge incident: %v", err)
	}
	if !handled {
		t.Fatal("expected ConnectWise reports to merge")
	}
	draft, err := db.GetDraft("draft-connectwise")
	if err != nil {
		t.Fatalf("get merged draft: %v", err)
	}
	for _, want := range []string{
		"id: brief-connectwise-original", "slug: 2026-10-connectwise-m365-compromise",
		`published_at: "2026-10-17T06:39:00Z"`, "Storm-0940", "severity: critical",
		"confirmed_active", "exploited: true", "CVE-2026-99999", "198.18.0.42",
		"cpe:2.3:a:connectwise:cloud_backup", "has_poc: true", "connectwise-poc",
		"ConnectWise service principal abuse", "Review anomalous use", "Revoke affected service principal",
	} {
		if !strings.Contains(draft.BriefYAML, want) {
			t.Fatalf("merged ConnectWise draft missing %q:\n%s", want, draft.BriefYAML)
		}
	}
	var sourceIDs []string
	if err := json.Unmarshal([]byte(draft.SourceIDs), &sourceIDs); err != nil {
		t.Fatalf("decode source IDs: %v", err)
	}
	if len(sourceIDs) != 2 || sourceIDs[0] != "connectwise:original" || sourceIDs[1] != "microsoft:storm-0940" {
		t.Fatalf("source IDs = %#v, want both reports", sourceIDs)
	}
	if draft.UpdateCount != 1 {
		t.Fatalf("update count = %d, want 1", draft.UpdateCount)
	}
	if !strings.Contains(draft.UpdateLog, `"level":"L3"`) {
		t.Fatalf("update log did not classify exploitation promotion as L3: %s", draft.UpdateLog)
	}
}

func TestMergeAssembledBriefIntoDraft_PersistsSeverityOnlyUpgrade(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	base := `id: stable
slug: stable
title: Stable incident
summary: Stable incident summary
severity: high
published_at: "2026-10-20T00:00:00Z"
content: Stable incident content
affected_vendors: [Acme]
affected_products: [Widget]
references: [https://acme.test/advisory]
`
	if err := db.CreateDraft(&storage.Draft{ID: "severity-only", Status: storage.StatusApproved, SourceIDs: `["acme:one"]`, BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	incoming := strings.Replace(base, "severity: high", "severity: critical", 1)
	if err := p.mergeAssembledBriefIntoDraft("severity-only", incoming, scraper.RawItem{SourceID: "acme:two", Source: "vendor"}); err != nil {
		t.Fatalf("merge severity upgrade: %v", err)
	}
	draft, _ := db.GetDraft("severity-only")
	if !strings.Contains(draft.BriefYAML, "severity: critical") {
		t.Fatalf("severity-only upgrade was discarded:\n%s", draft.BriefYAML)
	}
	if !strings.Contains(draft.SourceIDs, "acme:two") {
		t.Fatalf("severity-only merge did not retain source provenance: %s", draft.SourceIDs)
	}
}

type sameIncidentMockLLM struct {
	responses []sameIncidentLLMResponse
	respond   func(string) sameIncidentLLMResponse
	err       error
	calls     int
}

type sameIncidentRetirementPublisher struct {
	published []string
	retired   map[string]string
	drafts    map[string][2]string // retired brief ID -> {duplicate draft, canonical draft}
	flushes   int
}

// RetireBriefForDrafts is the durable retirement hook the real publisher
// offers; it records the draft IDs so the test can assert they are passed.
func (p *sameIncidentRetirementPublisher) RetireBriefForDrafts(id, slug, _, draftID, canonicalDraftID string) error {
	if p.drafts == nil {
		p.drafts = make(map[string][2]string)
	}
	p.drafts[id] = [2]string{draftID, canonicalDraftID}
	return p.RetireBrief(id, slug)
}

func (p *sameIncidentRetirementPublisher) Publish(raw string) error {
	p.published = append(p.published, raw)
	return nil
}

func (p *sameIncidentRetirementPublisher) Flush() error {
	p.flushes++
	return nil
}

func (p *sameIncidentRetirementPublisher) RetireBrief(id, slug string) error {
	if p.retired == nil {
		p.retired = make(map[string]string)
	}
	p.retired[id] = slug
	return nil
}

func (*sameIncidentRetirementPublisher) ValidatePublication(string) error { return nil }

func (*sameIncidentMockLLM) Generate(context.Context, string, string) (string, error) {
	return "", nil
}

func (m *sameIncidentMockLLM) GenerateJSON(_ context.Context, prompt string, _ string, out any) error {
	m.calls++
	if m.err != nil {
		return m.err
	}
	resp, ok := out.(*sameIncidentLLMResponse)
	if !ok {
		return nil
	}
	if m.respond != nil {
		*resp = m.respond(prompt)
		return nil
	}
	if len(m.responses) == 0 {
		return nil
	}
	idx := m.calls - 1
	if idx >= len(m.responses) {
		idx = len(m.responses) - 1
	}
	*resp = m.responses[idx]
	return nil
}

func TestMergeSameIncidentRanksBestCandidatesBeforeLLMBudget(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	now := time.Now().UTC()
	canonical := `id: exact-token-replay
slug: exact-token-replay
title: M365 token spray and replay campaign compromises business email accounts
summary: Attackers replayed Microsoft 365 tokens and sprayed accounts in a business email compromise campaign.
severity: high
published_at: "2026-10-20T00:00:00Z"
content: Existing exact campaign coverage.
affected_vendors: [Microsoft]
affected_products: [Microsoft 365]
references: [https://example.test/exact]
`
	if err := db.CreateDraft(&storage.Draft{
		ID: "exact-token-replay", Status: storage.StatusApproved, Source: "primary", BriefYAML: canonical,
		CreatedAt: now.Add(-6 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sameIncidentCandidateLimit; i++ {
		noise := fmt.Sprintf(`id: microsoft-noise-%d
slug: microsoft-noise-%d
title: Microsoft 365 token campaign report %d
summary: Separate Microsoft 365 token activity affecting another campaign.
severity: medium
published_at: "2026-10-22T00:00:00Z"
content: Separate event.
affected_vendors: [Microsoft]
affected_products: [Microsoft 365]
references: [https://example.test/noise/%d]
`, i, i, i, i)
		if err := db.CreateDraft(&storage.Draft{
			ID: fmt.Sprintf("noise-%d", i), Status: storage.StatusApproved, Source: "news", BriefYAML: noise,
			CreatedAt: now.Add(-time.Duration(i) * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	llm := &sameIncidentMockLLM{respond: func(prompt string) sameIncidentLLMResponse {
		merge := strings.Contains(prompt, "Existing exact campaign coverage")
		return sameIncidentLLMResponse{Merge: boolPtr(merge), PreferIncomingNarrative: boolPtr(false)}
	}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	incoming := `id: incoming-token-replay
slug: incoming-token-replay
title: M365 Token Spray and Replay Campaign Compromises Business Email Accounts
summary: Attackers used token spray and replay to compromise business email accounts in Microsoft 365.
severity: high
published_at: "2026-10-22T00:00:00Z"
content: New details for the exact token replay campaign.
affected_vendors: [Microsoft]
affected_products: [Microsoft 365]
references: [https://www.huntress.com/blog/token-replay-spray]
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{
		SourceID: "huntress:token-replay-spray", Source: "huntress", Title: "M365 Token Spray and Replay Campaign",
		URL: "https://www.huntress.com/blog/token-replay-spray",
	}, nil, &ExtractionResult{AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Microsoft 365"}})
	if err != nil {
		t.Fatalf("ranked same-incident merge: %v", err)
	}
	if !handled {
		t.Fatal("highest-similarity candidate should be evaluated before newer generic candidates")
	}
	if llm.calls != sameIncidentCandidateLimit {
		t.Fatalf("LLM calls=%d, want bounded %d", llm.calls, sameIncidentCandidateLimit)
	}
	draft, err := db.GetDraft("exact-token-replay")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(draft.BriefYAML, "huntress.com/blog/token-replay-spray") {
		t.Fatalf("ranked candidate was not merged:\n%s", draft.BriefYAML)
	}
}

func TestMergeSameIncidentAssembledProductBrief_ConvergesAllApprovedConnectWiseDuplicates(t *testing.T) {
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
	pub := &sameIncidentRetirementPublisher{}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm, Publisher: pub, AutoPublish: true})
	incoming := drafts[2].BriefYAML
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{
		SourceID: "microsoft:storm-0940", Source: "microsoft-threat-intel",
		Title: "Storm-0940 exploitation of ConnectWise Cloud Backup", URL: "https://www.microsoft.com/security/blog/storm-0940",
	}, nil, &ExtractionResult{AffectedVendors: []string{"ConnectWise", "Microsoft"}, AffectedProducts: []string{"ConnectWise Cloud Backup", "Microsoft 365"}})
	if err != nil {
		t.Fatalf("converge ConnectWise duplicates: %v", err)
	}
	if !handled {
		t.Fatalf("expected ConnectWise incident to be handled; LLM calls=%d", llm.calls)
	}
	canonical, err := db.GetDraft("connectwise-original")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"threat_actor: Storm-0940", "exploited: true", "144.172.64.128", "microsoft:storm-0940", "huntress:connectwise"} {
		if !strings.Contains(canonical.BriefYAML+canonical.SourceIDs, want) {
			t.Fatalf("canonical brief missing %q:\n%s\nsource IDs: %s", want, canonical.BriefYAML, canonical.SourceIDs)
		}
	}
	for _, id := range []string{"connectwise-huntress", "connectwise-microsoft"} {
		draft, err := db.GetDraft(id)
		if err != nil {
			t.Fatal(err)
		}
		if draft.Status != storage.StatusRejected {
			t.Fatalf("duplicate %s status=%s, want rejected", id, draft.Status)
		}
	}
	if pub.flushes != 1 || len(pub.retired) != 2 {
		t.Fatalf("publication convergence flushes=%d retired=%v", pub.flushes, pub.retired)
	}
	if len(pub.drafts) != 2 {
		t.Fatalf("retirements did not carry draft IDs for crash recovery: %v", pub.drafts)
	}
	for briefID, pair := range pub.drafts {
		if pair[0] == "" || pair[1] != "connectwise-original" {
			t.Fatalf("retirement %s draft IDs = %v, want duplicate draft and canonical connectwise-original", briefID, pair)
		}
	}
	for _, entryID := range []string{"connectwise-huntress:source", "connectwise-microsoft:source"} {
		entries, err := db.FindByTitleHash("")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if entry.SourceID == entryID && entry.DraftID == "connectwise-original" {
				found = true
			}
		}
		if !found {
			t.Fatalf("content index %s was not repointed to the canonical draft", entryID)
		}
	}
}

func TestMergeSameIncidentAssembledProductBrief_ConsolidatesEMudhraChainIncident(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{
		{Merge: boolPtr(true), PreferIncomingNarrative: boolPtr(true), Reason: "the certifi advisory remediates the same recovered eMudhra intermediate keys"},
		{Merge: boolPtr(true), PreferIncomingNarrative: boolPtr(false), Reason: "the SecurityWeek report covers the same eight recovered keys"},
	}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	now := time.Now().UTC()

	baseYAML := `id: brief-2026-10-20-certifi-compromised-roots
slug: 2026-10-certifi-compromised-roots
title: "Certifi: Bundled eMudhra root CAs with compromised intermediate keys"
summary: "Certifi removed eMudhra roots after related intermediate keys were recovered."
severity: high
published_at: "2026-10-20T23:53:18Z"
content: "The certifi package bundled eMudhra roots affected by the intermediate-key incident."
affected_vendors:
  - eMudhra
affected_products:
  - "certifi (< 2026.10.18)"
references:
  - https://github.com/advisories/GHSA-hw4v-5x4h-9v9j
tags:
  - supply-chain
`
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-emudhra",
		Status:    storage.StatusApproved,
		Source:    "ghsa",
		SourceIDs: `["ghsa:certifi"]`,
		BriefYAML: baseYAML,
		CreatedAt: now.Add(-12 * time.Hour),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}

	intermediateYAML := `id: brief-2026-10-21-emudhra-intermediate-key-compromise
slug: 2026-10-emudhra-intermediate-key-compromise
title: "eMudhra: Eight compromised intermediate CA keys threaten TLS trust"
summary: "Researchers recovered eight eMudhra intermediate CA private keys."
severity: critical
published_at: "2026-10-21T07:47:00Z"
content: "Eight weak eMudhra intermediate CA private keys were recovered, enabling certificate forgery until distrust and revocation completed."
affected_vendors:
  - eMudhra
affected_products:
  - "emSign intermediate CA certificates"
references:
  - https://blog.mozilla.org/security/2026/10/20/emudhra-incident/
tags:
  - cryptography
`
	intermediateItem := scraper.RawItem{
		SourceID: "mozilla:emudhra",
		Source:   "mozilla",
		Title:    "eMudhra intermediate key compromise",
		URL:      "https://blog.mozilla.org/security/2026/10/20/emudhra-incident/",
	}
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), intermediateYAML, intermediateItem, nil, &ExtractionResult{
		AffectedVendors:  []string{"eMudhra"},
		AffectedProducts: []string{"emSign intermediate CA certificates"},
	})
	if err != nil {
		t.Fatalf("merge intermediate brief: %v", err)
	}
	if !handled {
		t.Fatal("expected certifi and eMudhra intermediate briefs to merge")
	}

	caKeysYAML := `id: brief-2026-10-21-emudhra-ca-keys
slug: 2026-10-emudhra-ca-keys
title: "eMudhra: Intermediate Certificate Authority private key recovery"
summary: "Eight eMudhra intermediate CA private keys were recoverable."
severity: critical
published_at: "2026-10-21T12:20:28Z"
content: "SecurityWeek reported on the same eight recoverable eMudhra intermediate keys."
affected_vendors:
  - eMudhra
affected_products:
  - "Intermediate Certificate Authorities"
references:
  - https://www.securityweek.com/emudhra-ca-private-keys-recovered/
tags:
  - cryptography
`
	caKeysItem := scraper.RawItem{
		SourceID: "securityweek:emudhra",
		Source:   "securityweek",
		Title:    "eMudhra CA private keys recovered",
		URL:      "https://www.securityweek.com/emudhra-ca-private-keys-recovered/",
	}
	handled, err = p.mergeSameIncidentAssembledProductBrief(context.Background(), caKeysYAML, caKeysItem, nil, &ExtractionResult{
		AffectedVendors:  []string{"eMudhra"},
		AffectedProducts: []string{"Intermediate Certificate Authorities"},
	})
	if err != nil {
		t.Fatalf("merge CA keys brief: %v", err)
	}
	if !handled {
		t.Fatal("expected CA keys report to merge into the same incident")
	}

	draft, err := db.GetDraft("draft-emudhra")
	if err != nil {
		t.Fatalf("get merged draft: %v", err)
	}
	for _, want := range []string{
		"eMudhra: Eight compromised intermediate CA keys threaten TLS trust",
		"Eight weak eMudhra intermediate CA private keys were recovered",
		"certifi (< 2026.10.18)",
		"emSign intermediate CA certificates",
		"Intermediate Certificate Authorities",
		"GHSA-hw4v-5x4h-9v9j",
		"blog.mozilla.org",
		"securityweek.com",
	} {
		if !strings.Contains(draft.BriefYAML, want) {
			t.Fatalf("merged draft missing %q:\n%s", want, draft.BriefYAML)
		}
	}
	if strings.Contains(draft.BriefYAML, "title: 'Certifi:") || strings.Contains(draft.BriefYAML, "title: Certifi:") {
		t.Fatalf("expected richer incoming narrative to become canonical:\n%s", draft.BriefYAML)
	}
	if llm.calls != 2 {
		t.Fatalf("expected two incident decisions, got %d", llm.calls)
	}
}

func TestMergeSameIncidentAssembledProductBrief_RejectsUnrelatedSameVendorBrief(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{{
		Merge: boolPtr(false), Reason: "same vendor, separate vulnerability and product",
	}}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	base := `id: brief-acme-widget
slug: acme-widget
title: "Acme Widget authentication bypass"
summary: "Widget authentication bypass."
severity: high
published_at: "2026-10-21T00:00:00Z"
content: "Acme Widget authentication bypass."
affected_vendors: [Acme]
affected_products: [Widget]
references: [https://example.test/widget]
`
	if err := db.CreateDraft(&storage.Draft{ID: "draft-acme", Status: storage.StatusApproved, BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	incoming := `id: brief-acme-gateway
slug: acme-gateway
title: "Acme Gateway remote code execution"
summary: "Gateway remote code execution."
severity: critical
published_at: "2026-10-21T01:00:00Z"
content: "Acme Gateway remote code execution."
affected_vendors: [Acme]
affected_products: [Gateway]
references: [https://example.test/gateway]
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{SourceID: "acme:gateway", Source: "vendor"}, nil, nil)
	if err != nil {
		t.Fatalf("same-incident check: %v", err)
	}
	if handled {
		t.Fatal("unrelated same-vendor briefs must not merge")
	}
	if llm.calls != 0 {
		t.Fatalf("vendor-only candidate should not spend an LLM call, got %d", llm.calls)
	}
	draft, _ := db.GetDraft("draft-acme")
	if strings.Contains(draft.BriefYAML, "Gateway") {
		t.Fatalf("rejected incident merge changed target:\n%s", draft.BriefYAML)
	}
}

func TestMergeSameIncidentAssembledProductBrief_RejectsDisjointCVEEventsBeforeLLM(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{{
		Merge: boolPtr(true), PreferIncomingNarrative: boolPtr(true), Reason: "both mention Mozilla products",
	}}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	base := `id: brief-2026-10-21-mozilla-vulnerabilities
slug: 2026-10-mozilla-vulnerabilities
title: Mozilla Firefox and Thunderbird Multiple Vulnerabilities
summary: Multiple Mozilla browser vulnerabilities.
severity: high
published_at: "2026-10-21T14:19:28Z"
content: Mozilla Firefox and Thunderbird vulnerabilities.
cves: [CVE-2026-113399, CVE-2026-113866]
affected_vendors: [Mozilla]
affected_products: [Firefox, Thunderbird]
`
	if err := db.CreateDraft(&storage.Draft{ID: "draft-mozilla", Status: storage.StatusApproved, BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	incoming := `id: brief-2026-10-21-emudhra-ca-compromise
slug: 2026-10-emudhra-ca-compromise
title: eMudhra CA compromise requires Mozilla trust-store updates
summary: Compromised eMudhra intermediate keys affect browser trust stores.
severity: high
published_at: "2026-10-21T20:58:00Z"
content: Mozilla and other vendors distrusted the eMudhra intermediates.
cves: [CVE-2026-111943]
affected_vendors: [eMudhra, Mozilla]
affected_products: [Firefox, Go]
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{
		SourceID: "talos:emudhra", Source: "talos", Title: "eMudhra compromise response",
	}, []string{"CVE-2026-111943"}, &ExtractionResult{CVEs: []string{"CVE-2026-111943"}, AffectedVendors: []string{"eMudhra", "Mozilla"}})
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("disjoint CVE events must remain separate")
	}
	if llm.calls != 0 {
		t.Fatalf("disjoint CVE events should fail closed before LLM, got %d calls", llm.calls)
	}
	draft, _ := db.GetDraft("draft-mozilla")
	if draft.BriefYAML != base {
		t.Fatalf("Mozilla draft was mutated by disjoint eMudhra event:\n%s", draft.BriefYAML)
	}
}

func TestMergeSameIncidentAssembledProductBrief_RejectsExplicitLLMNegativeDecision(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{{
		Merge: boolPtr(false), Reason: "similar certificate terminology, separate events",
	}}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	base := `id: brief-acme-signing
slug: acme-signing
title: "Acme certificate key recovery"
summary: "Certificate key recovery in the signing service."
severity: high
published_at: "2026-10-21T00:00:00Z"
content: "Signing service event."
affected_vendors: [Acme]
affected_products: [Signing Service]
references: [https://example.test/signing]
`
	if err := db.CreateDraft(&storage.Draft{ID: "draft-acme", Status: storage.StatusApproved, BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	incoming := `id: brief-acme-trust
slug: acme-trust
title: "Acme certificate key rotation"
summary: "Certificate key rotation in a separate trust service event."
severity: high
published_at: "2026-10-21T01:00:00Z"
content: "Trust service event."
affected_vendors: [Acme]
affected_products: [Trust Service]
references: [https://example.test/trust]
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{SourceID: "acme:trust", Source: "vendor"}, nil, nil)
	if err != nil {
		t.Fatalf("same-incident check: %v", err)
	}
	if handled {
		t.Fatal("explicit negative decision must keep briefs separate")
	}
	if llm.calls != 1 {
		t.Fatalf("expected one LLM decision, got %d", llm.calls)
	}
}

func TestMergeSameIncidentAssembledProductBrief_MissingLLMDecisionDefers(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	base := `id: brief-acme-signing
slug: acme-signing
title: "Acme certificate key recovery"
summary: "Certificate key recovery in the signing service."
severity: high
published_at: "2026-10-21T00:00:00Z"
content: "Signing service event."
affected_vendors: [Acme]
affected_products: [Signing Service]
references: [https://example.test/signing]
`
	if err := db.CreateDraft(&storage.Draft{ID: "draft-acme", Status: storage.StatusApproved, BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	incoming := `id: brief-acme-trust
slug: acme-trust
title: "Acme certificate key rotation"
summary: "Certificate key rotation in a separate trust service event."
severity: high
published_at: "2026-10-21T01:00:00Z"
content: "Trust service event."
affected_vendors: [Acme]
affected_products: [Trust Service]
references: [https://example.test/trust]
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{SourceID: "acme:trust", Source: "vendor"}, nil, nil)
	if !errors.Is(err, errSameIncidentDecisionUnavailable) {
		t.Fatalf("same-incident check error = %v, want retryable unavailable decision", err)
	}
	if handled {
		t.Fatal("missing model decision must fail closed")
	}
	if llm.calls != 1 {
		t.Fatalf("expected one LLM decision, got %d", llm.calls)
	}
}

func TestMergeSameIncidentAssembledProductBrief_RemovesMultiWordVendorTokens(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{{Merge: boolPtr(false)}}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	base := `id: brief-palo-alto-firewall
slug: palo-alto-firewall
title: "Palo Alto Networks firewall authentication bypass"
summary: "Firewall authentication bypass."
severity: high
published_at: "2026-10-21T00:00:00Z"
content: "Firewall event."
affected_vendors: [Palo Alto Networks]
affected_products: [PAN-OS]
references: [https://example.test/firewall]
`
	if err := db.CreateDraft(&storage.Draft{ID: "draft-palo-alto", Status: storage.StatusApproved, BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	incoming := `id: brief-palo-alto-endpoint
slug: palo-alto-endpoint
title: "Palo Alto Networks endpoint privilege escalation"
summary: "Endpoint privilege escalation."
severity: high
published_at: "2026-10-21T01:00:00Z"
content: "Endpoint event."
affected_vendors: [Palo Alto Networks]
affected_products: [Cortex XDR]
references: [https://example.test/endpoint]
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{SourceID: "paloalto:endpoint", Source: "vendor"}, nil, nil)
	if err != nil {
		t.Fatalf("same-incident check: %v", err)
	}
	if handled {
		t.Fatal("unrelated multi-word-vendor briefs must not merge")
	}
	if llm.calls != 0 {
		t.Fatalf("vendor words must not satisfy the incident-token threshold, got %d calls", llm.calls)
	}
}

func TestMergeSameIncidentAssembledProductBrief_LLMErrorDefers(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{err: errors.New("model unavailable")}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	base := `id: brief-acme-signing
slug: acme-signing
title: "Acme Signing certificate key recovery"
summary: "Signing certificate key recovery."
severity: high
published_at: "2026-10-21T00:00:00Z"
content: "Acme Signing certificate key recovery."
affected_vendors: [Acme]
affected_products: [Signing Service]
references: [https://example.test/signing]
`
	if err := db.CreateDraft(&storage.Draft{ID: "draft-acme", Status: storage.StatusApproved, BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	incoming := `id: brief-acme-trust
slug: acme-trust
title: "Acme Trust bundle certificate key response"
summary: "Trust bundle response to a certificate key event."
severity: high
published_at: "2026-10-21T01:00:00Z"
content: "Acme Trust bundle certificate key response."
affected_vendors: [Acme]
affected_products: [Trust Bundle]
references: [https://example.test/trust]
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{SourceID: "acme:gateway", Source: "vendor"}, nil, nil)
	if !errors.Is(err, errSameIncidentDecisionUnavailable) {
		t.Fatalf("LLM failure error = %v, want retryable unavailable decision", err)
	}
	if handled {
		t.Fatal("LLM error must fail closed instead of merging")
	}
	if llm.calls != 1 {
		t.Fatalf("expected one LLM attempt for a plausible candidate, got %d", llm.calls)
	}
}
