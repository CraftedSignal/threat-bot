package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// stubNVD makes the CVE verifier report every CVE as existing, without
// network access, so enrichment sees every CVE a merged brief mentions.
func stubNVD(p *Pipeline) {
	p.cveVerifier.client = &http.Client{Transport: &mockNVDTransport{
		handler: func(*http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			_ = json.NewEncoder(rec).Encode(nvdDetailResponse{Vulnerabilities: []nvdVulnerability{{}}})
			return rec.Result(), nil
		},
	}}
}

const ioUringBriefYAML = `id: brief-2026-10-23-linux-kernel-lpe
slug: 2026-10-linux-kernel-lpe
title: "Linux Kernel: io_uring privilege escalation (CVE-2024-0582)"
summary: An io_uring use-after-free enables local privilege escalation.
severity: high
published_at: "2026-10-23T19:48:50Z"
content: CVE-2024-0582 lets a local user write /etc/passwd through io_uring.
affected_vendors:
  - Linux
affected_products:
  - Linux Kernel
cves:
  - id: CVE-2024-0582
    cvss: 7.8
`

func createIOUringDraft(t *testing.T, p *Pipeline, db *storage.DB) {
	t.Helper()
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-io-uring",
		Status:    storage.StatusApproved,
		Source:    "sploitus",
		SourceIDs: `["sploitus:io-uring"]`,
		BriefYAML: ioUringBriefYAML,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	p.indexContent("draft-io-uring", scraper.RawItem{
		SourceID: "sploitus:io-uring",
		Source:   "sploitus",
		Title:    "Exploit for CVE-2024-0582",
	}, nil, &ExtractionResult{
		CVEs:             []string{"CVE-2024-0582"},
		AffectedVendors:  []string{"Linux"},
		AffectedProducts: []string{"Linux Kernel"},
	}, ioUringBriefYAML)
}

// In October 2026 the io_uring brief absorbed an unrelated TCP use-after-free:
// both were Linux Kernel product briefs published in the same week, and the
// same-week product merge keyed on the product alone.
func TestMergeSameWeekAssembledProductBrief_DifferentCVEStaysSeparate(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	createIOUringDraft(t, p, db)

	incoming := `id: brief-2026-10-29-linux-kernel-tcp-race
slug: 2026-10-linux-kernel-tcp-race
title: "Linux Kernel: TCP IPv4 use-after-free (CVE-2026-98432)"
summary: A race in IPv4 TCP handshake handling allows remote code execution.
severity: critical
published_at: "2026-10-29T15:52:00Z"
affected_vendors:
  - Linux
affected_products:
  - Linux Kernel
cves:
  - id: CVE-2026-98432
    cvss: 9.8
`
	item := scraper.RawItem{
		SourceID: "sploitus:6854C6B5-0F5C-5F26-B4EF-B42BD296BCAE",
		Source:   "sploitus",
		Title:    "Exploit for CVE-2026-98432",
	}
	handled, err := p.mergeSameWeekAssembledProductBrief(incoming, item, []string{"CVE-2026-98432"}, &ExtractionResult{
		CVEs:             []string{"CVE-2026-98432"},
		AffectedVendors:  []string{"Linux"},
		AffectedProducts: []string{"Linux Kernel"},
	})
	if err != nil {
		t.Fatalf("same-week merge: %v", err)
	}
	if handled {
		t.Fatal("a brief about CVE-2026-98432 was merged into the CVE-2024-0582 brief")
	}
	draft, err := db.GetDraft("draft-io-uring")
	if err != nil {
		t.Fatal(err)
	}
	if draft.BriefYAML != ioUringBriefYAML {
		t.Fatalf("io_uring brief was modified:\n%s", draft.BriefYAML)
	}
}

// A merge copies an assembled brief's severity, actions and TTPs, so a brief
// that covers another CVE besides the existing brief's stays separate.
func TestMergeSameWeekAssembledProductBrief_MixedCVEBriefStaysSeparate(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	createIOUringDraft(t, p, db)

	incoming := `id: brief-2026-10-29-linux-kernel-fixes
slug: 2026-10-linux-kernel-fixes
title: "Linux Kernel fixes io_uring and TCP flaws"
summary: The release fixes CVE-2024-0582 and the critical TCP flaw CVE-2026-98432.
severity: critical
published_at: "2026-10-29T15:52:00Z"
affected_vendors:
  - Linux
affected_products:
  - Linux Kernel
cves:
  - id: CVE-2024-0582
  - id: CVE-2026-98432
`
	item := scraper.RawItem{SourceID: "news:kernel-fixes", Source: "bleepingcomputer", Title: "Linux kernel fixes"}
	handled, err := p.mergeSameWeekAssembledProductBrief(incoming, item, nil, &ExtractionResult{
		CVEs:             []string{"CVE-2024-0582", "CVE-2026-98432"},
		AffectedVendors:  []string{"Linux"},
		AffectedProducts: []string{"Linux Kernel"},
	})
	if err != nil {
		t.Fatalf("same-week merge: %v", err)
	}
	if handled {
		t.Fatal("a brief that also covers CVE-2026-98432 was merged into the CVE-2024-0582 brief")
	}
}

func TestMergeIntoDraft_RefusesDifferentCVE(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: mergeRelevanceMockLLM{
		merge:             true,
		referenceRelevant: true,
		cves:              []string{"CVE-2026-98432"},
		vendors:           []string{"Linux"},
		products:          []string{"Linux Kernel"},
	}})
	stubNVD(p)
	createIOUringDraft(t, p, db)

	item := scraper.RawItem{
		SourceID: "thn:linux-tcp",
		Source:   "the-hacker-news",
		Title:    "Linux kernel TCP flaw CVE-2026-98432 allows remote root",
		URL:      "https://thehackernews.com/2026/10/linux-kernel-tcp-flaw.html",
		Content:  "CVE-2026-98432 is a use-after-free in the Linux kernel IPv4 TCP stack.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-98432"},
		AffectedVendors:  []string{"Linux"},
		AffectedProducts: []string{"Linux Kernel"},
	}
	err := p.mergeIntoDraft(context.Background(), "draft-io-uring", extraction, item)
	if !errors.Is(err, errMergeNotRelevant) {
		t.Fatalf("merge error = %v, want a refusal callers process as a new item", err)
	}
	draft, err := db.GetDraft("draft-io-uring")
	if err != nil {
		t.Fatal(err)
	}
	if draft.BriefYAML != ioUringBriefYAML {
		t.Fatalf("io_uring brief was modified:\n%s", draft.BriefYAML)
	}
}

// A source about the brief's CVE that also covers an unchained second CVE
// updates the brief with the brief's CVE only. The brief title names no CVE,
// so the single-CVE title scope does not apply.
func TestMergeIntoDraft_KeepsOtherCVEOutOfBrief(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: mergeRelevanceMockLLM{
		merge:             true,
		referenceRelevant: true,
		cves:              []string{"CVE-2024-0582", "CVE-2026-98432"},
		vendors:           []string{"Linux"},
		products:          []string{"Linux Kernel"},
	}})
	stubNVD(p)
	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-io-uring", Status: storage.StatusApproved, Source: "sploitus",
		BriefYAML: strings.Replace(ioUringBriefYAML, " (CVE-2024-0582)", "", 1), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	item := scraper.RawItem{
		SourceID: "news:kernel-fixes",
		Source:   "bleepingcomputer",
		Title:    "Linux kernel fixes CVE-2024-0582 and CVE-2026-98432",
		URL:      "https://news.example/linux-kernel-fixes",
		Content:  "The release fixes CVE-2024-0582 in io_uring and CVE-2026-98432, a separate TCP flaw.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2024-0582", "CVE-2026-98432"},
		AffectedVendors:  []string{"Linux"},
		AffectedProducts: []string{"Linux Kernel"},
	}
	if err := p.mergeIntoDraft(context.Background(), "draft-io-uring", extraction, item); err != nil {
		t.Fatalf("merge: %v", err)
	}
	draft, err := db.GetDraft("draft-io-uring")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(draft.BriefYAML, item.URL) {
		t.Fatalf("merge did not add the source reference:\n%s", draft.BriefYAML)
	}
	if got := briefCVEIDs(parseBriefFrontmatter(draft.BriefYAML)); len(got) != 1 || !got["CVE-2024-0582"] {
		t.Fatalf("brief CVEs = %v, want only CVE-2024-0582:\n%s", got, draft.BriefYAML)
	}
}

// Enrichment after a merge reads CVE IDs from the whole brief, including the
// source URL the merge adds as a reference.
func TestMergeIntoDraft_DoesNotTakeCVEFromReferenceURL(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: mergeRelevanceMockLLM{
		merge:             true,
		referenceRelevant: true,
		cves:              []string{"CVE-2024-0582"},
		vendors:           []string{"Linux"},
		products:          []string{"Linux Kernel"},
	}})
	stubNVD(p)
	createIOUringDraft(t, p, db)

	item := scraper.RawItem{
		SourceID: "sploitus:KITPLOIT-CVE-2024-0582",
		Source:   "sploitus",
		Title:    "Exploit for CVE-2024-0582",
		URL:      "https://exploits.example/kernel?cves=CVE-2024-0582,CVE-2026-98432",
		Content:  "A public exploit for CVE-2024-0582 writes /etc/passwd through io_uring.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2024-0582"},
		AffectedVendors:  []string{"Linux"},
		AffectedProducts: []string{"Linux Kernel"},
	}
	if err := p.mergeIntoDraft(context.Background(), "draft-io-uring", extraction, item); err != nil {
		t.Fatalf("merge: %v", err)
	}
	draft, err := db.GetDraft("draft-io-uring")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(draft.BriefYAML, item.URL) {
		t.Fatalf("merge did not add the source reference:\n%s", draft.BriefYAML)
	}
	if got := briefCVEIDs(parseBriefFrontmatter(draft.BriefYAML)); len(got) != 1 || !got["CVE-2024-0582"] {
		t.Fatalf("brief CVEs = %v, want only CVE-2024-0582:\n%s", got, draft.BriefYAML)
	}
}

// Index rows are derived from drafts. After a correction removes a CVE from a
// brief, the rows indexed for it must not keep routing that CVE's coverage to
// the corrected brief.
func TestCheckPostExtraction_IgnoresCVERowsItsDraftNoLongerLists(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	tcpYAML := "affected_products:\n  - Linux Kernel\ncves:\n  - id: CVE-2026-98432\n"
	for _, d := range []*storage.Draft{
		{ID: "draft-io-uring", Status: storage.StatusApproved, Source: "sploitus", BriefYAML: ioUringBriefYAML, CreatedAt: time.Now()},
		{ID: "draft-tcp", Status: storage.StatusApproved, Source: "the-hacker-news", BriefYAML: tcpYAML, CreatedAt: time.Now()},
	} {
		if err := db.CreateDraft(d); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []storage.ContentIndexEntry{
		{CVEID: "CVE-2026-98432", DraftID: "draft-io-uring", SourceID: "sploitus:6854C6B5", Source: "sploitus", CreatedAt: time.Now()},
		{CVEID: "CVE-2026-98432", DraftID: "draft-tcp", SourceID: "thn:linux-tcp", Source: "the-hacker-news", CreatedAt: time.Now()},
	} {
		if err := db.IndexContent(&e); err != nil {
			t.Fatal(err)
		}
	}

	item := scraper.RawItem{
		SourceID: "bluesky:post",
		Source:   "bluesky-discovery",
		Title:    "CVE-2026-98432 | Ubuntu",
		Content:  "CVE-2026-98432 affects the Linux kernel IPv4 TCP stack.",
	}
	_, entries := dedup.CheckPostExtraction(item, &ExtractionResult{CVEs: []string{"CVE-2026-98432"}})
	for _, e := range entries {
		if e.DraftID == "draft-io-uring" {
			t.Fatalf("CVE-2026-98432 still routes to the io_uring brief: %+v", entries)
		}
	}
}

func TestCheckPreExtraction_SameTitleDifferentCVEIsNotDuplicate(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	title := "Linux Kernel Use-After-Free Vulnerability"
	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-io-uring", Status: storage.StatusApproved, Source: "nvd",
		BriefYAML: ioUringBriefYAML, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2024-0582", TitleHash: NormalizeTitleHash(title),
		DraftID: "draft-io-uring", SourceID: "nvd:CVE-2024-0582", Source: "nvd", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	item := scraper.RawItem{
		SourceID: "ghsa:tcp",
		Source:   "ghsa",
		Title:    title,
		Content:  "A race in the IPv4 TCP handshake frees request options early.",
		Metadata: map[string]string{"cve": "CVE-2026-98432"},
	}
	if decision, _, entries := dedup.CheckPreExtraction(item); decision != DedupNew {
		t.Fatalf("decision = %d against %+v, want DedupNew for a different CVE", decision, entries)
	}
}

// A source can describe an incident without naming a CVE while two existing
// briefs each cover a different CVE of it. Each brief keeps its own CVE.
func TestMergeSameIncidentAssembledProductBrief_DoesNotConvergeDifferentCVEBriefs(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	now := time.Now().UTC()
	drafts := []*storage.Draft{
		{
			ID: "gateway-auth-bypass", Status: storage.StatusApproved, Source: "nvd",
			SourceIDs: `["nvd:CVE-2026-1001"]`, CreatedAt: now.Add(-3 * 24 * time.Hour),
			BriefYAML: `id: brief-2026-10-acme-gateway-auth-bypass
slug: 2026-10-acme-gateway-auth-bypass
title: Acme Gateway SAML authentication bypass exploited in espionage campaign
summary: Attackers exploited an Acme Gateway SAML authentication bypass in an espionage campaign.
severity: critical
published_at: "2026-10-20T08:00:00Z"
content: CVE-2026-1001 lets attackers bypass Acme Gateway SAML authentication.
affected_vendors: [Acme]
affected_products: [Acme Gateway]
cves:
  - id: CVE-2026-1001
`,
		},
		{
			ID: "gateway-command-injection", Status: storage.StatusApproved, Source: "nvd",
			SourceIDs: `["nvd:CVE-2026-1002"]`, CreatedAt: now.Add(-2 * 24 * time.Hour),
			BriefYAML: `id: brief-2026-10-acme-gateway-command-injection
slug: 2026-10-acme-gateway-command-injection
title: Acme Gateway command injection exploited in espionage campaign
summary: Attackers exploited an Acme Gateway command injection in an espionage campaign.
severity: critical
published_at: "2026-10-21T08:00:00Z"
content: CVE-2026-1002 is a command injection in the Acme Gateway admin interface.
affected_vendors: [Acme]
affected_products: [Acme Gateway]
cves:
  - id: CVE-2026-1002
`,
		},
	}
	for _, draft := range drafts {
		if err := db.CreateDraft(draft); err != nil {
			t.Fatal(err)
		}
	}
	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{
		{Merge: boolPtr(true), PreferIncomingNarrative: boolPtr(false), Reason: "same Acme Gateway espionage campaign"},
	}}
	pub := &sameIncidentRetirementPublisher{}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm, Publisher: pub, AutoPublish: true})
	incoming := `id: brief-2026-10-acme-gateway-espionage
slug: 2026-10-acme-gateway-espionage
title: Espionage campaign exploited Acme Gateway appliances
summary: Attackers exploited Acme Gateway appliances in an espionage campaign.
severity: critical
published_at: "2026-10-22T08:00:00Z"
content: Acme reported an espionage campaign against Acme Gateway appliances.
affected_vendors: [Acme]
affected_products: [Acme Gateway]
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{
		SourceID: "acme:advisory", Source: "acme", Title: "Espionage campaign exploited Acme Gateway appliances",
	}, nil, &ExtractionResult{AffectedVendors: []string{"Acme"}, AffectedProducts: []string{"Acme Gateway"}})
	if err != nil {
		t.Fatalf("same-incident merge: %v", err)
	}
	if !handled {
		t.Fatalf("expected the CVE-less campaign brief to merge; LLM calls=%d", llm.calls)
	}
	if len(pub.retired) != 0 {
		t.Fatalf("retired %v; briefs about different CVEs must not converge", pub.retired)
	}
	for _, id := range []string{"gateway-auth-bypass", "gateway-command-injection"} {
		draft, err := db.GetDraft(id)
		if err != nil {
			t.Fatal(err)
		}
		if draft.Status != storage.StatusApproved {
			t.Fatalf("%s status = %s, want approved", id, draft.Status)
		}
	}
	canonical, err := db.GetDraft("gateway-auth-bypass")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(canonical.BriefYAML, "CVE-2026-1002") {
		t.Fatalf("CVE-2026-1001 brief absorbed CVE-2026-1002:\n%s", canonical.BriefYAML)
	}
}

// A source that documents two CVEs exploited as one chain describes one
// incident, so its CVEs and the brief's belong together.
func TestMergeIntoDraft_AddsCVEChainedWithBriefCVE(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: mergeRelevanceMockLLM{
		merge:             true,
		referenceRelevant: true,
		cves:              []string{"CVE-2024-0582", "CVE-2026-98432"},
		vendors:           []string{"Linux"},
		products:          []string{"Linux Kernel"},
	}})
	stubNVD(p)
	createIOUringDraft(t, p, db)

	item := scraper.RawItem{
		SourceID: "research:chain",
		Source:   "research",
		Title:    "Remote root on Linux by chaining CVE-2026-98432 with CVE-2024-0582",
		URL:      "https://research.example/linux-chain",
		Content:  "The exploit gains a foothold through CVE-2026-98432 and chains it with CVE-2024-0582 to become root.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2024-0582", "CVE-2026-98432"},
		ChainedCVEs:      [][]string{{"CVE-2026-98432", "CVE-2024-0582"}},
		AffectedVendors:  []string{"Linux"},
		AffectedProducts: []string{"Linux Kernel"},
	}
	if err := p.mergeIntoDraft(context.Background(), "draft-io-uring", extraction, item); err != nil {
		t.Fatalf("merge: %v", err)
	}
	draft, err := db.GetDraft("draft-io-uring")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CVE-2026-98432", "https://research.example/linux-chain"} {
		if !strings.Contains(draft.BriefYAML, want) {
			t.Fatalf("merged brief missing %q:\n%s", want, draft.BriefYAML)
		}
	}
}

func TestMergeSameWeekAssembledProductBrief_MergesChainedCVEs(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	createIOUringDraft(t, p, db)

	incoming := `id: brief-2026-10-29-linux-kernel-remote-root
slug: 2026-10-linux-kernel-remote-root
title: "Linux Kernel: remote root via CVE-2026-98432 and CVE-2024-0582"
summary: Attackers chain a TCP use-after-free with an io_uring flaw to get remote root.
severity: critical
published_at: "2026-10-29T15:52:00Z"
affected_vendors:
  - Linux
affected_products:
  - Linux Kernel
cves:
  - id: CVE-2026-98432
  - id: CVE-2024-0582
`
	item := scraper.RawItem{SourceID: "research:chain", Source: "research", Title: "Linux remote root chain"}
	handled, err := p.mergeSameWeekAssembledProductBrief(incoming, item, nil, &ExtractionResult{
		CVEs:             []string{"CVE-2026-98432", "CVE-2024-0582"},
		ChainedCVEs:      [][]string{{"CVE-2026-98432", "CVE-2024-0582"}},
		AffectedVendors:  []string{"Linux"},
		AffectedProducts: []string{"Linux Kernel"},
	})
	if err != nil {
		t.Fatalf("same-week merge: %v", err)
	}
	if !handled {
		t.Fatal("a brief that documents the chain was not merged into the brief for one of its CVEs")
	}
	draft, err := db.GetDraft("draft-io-uring")
	if err != nil {
		t.Fatal(err)
	}
	if got := briefCVEIDs(parseBriefFrontmatter(draft.BriefYAML)); !got["CVE-2024-0582"] || !got["CVE-2026-98432"] {
		t.Fatalf("brief CVEs = %v, want both CVEs of the chain:\n%s", got, draft.BriefYAML)
	}
}

func TestCVEChains_LinksCVEsThroughSharedCVE(t *testing.T) {
	chains := cveChains([][]string{
		{"cve-2026-10001", "CVE-2026-10002"},
		{"CVE-2026-10002", "CVE-2026-10003"},
		{"CVE-2026-10009"},
		{"not a cve", "CVE-2026-10008"},
	})
	if !chains.linked("CVE-2026-10001", "CVE-2026-10003") {
		t.Fatal("CVEs joined through a shared CVE are one chain")
	}
	if chains.linked("CVE-2026-10001", "CVE-2026-10009") || chains.linked("CVE-2026-10008", "CVE-2026-10001") {
		t.Fatal("a CVE outside a chain is not linked")
	}
	if !chains.linked("CVE-2026-10005", "cve-2026-10005") {
		t.Fatal("a CVE is linked to itself")
	}
}

// NVD titles repeat across CVEs of one product, so the class fingerprint plus
// a matching title used to drop the second CVE as a duplicate of the first.
func TestCheckPostExtraction_FingerprintMatchWithDifferentCVEIsNotDuplicate(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	vendors := []string{"Sourcecodester"}
	products := []string{"Pharmacy Management System"}
	title := "Sourcecodester Pharmacy Management System SQL Injection"
	fp := Fingerprint(vendors, products, "sql-injection")
	if fp == "" {
		t.Fatal("precondition: class fingerprint must not be empty")
	}
	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-pharmacy", Status: storage.StatusApproved, Source: "nvd",
		BriefYAML: "affected_vendors:\n  - Sourcecodester\naffected_products:\n  - Pharmacy Management System\ncves:\n  - id: CVE-2026-20001\n",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2026-20001", FingerprintHash: fp, TitleNorm: normalizeTitleTokens(title),
		DraftID: "draft-pharmacy", SourceID: "nvd:CVE-2026-20001", Source: "nvd", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	item := scraper.RawItem{
		SourceID: "ghsa:CVE-2026-20002", Source: "ghsa", Title: title,
		Content:  "CVE-2026-20002: SQL injection in the login form of Pharmacy Management System.",
		Metadata: map[string]string{"cve": "CVE-2026-20002"},
	}
	extraction := &ExtractionResult{
		CVEs: []string{"CVE-2026-20002"}, AffectedVendors: vendors, AffectedProducts: products, VulnClass: "sql-injection",
	}
	if decision, entries := dedup.CheckPostExtraction(item, extraction); decision != DedupNew {
		t.Fatalf("decision = %d against %+v, want DedupNew for a different CVE", decision, entries)
	}
}

func TestCheckPostExtraction_SimilarTitleProductMatchWithDifferentCVEIsNotMerged(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	vendors := []string{"Acme"}
	products := []string{"WidgetServer"}
	productFP := ProductFingerprint(vendors, products)
	if productFP == "" {
		t.Fatal("precondition: WidgetServer must produce a product fingerprint")
	}
	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-widget", Status: storage.StatusApproved, Source: "nvd",
		BriefYAML: "affected_vendors:\n  - Acme\naffected_products:\n  - WidgetServer\ncves:\n  - id: CVE-2026-30001\n",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2026-30001", ProductFingerprintHash: productFP,
		TitleNorm: normalizeTitleTokens("Acme WidgetServer authentication bypass"),
		DraftID:   "draft-widget", SourceID: "nvd:CVE-2026-30001", Source: "nvd", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	item := scraper.RawItem{
		SourceID: "ghsa:CVE-2026-30002", Source: "ghsa",
		Title:    "Acme WidgetServer authentication bypass in admin API",
		Content:  "CVE-2026-30002 bypasses authentication in the WidgetServer admin API.",
		Metadata: map[string]string{"cve": "CVE-2026-30002"},
	}
	extraction := &ExtractionResult{CVEs: []string{"CVE-2026-30002"}, AffectedVendors: vendors, AffectedProducts: products}
	if decision, entries := dedup.CheckPostExtraction(item, extraction); decision != DedupNew {
		t.Fatalf("decision = %d against %+v, want DedupNew for a different CVE", decision, entries)
	}
}

func TestMergeSameIncidentAssembledProductBrief_DifferentCVEIsRejectedBeforeLLM(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	llm := &sameIncidentMockLLM{responses: []sameIncidentLLMResponse{
		{Merge: boolPtr(true), PreferIncomingNarrative: boolPtr(false), Reason: "same Acme Gateway espionage campaign"},
	}}
	p := New(Config{DB: db, Logger: slog.Default(), LLMClient: llm})
	base := `id: brief-2026-10-acme-gateway-auth-bypass
slug: 2026-10-acme-gateway-auth-bypass
title: Acme Gateway SAML authentication bypass exploited in espionage campaign
summary: Attackers exploited an Acme Gateway SAML authentication bypass in an espionage campaign.
severity: critical
published_at: "2026-10-20T08:00:00Z"
content: CVE-2026-1001 lets attackers bypass Acme Gateway SAML authentication.
affected_vendors: [Acme]
affected_products: [Acme Gateway]
cves:
  - id: CVE-2026-1001
`
	if err := db.CreateDraft(&storage.Draft{ID: "gateway-auth-bypass", Status: storage.StatusApproved, BriefYAML: base, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	incoming := `id: brief-2026-10-acme-gateway-path-traversal
slug: 2026-10-acme-gateway-path-traversal
title: Acme Gateway path traversal exploited in espionage campaign
summary: Attackers exploited an Acme Gateway path traversal in an espionage campaign.
severity: high
published_at: "2026-10-22T08:00:00Z"
content: CVE-2026-1003 is a path traversal in the Acme Gateway file service.
affected_vendors: [Acme]
affected_products: [Acme Gateway]
cves:
  - id: CVE-2026-1003
`
	handled, err := p.mergeSameIncidentAssembledProductBrief(context.Background(), incoming, scraper.RawItem{
		SourceID: "nvd:CVE-2026-1003", Source: "nvd", Title: "Acme Gateway path traversal",
	}, []string{"CVE-2026-1003"}, &ExtractionResult{
		CVEs: []string{"CVE-2026-1003"}, AffectedVendors: []string{"Acme"}, AffectedProducts: []string{"Acme Gateway"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("a brief about CVE-2026-1003 was merged into the CVE-2026-1001 brief")
	}
	if llm.calls != 0 {
		t.Fatalf("different CVEs should be rejected before the LLM, got %d calls", llm.calls)
	}
	draft, err := db.GetDraft("gateway-auth-bypass")
	if err != nil {
		t.Fatal(err)
	}
	if draft.BriefYAML != base {
		t.Fatalf("CVE-2026-1001 brief was modified:\n%s", draft.BriefYAML)
	}
}
