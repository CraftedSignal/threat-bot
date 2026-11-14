package pipeline

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// cap-go: two DIFFERENT CVEs, SAME specific product, disclosed close together,
// different sources → two vulnerabilities, so two briefs.
func TestCheckPostExtraction_SameProductDifferentCVEStaysSeparate(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	fp := ProductFingerprint(nil, []string{"cap-go"})
	if fp == "" {
		t.Fatal("precondition: cap-go must produce a product fingerprint")
	}
	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-capgo", Status: storage.StatusPending, Source: "ghsa",
		BriefYAML: "cves:\n  - CVE-2026-56081\naffected_products:\n  - cap-go\n",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2026-56081", ProductFingerprintHash: fp,
		DraftID: "draft-capgo", SourceID: "ghsa:81", Source: "ghsa", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("index: %v", err)
	}

	item := scraper.RawItem{
		SourceID: "nvd:CVE-2026-56073", Source: "nvd",
		Title:   "CVE-2026-56073: Cap-go OTP Verification Authentication Bypass",
		Content: "An OTP verification flaw in cap-go allows authentication bypass.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-56073"},
		AffectedProducts: []string{"cap-go"},
		VulnClass:        "auth-bypass",
	}
	if decision, entries := dedup.CheckPostExtraction(item, extraction); decision != DedupNew {
		t.Fatalf("want DedupNew for same-product different-CVE, got %d against %+v", decision, entries)
	}
}

func TestMergeSameDayAssembledProductBrief_SigmaRuleMergesRules(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	now := time.Now().UTC()

	baseYAML := `id: brief-bedrock
title: AWS Bedrock Claude Detection Coverage
summary: Existing Bedrock Claude detection coverage.
severity: medium
published_at: "` + now.Format(time.RFC3339) + `"
content: Existing coverage.
affected_vendors:
  - AWS
affected_products:
  - AWS Bedrock Claude
references:
  - https://research.example.com/bedrock-large-prompts
rules:
  - title: Detect Large Prompts in AWS Bedrock Claude
    description: Detects unusually large prompts.
    logsource:
      product: aws
      service: bedrock
    detection:
      selection:
        eventName: InvokeModel
      condition: selection
    level: medium
`
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-bedrock",
		Status:    storage.StatusApproved,
		Source:    "splunk-escu",
		SourceIDs: `["splunk-escu:one"]`,
		BriefYAML: baseYAML,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}

	incomingYAML := `id: brief-bedrock-sensitive-data
title: Sensitive Data Exposure in AWS Bedrock Claude Prompts
summary: Adds sensitive-data prompt exposure coverage.
severity: high
published_at: "` + now.Format(time.RFC3339) + `"
content: Incoming coverage.
affected_vendors:
  - AWS
affected_products:
  - AWS Bedrock Claude
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_sensitive_data_in_prompts.yml
rules:
  - title: Detect Sensitive Data in AWS Bedrock Claude Prompts
    description: Detects secrets in prompts.
    logsource:
      product: aws
      service: bedrock
    detection:
      selection:
        eventName: InvokeModel
      condition: selection
    level: high
`
	item := scraper.RawItem{
		SourceID:    "splunk-escu:two",
		Source:      "splunk-escu",
		Title:       "Sensitive Data Exposure in AWS Bedrock Claude Prompts",
		URL:         "https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_sensitive_data_in_prompts.yml",
		PublishedAt: now,
		SigmaRule:   &scraper.SigmaRule{Title: "Detect Sensitive Data in AWS Bedrock Claude Prompts"},
	}

	handled, err := p.mergeSameWeekAssembledProductBrief(incomingYAML, item, nil, nil)
	if err != nil {
		t.Fatalf("merge same-day assembled brief: %v", err)
	}
	if !handled {
		t.Fatal("expected same-day assembled product brief to merge")
	}
	draft, err := db.GetDraft("draft-bedrock")
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}
	for _, want := range []string{
		"Detect Large Prompts in AWS Bedrock Claude",
		"Detect Sensitive Data in AWS Bedrock Claude Prompts",
		"added detection rule: Detect Sensitive Data in AWS Bedrock Claude Prompts",
		"source_urls:",
		item.URL,
		"severity: high",
	} {
		if !strings.Contains(draft.BriefYAML, want) {
			t.Fatalf("merged draft missing %q:\n%s", want, draft.BriefYAML)
		}
	}
	entries, err := db.FindByProductAndDay(briefProductFingerprint(incomingYAML), SourcePublishedDay(now))
	if err != nil {
		t.Fatalf("find product/day: %v", err)
	}
	if len(entries) == 0 || entries[0].DraftID != "draft-bedrock" {
		t.Fatalf("expected merged rule indexed under canonical draft, got %+v", entries)
	}
}

func TestMergeSameWeekAssembledProductBrief_IgnoresRejectedIndexTarget(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	now := time.Now().UTC()
	base := `id: rejected-token-replay
slug: rejected-token-replay
title: Rejected M365 token replay brief
summary: Rejected duplicate.
severity: high
published_at: "2026-10-22T00:00:00Z"
content: Rejected duplicate.
affected_vendors: [Microsoft]
affected_products: [Microsoft 365]
references: [https://example.test/rejected]
`
	if err := db.CreateDraft(&storage.Draft{
		ID: "rejected-token-replay", Status: storage.StatusRejected, Source: "huntress", BriefYAML: base, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	fp := briefProductFingerprint(base)
	if err := db.IndexContent(&storage.ContentIndexEntry{
		ProductFingerprintHash: fp, DraftID: "rejected-token-replay", SourceID: "huntress:old",
		Source: "huntress", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	incoming := strings.ReplaceAll(base, "rejected-token-replay", "incoming-token-replay")
	handled, err := p.mergeSameWeekAssembledProductBrief(incoming, scraper.RawItem{
		SourceID: "huntress:token-replay-spray", Source: "huntress", Title: "M365 token spray and replay campaign",
	}, nil, &ExtractionResult{AffectedVendors: []string{"Microsoft"}, AffectedProducts: []string{"Microsoft 365"}})
	if err != nil {
		t.Fatalf("rejected target should be ignored, got error: %v", err)
	}
	if handled {
		t.Fatal("rejected target must not handle the incoming brief")
	}
}

// Two unrelated CVEs sharing only a generic platform ("WordPress") must NOT merge.
func TestCheckPostExtraction_GenericProductDoesNotMerge(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	// Seed a WordPress brief (generic product → no product key, but prove no merge).
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2026-1000", ProductFingerprintHash: "wp",
		DraftID: "draft-wp", SourceID: "nvd:1000", Source: "nvd", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("index: %v", err)
	}
	item := scraper.RawItem{SourceID: "ghsa:x", Source: "ghsa", Title: "Some WordPress plugin issue", Content: "..."}
	extraction := &ExtractionResult{CVEs: []string{"CVE-2026-2000"}, AffectedProducts: []string{"WordPress"}}
	if decision, _ := dedup.CheckPostExtraction(item, extraction); decision == DedupMerge {
		t.Fatal("generic product must not merge")
	}
}

func TestProductFingerprint_GenericVendorProductSkipped(t *testing.T) {
	if fp := ProductFingerprint([]string{"Microsoft"}, []string{"Windows"}); fp != "" {
		t.Fatalf("generic vendor product must not produce fingerprint, got %q", fp)
	}
	if fp := ProductFingerprint(nil, []string{"cap-go"}); fp == "" {
		t.Fatal("specific vendorless product should still produce fingerprint")
	}
}

func TestCheckPostExtraction_SameDaySpecificProductMerges(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	productFP := ProductFingerprint([]string{"Acme"}, []string{"DeployOnce"})
	if productFP == "" {
		t.Fatal("precondition: DeployOnce must produce product fingerprint")
	}

	if err := db.CreateDraft(&storage.Draft{
		ID:     "draft-deployonce",
		Status: storage.StatusPending,
		Source: "research",
		BriefYAML: `affected_vendors:
  - "Acme"
affected_products:
  - "DeployOnce"
`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		ProductFingerprintHash: productFP,
		TitleNorm:              normalizeTitleTokens("Threat Actors Abuse Acme DeployOnce for Initial Access"),
		SourceURLHash:          SourceURLHash("https://research.example.com/deployonce-part-one"),
		SourcePublishedDay:     "2026-07-07",
		DraftID:                "draft-deployonce",
		SourceID:               "research:one",
		Source:                 "research",
		CreatedAt:              time.Now(),
	}); err != nil {
		t.Fatalf("index: %v", err)
	}

	item := scraper.RawItem{
		SourceID:    "research:two",
		Source:      "research",
		Title:       "Threat Actors Abuse Acme DeployOnce for Persistence",
		URL:         "https://research.example.com/deployonce-part-two",
		PublishedAt: time.Date(2026, 7, 7, 18, 0, 0, 0, time.UTC),
		Content:     "Follow-up coverage of DeployOnce abuse for persistence.",
	}
	extraction := &ExtractionResult{
		AffectedVendors:  []string{"Acme"},
		AffectedProducts: []string{"DeployOnce"},
	}

	decision, entries := dedup.CheckPostExtraction(item, extraction)
	if decision != DedupMerge {
		t.Fatalf("want DedupMerge for same-day specific product, got %d", decision)
	}
	if len(entries) == 0 || entries[0].DraftID != "draft-deployonce" {
		t.Fatalf("want merge target draft-deployonce, got %+v", entries)
	}
}

func TestCheckPostExtraction_CanonicalPythonProductMerges(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	productFP := ProductFingerprint([]string{"Python Software Foundation"}, []string{"Python"})
	if productFP == "" {
		t.Fatal("precondition: upstream Python runtime must produce product fingerprint")
	}
	if err := db.CreateDraft(&storage.Draft{
		ID:     "draft-python",
		Status: storage.StatusPending,
		Source: "cert",
		BriefYAML: `affected_vendors:
  - "Python Software Foundation"
affected_products:
  - "Python"
`,
		CreatedAt: time.Date(2026, 7, 10, 7, 29, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		ProductFingerprintHash: productFP,
		TitleNorm:              normalizeTitleTokens("Python: Vulnerability Enables File Manipulation"),
		SourcePublishedDay:     "2026-07-10",
		DraftID:                "draft-python",
		SourceID:               "cert:python-file",
		Source:                 "cert",
		CreatedAt:              time.Now(),
	}); err != nil {
		t.Fatalf("index: %v", err)
	}

	item := scraper.RawItem{
		SourceID:    "cert:python-rce",
		Source:      "cert",
		Title:       "Python Remote Code Execution Vulnerability",
		PublishedAt: time.Date(2026, 7, 10, 7, 35, 0, 0, time.UTC),
	}
	extraction := &ExtractionResult{
		AffectedVendors:  []string{"Python Software Foundation"},
		AffectedProducts: []string{"Python"},
	}
	decision, entries := dedup.CheckPostExtraction(item, extraction)
	if decision != DedupMerge {
		t.Fatalf("want DedupMerge for same-day Python runtime advisory, got %d", decision)
	}
	if len(entries) == 0 || entries[0].DraftID != "draft-python" {
		t.Fatalf("want merge target draft-python, got %+v", entries)
	}
}

func TestMergeSameDayAssembledProductBrief_MergesNonRulePythonAdvisory(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()

	p := New(Config{DB: db, Logger: slog.Default()})
	now := time.Date(2026, 7, 10, 7, 29, 0, 0, time.UTC)
	baseYAML := `id: "brief-2026-07-python-file-manipulation"
slug: "2026-07-python-file-manipulation"
title: "Python: Vulnerability Enables File Manipulation"
summary: "Python file manipulation vulnerability."
severity: "medium"
published_at: "2026-07-10T07:29:00Z"
affected_vendors:
  - "Python Software Foundation"
affected_products:
  - "Python"
references:
  - "https://example.test/python-file-manipulation"
tags:
  - "python"
rules:
  - title: "Detect Python File Manipulation"
    description: "Detects suspicious Python file writes."
    logsource:
      category: "file_event"
      product: "linux"
    detection:
      selection:
        Image|endswith: "/python"
      condition: "selection"
    level: "medium"
`
	baseItem := scraper.RawItem{
		SourceID:    "cert:python-file",
		Source:      "cert",
		Title:       "Python: Vulnerability Enables File Manipulation",
		URL:         "https://example.test/python-file-manipulation",
		PublishedAt: now,
	}
	extraction := &ExtractionResult{
		AffectedVendors:  []string{"Python Software Foundation"},
		AffectedProducts: []string{"Python"},
	}
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-python",
		Status:    storage.StatusPending,
		Source:    baseItem.Source,
		SourceIDs: `["cert:python-file"]`,
		BriefYAML: baseYAML,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	p.indexContent("draft-python", baseItem, nil, extraction, baseYAML)

	incomingYAML := `id: "brief-2026-07-python-rce"
slug: "2026-07-python-rce"
title: "Python Remote Code Execution Vulnerability"
summary: "Python remote code execution vulnerability."
severity: "high"
published_at: "2026-07-10T07:35:00Z"
affected_vendors:
  - "Python Software Foundation"
affected_products:
  - "Python"
references:
  - "https://example.test/python-rce"
tags:
  - "python"
  - "remote-code-execution"
rules:
  - title: "Detect Python RCE Staging"
    description: "Detects suspicious Python process execution."
    logsource:
      category: "process_creation"
      product: "linux"
    detection:
      selection:
        Image|endswith: "/python"
      condition: "selection"
    level: "high"
`
	item := scraper.RawItem{
		SourceID:    "cert:python-rce",
		Source:      "cert",
		Title:       "Python Remote Code Execution Vulnerability",
		URL:         "https://example.test/python-rce",
		PublishedAt: now.Add(6 * time.Minute),
	}
	handled, err := p.mergeSameWeekAssembledProductBrief(incomingYAML, item, nil, extraction)
	if err != nil {
		t.Fatalf("merge same-day assembled brief: %v", err)
	}
	if !handled {
		t.Fatal("expected non-rule same-day Python advisory to merge")
	}

	draft, err := db.GetDraft("draft-python")
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}
	for _, want := range []string{
		"https://example.test/python-rce",
		"Detect Python RCE Staging",
		"remote-code-execution",
		"severity: high",
	} {
		if !strings.Contains(draft.BriefYAML, want) {
			t.Fatalf("merged draft missing %q:\n%s", want, draft.BriefYAML)
		}
	}
}

func TestProductFingerprint_NormalizesVersionQualifierAndVendorPunctuation(t *testing.T) {
	// HUMANIST case: version qualifier in one product string should not split key.
	fp1 := ProductFingerprint(
		[]string{"Bilin Software and Informatics Consultancy Inc."},
		[]string{"HUMANIST Digital Human Resources (26.0)"},
	)
	fp2 := ProductFingerprint(
		[]string{"Bilin Software and Informatics Consultancy Inc."},
		[]string{"HUMANIST Digital Human Resources"},
	)
	if fp1 == "" || fp2 == "" {
		t.Fatal("expected both HUMANIST fingerprints to be non-empty")
	}
	if fp1 != fp2 {
		t.Fatalf("expected matching fingerprints for HUMANIST with/without version qualifier, got %q vs %q", fp1, fp2)
	}

	// GL.iNet case: punctuation/spacing variants should share a key.
	fp3 := ProductFingerprint([]string{"GL.iNet"}, []string{"GL-MT3000"})
	fp4 := ProductFingerprint([]string{"GL-INet"}, []string{"GL MT3000"})
	fp5 := ProductFingerprint([]string{"GLiNet"}, []string{"GLMT3000"})
	if fp3 == "" || fp4 == "" || fp5 == "" {
		t.Fatal("expected all GL.iNet fingerprints to be non-empty")
	}
	if fp3 != fp4 || fp4 != fp5 {
		t.Fatalf("expected matching fingerprints for GL.iNet variants, got %q / %q / %q", fp3, fp4, fp5)
	}
}

func TestMergeSameWeekAssembledProductBrief_SameSourceDifferentCVEStaysSeparate(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	now := time.Date(2026, 8, 4, 10, 19, 0, 0, time.UTC)

	baseYAML := `id: brief-2026-08-humanist-hardcoded-key
slug: "2026-08-humanist-hardcoded-key"
title: "Hard-coded Cryptographic Key Vulnerability in HUMANIST Digital Human Resources"
summary: "HUMANIST hard-coded key."
severity: critical
published_at: "2026-08-04T10:19:32Z"
affected_vendors:
  - "Bilin Software and Informatics Consultancy Inc."
affected_products:
  - "HUMANIST Digital Human Resources (26.0)"
cves:
  - "CVE-2026-14804"
references:
  - "https://nvd.nist.gov/vuln/detail/CVE-2026-14804"
`
	baseItem := scraper.RawItem{
		SourceID:    "nvd:CVE-2026-14804",
		Source:      "nvd",
		Title:       "CVE-2026-14804 — Use of hard-coded cryptographic key vulnerability...",
		URL:         "https://nvd.nist.gov/vuln/detail/CVE-2026-14804",
		PublishedAt: now.Add(32 * time.Second),
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-14804"},
		AffectedVendors:  []string{"Bilin Software and Informatics Consultancy Inc."},
		AffectedProducts: []string{"HUMANIST Digital Human Resources"},
	}
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-humanist",
		Status:    storage.StatusPending,
		Source:    baseItem.Source,
		SourceIDs: `["nvd:CVE-2026-14804"]`,
		BriefYAML: baseYAML,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	p.indexContent("draft-humanist", baseItem, nil, extraction, baseYAML)

	incomingYAML := `id: brief-2026-08-humanist-rce
slug: "2026-08-humanist-rce"
title: "Unauthenticated Remote Code Execution in HUMANIST Digital Human Resources"
summary: "HUMANIST file upload RCE."
severity: critical
published_at: "2026-08-04T10:19:31Z"
affected_vendors:
  - "Bilin Software and Informatics Consultancy Inc."
affected_products:
  - "HUMANIST Digital Human Resources"
cves:
  - "CVE-2026-14175"
references:
  - "https://nvd.nist.gov/vuln/detail/CVE-2026-14175"
`
	item := scraper.RawItem{
		SourceID:    "nvd:CVE-2026-14175",
		Source:      "nvd",
		Title:       "CVE-2026-14175 — Unrestricted upload of file with dangerous type...",
		URL:         "https://nvd.nist.gov/vuln/detail/CVE-2026-14175",
		PublishedAt: now.Add(31 * time.Second),
	}
	handled, err := p.mergeSameWeekAssembledProductBrief(incomingYAML, item, nil, extraction)
	if err != nil {
		t.Fatalf("merge same-week assembled brief: %v", err)
	}
	if handled {
		t.Fatal("CVE-2026-14175 was merged into the CVE-2026-14804 brief")
	}

	draft, err := db.GetDraft("draft-humanist")
	if err != nil {
		t.Fatalf("get draft: %v", err)
	}
	if draft.BriefYAML != baseYAML {
		t.Fatalf("CVE-2026-14804 brief was modified:\n%s", draft.BriefYAML)
	}
}

func TestMergeSameWeekAssembledProductBrief_RoundupDoesNotMergeWithProduct(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	now := time.Now().UTC()

	roundupYAML := fmt.Sprintf(`id: brief-%s-microsoft-security-updates
slug: "%s-microsoft-security-updates"
title: "Microsoft Security Updates — %s"
summary: "Roundup of Microsoft security advisories."
severity: high
published_at: "%s"
tags:
  - roundup
affected_vendors:
  - "Microsoft"
affected_products:
  - "Microsoft Windows"
cves:
  - "CVE-2026-9001"
`, now.Format("2006-01"), now.Format("2006-01"), now.Format("January 2006"), now.Format(time.RFC3339))
	roundupItem := scraper.RawItem{
		SourceID:    "msrc:1",
		Source:      "msrc",
		Title:       "Microsoft Security Updates",
		URL:         "https://msrc.microsoft.com/update-guide",
		PublishedAt: now,
	}
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-ms-roundup",
		Status:    storage.StatusPending,
		Source:    roundupItem.Source,
		SourceIDs: `["msrc:1"]`,
		BriefYAML: roundupYAML,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	p.indexContent("draft-ms-roundup", roundupItem, nil, nil, roundupYAML)

	incomingYAML := `id: brief-2026-08-windows-rce
slug: "2026-08-windows-rce"
title: "Remote Code Execution in Microsoft Windows"
summary: "Windows RCE."
severity: critical
published_at: "2026-08-04T10:00:00Z"
affected_vendors:
  - "Microsoft"
affected_products:
  - "Microsoft Windows"
cves:
  - "CVE-2026-9002"
references:
  - "https://example.com/windows-rce"
`
	item := scraper.RawItem{
		SourceID:    "nvd:CVE-2026-9002",
		Source:      "nvd",
		Title:       "CVE-2026-9002 — Remote Code Execution in Microsoft Windows",
		URL:         "https://nvd.nist.gov/vuln/detail/CVE-2026-9002",
		PublishedAt: now,
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-9002"},
		AffectedVendors:  []string{"Microsoft"},
		AffectedProducts: []string{"Microsoft Windows"},
	}
	handled, err := p.mergeSameWeekAssembledProductBrief(incomingYAML, item, nil, extraction)
	if err != nil {
		t.Fatalf("merge same-week assembled brief: %v", err)
	}
	if handled {
		t.Fatal("expected product advisory NOT to merge into roundup draft")
	}
}

func TestMergeSameWeekAssembledProductBrief_CampaignDoesNotMergeWithProduct(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	p := New(Config{DB: db, Logger: slog.Default()})
	now := time.Now().UTC()

	campaignYAML := `id: brief-2026-08-clickfix
slug: "2026-08-clickfix"
title: "ClickFix Social Engineering Campaign"
summary: "ClickFix campaign."
severity: high
published_at: "2026-08-04T10:00:00Z"
tags:
  - clickfix
  - social-engineering
affected_vendors:
  - "Example Vendor"
affected_products:
  - "Example Product"
references:
  - "https://example.com/clickfix"
`
	campaignItem := scraper.RawItem{
		SourceID:    "reddit:clickfix",
		Source:      "reddit-netsec",
		Title:       "ClickFix Social Engineering Campaign",
		URL:         "https://example.com/clickfix",
		PublishedAt: now,
	}
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-clickfix",
		Status:    storage.StatusPending,
		Source:    campaignItem.Source,
		SourceIDs: `["reddit:clickfix"]`,
		BriefYAML: campaignYAML,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	p.indexContent("draft-clickfix", campaignItem, nil, nil, campaignYAML)

	incomingYAML := `id: brief-2026-08-example-rce
slug: "2026-08-example-rce"
title: "Remote Code Execution in Example Product"
summary: "Example RCE."
severity: critical
published_at: "2026-08-04T10:00:00Z"
affected_vendors:
  - "Example Vendor"
affected_products:
  - "Example Product"
cves:
  - "CVE-2026-8000"
references:
  - "https://nvd.nist.gov/vuln/detail/CVE-2026-8000"
`
	item := scraper.RawItem{
		SourceID:    "nvd:CVE-2026-8000",
		Source:      "nvd",
		Title:       "CVE-2026-8000 — Remote Code Execution in Example Product",
		URL:         "https://nvd.nist.gov/vuln/detail/CVE-2026-8000",
		PublishedAt: now,
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-8000"},
		AffectedVendors:  []string{"Example Vendor"},
		AffectedProducts: []string{"Example Product"},
	}
	handled, err := p.mergeSameWeekAssembledProductBrief(incomingYAML, item, nil, extraction)
	if err != nil {
		t.Fatalf("merge same-week assembled brief: %v", err)
	}
	if handled {
		t.Fatal("expected product advisory NOT to merge into campaign draft")
	}
}

func TestCoalesceUpdateEvents_SameTimestampCVEAddsMerge(t *testing.T) {
	now := time.Date(2026, 8, 4, 14, 11, 0, 0, time.UTC)
	events := []storage.UpdateEvent{
		{At: now, Level: "L2", Summary: "added CVE-2026-66318", Sources: []string{"nvd"}, SourceURLs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-66318"}},
		{At: now.Add(3 * time.Second), Level: "L2", Summary: "added CVE-2026-65802", Sources: []string{"nvd"}, SourceURLs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-65802"}},
		{At: now.Add(7 * time.Second), Level: "L2", Summary: "added CVE-2026-62870", Sources: []string{"nvd"}, SourceURLs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-62870"}},
	}
	got := coalesceUpdateEvents(events)
	if len(got) != 1 {
		t.Fatalf("want 1 coalesced event, got %d: %+v", len(got), got)
	}
	want := "added CVE-2026-62870, CVE-2026-65802, CVE-2026-66318"
	if got[0].Summary != want {
		t.Fatalf("want summary %q, got %q", want, got[0].Summary)
	}
	if len(got[0].SourceURLs) != 3 {
		t.Fatalf("want 3 source URLs, got %d", len(got[0].SourceURLs))
	}
}

func TestCoalesceUpdateEvents_DifferentSourcesOrLevelsStaySeparate(t *testing.T) {
	now := time.Date(2026, 8, 4, 14, 11, 0, 0, time.UTC)
	events := []storage.UpdateEvent{
		{At: now, Level: "L2", Summary: "added CVE-2026-66318", Sources: []string{"nvd"}},
		{At: now.Add(10 * time.Second), Level: "L2", Summary: "added CVE-2026-65802", Sources: []string{"ghsa"}},
		{At: now.Add(20 * time.Second), Level: "L1", Summary: "added CVE-2026-62870", Sources: []string{"nvd"}},
	}
	got := coalesceUpdateEvents(events)
	if len(got) != 3 {
		t.Fatalf("want 3 separate events, got %d", len(got))
	}
}

func TestCoalesceUpdateEvents_NonCVEAddsStaySeparate(t *testing.T) {
	now := time.Date(2026, 8, 4, 14, 11, 0, 0, time.UTC)
	events := []storage.UpdateEvent{
		{At: now, Level: "L2", Summary: "added CVE-2026-66318", Sources: []string{"nvd"}},
		{At: now.Add(5 * time.Second), Level: "L2", Summary: "severity → critical", Sources: []string{"nvd"}},
	}
	got := coalesceUpdateEvents(events)
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
}

func TestAssembledUpdateSummary(t *testing.T) {
	cases := []struct {
		name     string
		incoming map[string]any
		want     string
	}{
		{
			name: "detection rule",
			incoming: map[string]any{
				"rules": []any{map[string]any{"title": "Suspicious PowerShell Download"}},
			},
			want: "added detection rule: Suspicious PowerShell Download",
		},
		{
			name: "single product",
			incoming: map[string]any{
				"title":             "HUMANIST Digital Human Resources Vulnerabilities",
				"affected_products": []any{"HUMANIST Digital Human Resources"},
			},
			want: "added coverage for HUMANIST Digital Human Resources",
		},
		{
			name: "multiple products",
			incoming: map[string]any{
				"title":             "GL.iNet Router Issues",
				"affected_products": []any{"GL.iNet GL-MT3000", "GL.iNet GL-MT6000"},
			},
			want: "added coverage for GL.iNet GL-MT3000 +1 products",
		},
		{
			name: "vendor only",
			incoming: map[string]any{
				"title":            "Microsoft Roundup",
				"affected_vendors": []any{"Microsoft"},
			},
			want: "added vendor: Microsoft",
		},
		{
			name: "ioc only",
			incoming: map[string]any{
				"title": "Campaign IOCs",
				"iocs":  []any{map[string]any{"type": "domain", "value": "evil.example"}},
			},
			want: "added 1 IOCs",
		},
		{
			name: "fallback title",
			incoming: map[string]any{
				"title": "Some Brief Title",
			},
			want: "merged coverage from Some Brief Title",
		},
		{
			name:     "empty fallback",
			incoming: map[string]any{},
			want:     "merged additional coverage",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := assembledUpdateSummary(tc.incoming)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Flowise variants: the vendor/product extraction may produce "Flowise", "FlowiseAI",
// "Flowise CSVAgent", or "FlowiseAI Flowise" for the same product family. Aliases
// must collapse these to a single merge key.
func TestCheckPostExtraction_FlowiseVariantsShareFingerprintButNotCVEs(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	variants := []string{"Flowise", "FlowiseAI", "Flowise CSVAgent", "FlowiseAI Flowise"}
	baseFP := ProductFingerprint(nil, []string{"Flowise"})
	if baseFP == "" {
		t.Fatal("precondition: Flowise must produce a product fingerprint")
	}
	for _, v := range variants {
		fp := ProductFingerprint(nil, []string{v})
		if fp == "" {
			t.Fatalf("variant %q produced empty fingerprint", v)
		}
		if fp != baseFP {
			t.Fatalf("variant %q fingerprint %q does not match base %q", v, fp, baseFP)
		}
	}

	if err := db.CreateDraft(&storage.Draft{
		ID: "draft-flowise", Status: storage.StatusPending, Source: "ghsa",
		BriefYAML: "cves:\n  - CVE-2026-69256\naffected_products:\n  - Flowise\n",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2026-69256", ProductFingerprintHash: baseFP,
		DraftID: "draft-flowise", SourceID: "ghsa:1", Source: "ghsa", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("index: %v", err)
	}

	item := scraper.RawItem{
		SourceID: "nvd:CVE-2026-69098", Source: "nvd",
		Title:   "CVE-2026-69098: FlowiseAI Broken Access Control",
		Content: "A broken access control vulnerability in FlowiseAI allows authenticated users to list files.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-69098"},
		AffectedProducts: []string{"FlowiseAI Flowise"},
	}
	if decision, entries := dedup.CheckPostExtraction(item, extraction); decision != DedupNew {
		t.Fatalf("want DedupNew for a different Flowise CVE, got %d against %+v", decision, entries)
	}
}
