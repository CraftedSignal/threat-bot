package pipeline

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestExtractCVEsFromText(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		content string
		want    []string
	}{
		{
			name:    "single CVE in title",
			title:   "Critical RCE in CVE-2026-1234",
			content: "Details about the vulnerability.",
			want:    []string{"CVE-2026-1234"},
		},
		{
			name:    "multiple CVEs",
			title:   "Advisory for CVE-2026-1234",
			content: "Also affects CVE-2026-5678 and CVE-2025-99999.",
			want:    []string{"CVE-2026-1234", "CVE-2026-5678", "CVE-2025-99999"},
		},
		{
			name:    "dedup same CVE",
			title:   "CVE-2026-1234 advisory",
			content: "CVE-2026-1234 is critical.",
			want:    []string{"CVE-2026-1234"},
		},
		{
			name:    "case normalization",
			title:   "cve-2026-1234 advisory",
			content: "",
			want:    []string{"CVE-2026-1234"},
		},
		{
			name:    "no CVEs",
			title:   "General threat report",
			content: "No specific vulnerabilities mentioned.",
			want:    nil,
		},
		{
			name:    "5-digit CVE ID",
			title:   "CVE-2026-12345 is critical",
			content: "",
			want:    []string{"CVE-2026-12345"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCVEsFromText(tt.title, tt.content)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNormalizeTitleHash(t *testing.T) {
	tests := []struct {
		name   string
		titleA string
		titleB string
		same   bool
	}{
		{
			name:   "identical titles",
			titleA: "Critical RCE in Example Software",
			titleB: "Critical RCE in Example Software",
			same:   true,
		},
		{
			name:   "case difference",
			titleA: "Critical RCE in Example Software",
			titleB: "critical rce in example software",
			same:   true,
		},
		{
			name:   "source tag removed",
			titleA: "[CISA] Critical RCE in Example Software",
			titleB: "[Reddit] Critical RCE in Example Software",
			same:   true,
		},
		{
			name:   "date removed",
			titleA: "Critical RCE 2026-01-15",
			titleB: "Critical RCE 2026-02-20",
			same:   true,
		},
		{
			name:   "different titles",
			titleA: "Critical RCE in Example Software",
			titleB: "SQL Injection in Other Product",
			same:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashA := NormalizeTitleHash(tt.titleA)
			hashB := NormalizeTitleHash(tt.titleB)
			if (hashA == hashB) != tt.same {
				t.Errorf("hash(%q) = %s, hash(%q) = %s, expected same=%v", tt.titleA, hashA, tt.titleB, hashB, tt.same)
			}
		})
	}

	// Deterministic output.
	h1 := NormalizeTitleHash("Test Title")
	h2 := NormalizeTitleHash("Test Title")
	if h1 != h2 {
		t.Error("expected deterministic hash")
	}
}

func TestEvaluateCVEOverlap(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	// Seed a CVE entry with no exploit/patch/active-exploitation context.
	seedEntry := storage.ContentIndexEntry{
		CVEID:      "CVE-2026-1234",
		DraftID:    "draft-1",
		SourceID:   "reddit:1",
		Source:     "reddit",
		CVEContext: `{"has_exploit":false,"has_patch":false,"active_exploitation":false,"source":"reddit","ioc_count":0}`,
		CreatedAt:  time.Now(),
	}
	if err := db.IndexContent(&seedEntry); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	tests := []struct {
		name   string
		item   scraper.RawItem
		expect DedupDecision
	}{
		{
			name: "same source → skip",
			item: scraper.RawItem{
				SourceID: "reddit:2",
				Source:   "reddit",
				Title:    "CVE-2026-1234 details",
				Content:  "More about CVE-2026-1234.",
			},
			expect: DedupSkip,
		},
		{
			name: "different source no new info → skip",
			item: scraper.RawItem{
				SourceID: "abuse-ch:1",
				Source:   "abuse-ch",
				Title:    "CVE-2026-1234 advisory",
				Content:  "A vulnerability was found.",
			},
			expect: DedupSkip,
		},
		{
			name: "exploit PoC → update (score 2: exploit+authority)",
			item: scraper.RawItem{
				SourceID: "cisa-kev:1",
				Source:   "cisa-kev",
				Title:    "CVE-2026-1234 PoC Released",
				Content:  "Proof of concept exploit code is now publicly available.",
			},
			expect: DedupUpdate,
		},
		{
			name: "patch available → update (score 2: patch+authority)",
			item: scraper.RawItem{
				SourceID: "ccb-belgium:1",
				Source:   "ccb-belgium",
				Title:    "CVE-2026-1234 patch released",
				Content:  "Vendor has released a security update.",
			},
			expect: DedupUpdate,
		},
		{
			name: "active exploitation → update (score 2)",
			item: scraper.RawItem{
				SourceID: "cisa-kev:2",
				Source:   "cisa-kev",
				Title:    "CVE-2026-1234",
				Content:  "This vulnerability is actively exploited in the wild.",
			},
			expect: DedupUpdate,
		},
		{
			// CISA KEV counts attempted exploitation. GreyNoise's Java4Shell
			// report was skipped as a duplicate on 2026-11-18 because no
			// update term matched its wording.
			name: "observed exploitation attempts → update",
			item: scraper.RawItem{
				SourceID: "greynoise:java4shell",
				Source:   "greynoise",
				Title:    "Global Event: CVE-2026-1234 Live Activity Report",
				Content:  "GreyNoise is monitoring scanning and exploitation attempts against CVE-2026-1234.",
			},
			expect: DedupUpdate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, _ := db.FindByCVE("CVE-2026-1234")
			got := dedup.evaluateCVEOverlap(tt.item, "CVE-2026-1234", entries)
			if got != tt.expect {
				t.Errorf("got %d, want %d", got, tt.expect)
			}
		})
	}
}

func TestCheckPreExtraction(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	// New item with no prior entries → DedupNew.
	item := scraper.RawItem{
		SourceID: "cisa-kev:1",
		Source:   "cisa-kev",
		Title:    "CVE-2026-9999 critical vulnerability",
		Content:  "A new CVE-2026-9999 vulnerability discovered.",
	}
	decision, cves, entries := dedup.CheckPreExtraction(item)
	if decision != DedupNew {
		t.Errorf("expected DedupNew for unseen CVE, got %d", decision)
	}
	if len(cves) != 1 || cves[0] != "CVE-2026-9999" {
		t.Errorf("expected [CVE-2026-9999], got %v", cves)
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %v", entries)
	}

	// Seed the CVE.
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID:      "CVE-2026-9999",
		TitleHash:  NormalizeTitleHash(item.Title),
		DraftID:    "draft-99",
		SourceID:   item.SourceID,
		Source:     item.Source,
		CVEContext: `{"has_exploit":false,"has_patch":false,"active_exploitation":false,"source":"cisa-kev"}`,
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	// Same source same CVE → skip.
	item2 := scraper.RawItem{
		SourceID: "cisa-kev:2",
		Source:   "cisa-kev",
		Title:    "CVE-2026-9999 update",
		Content:  "More details about CVE-2026-9999.",
	}
	decision2, _, _ := dedup.CheckPreExtraction(item2)
	if decision2 != DedupSkip {
		t.Errorf("expected DedupSkip for same-source CVE, got %d", decision2)
	}

	// Different source, no new info → skip.
	item3 := scraper.RawItem{
		SourceID: "reddit:1",
		Source:   "reddit",
		Title:    "CVE-2026-9999 discussion",
		Content:  "Discussing CVE-2026-9999 vulnerability.",
	}
	decision3, _, _ := dedup.CheckPreExtraction(item3)
	if decision3 != DedupSkip {
		t.Errorf("expected DedupSkip for cross-source no new info, got %d", decision3)
	}

	// Title hash dedup (no CVE).
	itemA := scraper.RawItem{
		SourceID: "reddit:10",
		Source:   "reddit",
		Title:    "LockBit Ransomware Campaign Targets Healthcare",
		Content:  "A new campaign has been observed.",
	}
	// Seed the title hash.
	if err := db.IndexContent(&storage.ContentIndexEntry{
		TitleHash: NormalizeTitleHash(itemA.Title),
		DraftID:   "draft-100",
		SourceID:  "abuse-ch:10",
		Source:    "abuse-ch",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seeding title: %v", err)
	}

	decision4, _, _ := dedup.CheckPreExtraction(itemA)
	if decision4 != DedupSkip {
		t.Errorf("expected DedupSkip for title hash match, got %d", decision4)
	}
}

func TestCheckPreExtractionDoesNotDeduplicateByHistoricalBodyCVE(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2024-4577", DraftID: "old-php-cgi", SourceID: "old:1",
		Source: "old", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	item := scraper.RawItem{
		SourceID: "news:new-php", Source: "the-hacker-news",
		Title:   "PHP security team warns of two new critical vulnerabilities",
		Content: "The disclosure is separate from CVE-2024-4577, an older PHP CGI flaw. The two new issues have no published CVE IDs yet.",
	}
	decision, cves, _ := dedup.CheckPreExtraction(item)
	if decision != DedupNew || len(cves) != 0 {
		t.Fatalf("historical body CVE suppressed new story: decision=%v cves=%v", decision, cves)
	}
}

func TestCheckPreExtractionTreatsAuthoritativeAdvisoryBodyCVEsAsUpdate(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2026-109618", DraftID: "php-release", SourceID: "cert-eu:php",
		Source: "cert-eu", CVEContext: `{"has_exploit":false,"has_patch":false,"active_exploitation":false,"source":"cert-eu"}`,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	item := scraper.RawItem{
		SourceID: "ms-isac:2026-119", Source: "ms-isac",
		Title:               "Multiple Vulnerabilities in PHP Could Allow for Remote Code Execution",
		Content:             "RCE via OOM corruption (CVE-2026-109618). Apply appropriate updates provided by PHP to vulnerable systems.",
		BodyCVEsAreSubjects: true,
	}
	decision, cves, entries := dedup.CheckPreExtraction(item)
	if decision != DedupUpdate || len(cves) != 1 || cves[0] != "CVE-2026-109618" || len(entries) != 1 || entries[0].DraftID != "php-release" {
		t.Fatalf("decision=%v cves=%v entries=%+v", decision, cves, entries)
	}
}

func TestCheckPostExtractionDoesNotDeduplicateByHistoricalBodyCVE(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID: "CVE-2024-4577", DraftID: "old-php-cgi", SourceID: "old:1",
		Source: "old", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	item := scraper.RawItem{
		SourceID: "news:new-php", Source: "the-hacker-news",
		Title:   "PHP security team warns of two new critical vulnerabilities",
		Content: "For comparison, CVE-2024-4577 was a different PHP CGI flaw.",
	}
	decision, _ := dedup.CheckPostExtraction(item, &ExtractionResult{CVEs: []string{"CVE-2024-4577"}})
	if decision != DedupNew {
		t.Fatalf("historical extracted CVE suppressed new story: decision=%v", decision)
	}
}

func TestConfirmedExtractionCVEsIncludesCurrentBodyIdentifier(t *testing.T) {
	item := scraper.RawItem{
		Title:   "Example Server authentication bypass disclosed",
		Content: "Example Server has an authentication bypass tracked as CVE-2026-12345. Administrators should upgrade.",
	}
	got := confirmedExtractionCVEs(item, &ExtractionResult{CVEs: []string{"CVE-2026-12345"}})
	if len(got) != 1 || got[0] != "CVE-2026-12345" {
		t.Fatalf("current body CVE omitted: %v", got)
	}
	item.Content = "For comparison, CVE-2024-4577 was an older PHP CGI flaw."
	got = confirmedExtractionCVEs(item, &ExtractionResult{CVEs: []string{"CVE-2024-4577"}})
	if len(got) != 0 {
		t.Fatalf("historical CVE promoted to subject: %v", got)
	}
}

func TestContentIndexDoesNotPromoteHistoricalExtractedCVE(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	pipe := &Pipeline{db: db, logger: slog.Default()}
	item := scraper.RawItem{
		SourceID: "news:new-php", Source: "the-hacker-news",
		Title:   "PHP security team warns of two new critical vulnerabilities",
		Content: "For comparison, CVE-2024-4577 was a different PHP CGI flaw.",
	}
	pipe.indexContent("new-php", item, nil, &ExtractionResult{CVEs: []string{"CVE-2024-4577"}})
	entries, err := db.FindByCVE("CVE-2024-4577")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("historical CVE linked to new PHP draft: %+v", entries)
	}
}

func TestEffectiveVulnClass(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		extraction *ExtractionResult
		want       string
	}{
		{
			name:       "LLM-provided class overrides regex",
			title:      "Remote Code Execution in Example App",
			extraction: &ExtractionResult{VulnClass: "sql-injection"},
			want:       "sql-injection",
		},
		{
			name:       "falls back to regex when LLM class is empty",
			title:      "Remote Code Execution in Example App",
			extraction: &ExtractionResult{},
			want:       "rce",
		},
		{
			name:       "nil extraction falls back to regex",
			title:      "SQL Injection in Example App",
			extraction: nil,
			want:       "sql-injection",
		},
		{
			name:       "returns empty when LLM class empty and no regex match",
			title:      "Generic Security Advisory",
			extraction: &ExtractionResult{},
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveVulnClass(tt.title, tt.extraction)
			if got != tt.want {
				t.Errorf("effectiveVulnClass() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCheckPostExtractionFingerprintUsesLLMClass verifies that when the LLM
// extraction provides a vuln_class, that class is used to compute the
// fingerprint lookup key — enabling a match even when the item title alone
// would not produce a class via regex.
func TestCheckPostExtractionFingerprintUsesLLMClass(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	// Source A indexed a PAN-OS RCE brief. Regex classifies "Remote Code
	// Execution" as "rce", so its fingerprint uses that class.
	fp := Fingerprint([]string{"Example Corp"}, []string{"Example App"}, "rce")
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID:           "",
		FingerprintHash: fp,
		TitleNorm:       normalizeTitleTokens("Remote Code Execution in Example App"),
		DraftID:         "draft-a",
		SourceID:        "source-a:1",
		Source:          "source-a",
		CreatedAt:       time.Now(),
	}); err != nil {
		t.Fatalf("seeding index: %v", err)
	}
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-a",
		Status:    storage.StatusPending,
		Score:     3.5,
		Source:    "source-a",
		BriefYAML: "title: Example RCE\n",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seeding draft: %v", err)
	}

	// Source B has "Arbitrary Code Execution" in the title. Regex returns ""
	// for that phrasing. Without LLM class the fingerprint would be empty →
	// lookup skipped → DedupNew. With LLM class "rce" the fingerprint matches
	// Source A. Titles share {code, execution, example, app} → Jaccard ≥ 0.6.
	item := scraper.RawItem{
		SourceID: "source-b:1",
		Source:   "source-b",
		Title:    "Arbitrary Code Execution in Example App",
	}

	// Confirm the regex alone returns "" for this title (proves the test is meaningful).
	if cls := InferVulnClass(item.Title, nil); cls != "" {
		t.Fatalf("precondition failed: InferVulnClass returned %q, expected empty — regex would already catch it", cls)
	}

	extraction := &ExtractionResult{
		AffectedVendors:  []string{"Example Corp"},
		AffectedProducts: []string{"Example App"},
		VulnClass:        "rce",
	}

	decision, entries := dedup.CheckPostExtraction(item, extraction)
	if decision == DedupNew {
		t.Errorf("expected dedup match via LLM-class fingerprint, got DedupNew")
	}
	if len(entries) == 0 || entries[0].DraftID != "draft-a" {
		t.Errorf("expected match against draft-a, got %v", entries)
	}
}

func TestInferVulnClass(t *testing.T) {
	tests := []struct {
		title string
		want  string
	}{
		{"Palo Alto PAN-OS Out-of-bounds Write Vulnerability", "oob"},
		{"PAN-OS Out-of-bounds Read in GlobalProtect", "oob"},
		{"OOB-write in curl leads to heap corruption", "oob"},
		{"Apache Remote Code Execution via Deserialization", "rce"}, // rce pattern fires before deserialization in pattern order
		{"Cisco IOS XE Command Injection (CVE-2026-1234)", "command-injection"},
		{"Fortinet FortiOS Remote Code Execution Vulnerability", "rce"},
		{"Buffer Overflow in OpenSSL allows RCE", "buffer-overflow"},
		{"General threat campaign", ""},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			got := InferVulnClass(tt.title, nil)
			if got != tt.want {
				t.Errorf("InferVulnClass(%q) = %q, want %q", tt.title, got, tt.want)
			}
		})
	}
}

func TestDeduplicatorIgnoresIndexRowsOwnedByRejectedDrafts(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())
	now := time.Now()
	url := "https://research.example.test/rejected-incident"
	content := strings.Repeat("Concrete incident evidence with detection details. ", 4)
	productFP := ProductFingerprint([]string{"Acme"}, []string{"Acme Identity Gateway"})
	if err := db.CreateDraft(&storage.Draft{
		ID: "rejected-incident", Status: storage.StatusRejected, Source: "vendor",
		BriefYAML: "title: Rejected incident\naffected_products: [Acme Identity Gateway]\n", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	urlHashes := SourceURLHashes(url)
	if len(urlHashes) != 1 {
		t.Fatalf("source URL hash precondition: %v", urlHashes)
	}
	if err := db.IndexContent(&storage.ContentIndexEntry{
		ContentHash: NormalizeContentHash("Acme identity incident", content), SourceURLHash: urlHashes[0],
		ProductFingerprintHash: productFP, DraftID: "rejected-incident", SourceID: "vendor:rejected",
		Source: "vendor", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	item := scraper.RawItem{
		SourceID: "vendor:rejected", Source: "vendor", Title: "Acme identity incident", URL: url, Content: content,
	}
	if decision, _, entries := dedup.CheckPreExtraction(item); decision != DedupNew || len(entries) != 0 {
		t.Fatalf("pre-extraction decision=%v entries=%v, want new with no rejected target", decision, entries)
	}
	if decision, entries := dedup.CheckPostExtraction(item, &ExtractionResult{
		AffectedVendors: []string{"Acme"}, AffectedProducts: []string{"Acme Identity Gateway"},
	}); decision != DedupNew || len(entries) != 0 {
		t.Fatalf("post-extraction decision=%v entries=%v, want new with no rejected target", decision, entries)
	}
}

func TestCheckPostExtractionProductFingerprint(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	// Seed a no-CVE RCE brief for PAN-OS from CERT-Bund.
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID:                  "",
		TitleHash:              NormalizeTitleHash("Palo Alto Networks PAN-OS: Remote Code Execution Vulnerability"),
		FingerprintHash:        Fingerprint([]string{"Palo Alto Networks"}, []string{"PAN-OS"}, "rce"),
		ProductFingerprintHash: ProductFingerprint([]string{"Palo Alto Networks"}, []string{"PAN-OS"}),
		TitleNorm:              normalizeTitleTokens("Palo Alto Networks PAN-OS: Remote Code Execution Vulnerability"),
		DraftID:                "draft-rce",
		SourceID:               "cert-bund:wid-sec-2026-1366",
		Source:                 "cert-bund",
		CreatedAt:              time.Now().Add(-90 * time.Minute),
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	// Seed the draft itself so isDraftThin can inspect it.
	if err := db.CreateDraft(&storage.Draft{
		ID:        "draft-rce",
		Status:    storage.StatusApproved,
		Score:     4.0,
		Source:    "cert-bund",
		BriefYAML: "title: PAN-OS RCE\nseverity: critical\nttps:\n  - tactic_id: TA0002\n",
		CreatedAt: time.Now().Add(-90 * time.Minute),
	}); err != nil {
		t.Fatalf("seeding draft: %v", err)
	}

	// New item from CISA KEV with CVE-2026-0300 described as "Out-of-bounds Write".
	item := scraper.RawItem{
		SourceID: "cisa-kev:cve-2026-0300",
		Source:   "cisa-kev",
		Title:    "Palo Alto Networks PAN-OS Out-of-bounds Write Vulnerability Added to CISA KEV Catalog",
		Content:  "CVE-2026-0300 is actively exploited in the wild.",
	}
	extraction := &ExtractionResult{
		CVEs:             []string{"CVE-2026-0300"},
		AffectedVendors:  []string{"Palo Alto Networks"},
		AffectedProducts: []string{"PAN-OS"},
	}

	decision, entries := dedup.CheckPostExtraction(item, extraction)
	if decision != DedupMerge {
		t.Errorf("expected DedupMerge via product-fingerprint path, got %v", decision)
	}
	if len(entries) == 0 || entries[0].DraftID != "draft-rce" {
		t.Errorf("expected match against draft-rce, got entries %v", entries)
	}
}

// TestDedupUpdateFromExploitSources verifies that a PoC publication from
// exploit-db or sploitus against an already-indexed CVE returns DedupUpdate
// (not DedupSkip) so the existing brief gets enriched instead of dropped.
func TestDedupUpdateFromExploitSources(t *testing.T) {
	db := mustOpenTestDB(t)
	defer db.Close()
	dedup := NewDeduplicator(db, slog.Default())

	// Seed a CVE entry from a low-authority source with no exploit context.
	if err := db.IndexContent(&storage.ContentIndexEntry{
		CVEID:      "CVE-2026-5555",
		TitleHash:  NormalizeTitleHash("Example App RCE"),
		DraftID:    "draft-x",
		SourceID:   "reddit:1",
		Source:     "reddit",
		CVEContext: `{"has_exploit":false,"has_patch":false,"active_exploitation":false,"source":"reddit","ioc_count":0}`,
		CreatedAt:  time.Now().Add(-6 * time.Hour),
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	cases := []struct {
		source  string
		content string
	}{
		{
			source:  "exploit-db",
			content: "Exploit for CVE-2026-5555 submitted to Exploit-DB. Remote exploit for the target service.",
		},
		{
			source:  "sploitus",
			content: "Exploit published for CVE-2026-5555 via sploitus aggregator. Public exploit available.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			item := scraper.RawItem{
				SourceID: tc.source + ":12345",
				Source:   tc.source,
				Title:    "CVE-2026-5555 - Remote Code Execution Exploit",
				Content:  tc.content,
			}
			decision, cves, entries := dedup.CheckPreExtraction(item)
			if decision != DedupUpdate {
				t.Errorf("expected DedupUpdate for %s PoC, got %v", tc.source, decision)
			}
			if len(cves) == 0 || cves[0] != "CVE-2026-5555" {
				t.Errorf("expected CVE-2026-5555 extracted, got %v", cves)
			}
			if len(entries) == 0 || entries[0].DraftID != "draft-x" {
				t.Errorf("expected match against draft-x, got %v", entries)
			}
		})
	}
}

func mustOpenTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	return db
}

func TestDedupIncompleteCVEAcceptsRicherSource(t *testing.T) {
	base := "id: brief-widget\nslug: widget\ntitle: Widget CVE-2026-9999\nsummary: Widget permits file deletion.\nseverity: high\npublished_at: \"2026-11-14T00:00:00Z\"\ncves: [CVE-2026-9999]\naffected_products: [Widget]\n"
	complete := "content: |\n  An administrator can trigger file deletion through Widget's rename operation.\n\n  ## Recommendation\n  Inventory affected Widget installations and consult the vendor advisory for remediation.\n"
	for _, tc := range []struct {
		name, body string
		want       DedupDecision
	}{
		{"complete", complete, DedupSkip},
		{"missing body", "", DedupMerge},
		{"registry paragraph without response", "content: An administrator can trigger file deletion through Widget's rename operation.\n", DedupMerge},
		{"QA veto", complete + "qa_status: {verdict: do_not_publish}\n", DedupMerge},
		{"TTP without detector or hunt", complete + "ttps: [{technique_id: T1190}]\n", DedupMerge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			if err := db.CreateDraft(&storage.Draft{ID: "prior", Status: storage.StatusApproved, BriefYAML: base + tc.body, CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := db.IndexContent(&storage.ContentIndexEntry{CVEID: "CVE-2026-9999", DraftID: "prior", SourceID: "nvd:prior", Source: "nvd", CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			d := NewDeduplicator(db, slog.Default())
			item := scraper.RawItem{SourceID: "research:richer", Source: "research", Title: "Widget CVE-2026-9999", Content: "The research details administrator prerequisites, the rename path, and telemetry defenders can collect."}
			if got, _, _ := d.CheckPreExtraction(item); got != tc.want {
				t.Errorf("pre-extraction decision=%v, want %v", got, tc.want)
			}
			if got, _ := d.CheckPostExtraction(item, &ExtractionResult{CVEs: []string{"CVE-2026-9999"}, AffectedProducts: []string{"Widget"}}); got != tc.want {
				t.Errorf("post-extraction decision=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestDedupChangedSourceRevisionTargetsExistingDraft(t *testing.T) {
	for _, tc := range []struct {
		name, revision, baseline string
		changedIdentity          bool
		want                     DedupDecision
	}{
		{name: "changed revision", baseline: "old", revision: "new", want: DedupMerge},
		{name: "changed subject and URL", baseline: "old", revision: "new", changedIdentity: true, want: DedupMerge},
		{name: "unchanged revision", baseline: "old", revision: "old", want: DedupSkip},
		{name: "no prior seen baseline", revision: "new", want: DedupSkip},
		{name: "legacy seen baseline", baseline: "legacy", revision: "new", want: DedupSkip},
		{name: "no incoming revision", baseline: "old", want: DedupSkip},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenTestDB(t)
			defer db.Close()
			const sourceID = "nvd:CVE-2026-4242"
			const body = "id: brief-widget\nslug: widget\ntitle: Widget CVE-2026-4242\nsummary: Widget permits file deletion.\nseverity: high\npublished_at: \"2026-11-14T00:00:00Z\"\ncves: [CVE-2026-4242]\naffected_products: [Widget]\ncontent: |\n  Widget permits file deletion through attachment renaming.\n\n  ## Recommendation\n  Inventory affected Widget installations and consult the vendor advisory for remediation.\nreferences: [https://vendor.example/original]\n"
			if err := db.CreateDraft(&storage.Draft{ID: "prior", Status: storage.StatusApproved, BriefYAML: body, CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := db.IndexContent(&storage.ContentIndexEntry{CVEID: "CVE-2026-4242", DraftID: "prior", SourceID: sourceID, Source: "nvd", TitleHash: NormalizeTitleHash("Widget CVE-2026-4242"), SourceURLHash: SourceURLHashes("https://vendor.example/original")[0], CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if tc.baseline == "legacy" {
				if err := db.MarkSeen(sourceID, "nvd", "Widget"); err != nil {
					t.Fatal(err)
				}
			} else if tc.baseline != "" {
				if err := db.MarkSeenRevision(sourceID, "nvd", "Widget", tc.baseline); err != nil {
					t.Fatal(err)
				}
			}
			item := scraper.RawItem{SourceID: sourceID, Source: "nvd", Revision: tc.revision, URL: "https://vendor.example/original", Title: "Widget CVE-2026-4242", Content: "Corrected vendor scope and administrator prerequisites."}
			extraction := &ExtractionResult{CVEs: []string{"CVE-2026-4242"}, AffectedProducts: []string{"Widget"}}
			if tc.changedIdentity {
				item.URL, item.Title = "https://vendor.example/corrected", "Corrected attachment deletion notice"
				extraction.CVEs = nil
			}
			d := NewDeduplicator(db, slog.Default())
			pre, _, entries := d.CheckPreExtraction(item)
			if pre != tc.want || len(entries) != 1 || entries[0].DraftID != "prior" {
				t.Errorf("pre=%v targets=%+v, want %v into prior", pre, entries, tc.want)
			}
			post, entries := d.CheckPostExtraction(item, extraction)
			if post != tc.want || len(entries) != 1 || entries[0].DraftID != "prior" {
				t.Errorf("post=%v targets=%+v, want %v into prior", post, entries, tc.want)
			}
			stored, err := db.GetDraft("prior")
			if err != nil || stored == nil || stored.BriefYAML != body {
				t.Fatalf("routing changed existing draft: %+v %v", stored, err)
			}
			if tc.want == DedupMerge {
				seen, err := db.HasSeenRevision(sourceID, tc.revision)
				if err != nil || seen {
					t.Fatalf("routing consumed unprocessed revision: seen=%v err=%v", seen, err)
				}
			}
		})
	}
}
