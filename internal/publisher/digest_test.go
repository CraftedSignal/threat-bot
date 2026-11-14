package publisher

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestClassifyBrief(t *testing.T) {
	tests := []struct {
		name     string
		brief    BundleBrief
		expected string
	}{
		{
			name:     "critical severity",
			brief:    BundleBrief{Severity: "critical"},
			expected: "Critical Vulnerabilities",
		},
		{
			name:     "has threat actor",
			brief:    BundleBrief{Severity: "high", ThreatActor: "APT29"},
			expected: "Active Campaigns",
		},
		{
			name: "has active campaign TTP",
			brief: BundleBrief{
				Severity: "medium",
				TTPs:     []BundleTTP{{TacticID: "TA0001", TacticName: "Initial Access"}},
			},
			expected: "Active Campaigns",
		},
		{
			name: "has rules",
			brief: BundleBrief{
				Severity: "medium",
				Rules:    []BundleRule{{Title: "Test Rule"}},
			},
			expected: "New Detection Rules",
		},
		{
			name:     "default category",
			brief:    BundleBrief{Severity: "low"},
			expected: "Threat Intelligence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyBrief(&tt.brief)
			if got != tt.expected {
				t.Errorf("classifyBrief() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestSeverityBadge(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "**CRITICAL**"},
		{"high", "**HIGH**"},
		{"medium", "MEDIUM"},
		{"low", "LOW"},
		{"informational", "INFO"},
		{"unknown", "UNKNOWN"},
	}

	for _, tt := range tests {
		got := severityBadge(tt.severity)
		if got != tt.expected {
			t.Errorf("severityBadge(%q) = %q, want %q", tt.severity, got, tt.expected)
		}
	}
}

func TestDigestRenderMarkdown_Empty(t *testing.T) {
	d := &Digest{
		GeneratedAt: time.Date(2026, 3, 22, 12, 0, 0, 0, time.UTC),
		Period:      "2026-03-22",
		TotalBriefs: 0,
	}

	md := d.RenderMarkdown()
	if !strings.Contains(md, "No approved briefs") {
		t.Error("expected empty digest message")
	}
	if !strings.Contains(md, "2026-03-22") {
		t.Error("expected period in heading")
	}
}

func TestDigestRenderMarkdown_WithEntries(t *testing.T) {
	d := &Digest{
		GeneratedAt: time.Date(2026, 3, 22, 12, 0, 0, 0, time.UTC),
		Period:      "2026-03-22",
		TotalBriefs: 2,
		Categories: []DigestCategory{
			{
				Name: "Critical Vulnerabilities",
				Briefs: []DigestEntry{
					{
						Title:    "CVE-2026-1234",
						Severity: "critical",
						Source:   "cisa",
						Summary:  "A critical vulnerability.",
						Rules:    1,
						IOCs:     3,
						TTPs:     2,
						URL:      "https://example.com/cve",
					},
				},
			},
			{
				Name: "Threat Intelligence",
				Briefs: []DigestEntry{
					{
						Title:    "New Malware Campaign",
						Severity: "medium",
						Source:   "dfir-report",
						Summary:  "A new campaign.",
						IOCs:     5,
					},
				},
			},
		},
	}

	md := d.RenderMarkdown()

	if !strings.Contains(md, "## Critical Vulnerabilities") {
		t.Error("expected Critical Vulnerabilities section")
	}
	if !strings.Contains(md, "## Threat Intelligence") {
		t.Error("expected Threat Intelligence section")
	}
	if !strings.Contains(md, "**CRITICAL**") {
		t.Error("expected severity badge")
	}
	if !strings.Contains(md, "[CVE-2026-1234](https://example.com/cve)") {
		t.Error("expected linked title")
	}
	if !strings.Contains(md, "1 rule(s)") {
		t.Error("expected rule count")
	}
	if !strings.Contains(md, "3 IOC(s)") {
		t.Error("expected IOC count")
	}
	if !strings.Contains(md, "5 IOC(s)") {
		t.Error("expected IOC count for second entry")
	}
}

func TestGenerateDigest(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Create some approved drafts.
	now := time.Now()
	drafts := []storage.Draft{
		{
			ID:     "draft-1",
			Status: storage.StatusApproved,
			Score:  8.0,
			Source: "cisa",
			BriefYAML: `id: brief-1
title: Critical CVE
summary: A critical issue
severity: critical
published_at: "2026-03-22T00:00:00Z"
iocs:
    - type: ipv4
      value: 1.2.3.4
ttps:
    - tactic_id: TA0001
      tactic_name: Initial Access
      technique_id: T1190
      technique_name: Exploit Public-Facing Application
`,
			CreatedAt: now,
		},
		{
			ID:     "draft-2",
			Status: storage.StatusApproved,
			Score:  6.0,
			Source: "sigma-hq",
			BriefYAML: `id: brief-2
title: New Sigma Rule
summary: A new detection rule
severity: medium
published_at: "2026-03-22T00:00:00Z"
rules:
    - title: Detect Something
      description: Detects something bad
      logsource:
          category: process_creation
      detection:
          selection:
              CommandLine|contains: evil
          condition: selection
      level: high
`,
			CreatedAt: now,
		},
		{
			ID:     "draft-3",
			Status: storage.StatusPending,
			Score:  3.0,
			Source: "reddit-netsec",
			BriefYAML: `id: brief-3
title: Pending Brief
summary: Should not appear
severity: low
published_at: "2026-03-22T00:00:00Z"
`,
			CreatedAt: now,
		},
	}

	for _, d := range drafts {
		if err := db.CreateDraft(&d); err != nil {
			t.Fatal(err)
		}
		if d.Status == storage.StatusApproved {
			if err := db.UpdateDraftStatus(d.ID, storage.StatusApproved, ""); err != nil {
				t.Fatal(err)
			}
		}
	}

	digest, err := GenerateDigest(context.Background(), db, DigestConfig{LookbackHours: 24})
	if err != nil {
		t.Fatal(err)
	}

	if digest.TotalBriefs != 2 {
		t.Errorf("expected 2 briefs, got %d", digest.TotalBriefs)
	}

	// Verify categories.
	catNames := make(map[string]bool)
	for _, c := range digest.Categories {
		catNames[c.Name] = true
	}
	if !catNames["Critical Vulnerabilities"] {
		t.Error("expected Critical Vulnerabilities category")
	}
	if !catNames["New Detection Rules"] {
		t.Error("expected New Detection Rules category")
	}

	md := digest.RenderMarkdown()
	if !strings.Contains(md, "Critical CVE") {
		t.Error("expected critical brief in markdown output")
	}
	if !strings.Contains(md, "New Sigma Rule") {
		t.Error("expected sigma brief in markdown output")
	}
	if strings.Contains(md, "Pending Brief") {
		t.Error("pending brief should not appear in digest")
	}
}

func TestGenerateDigest_DefaultLookback(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	digest, err := GenerateDigest(context.Background(), db, DigestConfig{LookbackHours: 0})
	if err != nil {
		t.Fatal(err)
	}
	if digest.TotalBriefs != 0 {
		t.Errorf("expected 0 briefs, got %d", digest.TotalBriefs)
	}
}

func TestGenerateDigest_ClusterMerge(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()

	// Three briefs with the same product title but different CVEs should merge.
	drafts := []storage.Draft{
		{
			ID:     "draft-c1",
			Status: storage.StatusApproved,
			Score:  9.0,
			Source: "cisa",
			BriefYAML: `id: brief-c1
title: "Belkin F9K1015 Buffer Overflow (CVE-2026-5610)"
summary: Buffer overflow in Belkin F9K1015 router firmware.
severity: critical
published_at: "2026-04-08T00:00:00Z"
cves:
    - id: CVE-2026-5610
      epss: 0.8
      cvss: 9.8
rules:
    - title: Detect Belkin Exploit
      description: Detects exploitation of Belkin router
      logsource:
          category: network_connection
      detection:
          selection:
              DestinationPort: 8080
          condition: selection
      level: critical
`,
			CreatedAt: now,
		},
		{
			ID:     "draft-c2",
			Status: storage.StatusApproved,
			Score:  9.0,
			Source: "cisa",
			BriefYAML: `id: brief-c2
title: "Belkin F9K1015 Buffer Overflow (CVE-2026-5611)"
summary: Another buffer overflow in Belkin F9K1015.
severity: critical
published_at: "2026-04-08T00:00:00Z"
cves:
    - id: CVE-2026-5611
      epss: 0.7
      cvss: 9.5
`,
			CreatedAt: now,
		},
		{
			ID:     "draft-c3",
			Status: storage.StatusApproved,
			Score:  9.0,
			Source: "nvd",
			BriefYAML: `id: brief-c3
title: "Belkin F9K1015 Buffer Overflow (CVE-2026-5612)"
summary: Yet another buffer overflow in Belkin F9K1015.
severity: critical
published_at: "2026-04-08T00:00:00Z"
cves:
    - id: CVE-2026-5612
      epss: 0.6
      cvss: 9.0
`,
			CreatedAt: now,
		},
	}

	for _, d := range drafts {
		if err := db.CreateDraft(&d); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateDraftStatus(d.ID, storage.StatusApproved, ""); err != nil {
			t.Fatal(err)
		}
	}

	digest, err := GenerateDigest(context.Background(), db, DigestConfig{LookbackHours: 24})
	if err != nil {
		t.Fatal(err)
	}

	// Should produce 1 merged entry, not 3.
	if digest.TotalBriefs != 1 {
		t.Errorf("expected 1 merged entry, got %d", digest.TotalBriefs)
	}

	md := digest.RenderMarkdown()

	if !strings.Contains(md, "(3 CVEs)") {
		t.Errorf("expected '(3 CVEs)' in markdown, got:\n%s", md)
	}
	if !strings.Contains(md, "CVE-2026-5610") {
		t.Error("expected CVE-2026-5610 in markdown")
	}
	if !strings.Contains(md, "CVE-2026-5611") {
		t.Error("expected CVE-2026-5611 in markdown")
	}
	if !strings.Contains(md, "CVE-2026-5612") {
		t.Error("expected CVE-2026-5612 in markdown")
	}
}

func TestGenerateDigest_UsesConfiguredNow(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	target := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	drafts := []storage.Draft{
		{
			ID:     "draft-current",
			Status: storage.StatusApproved,
			Score:  8.0,
			Source: "cisa",
			BriefYAML: `id: brief-current
title: Current Brief
summary: Included in target window.
severity: high
published_at: "2026-07-03T12:00:00Z"
`,
			CreatedAt: target.Add(-2 * time.Hour),
		},
		{
			ID:     "draft-old",
			Status: storage.StatusApproved,
			Score:  8.0,
			Source: "cisa",
			BriefYAML: `id: brief-old
title: Old Brief
summary: Outside target window.
severity: high
published_at: "2026-07-02T12:00:00Z"
`,
			CreatedAt: target.Add(-25 * time.Hour),
		},
	}

	for _, d := range drafts {
		if err := db.CreateDraft(&d); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateDraftStatus(d.ID, storage.StatusApproved, ""); err != nil {
			t.Fatal(err)
		}
	}

	digest, err := GenerateDigest(context.Background(), db, DigestConfig{LookbackHours: 24, Now: target})
	if err != nil {
		t.Fatal(err)
	}
	if got := digest.Period; got != "2026-07-03" {
		t.Fatalf("Period = %q, want 2026-07-03", got)
	}
	if !digest.GeneratedAt.Equal(target) {
		t.Fatalf("GeneratedAt = %s, want %s", digest.GeneratedAt, target)
	}
	md := digest.RenderMarkdown()
	if !strings.Contains(md, "Current Brief") {
		t.Fatalf("expected current brief in digest, got:\n%s", md)
	}
	if strings.Contains(md, "Old Brief") {
		t.Fatalf("did not expect old brief in digest, got:\n%s", md)
	}
}

func TestGenerateDigest_PreviouslyReported(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	yesterday := time.Now().AddDate(0, 0, -1).UTC().Format("2006-01-02")
	previousDigestID := "daily-" + yesterday

	// Seed a previous digest cluster with 2 brief IDs.
	prevIDs, _ := json.Marshal([]string{"brief-1", "brief-2"})
	if err := db.SaveDigestCluster(storage.DigestCluster{
		DigestID:   previousDigestID,
		ClusterKey: normalizeTitle("Belkin F9K1015 Buffer Overflow (CVE-2026-5610)"),
		BriefIDs:   string(prevIDs),
		Summary:    "Two buffer overflow vulnerabilities in Belkin F9K1015.",
	}); err != nil {
		t.Fatal(err)
	}

	// Create 3 approved drafts today that normalize to the same cluster key.
	drafts := []storage.Draft{
		{
			ID:     "draft-p1",
			Status: storage.StatusApproved,
			Score:  9.0,
			Source: "cisa",
			BriefYAML: `id: brief-1
title: "Belkin F9K1015 Buffer Overflow (CVE-2026-5610)"
summary: Buffer overflow in Belkin F9K1015 router.
severity: critical
published_at: "2026-04-08T00:00:00Z"
cves:
    - id: CVE-2026-5610
      epss: 0.8
      cvss: 9.8
`,
			CreatedAt: now,
		},
		{
			ID:     "draft-p2",
			Status: storage.StatusApproved,
			Score:  9.0,
			Source: "cisa",
			BriefYAML: `id: brief-2
title: "Belkin F9K1015 Buffer Overflow (CVE-2026-5611)"
summary: Another buffer overflow in Belkin F9K1015.
severity: critical
published_at: "2026-04-08T00:00:00Z"
cves:
    - id: CVE-2026-5611
      epss: 0.7
      cvss: 9.5
`,
			CreatedAt: now,
		},
		{
			ID:     "draft-p3",
			Status: storage.StatusApproved,
			Score:  9.0,
			Source: "nvd",
			BriefYAML: `id: brief-3
title: "Belkin F9K1015 Buffer Overflow (CVE-2026-5612)"
summary: New buffer overflow in Belkin F9K1015.
severity: critical
published_at: "2026-04-08T00:00:00Z"
cves:
    - id: CVE-2026-5612
      epss: 0.6
      cvss: 9.0
`,
			CreatedAt: now,
		},
	}

	for _, d := range drafts {
		if err := db.CreateDraft(&d); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateDraftStatus(d.ID, storage.StatusApproved, ""); err != nil {
			t.Fatal(err)
		}
	}

	digest, err := GenerateDigest(context.Background(), db, DigestConfig{LookbackHours: 24})
	if err != nil {
		t.Fatal(err)
	}

	md := digest.RenderMarkdown()

	if !strings.Contains(md, "Previously Reported") {
		t.Errorf("expected 'Previously Reported' in markdown, got:\n%s", md)
	}
	if !strings.Contains(md, "Updated") {
		t.Errorf("expected 'Updated' in markdown, got:\n%s", md)
	}
	if !strings.Contains(md, "new CVE") || !strings.Contains(md, "CVE-2026-5612") {
		t.Errorf("expected 'new CVE' and 'CVE-2026-5612' in markdown, got:\n%s", md)
	}
}
