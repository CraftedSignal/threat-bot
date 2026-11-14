package publisher

import (
	"testing"
)

func TestNormalizeTitle(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no CVE",
			input: "Apache Log4j Remote Code Execution",
			want:  "apache log4j remote code execution",
		},
		{
			name:  "CVE at end with parens",
			input: "Apache Log4j Remote Code Execution (CVE-2021-44228)",
			want:  "apache log4j remote code execution",
		},
		{
			name:  "CVE at end without parens",
			input: "Apache Log4j Remote Code Execution CVE-2021-44228",
			want:  "apache log4j remote code execution",
		},
		{
			name:  "CVE at beginning",
			input: "CVE-2021-44228 Apache Log4j Remote Code Execution",
			want:  "apache log4j remote code execution",
		},
		{
			name:  "multiple CVEs",
			input: "Apache Log4j (CVE-2021-44228) and (CVE-2021-45046) RCE",
			want:  "apache log4j  and  rce",
		},
		{
			name:  "trailing punctuation after CVE strip",
			input: "Fortinet SSL-VPN Vulnerability (CVE-2024-21762).",
			want:  "fortinet ssl-vpn vulnerability",
		},
		{
			name:  "preserves inner punctuation",
			input: "Microsoft Exchange ProxyLogon (CVE-2021-26855)",
			want:  "microsoft exchange proxylogon",
		},
		{
			name:  "CVE with longer number",
			input: "Some Product CVE-2023-123456",
			want:  "some product",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeTitle(tt.input)
			if got != tt.want {
				t.Errorf("normalizeTitle(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestClusterBriefs(t *testing.T) {
	// 5 briefs: 3 share a normalized title, 2 are unique
	briefs := []*BundleBrief{
		{
			ID:         "brief-1",
			Title:      "Fortinet SSL-VPN Vulnerability (CVE-2024-21762)",
			Severity:   "critical",
			CVEs:       []BundleCVE{{ID: "CVE-2024-21762"}},
			Rules:      []BundleRule{{Title: "rule1"}, {Title: "rule2"}},
			IOCs:       []BundleIOC{{Type: "ip", Value: "1.2.3.4"}},
			TTPs:       []BundleTTP{{TechniqueID: "T1190"}},
			References: []string{"https://example.com/1"},
			Summary:    "First brief summary",
			Content:    "First brief content",
		},
		{
			ID:         "brief-2",
			Title:      "Fortinet SSL-VPN Vulnerability CVE-2024-21762",
			Severity:   "high",
			CVEs:       []BundleCVE{{ID: "CVE-2024-21762"}, {ID: "CVE-2024-23113"}},
			Rules:      []BundleRule{{Title: "rule3"}},
			IOCs:       []BundleIOC{{Type: "domain", Value: "evil.com"}, {Type: "ip", Value: "5.6.7.8"}},
			References: []string{"https://example.com/2"},
		},
		{
			ID:         "brief-3",
			Title:      "Fortinet SSL-VPN Vulnerability",
			Severity:   "medium",
			CVEs:       []BundleCVE{{ID: "CVE-2024-23113"}},
			Rules:      []BundleRule{},
			IOCs:       []BundleIOC{},
			References: []string{"https://example.com/1", "https://example.com/3"},
		},
		{
			ID:       "brief-4",
			Title:    "Ivanti Connect Secure Zero-Day (CVE-2025-0282)",
			Severity: "critical",
			CVEs:     []BundleCVE{{ID: "CVE-2025-0282"}},
			Rules:    []BundleRule{{Title: "rule4"}},
			IOCs:     []BundleIOC{},
		},
		{
			ID:       "brief-5",
			Title:    "Palo Alto PAN-OS Command Injection",
			Severity: "high",
			CVEs:     []BundleCVE{},
			Rules:    []BundleRule{},
			IOCs:     []BundleIOC{},
		},
	}

	clusters := clusterBriefs(briefs)

	if len(clusters) != 3 {
		t.Fatalf("expected 3 clusters, got %d", len(clusters))
	}

	// First cluster should be the merged Fortinet one (insertion order)
	fc := clusters[0]

	// CVEs: CVE-2024-21762 and CVE-2024-23113 (deduped, sorted)
	if len(fc.CVEs) != 2 {
		t.Errorf("expected 2 CVEs in merged cluster, got %d: %v", len(fc.CVEs), fc.CVEs)
	}
	if fc.CVEs[0] != "CVE-2024-21762" || fc.CVEs[1] != "CVE-2024-23113" {
		t.Errorf("unexpected CVE order: %v", fc.CVEs)
	}

	// Highest severity should be critical (from brief-1)
	if fc.HighestSeverity != "critical" {
		t.Errorf("expected HighestSeverity=critical, got %q", fc.HighestSeverity)
	}

	// TotalRules: 2 + 1 + 0 = 3
	if fc.TotalRules != 3 {
		t.Errorf("expected TotalRules=3, got %d", fc.TotalRules)
	}

	// TotalIOCs: 1 + 2 + 0 = 3
	if fc.TotalIOCs != 3 {
		t.Errorf("expected TotalIOCs=3, got %d", fc.TotalIOCs)
	}

	// TotalTTPs: 1 + 0 + 0 = 1
	if fc.TotalTTPs != 1 {
		t.Errorf("expected TotalTTPs=1, got %d", fc.TotalTTPs)
	}

	// BriefIDs should have 3 entries
	if len(fc.BriefIDs) != 3 {
		t.Errorf("expected 3 BriefIDs, got %d: %v", len(fc.BriefIDs), fc.BriefIDs)
	}

	// References union: 3 unique refs
	if len(fc.References) != 3 {
		t.Errorf("expected 3 references, got %d: %v", len(fc.References), fc.References)
	}

	// RepContent should be from the first brief
	if fc.RepContent != briefs[0].Content {
		t.Errorf("expected RepContent from first brief, got %q", fc.RepContent)
	}

	// For single-brief clusters, OriginalSummary and OriginalURL should not be set
	// (they are only for single-brief clusters in this implementation)
	// The merged cluster has 3 briefs so OriginalSummary should be empty
	if fc.OriginalSummary != "" {
		t.Errorf("merged cluster should not have OriginalSummary set, got %q", fc.OriginalSummary)
	}

	// Check single-brief clusters have OriginalSummary set
	ivantiCluster := clusters[1]
	if ivantiCluster.OriginalSummary != briefs[3].Summary {
		t.Errorf("single cluster OriginalSummary: got %q, want %q", ivantiCluster.OriginalSummary, briefs[3].Summary)
	}

	// DisplayTitle should preserve original case (from first brief in cluster)
	if fc.DisplayTitle == "" {
		t.Error("DisplayTitle should not be empty")
	}
}

func TestClusterBriefs_SinglesNotMerged(t *testing.T) {
	briefs := []*BundleBrief{
		{
			ID:       "brief-a",
			Title:    "Cisco IOS XE Privilege Escalation (CVE-2023-20198)",
			Severity: "critical",
			CVEs:     []BundleCVE{{ID: "CVE-2023-20198"}},
			Summary:  "Cisco brief summary",
		},
		{
			ID:       "brief-b",
			Title:    "MOVEit Transfer SQL Injection (CVE-2023-34362)",
			Severity: "high",
			CVEs:     []BundleCVE{{ID: "CVE-2023-34362"}},
			Summary:  "MOVEit brief summary",
		},
	}

	clusters := clusterBriefs(briefs)

	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters for 2 unique briefs, got %d", len(clusters))
	}

	// Each cluster should have exactly 1 brief
	for i, c := range clusters {
		if len(c.BriefIDs) != 1 {
			t.Errorf("cluster %d: expected 1 BriefID, got %d", i, len(c.BriefIDs))
		}
	}

	// Single-brief clusters should have OriginalSummary populated
	if clusters[0].OriginalSummary != briefs[0].Summary {
		t.Errorf("cluster 0 OriginalSummary: got %q, want %q", clusters[0].OriginalSummary, briefs[0].Summary)
	}
	if clusters[1].OriginalSummary != briefs[1].Summary {
		t.Errorf("cluster 1 OriginalSummary: got %q, want %q", clusters[1].OriginalSummary, briefs[1].Summary)
	}
}
