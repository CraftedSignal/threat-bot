package pipeline

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidatePublicationConsistency(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		contains string
	}{
		{
			name: "backdated CVE without later update",
			yaml: `title: n8n MCP server-side request forgery
published_at: "2024-01-30T00:00:00Z"
cves: [CVE-2026-42010]
affected_products: [n8n MCP]
`,
			contains: "predate",
		},
		{
			name: "older brief updated with later CVE",
			yaml: `title: n8n MCP advisory
published_at: "2024-01-30T00:00:00Z"
lastmod: "2026-05-01T00:00:00Z"
cves: [CVE-2026-42010]
affected_products: [n8n MCP]
`,
		},
		{
			name: "server exploitation mapped to client technique",
			yaml: `title: "Apache Struts: File upload remote code execution (CVE-2024-53677)"
summary: A path traversal flaw in a public-facing web application.
published_at: "2026-09-15T00:00:00Z"
ttps:
  - technique_id: T1203
    evidence: An HTTP POST to the server's file upload endpoint writes a web shell.
`,
			contains: "T1203",
		},
		{
			name: "actual client exploitation",
			yaml: `title: Browser vulnerability exploited with malicious document
published_at: "2026-09-15T00:00:00Z"
ttps:
  - technique_id: T1203
    evidence: The victim opens a malicious document in a client application.
action_plan:
  hunt_leads:
    - lead: Review client application crashes after document opens.
      data_needed: [Endpoint process and crash telemetry]
      evidence: The victim opens a malicious document in a client application.
`,
		},
		{
			name: "narrow DD-WRT brief contaminated by unrelated products",
			yaml: `title: "DD-WRT: UPnP buffer overflow (CVE-2021-27137)"
published_at: "2026-07-01T00:00:00Z"
affected_vendors: [DD-WRT, Langflow, WordPress]
affected_products: [DD-WRT]
cves: [CVE-2021-27137, CVE-2026-63030, CVE-2026-60137]
`,
			contains: "scope",
		},
		{
			name: "WordPress two-CVE chain",
			yaml: `title: "WordPress: Two-CVE remote code execution chain"
published_at: "2026-07-01T00:00:00Z"
affected_vendors: [WordPress]
affected_products: [WordPress Core]
cves: [CVE-2026-63030, CVE-2026-60137]
`,
		},
		{
			name: "broad multi-vendor campaign",
			yaml: `title: Supply chain campaign across multiple software vendors
published_at: "2026-07-01T00:00:00Z"
affected_vendors: [Acme, Beta, Gamma]
affected_products: [Acme App, Beta App, Gamma App]
`,
		},
		{
			name: "Splunk behavior without rule or hunt",
			yaml: `title: "Splunk Enterprise: Scheduled search SPL command safeguard bypass (CVE-2026-76291)"
summary: Authenticated users can bypass risky-command safeguards in scheduled searches.
published_at: "2026-10-21T23:49:08Z"
affected_products: [Splunk Enterprise]
ttps:
  - tactic_id: TA0002
    technique_id: T1059
    evidence: A schedule_search user can run restricted SPL commands.
action_plan:
  mitigation_plan:
    - action: Audit roles with the schedule_search capability.
      evidence: Vendor safeguard documentation.
`,
			contains: "rule or hunt lead",
		},
		{
			name: "Splunk behavior with operational hunt",
			yaml: `title: "Splunk Enterprise: Scheduled search SPL command safeguard bypass (CVE-2026-76291)"
summary: Authenticated users can bypass risky-command safeguards in scheduled searches.
published_at: "2026-10-21T23:49:08Z"
affected_products: [Splunk Enterprise]
ttps:
  - tactic_id: TA0002
    technique_id: T1059
    evidence: A schedule_search user can run restricted SPL commands.
action_plan:
  hunt_leads:
    - lead: Review risky commands and outlier export volume in scheduled searches by user.
      data_needed: [Splunk audit and search history]
      evidence: A schedule_search user can run restricted SPL commands.
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// These cases isolate date/scope/ATT&CK consistency. Supply the
			// editorial minimum independently of those signals.
			complete := tt.yaml + "content: |\n  ## Overview\n  The cited source describes the issue or observed behavior named above.\n\n  ## Recommendation\n  Review affected assets and the cited source for the applicable response.\n"
			issues := ValidatePublicationConsistency(complete)
			if tt.contains == "" {
				if len(issues) > 0 {
					t.Fatalf("unexpected issues: %v", issues)
				}
				return
			}
			if len(issues) == 0 || !strings.Contains(strings.Join(issues, " "), tt.contains) {
				t.Fatalf("issues = %v, want %q", issues, tt.contains)
			}
		})
	}
}

func TestValidatePublicationConsistencyRejectsSingleCVEIdentityOnHugeRoundup(t *testing.T) {
	// Mirrors the public Microsoft roundup's 1,090-CVE inventory and
	// single-CVE Office Word title.
	cves := make([]string, 1090)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2026-%05d", i+10000)
	}
	cves[0] = "CVE-2026-111306"
	raw, err := yaml.Marshal(map[string]any{
		"title":   "Microsoft Office Word heap-based buffer overflow (CVE-2026-111306)",
		"summary": "A heap-based buffer overflow in Microsoft Office Word.",
		"content": "## Overview\nA heap-based buffer overflow in Microsoft Office Word, tracked as CVE-2026-111306.\n\n## Recommendation\nApply current Microsoft Office updates.",
		"tags":    []string{"roundup", "Microsoft", "Office"},
		"cves":    cves,
	})
	if err != nil {
		t.Fatal(err)
	}
	issues := strings.Join(ValidatePublicationConsistency(string(raw)), "; ")
	if !strings.Contains(issues, "roundup") {
		t.Fatalf("single-CVE title accepted for a 1,090-CVE roundup: %s", issues)
	}
}

func TestValidatePublicationConsistencyAllowsSmallCVEChainAndGenericLargeRoundup(t *testing.T) {
	for name, doc := range map[string]map[string]any{
		"small chain": {
			"title":   "Widget: two-CVE remote code execution chain (CVE-2026-10001)",
			"summary": "Two related vulnerabilities combine into an attack chain.",
			"content": "## Overview\nThe chain uses CVE-2026-10001 and CVE-2026-10002.\n\n## Recommendation\nApply the vendor patch.",
			"tags":    []string{"roundup"}, "cves": []string{"CVE-2026-10001", "CVE-2026-10002"},
		},
		"generic large roundup": {
			"title":   "Microsoft Security Updates - November 2026",
			"summary": "Microsoft's November security updates address vulnerabilities across supported products.",
			"content": "## Overview\nThe monthly security release addresses vulnerabilities across Microsoft products.\n\n## Recommendation\nPrioritize the vendor's actively exploited issues and apply the cumulative updates through the normal patch process.",
			"tags":    []string{"roundup", "Microsoft"}, "cves": func() []string {
				ids := make([]string, 1090)
				for i := range ids {
					ids[i] = fmt.Sprintf("CVE-2026-%05d", i+10000)
				}
				return ids
			}(),
		},
		"aggregate title with one named CVE": {
			"title":   "Microsoft November security updates address CVE-2026-111306",
			"summary": "Microsoft's November security updates address vulnerabilities across supported products.",
			"content": "## Overview\nThe monthly security release addresses vulnerabilities across Microsoft products.\n\n## Recommendation\nPrioritize the vendor's actively exploited issues and apply the cumulative updates through the normal patch process.",
			"tags":    []string{"roundup", "Microsoft"}, "cves": func() []string {
				ids := make([]string, 1090)
				for i := range ids {
					ids[i] = fmt.Sprintf("CVE-2026-%05d", i+10000)
				}
				ids[0] = "CVE-2026-111306"
				return ids
			}(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			issues := strings.Join(ValidatePublicationConsistency(string(raw)), "; ")
			if strings.Contains(issues, "roundup") {
				t.Fatalf("valid roundup/chain was rejected: %s", issues)
			}
		})
	}
}

func TestSafeExploitationWithdrawalCannotBypassRoundupIdentityCheck(t *testing.T) {
	cves := make([]string, 1090)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2026-%05d", i+10000)
	}
	cves[0] = "CVE-2026-111306"
	doc := map[string]any{
		"title":   "Microsoft Office Word heap-based buffer overflow (CVE-2026-111306)",
		"summary": "A heap-based buffer overflow in Microsoft Office Word.",
		"content": "## Overview\nA heap-based buffer overflow in Microsoft Office Word, tracked as CVE-2026-111306.\n\n## Recommendation\nApply current Microsoft Office updates.",
		"tags":    []string{"roundup", "Microsoft", "Office"}, "cves": cves,
		"exploited": false, "exploitation_evidence": map[string]any{"status": "unknown"},
		"updates": []any{map[string]any{
			"level": "L1", "summary": "exploitation evidence corrected: an exploit-code listing is not exploitation",
			"sources": []string{"threat-bot"}, "source_urls": []string{},
		}},
	}
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	issues := strings.Join(ValidatePublicationConsistency(string(raw)), "; ")
	if !strings.Contains(issues, "roundup") {
		t.Fatalf("safe withdrawal bypassed roundup identity check: %s", issues)
	}
}
