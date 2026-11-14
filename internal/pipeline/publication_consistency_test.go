package pipeline

import (
	"strings"
	"testing"
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
			issues := ValidatePublicationConsistency(tt.yaml)
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
