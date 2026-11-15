package pipeline

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

func TestBriefContractRejectsIncompletePublicationFields(t *testing.T) {
	base := "id: brief-test\nslug: 2026-10-test\ntitle: Test advisory\nsummary: Verified notice\nseverity: high\npublished_at: \"2026-10-21T07:00:00Z\"\n"
	for _, tc := range []struct{ name, old, replacement, want string }{
		{"title", "title: Test advisory\n", "", "title"},
		{"summary", "summary: Verified notice\n", "", "summary"},
		{"date", "published_at: \"2026-10-21T07:00:00Z\"\n", "", "published_at"},
		{"bad date", "2026-10-21T07:00:00Z", "not-a-date", "published_at"},
		{"bad severity", "severity: high", "severity: urgent", "severity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBriefContract(strings.Replace(base, tc.old, tc.replacement, 1))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("contract error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNormalizeExploitationEvidenceDropsInvalidNonActiveConfidence(t *testing.T) {
	brief := &briefYAML{
		ID: "brief-invalid-non-active-confidence",
		ExploitationEvidence: &ExploitationEvidence{
			Status:     "not_observed",
			Confidence: "0",
		},
	}
	if err := normalizeExploitationEvidence(brief); err != nil {
		t.Fatalf("normalizeExploitationEvidence: %v", err)
	}
	if got := brief.ExploitationEvidence.Confidence; got != "" {
		t.Fatalf("confidence = %q, want empty", got)
	}
}

func TestValidate_SynchronizesMentionedCVEs(t *testing.T) {
	input := `
id: brief-cve-sync
slug: 2026-10-cve-sync
title: CVE-2026-1000 and cve-2026-2000 exploitation
summary: Includes CVE-2026-1000.
severity: high
published_at: "2026-10-20T00:00:00Z"
content: See CVE-2026-3000.
references:
  - https://vendor.example/CVE-2026-3000
cves:
  - id: CVE-2026-1000
    cvss: 9.8
`
	cleaned, _, err := NewBriefValidator().Validate(input)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		CVEs []struct {
			ID        string `yaml:"id"`
			KEVStatus string `yaml:"kev_status"`
		} `yaml:"cves"`
	}
	if err := yaml.Unmarshal([]byte(cleaned), &got); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, cve := range got.CVEs {
		ids = append(ids, cve.ID)
		if cve.KEVStatus == "" {
			t.Fatalf("CVE %s missing tri-state kev_status", cve.ID)
		}
	}
	want := []string{"CVE-2026-1000", "CVE-2026-2000", "CVE-2026-3000"}
	if !slices.Equal(ids, want) {
		t.Fatalf("cves = %#v, want %#v\n%s", ids, want, cleaned)
	}
}

func TestValidate_CanonicalizesATTACKNames(t *testing.T) {
	input := `
id: brief-attack-names
slug: 2026-10-attack-names
title: Test
summary: Test
severity: medium
published_at: "2026-10-20T00:00:00Z"
content: Test
references: [https://example.com/report]
ttps:
  - tactic_id: TA0002
    tactic_name: Made Up Tactic
    technique_id: T1059.003
    technique_name: Made Up Technique
`
	cleaned, _, err := NewBriefValidator().Validate(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cleaned, "tactic_name: Execution") || !strings.Contains(cleaned, "technique_name: Windows Command Shell") {
		t.Fatalf("ATT&CK names were not canonicalized:\n%s", cleaned)
	}
}

func TestValidate_RejectsUnsourcedThreatAndRumour(t *testing.T) {
	for _, input := range []string{
		`id: brief-threat
slug: threat
title: Threat
summary: Threat
severity: high
threat_actor: APT29
published_at: "2026-10-20T00:00:00Z"
content: Threat
`,
		`id: brief-rumour
slug: rumour
title: Rumour
summary: Rumour
severity: rumour
published_at: "2026-10-20T00:00:00Z"
content: Rumour
`,
	} {
		if _, _, err := NewBriefValidator().Validate(input); err == nil {
			t.Fatal("expected unsourced threat/rumour to fail")
		}
	}
}

func TestValidateDoesNotConvertBareExploitationFlagsIntoEvidence(t *testing.T) {
	raw := `id: bare-signal
title: Bare exploitation signal
summary: A vulnerability report
severity: high
published_at: "2026-10-20T10:00:00Z"
content: A vulnerability report with no attributed exploitation evidence.
references:
  - https://example.test/advisory
exploited: true
priority_signals:
  - active_exploitation
ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
`
	cleaned, _, err := NewBriefValidator().Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cleaned, "status: confirmed_active") {
		t.Fatalf("bare flags became confirmed evidence:\n%s", cleaned)
	}
}

func TestValidate_RejectsNegatedConfirmedExploitation(t *testing.T) {
	input := `
id: brief-negated
slug: negated
title: Vulnerability
summary: No evidence of exploitation in the wild.
severity: high
published_at: "2026-10-20T00:00:00Z"
content: The vendor says the issue is not actively exploited.
references: [https://vendor.example/advisory]
exploitation_evidence:
  status: confirmed_active
  source_url: https://vendor.example/advisory
  observed_at: "2026-10-19T00:00:00Z"
  confidence: high
`
	if _, _, err := NewBriefValidator().Validate(input); err == nil {
		t.Fatal("expected contradictory confirmed exploitation to fail")
	}
}

func TestValidate_StripPlaceholders(t *testing.T) {
	input := `
id: "brief-2026-02-17-test"
slug: "2026-02-test"
title: "Test Brief"
summary: "Test summary"
severity: "high"
threat_actor: "unknown"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://example.com"
iocs:
  - type: "domain"
    value: "N/A"
    context: "placeholder"
  - type: "ip"
    value: "TBD"
    context: "another placeholder"
ttps:
  - tactic_id: "TA0001"
    tactic_name: "Initial Access"
    technique_id: "T1566"
    technique_name: "Phishing"
`

	v := NewBriefValidator()
	cleaned, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// threat_actor should be stripped
	if strings.Contains(cleaned, "threat_actor") {
		t.Error("expected threat_actor to be stripped from output")
	}

	// iocs section should be removed entirely (both entries were placeholders)
	if strings.Contains(cleaned, "iocs") {
		t.Error("expected iocs section to be removed from output")
	}

	// Should have notes about what was stripped
	if len(notes) == 0 {
		t.Error("expected validation notes about stripped placeholders")
	}

	foundActorNote := false
	foundIOCNote := false
	for _, note := range notes {
		if strings.Contains(note, "threat_actor") {
			foundActorNote = true
		}
		if strings.Contains(note, "ioc") || strings.Contains(note, "IOC") {
			foundIOCNote = true
		}
	}
	if !foundActorNote {
		t.Errorf("expected note about threat_actor removal, got notes: %v", notes)
	}
	if !foundIOCNote {
		t.Errorf("expected note about IOC removal, got notes: %v", notes)
	}
}

func TestValidate_InvalidATTACKIDs(t *testing.T) {
	input := `
id: "brief-2026-02-17-test"
slug: "2026-02-test"
title: "Test Brief"
summary: "Test summary"
severity: "high"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://example.com"
ttps:
  - tactic_id: "TA0001"
    tactic_name: "Initial Access"
    technique_id: "T1566"
    technique_name: "Phishing"
  - tactic_id: "TA0099"
    tactic_name: "Fake Tactic"
    technique_id: "T9999"
    technique_name: "Fake Technique"
  - tactic_id: "TA0002"
    tactic_name: "Execution"
    technique_id: "T1219"
    technique_name: "Remote Access Software"
    subtechnique_id: "T1219.003"
    subtechnique_name: "Fake Subtechnique"
`

	v := NewBriefValidator()
	cleaned, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the first TTP should remain (TA0001/T1566)
	if !strings.Contains(cleaned, "T1566") {
		t.Error("expected valid TTP T1566 to remain")
	}
	if strings.Contains(cleaned, "T9999") {
		t.Error("expected invalid technique T9999 to be removed")
	}
	if strings.Contains(cleaned, "TA0099") {
		t.Error("expected invalid tactic TA0099 to be removed")
	}
	if strings.Contains(cleaned, "T1219.003") {
		t.Error("expected invalid subtechnique T1219.003 to be removed")
	}

	// Should have notes about removed TTPs
	if len(notes) < 2 {
		t.Errorf("expected at least 2 notes about removed TTPs, got %d: %v", len(notes), notes)
	}
}

func TestValidate_PreservesCTIMetadata(t *testing.T) {
	input := `
id: "brief-2026-08-02-metadata"
slug: "2026-08-metadata"
title: "Metadata Brief"
summary: "Test summary"
severity: "high"
published_at: "2026-08-02T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://source.example/report"
source_assessment:
  rating: B2
  confidence: moderate
  flags:
    - type: single_source
      detail: "one source"
qa_status:
  verdict: pass_with_fixes
  manual_verification:
    - "validate telemetry"
action_plan:
  priority: elevated
  immediate_actions:
    - action: "review rule"
      owner: "SOC"
rules:
  - title: "Detect Evil"
    description: "Detects evil.exe"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\evil.exe"
      condition: selection
    level: high
    handoff:
      detection_confidence: high
      required_telemetry:
        - log_source: Sysmon
          required_fields:
            - Image
iocs:
  - type: "domain"
    value: "evil.test"
    context: "Observed C2"
    confidence: 0.8
    handling:
      recommended_action: monitor-only
      source_sentence: "evil.test was observed as C2."
ttps:
  - tactic_id: "TA0002"
    tactic_name: "Execution"
    technique_id: "T1059"
    technique_name: "Command and Scripting Interpreter"
`

	v := NewBriefValidator()
	cleaned, _, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"source_assessment:",
		"rating: B2",
		"qa_status:",
		"manual_verification:",
		"action_plan:",
		"immediate_actions:",
		"handoff:",
		"required_telemetry:",
		"handling:",
		"recommended_action: monitor-only",
	} {
		if !strings.Contains(cleaned, want) {
			t.Fatalf("cleaned YAML missing %q:\n%s", want, cleaned)
		}
	}
}

func TestValidate_PreservesAndCleansCPEs(t *testing.T) {
	input := `
id: "brief-2026-08-cpe"
slug: "2026-08-cpe"
title: "CPE Brief"
summary: "Test summary"
severity: "high"
published_at: "2026-08-28T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
cpes:
  - cpe:2.3:a:synology:chat_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:synology:chat_server:*:*:*:*:*:*:*:*
  - unknown
  - cpe:/a:synology:chat_server
references:
  - "https://example.com"
`

	v := NewBriefValidator()
	cleaned, _, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Count(cleaned, "cpe:2.3:a:synology:chat_server:*:*:*:*:*:*:*:*") != 1 {
		t.Fatalf("expected one valid CPE to survive:\n%s", cleaned)
	}
	if strings.Contains(cleaned, "cpe:/a:") || strings.Contains(cleaned, "- unknown\n") {
		t.Fatalf("expected invalid CPE entries to be removed:\n%s", cleaned)
	}
}

// Every CPE component constrains applicability. Cleaning must preserve exact
// source bindings, including release candidates, editions and architectures.
func TestCleanCPEListPreservesExactSourceScope(t *testing.T) {
	input := []string{
		"cpe:2.3:a:adobe:coldfusion:2023:update1:*:*:*:*:*:*",
		"cpe:2.3:a:adobe:coldfusion:2023:update2:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:7.2:rc1:*:*:*:*:*:*",
		"cpe:2.3:o:linux:linux_kernel:7.2:rc2:*:*:*:*:*:*",
		"cpe:2.3:a:acme:widget:1.0:*:enterprise:*:*:*:*:*",
		"cpe:2.3:a:acme:widget:1.0:*:standard:*:*:*:*:*",
		"cpe:2.3:a:acme:widget:1.0:*:*:en:*:*:*:*",
		"cpe:2.3:a:acme:widget:1.0:*:*:fr:*:*:*:*",
		"cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*",
		"cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*",
		"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:variant1",
		"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:variant2",
		`cpe:2.3:a:acme:widget\:pro:1.0:rc1:*:*:*:*:*:*`,
		`cpe:2.3:a:acme:widget\:pro:1.0:rc2:*:*:*:*:*:*`,
		// Explicit wildcards are source facts too, and must not swallow exact entries.
		"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
	}
	want := slices.Clone(input)
	slices.Sort(want)
	input = append(input, " "+input[0]+" ", input[1], "", "unknown", "not-a-cpe")
	got := CleanCPEList(input)
	if !slices.Equal(got, want) {
		t.Fatalf("source CPE scope changed:\n got: %q\nwant: %q", got, want)
	}
	slices.Reverse(input)
	if reversed := CleanCPEList(input); !slices.Equal(reversed, want) {
		t.Fatalf("source order changed canonical CPEs: %q", reversed)
	}
}

func TestValidate_NullSubtechniqueFields(t *testing.T) {
	input := `
id: "brief-2026-02-17-test"
slug: "2026-02-test"
title: "Test Brief"
summary: "Test summary"
severity: "high"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://www.cisa.gov/news-events/alerts/2026/02/17/test"
ttps:
  - tactic_id: "TA0001"
    tactic_name: "Initial Access"
    technique_id: "T1566"
    technique_name: "Phishing"
    subtechnique_id: null
    subtechnique_name: null
`

	v := NewBriefValidator()
	cleaned, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The TTP should remain (it's valid)
	if !strings.Contains(cleaned, "T1566") {
		t.Error("expected valid TTP T1566 to remain")
	}

	// subtechnique_id and subtechnique_name should be stripped
	if strings.Contains(cleaned, "subtechnique_id") {
		t.Error("expected null subtechnique_id to be stripped from output")
	}
	if strings.Contains(cleaned, "subtechnique_name") {
		t.Error("expected null subtechnique_name to be stripped from output")
	}

	// Should have no validation notes -- this is a clean brief after stripping nulls
	if len(notes) != 0 {
		t.Errorf("expected no validation notes for null subtechnique stripping, got: %v", notes)
	}
}

func TestValidate_CleanBriefPassesThrough(t *testing.T) {
	input := `
id: "brief-2026-02-17-phishing-campaign"
slug: "2026-02-phishing-campaign"
title: "Phishing Campaign Targeting Finance"
summary: "APT group targets financial institutions with spearphishing"
severity: "high"
threat_actor: "FIN7"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Detailed threat content.
tags:
  - phishing
  - finance
references:
  - "https://www.cisa.gov/news-events/alerts/2026/02/17/phishing-campaign"
rules:
  - title: "Suspicious PowerShell Execution"
    description: "Detects suspicious PowerShell activity"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\powershell.exe"
        CommandLine|contains: "-enc "
      condition: selection
    level: high
    tags:
      - attack.execution
      - attack.t1059.001
    tests:
      positive:
        - name: "PowerShell execution"
          data:
            - Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
              CommandLine: "powershell.exe -enc SQBFAFgA..."
      negative:
        - name: "Normal process"
          data:
            - Image: "C:\\Windows\\System32\\notepad.exe"
              CommandLine: "notepad.exe test.txt"
iocs:
  - type: "domain"
    value: "malicious-finance-login.com"
    context: "C2 server used in campaign"
  - type: "hash_sha256"
    value: "7b3f2e4d8c1a9f5e6b0d3c7a2e8f4b1d9c6a3e7f0b5d2c8a4e1f7b3d9c6a2e8f"
    context: "Malware payload hash"
ttps:
  - tactic_id: "TA0001"
    tactic_name: "Initial Access"
    technique_id: "T1566"
    technique_name: "Phishing"
    subtechnique_id: "T1566.001"
    subtechnique_name: "Spearphishing Attachment"
  - tactic_id: "TA0002"
    tactic_name: "Execution"
    technique_id: "T1059"
    technique_name: "Command and Scripting Interpreter"
    subtechnique_id: "T1059.001"
    subtechnique_name: "PowerShell"
`

	v := NewBriefValidator()
	cleaned, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No notes should be generated for a clean brief
	if len(notes) != 0 {
		t.Errorf("expected no validation notes for clean brief, got: %v", notes)
	}

	// All key elements should remain
	if !strings.Contains(cleaned, "FIN7") {
		t.Error("expected threat_actor FIN7 to remain")
	}
	if !strings.Contains(cleaned, "T1566.001") {
		t.Error("expected T1566.001 to remain")
	}
	if !strings.Contains(cleaned, "malicious-finance-login.com") {
		t.Error("expected IOC to remain")
	}
	if !strings.Contains(cleaned, "logsource") {
		t.Error("expected logsource to remain in rules")
	}
	if !strings.Contains(cleaned, "level: high") {
		t.Error("expected level: high to remain in rules")
	}
}

func TestValidate_MissingRuleLevel(t *testing.T) {
	input := `
id: "brief-2026-02-17-test"
slug: "2026-02-test"
title: "Test Brief"
summary: "Test summary"
severity: "high"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://example.com"
rules:
  - title: "Detect Something"
    description: "Detects something"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\cmd.exe"
      condition: selection
    tags:
      - attack.execution
      - attack.t1059.003
`

	v := NewBriefValidator()
	cleaned, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Level should be defaulted to "medium"
	if !strings.Contains(cleaned, "level: medium") {
		t.Errorf("expected level to be defaulted to medium, got:\n%s", cleaned)
	}

	// Should have a note about the fix
	foundLevelNote := false
	for _, note := range notes {
		if strings.Contains(note, "level") {
			foundLevelNote = true
			break
		}
	}
	if !foundLevelNote {
		t.Errorf("expected note about added level, got notes: %v", notes)
	}
}

func TestValidate_MissingRequiredFields(t *testing.T) {
	input := `
title: "Test Brief"
summary: "Test summary"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://example.com"
`

	v := NewBriefValidator()
	cleaned, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have auto-generated id and slug
	if !strings.Contains(cleaned, "id:") {
		t.Error("expected id to be auto-generated")
	}

	// Should have defaulted severity
	if !strings.Contains(cleaned, "severity: medium") {
		t.Errorf("expected severity to be defaulted to medium, got:\n%s", cleaned)
	}

	foundIDNote := false
	foundSeverityNote := false
	for _, note := range notes {
		if strings.Contains(note, "id") {
			foundIDNote = true
		}
		if strings.Contains(note, "severity") {
			foundSeverityNote = true
		}
	}
	if !foundIDNote {
		t.Errorf("expected note about added id, got notes: %v", notes)
	}
	if !foundSeverityNote {
		t.Errorf("expected note about added severity, got notes: %v", notes)
	}
}

func TestValidate_SigmaTestFieldMismatch(t *testing.T) {
	input := `
id: "brief-2026-02-17-test"
slug: "2026-02-test"
title: "Test Brief"
summary: "Test summary"
severity: "high"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://example.com"
rules:
  - title: "Detect Suspicious Process"
    description: "Detects suspicious process creation"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\cmd.exe"
        CommandLine|contains: "whoami"
      condition: selection
    level: high
    tags:
      - attack.execution
      - attack.t1059.003
    tests:
      positive:
        - name: "Suspicious cmd.exe"
          data:
            - wrong_field: "bad_value"
              another_wrong: "also bad"
      negative:
        - name: "Normal activity"
          data:
            - wrong_field: "normal_value"
ttps:
  - tactic_id: "TA0002"
    tactic_name: "Execution"
    technique_id: "T1059"
    technique_name: "Command and Scripting Interpreter"
`

	v := NewBriefValidator()
	_, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have a note about field mismatch
	foundMismatchNote := false
	for _, note := range notes {
		if strings.Contains(note, "field") || strings.Contains(note, "detection") {
			foundMismatchNote = true
			break
		}
	}
	if !foundMismatchNote {
		t.Errorf("expected note about Sigma test field mismatch, got notes: %v", notes)
	}
}

func TestValidate_SigmaInvalidLevel(t *testing.T) {
	input := `
id: "brief-2026-02-17-test"
slug: "2026-02-test"
title: "Test Brief"
summary: "Test summary"
severity: "high"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://example.com"
rules:
  - title: "Detect Something"
    description: "Detects something"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\cmd.exe"
      condition: selection
    level: "severe"
`

	v := NewBriefValidator()
	cleaned, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invalid level should be defaulted to "medium"
	if !strings.Contains(cleaned, "level: medium") {
		t.Errorf("expected invalid level to be defaulted to medium, got:\n%s", cleaned)
	}

	foundLevelNote := false
	for _, note := range notes {
		if strings.Contains(note, "invalid level") {
			foundLevelNote = true
			break
		}
	}
	if !foundLevelNote {
		t.Errorf("expected note about invalid level, got notes: %v", notes)
	}
}

func TestValidate_SigmaMissingCondition(t *testing.T) {
	input := `
id: "brief-2026-02-17-test"
slug: "2026-02-test"
title: "Test Brief"
summary: "Test summary"
severity: "high"
published_at: "2026-02-17T00:00:00Z"
content: |
  ## Overview
  Test content.
tags:
  - test
references:
  - "https://example.com"
rules:
  - title: "Detect Something"
    description: "Detects something"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\cmd.exe"
    level: high
`

	v := NewBriefValidator()
	_, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundConditionNote := false
	for _, note := range notes {
		if strings.Contains(note, "condition") {
			foundConditionNote = true
			break
		}
	}
	if !foundConditionNote {
		t.Errorf("expected note about missing condition, got notes: %v", notes)
	}
}

func TestValidate_DoSDowngrade(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		summary    string
		inSeverity string
		wantSev    string
		wantNote   bool
	}{
		{
			name:       "pure DoS crash downgraded from high",
			title:      "Apache Traffic Server Denial of Service (CVE-2026-1234)",
			summary:    "A crash bug in Apache Traffic Server allows remote attackers to cause a denial of service via crafted HTTP requests.",
			inSeverity: "high",
			wantSev:    "medium",
			wantNote:   true,
		},
		{
			name:       "DoS with RCE left alone",
			title:      "FooBar DoS and RCE",
			summary:    "Crash bug that also allows remote code execution.",
			inSeverity: "critical",
			wantSev:    "critical",
			wantNote:   false,
		},
		{
			name:       "resource exhaustion downgraded",
			title:      "XYZ Resource Exhaustion",
			summary:    "Memory exhaustion via malformed packet causes service crash.",
			inSeverity: "critical",
			wantSev:    "medium",
			wantNote:   true,
		},
		{
			name:       "actively exploited DoS kept high",
			title:      "ACME Denial of Service",
			summary:    "Denial of service vulnerability, actively exploited in the wild.",
			inSeverity: "high",
			wantSev:    "high",
			wantNote:   false,
		},
		{
			name:       "non-DoS brief untouched",
			title:      "Phishing campaign targeting finance",
			summary:    "APT group conducting spearphishing against financial orgs.",
			inSeverity: "high",
			wantSev:    "high",
			wantNote:   false,
		},
		{
			name:       "medium DoS left alone (not high/critical)",
			title:      "Small DoS bug",
			summary:    "Minor denial of service in internal tool.",
			inSeverity: "medium",
			wantSev:    "medium",
			wantNote:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := `
id: "brief-test"
slug: "test"
title: "` + tc.title + `"
summary: "` + tc.summary + `"
severity: "` + tc.inSeverity + `"
published_at: "2026-02-17T00:00:00Z"
content: |
  Details.
tags: []
references: []
ttps:
  - tactic_id: "TA0001"
    tactic_name: "Initial Access"
    technique_id: "T1566"
    technique_name: "Phishing"
`
			v := NewBriefValidator()
			cleaned, notes, err := v.Validate(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !strings.Contains(cleaned, "severity: "+tc.wantSev) {
				t.Errorf("expected severity %q in output, got:\n%s", tc.wantSev, cleaned)
			}

			gotNote := false
			for _, n := range notes {
				if strings.Contains(n, "downgraded") && strings.Contains(n, "DoS") {
					gotNote = true
					break
				}
			}
			if gotNote != tc.wantNote {
				t.Errorf("want downgrade note=%v, got=%v, notes=%v", tc.wantNote, gotNote, notes)
			}
		})
	}
}

func TestConfidenceBand(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0.95, "high"},
		{0.80, "high"},
		{0.79, "med"},
		{0.50, "med"},
		{0.49, "low"},
		{0.01, "low"},
		{0.0, ""},  // unscored
		{-1.0, ""}, // unscored
	}
	for _, c := range cases {
		if got := confidenceBand(c.in); got != c.want {
			t.Errorf("confidenceBand(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateDerivesConfidenceBand(t *testing.T) {
	in := `id: brief-2026-06-02-test
title: Test
ttps:
  - tactic_id: "TA0001"
    tactic_name: "Initial Access"
    technique_id: "T1566"
    technique_name: "Phishing"
    evidence: "The actor sent a spearphishing email with a malicious attachment."
    confidence: 0.9
`
	v := NewBriefValidator()
	cleaned, _, _ := v.Validate(in)
	if !strings.Contains(cleaned, "confidence_band: high") {
		t.Errorf("expected derived confidence_band: high in cleaned output, got:\n%s", cleaned)
	}
}

func TestValidate_AffectedFieldsPassthrough(t *testing.T) {
	input := `
id: "brief-test"
slug: "test"
title: "Test brief"
summary: "Test summary"
severity: "medium"
published_at: "2026-02-17T00:00:00Z"
content: |
  Body.
tags: []
references: []
affected_vendors:
  - "Microsoft"
  - "  microsoft  "
  - "unknown"
affected_products:
  - "Exchange Server 2019"
affected_os:
  - "Windows Server 2022"
ttps:
  - tactic_id: "TA0001"
    tactic_name: "Initial Access"
    technique_id: "T1566"
    technique_name: "Phishing"
`
	v := NewBriefValidator()
	cleaned, _, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(cleaned, "affected_vendors:") {
		t.Errorf("expected affected_vendors in output:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "Microsoft") {
		t.Errorf("expected Microsoft preserved:\n%s", cleaned)
	}
	// Duplicate (case-insensitive) should be removed.
	if strings.Count(strings.ToLower(cleaned), "microsoft") != 1 {
		t.Errorf("expected single Microsoft entry, got multiple:\n%s", cleaned)
	}
	// Placeholder "unknown" should be stripped.
	lower := strings.ToLower(cleaned)
	if strings.Contains(lower, "- unknown") || strings.Contains(lower, "- \"unknown\"") {
		t.Errorf("expected placeholder 'unknown' to be stripped:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "Exchange Server 2019") {
		t.Errorf("expected affected_products preserved:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "Windows Server 2022") {
		t.Errorf("expected affected_os preserved:\n%s", cleaned)
	}
}

func TestValidate_NormalizesGeneratedProsePunctuation(t *testing.T) {
	input := `
id: "brief-2026-07-clickonce"
slug: "2026-07-clickonce"
title: "ClickOnce abuse — persistence"
summary: "Threat actors use ClickOnce — no admin rights required."
severity: "high"
published_at: "2026-07-08T00:00:00Z"
content: |
  ## Overview
  ClickOnce deployment — normally legitimate — is abused for payload delivery.
tags: []
references:
  - https://example.com/clickonce
rules:
  - title: "ClickOnce execution — dfsvc"
    description: "Detects ClickOnce launch — dfsvc.exe spawning payloads"
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: "\\dfsvc.exe"
      condition: selection
    level: high
iocs:
  - type: url
    value: https://malicious.example/app.application
    context: "Delivery URL — observed in campaign"
`
	v := NewBriefValidator()
	cleaned, notes, err := v.Validate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(cleaned, "—") || strings.Contains(cleaned, "–") {
		t.Fatalf("expected generated dash punctuation normalized:\n%s", cleaned)
	}
	foundNote := false
	for _, note := range notes {
		if strings.Contains(note, "normalized generated prose punctuation") {
			foundNote = true
			break
		}
	}
	if !foundNote {
		t.Fatalf("expected punctuation normalization note, got %v", notes)
	}
}

func TestValidate_RejectsInvalidSigmaRules(t *testing.T) {
	raw := `id: brief-2026-10-09-sigma
slug: 2026-10-sigma
title: Sigma
summary: A test
severity: high
published_at: "2026-10-09T10:00:00Z"
content: test
rules:
  - title: Valid
    logsource: {category: process_creation, product: windows}
    detection:
      selection:
        Image|endswith: '\tool.exe'
      condition: selection
    level: high
  - title: Undefined filter
    logsource: {category: process_creation, product: windows}
    detection:
      selection:
        Image|endswith: '\tool.exe'
      condition: selection and not filter
    level: high
`
	cleaned, notes, err := NewBriefValidator().Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	var brief briefYAML
	if err := yaml.Unmarshal([]byte(cleaned), &brief); err != nil {
		t.Fatal(err)
	}
	if len(brief.Rules) != 1 || brief.Rules[0].Title != "Valid" {
		t.Fatalf("expected only the valid rule to survive, got %+v", brief.Rules)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "Undefined filter") {
		t.Fatalf("expected a note about the rejected rule, got %q", notes)
	}
}

// Names become public site taxonomy terms: version and model lists are not
// part of a product's name, and no term may outgrow a file name.
func TestCleanAffectedList_NormalizesNames(t *testing.T) {
	got := CleanAffectedList([]string{
		"VIVOTEK Camera Firmware (FD9187, FD9189, FD9365, FD9387, FD9389, FD9391, FE9180, FE9191, FE9382, FE9391, IB9365, IB9387, IB93587LPR)",
		"IBM MQ (9.1.0.0 through 9.1.0.37 LTS, 9.2.0.0 through 9.2.0.43 LTS, 9.3.0.0 through 9.3.0.41 LTS, 9.4.0.0 through 9.4.0.15)",
		"IBM MQ",
		"Windows Subsystem for Linux (WSL)",
		"Chrome (versions before 120)",
	})
	want := []string{"VIVOTEK Camera Firmware", "IBM MQ", "Windows Subsystem for Linux (WSL)", "Chrome (versions before 120)"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("CleanAffectedList = %q, want %q", got, want)
	}

	long := strings.Repeat("Enterprise Application Server Component ", 10)
	capped := CleanAffectedList([]string{long})
	if len(capped) != 1 || len(capped[0]) > MaxTermBytes || strings.HasSuffix(capped[0], " ") || !strings.HasPrefix(long, capped[0]) {
		t.Fatalf("expected a word-boundary cut within %d bytes, got %q", MaxTermBytes, capped)
	}
	if runes := CapTerm(strings.Repeat("é", MaxTermBytes)); !utf8.ValidString(runes) || len(runes) > MaxTermBytes {
		t.Fatalf("CapTerm cut inside a rune or over the limit: %q", runes)
	}
}

func TestValidateNormalizesVendorSeverity(t *testing.T) {
	for in, want := range map[string]string{
		"important": "high", "Moderate": "medium", "7.5": "high", "9.8": "critical",
		"5.0": "medium", "2.1": "low", "Critical": "critical", "severe": "high",
	} {
		raw := "id: brief-x\nslug: 2026-10-x\ntitle: T\nsummary: S\nseverity: \"" + in + "\"\npublished_at: \"2026-10-20T10:00:00Z\"\ncontent: c\n"
		cleaned, _, err := NewBriefValidator().Validate(raw)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		var got struct {
			Severity string `yaml:"severity"`
		}
		if err := yaml.Unmarshal([]byte(cleaned), &got); err != nil {
			t.Fatal(err)
		}
		if got.Severity != want {
			t.Errorf("severity %q -> %q, want %q", in, got.Severity, want)
		}
		if err := ValidateBriefContract(cleaned); err != nil {
			t.Errorf("%q: contract: %v", in, err)
		}
	}
}

func TestValidateAcceptsDateOnlyObservedAt(t *testing.T) {
	raw := `id: brief-x
slug: 2026-10-x
title: T
summary: Actively exploited
severity: high
published_at: "2026-10-20T10:00:00Z"
content: c
references: [https://vendor.example/a]
exploitation_evidence:
  status: confirmed_active
  source_url: https://vendor.example/a
  observed_at: 2026-10-19
`
	cleaned, _, err := NewBriefValidator().Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cleaned, "2026-10-19T00:00:00Z") {
		t.Fatalf("observed_at not normalised to RFC3339:\n%s", cleaned)
	}
}

func TestBundleCVEAcceptsScalarEntries(t *testing.T) {
	var doc struct {
		CVEs []BundleCVE `yaml:"cves"`
	}
	if err := yaml.Unmarshal([]byte("cves:\n  - CVE-2026-1111\n  - id: CVE-2026-2222\n    cvss: 7.5\n"), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.CVEs) != 2 || doc.CVEs[0].ID != "CVE-2026-1111" || doc.CVEs[1].CVSS != 7.5 {
		t.Fatalf("got %+v", doc.CVEs)
	}
}
