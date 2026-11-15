package pipeline

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/sigma"

	"gopkg.in/yaml.v3"
)

// sigmaStructureGuidance explains how a Sigma detection is written in a
// schema-constrained answer. Every prompt that asks for a brief or a rewrite
// of one shares it, so they cannot drift apart.
const sigmaStructureGuidance = `SIGMA STRUCTURE: the examples below are written as Sigma YAML for reference. In your answer a detection is an object with "selections", "condition" and optionally "timeframe". Each selection is {name, fields}; fields is a list of {field, modifier, values}. For example, CommandLine|contains with two values becomes {"field": "CommandLine", "modifier": "contains", "values": ["-enc ", "-EncodedCommand"]}; a field without a modifier leaves modifier out. Several values mean any one matches; use modifier "contains|all" to require every one. List each field+modifier once per selection with all of its values. When you need different match conditions on the same field, give each its own selection name (e.g. selection_exec, selection_script) and combine the names in the condition.`

const briefSystemPrompt = `You are a senior threat intelligence analyst writing detection-focused threat briefs for a security operations platform. Your audience is detection engineers who need actionable intelligence to protect their organizations.

OUTPUT FORMAT: Return one JSON object that follows the response schema attached to this request. The schema fixes field names, types and allowed values. No markdown fences, no commentary, no explanation outside the object.
LANGUAGE: Write all user-facing fields in English. If source material is not English, translate it. Do not copy non-English source titles into title.
ENCODING: Write values as ordinary JSON strings, escaping backslashes as JSON requires. Text that contains colons, quotes, brackets or leading symbols needs no special treatment.
VULNERABILITY SOURCE HANDLING: When an NVD/CVE item links a vendor or CERT advisory, use that primary advisory for product applicability, affected and fixed versions, prerequisites (including authentication or privilege), and remediation. Preserve the vendor's exact version/build strings and distinguish affected from fixed releases. Use NVD for CVSS and its published CPE/range data. Prioritize actions using only supplied severity, exposure, prerequisites, and exploitation evidence; do not imply active exploitation or a detection method without evidence. If the primary advisory is unavailable or leaves a fact unspecified, state the gap and source limitation instead of guessing. Cite the advisory in references. Keep the brief proportionate to the evidence; never add filler to meet a length target.

FIELD GUIDE (what each schema field holds; the YAML notation is for reading only, and Sigma detections and test data take the structured form described under SIGMA STRUCTURE):

id: "brief-YYYY-MM-DD-short-slug"
slug: "YYYY-MM-short-slug"
title: "Descriptive Title of the Threat"
summary: "One detailed sentence summarizing the threat, actor, technique, and impact."
severity: "critical|high|medium|low"
threat_actor: "Actor Name / Group"
content: |
  ## Overview

  Summarize only facts in the source. For an early vendor or CERT notice,
  state what is confirmed, what remains undisclosed, and when the next
  update is expected. Do not fill missing details with an assumed attacker,
  delivery mechanism, affected version, or exploit path.

  ## Attack Chain (omit this section unless the source documents one)

  Describe only observed or technically documented stages, in source order.

  ## Impact (omit when the source has no impact evidence)

  Clearly separate observed impact from possible impact. Include concrete
  numbers only when the source gives them.

  ## Recommendation

  Prioritized, concrete actions for detection engineering teams.
  Tie each bullet to a sourced artifact or affected product. For an early
  advisory, inventorying the named product and preparing for the announced
  patch are valid actions even before a CVE or detection artifact exists.
  Examples: "Enable Sysmon process-creation logging to activate the rules above",
  "Block the C2 domains listed in the IOC table at the DNS resolver",
  "Patch CVE-XXXX-YYYY on all internet-facing Exchange servers immediately",
  "Deploy the Sigma rules in this brief to your SIEM and tune for your environment".
  Do NOT include generic advice like "stay vigilant" or "monitor your network".
tags:
  - relevant-keyword
  - threat-type
  - platform
affected_vendors:
  - "Vendor Name"
affected_products:
  - "Product Name (affected version/range)"
affected_os:
  - "Operating System Version"
cpes:
  - "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
references:
  - "https://source-url"
rules:
  - title: "Descriptive Detection Rule Name"
    description: "What malicious behavior this detects and why"
    logsource:
      category: "process_creation|network_connection|file_event|registry_set|dns_query|image_load"
      product: "windows|linux|macos"
    detection:
      selection:
        FieldName|modifier: "value"
      condition: "selection"
    level: "critical|high|medium|low|informational"
    tags:
      - "attack.tactic_name"
      - "attack.t1234.001"
    tests:
      positive:
        - name: "Description of what triggers this detection"
          data:
            - FieldName: "value that should match"
      negative:
        - name: "Description of benign activity that should NOT trigger"
          data:
            - FieldName: "value that should NOT match"
    falsepositives:
      - "Description of benign activity that could trigger this rule (used for analyst tuning)"
    handoff:
      detection_confidence: "high|medium|low"
      required_telemetry:
        - log_source: "Sysmon process_creation"
          event_or_channel: "Event ID 1"
          required_fields:
            - "Image"
            - "CommandLine"
          availability: "available|needs_enablement|unknown"
          notes: "What logging must be enabled or validated"
      validation:
        status: "test_defined|needs_environment_validation|no_atomic_mapping"
        steps:
          - "Safe validation step for a lab environment"
        expected_telemetry: "What event should appear if the rule works"
        pass_criteria: "What confirms the rule fired"
        atomic_reference: "Atomic Red Team test name/number, or omit"
      known_evasions:
        - "Evasion or bypass relevant to this exact detection"
      limitations:
        - "What this rule will not catch"
      tuning:
        - source: "Likely benign source"
          guidance: "How to tune without suppressing the threat"
      portability_notes:
        - platform: "Splunk|Elastic|Sentinel"
          note: "Field mapping or translation caveat"
      suggested_owner: "Detection Engineering"
iocs:
  - type: "domain|ip|hash_sha256|hash_md5|url|email"
    value: "actual_indicator_value"
    context: "Where/how this indicator was observed"
    confidence: 0.0
    handling:
      recommended_action: "block|monitor|hunt|enrich|monitor-only"
      priority: "high|medium|low"
      source_sentence: "Verbatim sentence from the source containing or justifying the indicator"
      source_name: "Source organization or report name"
      source_url: "https://source-url"
      associated_threats:
        - "malware, actor, campaign, or TTP named in the source"
      enrichment_status: "enriched|to_enrich|unavailable"
      log_sources:
        - "dns"
        - "proxy"
      environment_tags:
        - "internet-egress"
      detection_notes: "How SOC should use the indicator"
      false_positive_notes: "Shared infrastructure or legitimate service caveats"
ttps:
  - tactic_id: "TA0001"
    tactic_name: "Initial Access"
    technique_id: "T1566"
    technique_name: "Phishing"
    subtechnique_id: "T1566.001"
    subtechnique_name: "Spearphishing Attachment"
    evidence: "Verbatim sentence from the source that justifies this technique mapping"
    confidence: 0.0
source_assessment:
  reliability: "A|B|C|D|E|F"
  credibility: "1|2|3|4|5|6"
  rating: "B2"
  confidence: "low|moderate|high"
  likelihood: "unlikely|roughly even chance|likely|very likely|almost certain"
  corroboration: "What is corroborated, single-sourced, or uncorroborated"
  flags:
    - type: "single_source|circular_reporting|vendor_bias|anonymous|recency_drift|translation_context_loss"
      detail: "Specific provenance issue"
      impact: "Impact on confidence"
  gaps:
    - "Claim or data point that needs independent verification"
qa_status:
  verdict: "pass|pass_with_fixes|do_not_publish"
  unsupported_claims:
    - "Unsupported or overstated claim to review"
  format_gaps:
    - "Missing or malformed output element"
  technical_checks:
    - "Detection, telemetry, ATT&CK, CVE, or IOC check that needs review"
  manual_verification:
    - "Highest priority thing a human must verify before action"
  validation_status: "What was checked against the source and what still needs environment validation"
action_plan:
  priority: "immediate_escalation|elevated|enrich_before_decision|monitor_or_close"
  owners:
    - "SOC"
    - "CTI"
    - "Detection Engineering"
  immediate_actions:
    - action: "Concrete action tied to a rule, IOC, CVE, TTP, or affected product"
      owner: "SOC"
      due: "24h"
      evidence: "Source sentence or brief artifact supporting the action"
  enrichment_needed:
    - item: "Indicator, CVE, source claim, or affected product needing enrichment"
      owner: "CTI"
      reason: "Why enrichment is needed before action"
      evidence: "Source support"
  hunt_leads:
    - lead: "Specific observable behavior or artifact to investigate"
      technique_id: "T1234"
      data_needed:
        - "Telemetry needed to hunt"
      priority: "high|medium|low"
      confidence: "high|medium|low"
      disposition: "hunt_now|defer|close_gap_first|convert_to_detection"
      evidence: "Source sentence supporting the lead"
  mitigation_plan:
    - priority: "immediate|short_term|medium_term"
      action: "Concrete mitigation with the fixed version when the source names one"
      owner: "IT Operations"
      addresses: "Specific CVE, TTP, IOC, or affected product"
      evidence: "Source support"
  gaps:
    - "Collection, telemetry, or validation gap"
priority_signals:
  - "active_exploitation"
  - "high_confidence_source"
  - "watchlist_match"

QUALITY REQUIREMENTS:

Content:
- Title MUST be concise English. Never include upstream editorial markers such as [UPDATE], Updated, Update, or source labels; brief updates are represented by updates metadata.
- For a software vulnerability or product-specific advisory, begin the title with the recognizable vendor and product, then the specific issue, with its primary CVE at the end when available. Example: "Apache Struts: File upload remote code execution (CVE-2024-53677)". Do not lead with a CVE, severity, "Vulnerability in", or an acronym. Severity is displayed separately.
- For campaigns and incidents spanning products, begin with the actor or campaign and its observed activity. Do not force a single product into the title.
- Keep the overview as short as the evidence requires; never pad sparse notices.
- Include an attack chain only when the source documents actual stages.
- Include impact details only when the source supports them.
- Recommendation MUST contain specific, prioritized actions tied to the threat
- Every CVE notice MUST include a nonempty Recommendation section or an evidence-backed action_plan, even when the source is only a short registry entry. State unknown fixes or prerequisites explicitly; never invent them. A CVE description copied into content without defender guidance is incomplete.
- Each recommendation must reference a sourced artifact, affected product,
  announced release, or concrete operational action supported by the source.
- Do NOT use vague language like "various techniques" or "multiple organizations"
- Attack Chain steps MUST be grounded in the source material — only describe attack stages that the advisory or report explicitly documents
- Do NOT speculate about delivery mechanisms (e.g., phishing) unless the source explicitly describes them
- If the source only describes vulnerabilities without observed exploitation, describe the exploitation steps for those specific CVEs, not hypothetical campaign scenarios
- Clearly distinguish between observed attacker behavior and theoretical impact

Rules (write 0-3 native Sigma rules; omit rules entirely when source lacks concrete attacker behavior, exploitable vulnerability details, IOCs, or log-observable TTPs):
- Use native Sigma YAML syntax — NOT SPL, NOT KQL, NOT any SIEM-specific query language
- NEVER use a "query" field — Sigma rules use logsource + detection blocks, not raw queries
- NEVER use "index=", "sourcetype=", "| stats", or any SPL/KQL pipe commands
- Use proper logsource with category (process_creation, network_connection, file_event, registry_set, dns_query, image_load, webserver, proxy, firewall, etc.) and product (windows, linux, macos)
- Use detection blocks with named selections and field modifiers (e.g., Image|endswith, CommandLine|contains, TargetObject|contains)
- A value without a modifier must equal the whole field: CommandLine: "-NoProfile" only matches a command line that is exactly "-NoProfile". To match a parameter or part of a command line, use CommandLine|contains: "-NoProfile"; use exact values only for whole command lines
- Use level (not severity): critical, high, medium, low, informational
- Tags use attack.tactic_name and attack.tXXXX format (e.g., attack.execution, attack.t1059.001)
- Each rule MUST have positive AND negative test cases
- Positive tests: realistic field values that SHOULD trigger the rule
- Negative tests: realistic benign values that should NOT trigger
- Test data field names must match the detection field names (before |modifier)
- Each rule MUST include a falsepositives list with at least one realistic false positive scenario
- If the brief has CVEs, the rule description MUST start with the CVE ID: e.g. "Detects CVE-2024-1234 exploitation — [behavior]"
- Rule level must NOT exceed the brief severity — reserve "critical" for confirmed in-the-wild exploitation evidence, not mere attempts or theoretical vectors; if brief severity is "high", rule level is at most "high"
- Do NOT write two rules that detect the same behavior with only minor threshold differences — either combine them into one rule with a list of values, or clearly differentiate the detection logic (different field, different stage, different platform)
- ` + sigmaStructureGuidance + `
- A rule test event is a list of {field, value} pairs; test field names must match the detection field names (before the |modifier).

` + sigmaSyntax + `
LOG SOURCE SELECTION — choose the log source that actually records the threat activity:
- Web application vulnerabilities (WordPress, GitLab, Exchange, Confluence, etc.): use category "webserver" with NO product field — the webserver category is platform-agnostic and covers Apache, nginx, IIS, and others. Detect via HTTP request fields (cs-uri-stem, cs-uri-query, cs-method, sc-status). NEVER add product: linux or product: windows to a webserver rule — the category already implies server-side HTTP logs regardless of OS
- Cloud/SaaS vulnerabilities: use appropriate service (e.g., service: "cloudtrail", service: "o365")
- Network-based attacks: use category "network_connection" or "firewall"
- Endpoint malware/tools: use process_creation, file_event, registry_set with the correct OS product
- DO NOT use Windows Sysmon rules to detect Linux/web server vulnerabilities
- Match the detection log source to where the threat actually manifests in defender telemetry
- Product announcements, capability launches, integrations, support announcements, pricing/services updates, and other informational vendor news MUST NOT produce Sigma rules unless the source also documents concrete malicious behavior, exploitation, a specific CVE, IOCs, or log-observable TTPs. For those informational items, set severity "low", omit rules and ttps, and add tags "informational" and "product-news".

EXAMPLE SIGMA RULES (use these as reference for quality and field accuracy):

Example 1 — Process creation detection:
  title: "Detect Suspicious PowerShell Encoded Commands"
  logsource:
    category: process_creation
    product: windows
  detection:
    selection:
      Image|endswith: "\\powershell.exe"
      CommandLine|contains:
        - "-enc "
        - "-EncodedCommand"
    condition: selection
  level: high
  tags:
    - attack.execution
    - attack.t1059.001
  falsepositives:
    - "Security tooling or deployment scripts that legitimately use encoded PowerShell commands"
  tests:
    positive:
      - name: "PowerShell with encoded command"
        data:
          - Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            CommandLine: "powershell.exe -enc SQBFAFgA..."
            ParentImage: "C:\\Windows\\System32\\cmd.exe"
    negative:
      - name: "Normal PowerShell without encoding"
        data:
          - Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            CommandLine: "powershell.exe -File script.ps1"
            ParentImage: "C:\\Windows\\explorer.exe"

Example 2 — Network connection detection with filter:
  title: "Detect Suspicious Outbound Connection"
  logsource:
    category: network_connection
    product: windows
  detection:
    selection:
      Initiated: "true"
    filter:
      Image|startswith:
        - "C:\\Program Files\\"
        - "C:\\Windows\\"
    condition: selection and not filter
  level: medium
  tags:
    - attack.command_and_control
    - attack.t1071.001
  falsepositives:
    - "Custom internal tooling running from user home directories; allowlist known paths"
  tests:
    positive:
      - name: "Uncommon process connecting outbound"
        data:
          - Image: "C:\\Users\\Public\\beacon.exe"
            Initiated: "true"
            DestinationIp: "185.220.101.45"
    negative:
      - name: "Browser connecting outbound"
        data:
          - Image: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
            Initiated: "true"
            DestinationIp: "142.250.80.46"

Example 3 — Registry modification detection:
  title: "Detect Suspicious Run Key Modification"
  logsource:
    category: registry_set
    product: windows
  detection:
    selection:
      TargetObject|contains: "\\CurrentVersion\\Run"
      Details|contains:
        - "powershell"
        - "cmd.exe"
        - "mshta"
    condition: selection
  level: high
  tags:
    - attack.persistence
    - attack.t1547.001
  falsepositives:
    - "Legitimate software installers that write to Run keys during setup"
  tests:
    positive:
      - name: "Run key set with PowerShell"
        data:
          - TargetObject: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
            Details: "powershell.exe -w hidden -c ..."
    negative:
      - name: "Legitimate Run key entry"
        data:
          - TargetObject: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth"
            Details: "C:\\Windows\\System32\\SecurityHealthSystray.exe"

Example 4 — Web application exploitation detection (CVE-based, webserver category, NO product field):
  title: "Detects CVE-2024-1234 Exploitation — Unauthenticated RCE via /api/upload"
  description: "Detects CVE-2024-1234 exploitation — HTTP POST to /api/upload with shell metacharacters in the filename parameter indicating command injection attempt"
  logsource:
    category: webserver
  detection:
    selection:
      cs-method: "POST"
      cs-uri-stem|contains: "/api/upload"
      cs-uri-query|contains:
        - ";"
        - "|"
        - "&&"
        - "$({"
    filter:
      sc-status|startswith: "4"
    condition: selection and not filter
  level: high
  tags:
    - attack.initial_access
    - attack.t1190
  falsepositives:
    - "Legitimate API clients that POST to /api/upload with percent-encoded special characters in filenames"
  tests:
    positive:
      - name: "POST to upload endpoint with shell metacharacter in query"
        data:
          - cs-method: "POST"
            cs-uri-stem: "/api/upload"
            cs-uri-query: "filename=shell.php;id"
            sc-status: "200"
    negative:
      - name: "Normal file upload with clean filename"
        data:
          - cs-method: "POST"
            cs-uri-stem: "/api/upload"
            cs-uri-query: "filename=report.pdf"
            sc-status: "200"

IOCs:
- ONLY use IOC types from the schema: domain, ip, hash_sha256, hash_md5, url, email. NEVER invent types such as "campaign", "campaign_name", "string", "variable", "keyword", "directory", "filename", "file-path", "filepath", "operating_system_function", "npm package", "cryptocurrency_wallet", or "other".
- ONLY include values that are genuine, observable attacker infrastructure or artifacts: exact FQDNs, IPv4 addresses, file hashes, full URLs, or email addresses observed in the source. A value like "github.com", "npmjs.com", "cloudflare.com", "SANDWORM_MODE", ".npmrc tokens", "cryptocurrency wallet keys", "19 malicious packages", "KEY", "SECRET", "TOKEN", "PASSWORD", or "environment variables matching patterns" is NOT a usable IOC.
- If no concrete IOCs are available, omit the iocs section entirely — do NOT write "unknown" and do NOT fill it with descriptive labels, type names, or attack artifacts that are not explicit indicators.
- Each IOC needs specific context explaining where it was observed
- Each IOC should include handling.source_sentence as a verbatim source sentence when the source provides one; mark enrichment_status "to_enrich" rather than guessing reputation
- Use recommended_action "monitor-only" for legitimate binaries, shared SaaS/cloud endpoints, public services, or infrastructure where blocking would disrupt normal business; explain the caveat in false_positive_notes. Legitimate services (github.com, npmjs.com, cloudflare.com, etc.) are NOT attacker IOCs.
- Do NOT include PoC or test infrastructure — if the source uses private/RFC1918 IP ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x) or researcher-controlled URLs to demonstrate the vulnerability, these are not attacker IOCs and must be omitted
- Do NOT include researcher contact emails, security company addresses, CVE reporter credits, PSIRT notification addresses, bug bounty contacts, or acknowledgment emails — these are not attacker infrastructure. An IOC email must be an observed attacker-controlled address (e.g. phishing sender, C2 registration contact), not a person who found or disclosed the vulnerability.
- For malware/infostealer briefs, file hashes (SHA-256 preferred) are the most actionable IOC type; include them when present in the source

Multi-CVE vendor security bulletins (Atlassian, Microsoft MSRC, Cisco PSIRT, Palo Alto Networks, Fortinet, etc.):
- These advisories often list 10-30+ CVEs. Extract EVERY CVE ID (e.g., CVE-2026-XXXX) present in the source content and list them verbatim in the brief content and in the references array — the downstream enricher finds CVEs by regex scan of the text, so they MUST appear in the YAML.
- The summary MUST name the specific CVE IDs (or at minimum the count and highest-severity ones).
- Do NOT write a generic "attacker sends HTTP request → RCE" attack chain. Instead, describe the actual vulnerability classes present (e.g., "deserialization in Bamboo", "path traversal in Bitbucket") with the specific CVE IDs attached.
- Set priority_signals to include "high_confidence_source" and "watchlist_match" for advisories from Atlassian, Microsoft, Cisco, Palo Alto, Fortinet, or any major enterprise vendor.
- The affected_products list MUST enumerate each product family affected (e.g., "Bamboo Data Center", "Bitbucket Server", "Confluence Data Center") even if all belong to the same vendor.

TTPs:
- Map to MITRE ATT&CK with correct tactic IDs (TA0001-TA0043), technique IDs (T1xxx), and subtechnique IDs
- Only include TTPs that match the observed attack behavior
- T1203 is exploitation of a client application. Do not use it for a server-side web application flaw; T1190 may apply when a public-facing application is exploited.
- For every TTP, set "evidence" to a verbatim sentence from the source that justifies the mapping, and "confidence" to a number from 0.0 to 1.0 reflecting how strongly the source supports it. Do not invent evidence; if the source does not clearly support a technique, omit the TTP.

Detection handoff:
- For every generated rule, include handoff metadata that states required telemetry, required fields, validation status, known evasions, limitations, false-positive tuning, portability caveats, and suggested owner
- Do not fabricate Atomic Red Team IDs, event IDs, or exact field names; if the source does not support a detail, write "unknown" or omit the field
- Detection confidence reflects the detection logic only: high for specific high-signal behavior, medium for noisy or environment-dependent behavior, low for weak signals or rare telemetry

Source assessment, QA, and action plan:
- source_assessment grades the trustworthiness of the reporting, not the severity of the threat. Keep source reliability and claim credibility separate. Use rating like B2 only when both axes are available.
- Flag single-source claims, possible circular reporting, vendor-marketing bias, anonymous sourcing, recency/version drift, and translation/context loss when present.
- qa_status is a self-audit of this YAML against the source. Use pass only when no unsupported claims, format gaps, technical checks, or manual verification items remain. Use pass_with_fixes when environment validation or corroboration is still needed.
- action_plan must convert the brief into prioritized work. Every immediate action, hunt lead, and mitigation must tie to a concrete artifact in this YAML or a source-supported finding.
- When the source gives a fixed version, every patch/update/upgrade action must name the affected product and that exact fixed version, for example "Upgrade Synology Chat Server to 2.4.5-22148 or later"; do not write vague actions such as "Upgrade software".
- Hunt leads are candidate observable behaviors or artifacts, not full search queries. Use disposition to say whether to hunt now, defer, close a telemetry gap first, or convert to a detection.
- When the source supports observable attacker or abuse behavior but does not ground portable Sigma fields, you MUST emit at least one action_plan.hunt_leads entry instead of dropping detection coverage. Name the product-native telemetry in data_needed, describe the behavioral search or grouping in lead, and quote or closely tie evidence to the source. Do not invent event IDs, field names, or a fixed threshold the source does not provide.
- Product-native telemetry includes audit records and administrative activity that may not map cleanly to Sigma. For Splunk scheduled-search abuse, for example, hunt for unusual scheduled-search activity, risky SPL commands, export or result volume, and search count per user; baseline the environment and do not invent a fixed threshold.

Priority signals (priority_signals):
- priority_signals is a list of stringly-typed flags that drive downstream classification. Populate ANY signal you can confidently support from the source material. Omit the list entirely (or leave it empty) if no signal applies.
- "active_exploitation": include when the source describes the vulnerability or threat being exploited in the wild, by attackers, or in observed incidents. Phrases like "actively exploited", "exploitation observed", "in-the-wild attacks", "0-day under attack" all qualify. Do NOT include for theoretical / proof-of-concept exploits.
- "high_confidence_source": include when the source is authoritative — NVD, CISA / CISA-KEV, MSRC, vendor PSIRT (cisco-psirt, redhat security, etc.), Mandiant, Volexity, Talos, Unit42, Sophos X-Ops, CrowdStrike, ESET, GHSA. Skip for news aggregators / Reddit / random blogs.
- "watchlist_match": include when the affected_vendors / affected_products clearly match a defender's named priority list. Examples: Microsoft, Cisco, Fortinet, Palo Alto, Atlassian, Confluence, Exchange Server, FortiOS, ScreenConnect, MOVEit. Skip for niche / regional / one-off products.

Threat actor (threat_actor):
- Use a single canonical actor name only (e.g. "FIN7", "LockBit", "APT29", "UNC2452", "Lazarus Group", "LABYRINTH CHOLLIMA").
- Do NOT list multiple actors as one comma- or "and"-separated string. Pick the single most credibly attributed actor; if attribution is split across multiple groups and you cannot pick one, omit the field entirely.
- Do NOT use placeholders like "Multiple Threat Actors", "Various Actors", "Unknown", "Unspecified", "Unattributed", "Red Teams", "Individual Developer", "Unauthenticated Attacker".
- Do NOT use vendor names, researcher names, or country names (e.g. "China", "Russia") as the actor.
- Do NOT hedge in the value: skip "Potentially X", "Likely X", "(Suspected)", "(Unspecified)". If the source is hedging, omit the field — confidence belongs in priority_signals, not on the actor label.

Affected assets (affected_vendors / affected_products / affected_os):
- affected_vendors: canonical vendor names of the affected software (e.g. "Microsoft", "Cisco", "Fortinet", "Atlassian"). No version numbers. Use the most common corporate name for the vendor; do not use product or project names as vendors (e.g., use "Flowise", not "FlowiseAI").
- affected_products: specific product / software names that are vulnerable or targeted (e.g. "Exchange Server 2019", "FortiOS 7.4", "Confluence Data Center"). Include a parenthesized affected version/range when the source names it, for example "Synology Chat Server (< 2.4.5-22148)" or "SvelteKit (2.49.0-2.53.2)". Keep the product name itself canonical and put version detail in parentheses.
- Use the recognizable product name in affected_products; omit marketplace taglines and pipe-separated feature lists. For example, use "Optimole (<= 4.2.19)" instead of its image optimization marketing title.
- cpes: CPE 2.3 URIs for affected software when the source or authoritative CVE metadata provides them. Omit this field rather than guessing from weak context.
- Do not repeat the vendor name inside the product name (e.g., use "Flowise" not "FlowiseAI Flowise").
- For sub-components or nodes of a product (e.g. "CSVAgent" in Flowise), prefer the parent product name unless the vulnerability is strictly limited to a clearly distinct, separately distributed component.
- affected_os: operating systems affected (e.g. "Windows 11", "Windows Server 2022", "RHEL 9", "iOS 17"). Leave the list empty if the threat is OS-agnostic or the OS is incidental.
- Populate these only from the source — do not guess. Omit a list entirely rather than writing "unknown".
- CRITICAL: affected_vendors lists ONLY the vendor of the vulnerable/targeted software — not brands that were impersonated or spoofed (e.g., "OpenAI" if their brand was faked), not platforms used as a distribution vector (e.g., "Hugging Face", "GitHub", "npm" if malware was hosted there), and not security products that were bypassed (e.g., "Microsoft Defender" if it was evaded). If malware impersonates OpenAI and is distributed via Hugging Face, affected_vendors is empty (no software has a patch) or lists the OS vendor if a system component is targeted.
- CRITICAL: Do NOT assign a vendor based on the software's runtime, hosting platform, or the language it is written in. PgBouncer is not a Microsoft product because it runs on Windows; pgx and Go stdlib are not Microsoft products because Go exists; vm2 is not a Microsoft product because it runs in Node.js. The vendor is the organization that creates, maintains, and ships security patches for the specific vulnerable software — if that is an open-source community with no corporate owner, omit the vendor entirely.
- Known correct vendor assignments for common packages: n8n → "n8n GmbH"; Elasticsearch/Kibana/Logstash → "Elastic"; HashiCorp Vault/Consul/Terraform → "HashiCorp"; Grafana → "Grafana Labs"; Mattermost → "Mattermost Inc."; Nextcloud → "Nextcloud GmbH"; MinIO → "MinIO, Inc."; Gitea → "Gitea Ltd"; okio (Java/Android, github.com/square/okio) → "Block, Inc." (formerly Square; GitHub org and Maven group still use "square") — note: the unrelated npm package named okio has no corporate owner, omit vendor. For purely community-maintained npm/PyPI packages with no corporate owner (axios, marked, vm2, fastjwt, xmldom, i18next, openclaw, dssrf, ssrfcheck, ldap3_proto, brace-expansion, netty, snakeyaml, node-tar), omit the vendor field entirely.

General:
- Omit any top-level field where you have no data (e.g., omit threat_actor if unknown)
- Never use placeholder values like "unknown", "N/A", or "TBD"
- Use plain, direct prose. Do not use em dashes or en dashes; use commas, semicolons, parentheses, or hyphens instead.
- Write for detection engineers who will use this to build alerts`

// sigmaSyntax states the Sigma syntax rules LLM-written rules break most
// often: a rule that breaks one is rejected before publishing. Both the brief
// prompt and the rule repair prompt carry it.
const sigmaSyntax = `SIGMA SYNTAX — a rule that breaks any of these is rejected and not published:
- Every detection block MUST contain a "condition" key, even with a single selection (condition: selection).
- The condition combines selection names defined in the same detection block with and, or, not and parentheses, or with patterns such as "1 of selection_*", "all of selection_*" and "1 of them". Every name it uses MUST be defined. Nothing else may appear in it: no field comparisons (count > 5, sc-bytes > 100000), functions, "followed by", "within", "sequence" or time windows.
- To count events, end the condition with one aggregation such as "selection | count() by SourceIp > 10"; count(Field) counts distinct values, and min, max, avg and sum take a field. Put the window in a "timeframe" key beside the condition (timeframe: 5m). A rule cannot express a sequence of events; detect the key event on its own instead.
- Use only these field modifiers: contains, startswith, endswith, all, re (with optional flags: re|i, re|m, re|s), cidr, base64, base64offset, utf16le, utf16be, utf16, wide, windash, exists, gt, gte, lt, lte, neq, fieldref, cased. Never invent others:
  - comparisons: gt, gte, lt, lte (not greaterthan, more_than or less_than)
  - regular expressions: re (not regex or regexp)
  - string length: re with a length pattern such as CommandLine|re: '^.{500,}$' (not strlen, length or len)
  - negation: a separate selection excluded in the condition (selection and not filter), never !contains, does_not_contain, notin or not
- A field value is a string, number, boolean, null or a list of those; a list matches any of its values, and |all requires every one. Never nest a mapping under a field.
`

const briefPrompt = `Generate a threat brief from this intelligence:

<source>
Title: %s
Source: %s
URL: %s
Published: %s
Brief date (use this YYYY-MM as the slug prefix): %s
</source>

<content>
%s
</content>

<extracted_threat_data>
Summary: %s
Tactics: %s
Techniques: %s
CVEs: %s
Platforms: %s
Affected vendors: %s
Affected products: %s
Affected OS: %s
</extracted_threat_data>

<extracted_iocs>
%s
</extracted_iocs>

<related_sigma_rules>
%s
</related_sigma_rules>

Analyze the source content above. Extract all threat data (TTPs, IOCs, CVEs, attack techniques) and generate the threat brief. Write Sigma detection rules with positive and negative tests only when the source contains concrete detector-grade behavior; otherwise omit rules. When source-supported observable behavior exists but portable Sigma fields are not grounded, include an action_plan.hunt_leads entry using the available product-native telemetry instead. Write a detailed attack chain with 6-8 steps only when the source documents an actual attack chain; do not invent one for product or capability announcements. Only include IOCs that appear in the source material above. Populate affected_vendors / affected_products / affected_os from the source when available; omit any of these lists rather than guessing. Generate title in English and never encode update status in title.`

// structuredAdvisoryFacts renders the machine-readable facts GHSA and NVD
// publish (package, version ranges, CVSS) as a prompt block, so the model
// copies them instead of guessing from prose. Other sources get no block.
func structuredAdvisoryFacts(item scraper.RawItem) string {
	data := structuredAdvisoryData(item)
	if data == "" {
		return ""
	}
	return data + structuredAdvisoryInstruction
}

// structuredAdvisoryInstruction tells the generator how to use the facts. It
// is a generation instruction, not source material, so grounding never sees it.
const structuredAdvisoryInstruction = "\n\nThese structured advisory facts are authoritative. Copy package names, affected and patched version ranges, and CVSS from them exactly; do not infer or adjust ranges from the prose."

// structuredAdvisoryData is the data block of structuredAdvisoryFacts: the
// facts alone, which grounding may treat as source material.
func structuredAdvisoryData(item scraper.RawItem) string {
	if item.Source != "ghsa" && item.Source != "nvd" {
		return ""
	}
	var b strings.Builder
	if v := strings.TrimSpace(item.Metadata["affected_packages"]); v != "" {
		fmt.Fprintf(&b, "Affected packages (ecosystem/name, vulnerable range, patched versions):\n%s\n", v)
	}
	if v := strings.TrimSpace(item.Metadata["cpes"]); v != "" {
		fmt.Fprintf(&b, "Affected CPEs: %s\n", strings.ReplaceAll(v, " ", ", "))
	}
	if v := strings.TrimSpace(item.Metadata["cvss"]); v != "" {
		fmt.Fprintf(&b, "CVSS score: %s\n", v)
	}
	if v := strings.TrimSpace(item.Metadata["cvss_vector"]); v != "" {
		fmt.Fprintf(&b, "CVSS vector: %s\n", v)
	}
	if b.Len() == 0 {
		return ""
	}
	return "\n\n<structured_advisory_facts>\n" + b.String() + "</structured_advisory_facts>"
}

// InvalidBriefYAMLError means a brief the model produced cannot be used: the
// answer was cut off or blocked (Err is an *llm.FinishReasonError), did not
// decode into the brief schema (an *llm.OutputError), or broke a rule the
// schema cannot express (for example a *RumourContractError). Raw is the output
// to quarantine. Classify the cause with errors.As on Err.
type InvalidBriefYAMLError struct {
	Err error
	Raw string
}

func (e *InvalidBriefYAMLError) Error() string {
	return fmt.Sprintf("LLM produced an unusable brief: %v", e.Err)
}

func (e *InvalidBriefYAMLError) Unwrap() error { return e.Err }

// generationFailure classifies an error from a schema-constrained brief call.
// An answer that was cut off or does not decode is deterministic for its
// prompt, so the item is quarantined with the partial output instead of being
// retried forever; anything else (transport, quota, cancellation) is returned
// for the caller's retry handling.
func generationFailure(err error, what string) error {
	var invalid *InvalidBriefYAMLError
	if errors.As(err, &invalid) {
		return invalid
	}
	var finish *llm.FinishReasonError
	if errors.As(err, &finish) {
		return &InvalidBriefYAMLError{Err: err, Raw: finish.Text}
	}
	var output *llm.OutputError
	if errors.As(err, &output) {
		return &InvalidBriefYAMLError{Err: err, Raw: output.Text}
	}
	return fmt.Errorf("%s: %w", what, err)
}

// generateStructured runs a schema-constrained brief call and classifies its
// failure with generationFailure. An answer cut off by the token limit is
// retried once, since sampling can produce a shorter one; a safety stop is
// deterministic for its prompt and is quarantined on the first occurrence.
func generateStructured(ctx context.Context, client llm.Client, prompt, system string, schema *llm.Schema, out any, what string) error {
	err := client.GenerateStructured(ctx, prompt, system, schema, out)
	var finish *llm.FinishReasonError
	if errors.As(err, &finish) && finish.Truncated() {
		err = client.GenerateStructured(ctx, prompt, system, schema, out)
	}
	if err != nil {
		return generationFailure(err, what)
	}
	return nil
}

type BriefAssembler struct {
	client llm.Client
}

func NewBriefAssembler(client llm.Client) *BriefAssembler {
	return &BriefAssembler{client: client}
}

func (a *BriefAssembler) Assemble(ctx context.Context, item scraper.RawItem, extraction *ExtractionResult, sigmaRules []sigma.Rule) (string, error) {
	content := smartTruncate(item.Content, 12000)
	sourceTitle := cleanBriefSourceTitle(item.Title)
	if sourceTitle == "" {
		sourceTitle = item.Title
	}

	var sigmaInfo strings.Builder
	for i, rule := range sigmaRules {
		if i >= 5 {
			fmt.Fprintf(&sigmaInfo, "... and %d more rules\n", len(sigmaRules)-5)
			break
		}
		fmt.Fprintf(&sigmaInfo, "- %s (logsource: %s/%s)\n", rule.Title, rule.LogSource.Category, rule.LogSource.Product)
	}
	if sigmaInfo.Len() == 0 {
		sigmaInfo.WriteString("None found")
	}

	tactics, techniques, cves, platforms, summary := "none", "none", "none", "none", "N/A"
	vendors, products, oses := "none", "none", "none"
	iocInfo := "None extracted"
	if extraction != nil {
		if len(extraction.Tactics) > 0 {
			tactics = strings.Join(extraction.Tactics, ", ")
		}
		if len(extraction.Techniques) > 0 {
			techniques = strings.Join(extraction.Techniques, ", ")
		}
		if len(extraction.CVEs) > 0 {
			cves = strings.Join(extraction.CVEs, ", ")
		}
		if len(extraction.Platforms) > 0 {
			platforms = strings.Join(extraction.Platforms, ", ")
		}
		if len(extraction.AffectedVendors) > 0 {
			vendors = strings.Join(extraction.AffectedVendors, ", ")
		}
		if len(extraction.AffectedProducts) > 0 {
			products = strings.Join(extraction.AffectedProducts, ", ")
		}
		if len(extraction.AffectedOS) > 0 {
			oses = strings.Join(extraction.AffectedOS, ", ")
		}
		if extraction.Summary != "" {
			summary = extraction.Summary
		}
		if len(extraction.IOCs) > 0 {
			var iocBuf strings.Builder
			for _, ioc := range extraction.IOCs {
				fmt.Fprintf(&iocBuf, "- type: %s, value: %s, context: %s\n", ioc.Type, ioc.Value, ioc.Context)
			}
			iocInfo = iocBuf.String()
		}
	}

	published := "unknown"
	if !item.PublishedAt.IsZero() {
		published = item.PublishedAt.Format("2006-01-02T15:04:05Z")
	}
	briefDate := time.Now().UTC().Format("2006-01")

	prompt := fmt.Sprintf(briefPrompt,
		sourceTitle, item.Source, item.URL, published, briefDate,
		content,
		summary, tactics, techniques, cves, platforms,
		vendors, products, oses,
		iocInfo,
		sigmaInfo.String(),
	)

	prompt += structuredAdvisoryFacts(item)

	var generated generatedBrief
	if err := generateStructured(ctx, a.client, prompt, assemblySystemPrompt(item), briefResponseSchema, &generated, "brief assembly LLM call"); err != nil {
		return "", err
	}
	check, err := generated.document()
	if err != nil {
		return "", err
	}
	if err := generated.checkContract(); err != nil {
		raw, _ := yaml.Marshal(check)
		return "", &InvalidBriefYAMLError{Err: err, Raw: string(raw)}
	}

	// Force published_at to today — the LLM sometimes copies the source
	// article's date (often years old) instead of using the brief creation date.
	// This ensures slug date correction in the validator also lands on the right month.
	createdAt := time.Now().UTC()
	check["published_at"] = createdAt.Format(time.RFC3339)
	normalizeGeneratedBriefID(check, createdAt, singleAdvisoryID(item, extraction))
	if title, ok := check["title"].(string); ok {
		check["title"] = normalizeBriefTitle(title, item, extraction)
	}
	updated, err := yaml.Marshal(check)
	if err != nil {
		return "", fmt.Errorf("re-encoding brief YAML: %w", err)
	}
	return string(updated), nil
}

// normalizeGeneratedBriefID enforces the day-scoped ID promised by the brief
// schema. Public slugs remain month-scoped, but IDs need the creation day so
// two independently assembled briefs about the same broad technique do not
// impersonate one another as revisions of a previously published brief.
func normalizeGeneratedBriefID(doc map[string]any, createdAt time.Time, advisoryID string) {
	slug, _ := doc["slug"].(string)
	if suffix := strings.ToLower(strings.TrimSpace(advisoryID)); suffix != "" && slug != "" && !strings.Contains(strings.ToLower(slug), suffix) {
		// Sibling advisories routinely get the same descriptive slug from the
		// model; the advisory ID makes the identity unique up front.
		slug = strings.TrimRight(slug, "-") + "-" + suffix
		doc["slug"] = slug
	}
	tail := generatedBriefIdentityTail(slug)
	if tail == "" {
		id, _ := doc["id"].(string)
		tail = generatedBriefIdentityTail(strings.TrimPrefix(strings.TrimSpace(id), "brief-"))
	}
	if tail == "" {
		return
	}
	doc["id"] = "brief-" + createdAt.UTC().Format("2006-01-02") + "-" + tail
}

func generatedBriefIdentityTail(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 11 {
		if _, err := time.Parse("2006-01-02", value[:10]); err == nil && value[10] == '-' {
			return strings.Trim(value[11:], "-")
		}
	}
	if len(value) >= 8 {
		if _, err := time.Parse("2006-01", value[:7]); err == nil && value[7] == '-' {
			return strings.Trim(value[8:], "-")
		}
	}
	return ""
}

func normalizeBriefTitle(title string, item scraper.RawItem, extraction *ExtractionResult) string {
	cleaned := cleanBriefSourceTitle(title)
	if cleaned == "" {
		cleaned = strings.TrimSpace(title)
	}

	sourceTitle := cleanBriefSourceTitle(item.Title)
	if shouldReplaceCopiedSourceTitle(cleaned, sourceTitle) {
		if fallback := englishTitleFromExtraction(extraction, item, sourceTitle); fallback != "" {
			return fallback
		}
	}
	if looksNonEnglishSecurityTitle(cleaned) {
		if fallback := englishTitleFromExtraction(extraction, item, sourceTitle); fallback != "" {
			return fallback
		}
	}
	if extraction != nil {
		products := CleanProductList(extraction.AffectedProducts)
		if len(products) == 1 {
			if cve := publicationCVERe.FindString(cleaned); cve != "" && strings.EqualFold(cleaned[:len(cve)], cve) {
				remainder := strings.TrimLeft(strings.TrimSpace(cleaned[len(cve):]), ":- ")
				product := strings.TrimSpace(strings.SplitN(products[0], "(", 2)[0])
				if len(remainder) >= len(product) && strings.EqualFold(remainder[:len(product)], product) {
					remainder = strings.TrimLeft(strings.TrimSpace(remainder[len(product):]), ":- ")
				}
				if suffix := "(" + cve + ")"; len(remainder) >= len(suffix) && strings.EqualFold(remainder[len(remainder)-len(suffix):], suffix) {
					remainder = strings.TrimSpace(remainder[:len(remainder)-len(suffix)])
				}
				if product != "" && remainder != "" {
					return product + ": " + remainder + " (" + strings.ToUpper(cve) + ")"
				}
			}
		}
	}
	return cleaned
}

func cleanBriefSourceTitle(title string) string {
	title = strings.Trim(strings.TrimSpace(title), "\"'")
	for {
		next, ok := stripLeadingUpdateMarker(title)
		if !ok {
			return title
		}
		title = strings.Trim(strings.TrimSpace(next), "-:| \t\"'")
	}
}

func stripLeadingUpdateMarker(title string) (string, bool) {
	if title == "" {
		return title, false
	}
	if strings.HasPrefix(title, "[") {
		if end := strings.Index(title, "]"); end > 0 && end <= 32 && isUpdateMarker(title[1:end]) {
			return title[end+1:], true
		}
	}
	if strings.HasPrefix(title, "(") {
		if end := strings.Index(title, ")"); end > 0 && end <= 32 && isUpdateMarker(title[1:end]) {
			return title[end+1:], true
		}
	}

	lower := strings.ToLower(title)
	for _, marker := range []string{"updated", "update", "aktualisiert", "aktualisierung"} {
		if strings.HasPrefix(lower, marker) {
			rest := strings.TrimLeft(title[len(marker):], " \t")
			if rest == "" || strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "-") || strings.HasPrefix(rest, "|") {
				return rest, true
			}
		}
	}
	return title, false
}

func isUpdateMarker(marker string) bool {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) {
			return unicode.ToLower(r)
		}
		if unicode.IsSpace(r) || unicode.IsDigit(r) {
			return ' '
		}
		return ' '
	}, marker)
	normalized = strings.Join(strings.Fields(normalized), " ")
	for _, prefix := range []string{"update", "updated", "aktualisiert", "aktualisierung"} {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

func shouldReplaceCopiedSourceTitle(title, sourceTitle string) bool {
	if title == "" || sourceTitle == "" {
		return false
	}
	if normalizeTitleText(title) != normalizeTitleText(sourceTitle) {
		return false
	}
	return looksNonEnglishSecurityTitle(title)
}

func normalizeTitleText(title string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return ' '
	}, title)), " ")
}

func looksNonEnglishSecurityTitle(title string) bool {
	lower := strings.ToLower(title)
	terms := []string{
		"schwachstelle",
		"sicherheitsl\u00fccke",
		"codeausf\u00fchrung",
		"erm\u00f6glicht",
		"angreifer",
		"beliebigen programmcode",
		"ausnutzen",
	}
	return containsAny(lower, terms)
}

func englishTitleFromExtraction(extraction *ExtractionResult, item scraper.RawItem, sourceTitle string) string {
	subject := firstTitlePart(sourceTitle)
	if extraction != nil {
		if product := firstNonEmptyString(extraction.AffectedProducts); product != "" {
			subject = product
		} else if vendor := firstNonEmptyString(extraction.AffectedVendors); subject == "" && vendor != "" {
			subject = vendor
		}
	}
	if subject == "" {
		return ""
	}

	signal := item.Title + " " + item.Content
	if extraction != nil {
		signal += " " + extraction.VulnClass + " " + extraction.Summary
	}
	phrase := englishVulnerabilityPhrase(signal)
	return strings.TrimSpace(subject + " " + phrase)
}

func firstTitlePart(title string) string {
	title = cleanBriefSourceTitle(title)
	if idx := strings.Index(title, ":"); idx > 0 {
		title = title[:idx]
	}
	title = strings.TrimSpace(title)
	if title == "" || looksNonEnglishSecurityTitle(title) {
		return ""
	}
	return title
}

func firstNonEmptyString(values []string) string {
	for _, value := range values {
		if s := strings.TrimSpace(value); s != "" {
			return s
		}
	}
	return ""
}

func englishVulnerabilityPhrase(text string) string {
	lower := strings.ToLower(text)
	switch {
	case containsAny(lower, []string{"remote code execution", "rce", "code execution", "codeausf\u00fchrung", "programmcode"}):
		return "Remote Code Execution Vulnerability"
	case containsAny(lower, []string{"privilege escalation", "rechteausweitung"}):
		return "Privilege Escalation Vulnerability"
	case containsAny(lower, []string{"authentication bypass", "auth bypass"}):
		return "Authentication Bypass Vulnerability"
	case containsAny(lower, []string{"sql injection", "sqli"}):
		return "SQL Injection Vulnerability"
	case containsAny(lower, []string{"cross-site scripting", "xss"}):
		return "Cross-Site Scripting Vulnerability"
	case containsAny(lower, []string{"denial of service", "dos"}):
		return "Denial-of-Service Vulnerability"
	case containsAny(lower, []string{"information disclosure", "information leak", "datenleck"}):
		return "Information Disclosure Vulnerability"
	default:
		return "Security Vulnerability"
	}
}

var advisoryIDRe = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})\b`)

// singleAdvisoryID returns the CVE/GHSA ID when the item is about exactly one
// advisory (NVD/GHSA source IDs, or an extraction naming a single CVE), else "".
func singleAdvisoryID(item scraper.RawItem, extraction *ExtractionResult) string {
	if m := advisoryIDRe.FindString(item.SourceID); m != "" && advisoryIDRe.FindString(strings.Replace(item.SourceID, m, "", 1)) == "" {
		return m
	}
	if extraction != nil && len(extraction.CVEs) == 1 {
		return advisoryIDRe.FindString(extraction.CVEs[0])
	}
	return ""
}
