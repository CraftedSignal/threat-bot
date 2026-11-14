package pipeline

import (
	"context"
	"fmt"

	"github.com/craftedsignal/threat-bot/internal/llm"
	"github.com/craftedsignal/threat-bot/internal/scraper"
)

const extractionSystemPrompt = `You are a threat intelligence analyst. Extract structured threat data from the given content.

Extract:
- tactics: MITRE ATT&CK tactic names (lowercase, hyphenated: initial-access, execution, persistence, etc.)
- techniques: MITRE ATT&CK technique IDs (T1059.003 format)
- iocs: Indicators of compromise with type (ip, domain, url, hash_sha256, hash_md5, email), value, and context. Include only malicious infrastructure, payload hashes, accounts, or addresses that are part of the described threat. Do not include article URLs, advisory URLs, package mirrors, download APIs, GitHub/API endpoints, cloud storage/CDN hosts, or vendor infrastructure unless the source explicitly identifies that exact value as malicious infrastructure for this threat.
- cves: CVE IDs (CVE-YYYY-NNNNN format) for the vulnerabilities that are the subject of this item. Exclude older CVEs mentioned only for comparison, background, or as links to other incidents. An announced vulnerability can have no public CVE yet; leave this list empty rather than borrowing a historical ID.
- chained_cves: Groups of CVE IDs from cves that the source says are exploited together as one attack chain, one group per chain (e.g. [["CVE-2026-1001", "CVE-2026-1002"]]). Leave empty when the source does not document a chain; CVEs merely fixed together or disclosed together are not a chain.
- platforms: Affected platforms (windows, linux, macos, cloud, network)
- affected_vendors: Vendor/manufacturer/operator names for affected products and services (e.g. "Microsoft", "Cisco", "Fortinet", "CloudCharge", "GitHub", "Atlassian"). Use the canonical vendor name, no version numbers. Always populate this when there is a clearly identified vendor - including for SaaS, cloud services, web apps, and managed platforms. Do not list vendors whose brands are impersonated, hosting/distribution platforms, code repositories, runtime providers, security tools that are evaded, or products merely mentioned for context.
- affected_products: Specific product, software, or service names that are affected (e.g. "Exchange Server", "FortiOS", "Confluence Data Center"). For SaaS / cloud services with no installable version, list the service hostname or product name (e.g. "cloudcharge.se", "github.com", "Bitbucket Cloud"). Include the version qualifier in parentheses when meaningful: a version range for packaged software ("< 16.0.15522.218"), or a date qualifier for SaaS / undated builds when a fix date is known ("<= 2026-06-13" meaning affected up to and including that date). Omit the qualifier entirely when the affected window is unknown or the vendor has not patched. Do not list brands, games, chat apps, developer platforms, package registries, runtimes, or operating systems unless they are the vulnerable/targeted product in this source.
- affected_os: Operating systems affected (e.g. "Windows 11", "Windows Server 2022", "RHEL 9", "iOS 17", "Ubuntu 22.04"). Leave empty if the threat is OS-agnostic, SaaS-only, or OS is incidental rather than directly vulnerable or targeted.
- threat_actor: The explicitly named actor or intrusion set responsible for this same incident (for example "Storm-0940"). Leave empty for unknown or unattributed actors.
- active_exploitation: true only when the source explicitly says attackers exploited, abused, or used this issue/campaign against real targets. A proof of concept or theoretical exploit is false.
- exploitation_evidence: When active_exploitation is true, copy one short exact sentence from the source that establishes observed malicious use. Otherwise leave empty.
- summary: One paragraph summarizing the threat for a detection engineer
- vuln_class: The primary vulnerability class using one of these exact labels (leave empty if none fits): buffer-overflow, oob, sql-injection, command-injection, ssrf, xss, csrf, rce, path-traversal, auth-bypass, privilege-escalation, use-after-free, deserialization, dos, xxe, open-redirect
- claim_assessment: For public-social discovery, separate the single primary reported claim from established_facts. Set status to unverified unless independently confirmed. likelihood must be exactly unlikely, roughly even chance, or likely. Evidence entries use a concrete type such as first_party_observation, mechanism, artifact, or corroboration, with detail and source_url. Author biography, follower count, repetition, likes, reposts, and engagement are never evidence. Without independent corroboration, likely requires both a first_party_observation and concrete mechanism or artifact evidence. List unresolved gaps.

For vulnerability/CVE reports, affected vendors/products are the parties that ship the vulnerable component or the patch. For malware/campaign reports, affected vendors/products are targets only when the source says they are targeted; not when they are abused as lures, hosting, delivery, runtime, or social context.

Only include items explicitly mentioned or clearly implied by the content as relevant to this same threat. Do not speculate. Leave any list empty rather than filling with guesses.

Respond in JSON: {"tactics": [], "techniques": [], "iocs": [{"type":"","value":"","context":""}], "cves": [], "chained_cves": [], "platforms": [], "affected_vendors": [], "affected_products": [], "affected_os": [], "threat_actor":"", "active_exploitation":false, "exploitation_evidence":"", "summary": "", "vuln_class": "", "claim_assessment":{"claim":"","status":"unverified","likelihood":"unlikely|roughly even chance|likely","evidence":[{"type":"first_party_observation|mechanism|artifact|corroboration","detail":"","source_url":""}],"gaps":[],"established_facts":[]}}`

const extractionPrompt = `Extract threat intelligence from this content:

Title: %s
Source: %s

Content:
%s`

type ExtractionResult struct {
	Tactics              []string         `json:"tactics"`
	Techniques           []string         `json:"techniques"`
	IOCs                 []ExtractedIOC   `json:"iocs"`
	CVEs                 []string         `json:"cves"`
	ChainedCVEs          [][]string       `json:"chained_cves"`
	Platforms            []string         `json:"platforms"`
	AffectedVendors      []string         `json:"affected_vendors"`
	AffectedProducts     []string         `json:"affected_products"`
	AffectedOS           []string         `json:"affected_os"`
	ThreatActor          string           `json:"threat_actor"`
	ActiveExploitation   bool             `json:"active_exploitation"`
	ExploitationEvidence string           `json:"exploitation_evidence"`
	Summary              string           `json:"summary"`
	VulnClass            string           `json:"vuln_class"`
	ClaimAssessment      *ClaimAssessment `json:"claim_assessment"`
}

type ClaimAssessment struct {
	Claim            string          `json:"claim" yaml:"claim"`
	Status           string          `json:"status" yaml:"status"`
	Likelihood       string          `json:"likelihood" yaml:"likelihood"`
	Evidence         []ClaimEvidence `json:"evidence" yaml:"evidence"`
	Gaps             []string        `json:"gaps" yaml:"gaps"`
	EstablishedFacts []string        `json:"established_facts" yaml:"established_facts"`
}
type ClaimEvidence struct {
	Type      string `json:"type" yaml:"type"`
	Detail    string `json:"detail" yaml:"detail"`
	SourceURL string `json:"source_url" yaml:"source_url"`
	// Only pipeline source checks may attest evidence. Model JSON cannot mint it.
	Provenance *ClaimEvidenceProvenance `json:"-" yaml:"provenance,omitempty"`
}

type ExtractedIOC struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context"`
}

type ThreatExtractor struct {
	client llm.Client
}

func NewThreatExtractor(client llm.Client) *ThreatExtractor {
	return &ThreatExtractor{client: client}
}

func (e *ThreatExtractor) Extract(ctx context.Context, item scraper.RawItem) (*ExtractionResult, error) {
	req := extractionRequest(item)

	var result ExtractionResult
	if err := e.client.GenerateJSON(ctx, req.Prompt, req.System, &result); err != nil {
		return nil, fmt.Errorf("extraction LLM call: %w", err)
	}
	return &result, nil
}

func extractionRequest(item scraper.RawItem) llm.Request {
	content := item.Content
	if len(content) > 12000 {
		content = truncateUTF8(content, 12000)
	}
	return llm.Request{Prompt: fmt.Sprintf(extractionPrompt, item.Title, item.Source, content), System: extractionSystemPrompt, JSON: true}
}
