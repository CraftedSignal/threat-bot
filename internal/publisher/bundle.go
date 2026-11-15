package publisher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Bundle types matching the threat-feed compiler format (Sigma-native).

type BundleManifest struct {
	Version     string `json:"version"`
	PublishedAt string `json:"published_at"`
	Checksum    string `json:"checksum"`
	Content     string `json:"content"` // base64 AES-GCM encrypted
}

type BundleContent struct {
	Briefs  []BundleBrief  `json:"briefs"`
	Digests []BundleDigest `json:"digests,omitempty"`
}

// BundleDigest is a daily/weekly roll-up summary included in the bundle.
type BundleDigest struct {
	ID            string `json:"id"`   // e.g. "daily-2026-03-22" or "weekly-2026-03-22"
	Type          string `json:"type"` // "daily_digest" or "weekly_digest"
	Title         string `json:"title"`
	Summary       string `json:"summary"` // Human-readable summary of digest contents
	Content       string `json:"content"` // Markdown
	Period        string `json:"period"`  // e.g. "2026-03-22"
	LookbackHours int    `json:"lookback_hours"`
	TotalBriefs   int    `json:"total_briefs"`
	PublishedAt   string `json:"published_at"` // RFC3339
}

type BundleBrief struct {
	ID              string           `json:"id" yaml:"id"`
	Slug            string           `json:"slug" yaml:"slug"`
	EventID         string           `json:"event_id,omitempty" yaml:"event_id,omitempty"`
	Revision        int              `json:"revision,omitempty" yaml:"revision,omitempty"`
	RevisionHistory []BundleRevision `json:"revision_history,omitempty" yaml:"revision_history,omitempty"`
	Title           string           `json:"title" yaml:"title"`
	Summary         string           `json:"summary" yaml:"summary"`
	Content         string           `json:"content" yaml:"content"`
	Severity        string           `json:"severity" yaml:"severity"`
	ClaimState      string           `json:"claim_state,omitempty" yaml:"claim_state,omitempty"`
	ThreatActor     string           `json:"threat_actor,omitempty" yaml:"threat_actor"`
	PublishedAt     string           `json:"published_at" yaml:"published_at"`
	// Source carries the originating scraper name (e.g. "sigma-hq",
	// "cisa", "nvd"). Pipeline injects it into the brief YAML so the
	// classifier can tell rule-feed-sourced briefs apart from
	// vulnerability writeups that happen to have a synthesized rule.
	// Empty on briefs published before that change shipped.
	Source               string                              `json:"source,omitempty" yaml:"source,omitempty"`
	Tags                 []string                            `json:"tags,omitempty" yaml:"tags"`
	References           []string                            `json:"references,omitempty" yaml:"references"`
	Rules                []BundleRule                        `json:"rules,omitempty" yaml:"rules"`
	IOCs                 []BundleIOC                         `json:"iocs,omitempty" yaml:"iocs"`
	TTPs                 []BundleTTP                         `json:"ttps,omitempty" yaml:"ttps"`
	Priority             string                              `json:"priority,omitempty" yaml:"priority"`
	PriorityScore        int                                 `json:"priority_score,omitempty" yaml:"priority_score"`
	PrioritySignals      []string                            `json:"priority_signals,omitempty" yaml:"priority_signals"`
	CVEVerification      map[string]pipeline.CVEVerification `json:"cve_verification,omitempty" yaml:"cve_verification,omitempty"`
	CVEs                 []BundleCVE                         `json:"cves,omitempty" yaml:"cves"`
	ExploitationEvidence *BundleExploitationEvidence         `json:"exploitation_evidence,omitempty" yaml:"exploitation_evidence,omitempty"`

	SourceAssessment *BundleSourceAssessment `json:"source_assessment,omitempty" yaml:"source_assessment,omitempty"`
	QAStatus         *BundleQAStatus         `json:"qa_status,omitempty" yaml:"qa_status,omitempty"`
	ActionPlan       *BundleActionPlan       `json:"action_plan,omitempty" yaml:"action_plan,omitempty"`

	AffectedVendors  []string `json:"affected_vendors,omitempty" yaml:"affected_vendors,omitempty"`
	AffectedProducts []string `json:"affected_products,omitempty" yaml:"affected_products,omitempty"`
	AffectedOS       []string `json:"affected_os,omitempty" yaml:"affected_os,omitempty"`

	// CPEs is the deduplicated list of vulnerable CPE URIs across all CVEs,
	// sourced from NVD configurations or a conservative vendor/product fallback.
	CPEs []string `json:"cpes,omitempty" yaml:"cpes,omitempty"`

	// HasPOC is set when a public proof-of-concept or exploit has been
	// published for one of this brief's CVEs (e.g. via ExploitDB or Sploitus).
	HasPOC        bool     `json:"has_poc,omitempty" yaml:"has_poc,omitempty"`
	PocReferences []string `json:"poc_references,omitempty" yaml:"poc_references,omitempty"`

	// Lastmod and UpdateLog are populated by the pipeline when a merge
	// enriches the brief with structured data from a later source. Empty
	// for briefs that have only ever had one author.
	Lastmod   string         `json:"lastmod,omitempty" yaml:"lastmod,omitempty"`
	UpdateLog []BundleUpdate `json:"updates,omitempty" yaml:"updates,omitempty"`
}

// BundleRevision records one accepted material state of a published brief.
// The current BundleBrief fields remain the latest snapshot for compatibility;
// encrypted segment history and Git retain the full prior payloads.
type BundleRevision struct {
	Revision      int      `json:"revision" yaml:"revision"`
	At            string   `json:"at" yaml:"at"`
	Checksum      string   `json:"checksum" yaml:"checksum"`
	Summary       string   `json:"summary" yaml:"summary"`
	ChangedFields []string `json:"changed_fields,omitempty" yaml:"changed_fields,omitempty"`
	SourceURLs    []string `json:"source_urls,omitempty" yaml:"source_urls,omitempty"`
	// Maintenance marks a storage or identity correction that does not
	// represent new threat intelligence and must not move activity_at.
	Maintenance bool `json:"maintenance,omitempty" yaml:"maintenance,omitempty"`
}

// BundleUpdate mirrors the storage.UpdateEvent shape so the publisher
// can pass through the merge log without importing the storage package.
type BundleUpdate struct {
	At         string   `json:"at" yaml:"at"`
	Level      string   `json:"level" yaml:"level"`
	Summary    string   `json:"summary" yaml:"summary"`
	Sources    []string `json:"sources,omitempty" yaml:"sources,omitempty"`
	SourceURLs []string `json:"source_urls,omitempty" yaml:"source_urls,omitempty"`
}

// BundleCVE holds enrichment data for a CVE referenced in a brief.
// SYNC: keep in sync with pipeline.BundleCVE (duplicate to avoid circular imports).
type BundleCVE struct {
	ID             string  `json:"id" yaml:"id"`
	Product        string  `json:"product,omitempty" yaml:"product,omitempty"`
	EPSS           float64 `json:"epss" yaml:"epss"`
	EPSSPercentile float64 `json:"epss_percentile" yaml:"epss_percentile"`
	CVSS           float64 `json:"cvss" yaml:"cvss"`
	CVSSVector     string  `json:"cvss_vector,omitempty" yaml:"cvss_vector,omitempty"`
	KEV            bool    `json:"kev,omitempty" yaml:"kev"`
	KEVStatus      string  `json:"kev_status,omitempty" yaml:"kev_status,omitempty"`
}

// BundleExploitationEvidence is the public, attributed tri-state for active
// exploitation. Status is confirmed_active, not_observed, or unknown.
type BundleExploitationEvidence struct {
	Status     string `json:"status" yaml:"status"`
	SourceURL  string `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	ObservedAt string `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
	Confidence string `json:"confidence,omitempty" yaml:"confidence,omitempty"`
}

// UnmarshalYAML accepts both the mapping form and a bare CVE ID string —
// the LLM sometimes emits `cves: [CVE-2026-1234]` and update auto-publish
// must not fail on it.
func (c *BundleCVE) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		c.ID = strings.TrimSpace(value.Value)
		return nil
	}
	type plain BundleCVE
	var p plain
	if err := value.Decode(&p); err != nil {
		return err
	}
	*c = BundleCVE(p)
	return nil
}

type BundleRule struct {
	Title       string           `json:"title" yaml:"title"`
	Description string           `json:"description,omitempty" yaml:"description"`
	LogSource   BundleLogSource  `json:"logsource" yaml:"logsource"`
	Detection   map[string]any   `json:"detection" yaml:"detection"`
	Level       string           `json:"level" yaml:"level"`
	Tags        []string         `json:"tags,omitempty" yaml:"tags"`
	Tests       *BundleTestSuite `json:"tests,omitempty" yaml:"tests"`
	Handoff     *BundleHandoff   `json:"handoff,omitempty" yaml:"handoff,omitempty"`
}

type BundleLogSource struct {
	Category string `json:"category,omitempty" yaml:"category"`
	Product  string `json:"product,omitempty" yaml:"product"`
	Service  string `json:"service,omitempty" yaml:"service"`
}

type BundleTestSuite struct {
	Positive []BundleTestCase `json:"positive,omitempty" yaml:"positive"`
	Negative []BundleTestCase `json:"negative,omitempty" yaml:"negative"`
}

type BundleTestCase struct {
	Name string                   `json:"name" yaml:"name"`
	Data []map[string]interface{} `json:"data,omitempty" yaml:"data"`
}

type BundleIOC struct {
	Type       string             `json:"type" yaml:"type"`
	Value      string             `json:"value" yaml:"value"`
	Context    string             `json:"context,omitempty" yaml:"context,omitempty"`
	Confidence float64            `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Handling   *BundleIOCHandling `json:"handling,omitempty" yaml:"handling,omitempty"`
}

type BundleTTP struct {
	TacticID         string  `json:"tactic_id" yaml:"tactic_id"`
	TacticName       string  `json:"tactic_name" yaml:"tactic_name"`
	TechniqueID      string  `json:"technique_id" yaml:"technique_id"`
	TechniqueName    string  `json:"technique_name" yaml:"technique_name"`
	SubtechniqueID   string  `json:"subtechnique_id,omitempty" yaml:"subtechnique_id,omitempty"`
	SubtechniqueName string  `json:"subtechnique_name,omitempty" yaml:"subtechnique_name,omitempty"`
	Evidence         string  `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Confidence       float64 `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	ConfidenceBand   string  `json:"confidence_band,omitempty" yaml:"confidence_band,omitempty"`
}

type BundleSourceAssessment struct {
	Reliability   string             `json:"reliability,omitempty" yaml:"reliability,omitempty"`
	Credibility   string             `json:"credibility,omitempty" yaml:"credibility,omitempty"`
	Rating        string             `json:"rating,omitempty" yaml:"rating,omitempty"`
	Confidence    string             `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Likelihood    string             `json:"likelihood,omitempty" yaml:"likelihood,omitempty"`
	Corroboration string             `json:"corroboration,omitempty" yaml:"corroboration,omitempty"`
	Flags         []BundleSourceFlag `json:"flags,omitempty" yaml:"flags,omitempty"`
	Gaps          []string           `json:"gaps,omitempty" yaml:"gaps,omitempty"`
}

type BundleSourceFlag struct {
	Type   string `json:"type,omitempty" yaml:"type,omitempty"`
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
	Impact string `json:"impact,omitempty" yaml:"impact,omitempty"`
}

type BundleQAStatus struct {
	Verdict            string   `json:"verdict,omitempty" yaml:"verdict,omitempty"`
	UnsupportedClaims  []string `json:"unsupported_claims,omitempty" yaml:"unsupported_claims,omitempty"`
	FormatGaps         []string `json:"format_gaps,omitempty" yaml:"format_gaps,omitempty"`
	TechnicalChecks    []string `json:"technical_checks,omitempty" yaml:"technical_checks,omitempty"`
	ManualVerification []string `json:"manual_verification,omitempty" yaml:"manual_verification,omitempty"`
	ValidationStatus   string   `json:"validation_status,omitempty" yaml:"validation_status,omitempty"`
}

type BundleActionPlan struct {
	Priority         string                   `json:"priority,omitempty" yaml:"priority,omitempty"`
	Owners           []string                 `json:"owners,omitempty" yaml:"owners,omitempty"`
	ImmediateActions []BundleActionItem       `json:"immediate_actions,omitempty" yaml:"immediate_actions,omitempty"`
	EnrichmentNeeded []BundleEnrichmentNeeded `json:"enrichment_needed,omitempty" yaml:"enrichment_needed,omitempty"`
	HuntLeads        []BundleHuntLead         `json:"hunt_leads,omitempty" yaml:"hunt_leads,omitempty"`
	MitigationPlan   []BundleMitigation       `json:"mitigation_plan,omitempty" yaml:"mitigation_plan,omitempty"`
	Gaps             []string                 `json:"gaps,omitempty" yaml:"gaps,omitempty"`
}

type BundleActionItem struct {
	Action   string `json:"action,omitempty" yaml:"action,omitempty"`
	Owner    string `json:"owner,omitempty" yaml:"owner,omitempty"`
	Due      string `json:"due,omitempty" yaml:"due,omitempty"`
	Evidence string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Status   string `json:"status,omitempty" yaml:"status,omitempty"`
}

type BundleEnrichmentNeeded struct {
	Item     string `json:"item,omitempty" yaml:"item,omitempty"`
	Owner    string `json:"owner,omitempty" yaml:"owner,omitempty"`
	Reason   string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

type BundleHuntLead struct {
	Lead        string   `json:"lead,omitempty" yaml:"lead,omitempty"`
	TechniqueID string   `json:"technique_id,omitempty" yaml:"technique_id,omitempty"`
	DataNeeded  []string `json:"data_needed,omitempty" yaml:"data_needed,omitempty"`
	Priority    string   `json:"priority,omitempty" yaml:"priority,omitempty"`
	Confidence  string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Disposition string   `json:"disposition,omitempty" yaml:"disposition,omitempty"`
	Evidence    string   `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

type BundleMitigation struct {
	Priority  string `json:"priority,omitempty" yaml:"priority,omitempty"`
	Action    string `json:"action,omitempty" yaml:"action,omitempty"`
	Owner     string `json:"owner,omitempty" yaml:"owner,omitempty"`
	Addresses string `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	Evidence  string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

type BundleHandoff struct {
	DetectionConfidence string                      `json:"detection_confidence,omitempty" yaml:"detection_confidence,omitempty"`
	RequiredTelemetry   []BundleRequiredTelemetry   `json:"required_telemetry,omitempty" yaml:"required_telemetry,omitempty"`
	Validation          *BundleDetectionValidation  `json:"validation,omitempty" yaml:"validation,omitempty"`
	KnownEvasions       []string                    `json:"known_evasions,omitempty" yaml:"known_evasions,omitempty"`
	Limitations         []string                    `json:"limitations,omitempty" yaml:"limitations,omitempty"`
	Tuning              []BundleFalsePositiveTuning `json:"tuning,omitempty" yaml:"tuning,omitempty"`
	PortabilityNotes    []BundlePortabilityNote     `json:"portability_notes,omitempty" yaml:"portability_notes,omitempty"`
	SuggestedOwner      string                      `json:"suggested_owner,omitempty" yaml:"suggested_owner,omitempty"`
	Gaps                []string                    `json:"gaps,omitempty" yaml:"gaps,omitempty"`
}

type BundleRequiredTelemetry struct {
	LogSource      string   `json:"log_source,omitempty" yaml:"log_source,omitempty"`
	EventOrChannel string   `json:"event_or_channel,omitempty" yaml:"event_or_channel,omitempty"`
	RequiredFields []string `json:"required_fields,omitempty" yaml:"required_fields,omitempty"`
	Availability   string   `json:"availability,omitempty" yaml:"availability,omitempty"`
	Notes          string   `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type BundleDetectionValidation struct {
	Status            string   `json:"status,omitempty" yaml:"status,omitempty"`
	Steps             []string `json:"steps,omitempty" yaml:"steps,omitempty"`
	ExpectedTelemetry string   `json:"expected_telemetry,omitempty" yaml:"expected_telemetry,omitempty"`
	PassCriteria      string   `json:"pass_criteria,omitempty" yaml:"pass_criteria,omitempty"`
	AtomicReference   string   `json:"atomic_reference,omitempty" yaml:"atomic_reference,omitempty"`
}

type BundleFalsePositiveTuning struct {
	Source   string `json:"source,omitempty" yaml:"source,omitempty"`
	Guidance string `json:"guidance,omitempty" yaml:"guidance,omitempty"`
}

type BundlePortabilityNote struct {
	Platform string `json:"platform,omitempty" yaml:"platform,omitempty"`
	Note     string `json:"note,omitempty" yaml:"note,omitempty"`
}

type BundleIOCHandling struct {
	RecommendedAction  string   `json:"recommended_action,omitempty" yaml:"recommended_action,omitempty"`
	Priority           string   `json:"priority,omitempty" yaml:"priority,omitempty"`
	SourceSentence     string   `json:"source_sentence,omitempty" yaml:"source_sentence,omitempty"`
	SourceName         string   `json:"source_name,omitempty" yaml:"source_name,omitempty"`
	SourceURL          string   `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	AssociatedThreats  []string `json:"associated_threats,omitempty" yaml:"associated_threats,omitempty"`
	EnrichmentStatus   string   `json:"enrichment_status,omitempty" yaml:"enrichment_status,omitempty"`
	LogSources         []string `json:"log_sources,omitempty" yaml:"log_sources,omitempty"`
	EnvironmentTags    []string `json:"environment_tags,omitempty" yaml:"environment_tags,omitempty"`
	DetectionNotes     string   `json:"detection_notes,omitempty" yaml:"detection_notes,omitempty"`
	FalsePositiveNotes string   `json:"false_positive_notes,omitempty" yaml:"false_positive_notes,omitempty"`
}

const keySalt = "craftedsignal-threat-feed-v1"

// DeriveKey derives a 32-byte AES key from the public key hex string.
func DeriveKey(publicKeyHex string) ([]byte, error) {
	pubKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding public key hex: %w", err)
	}
	h := sha256.New()
	h.Write(pubKey)
	h.Write([]byte(keySalt))
	return h.Sum(nil), nil
}

// Encrypt encrypts BundleContent into a BundleManifest using AES-256-GCM.
func Encrypt(content *BundleContent, version, publishedAt, publicKeyHex string) (*BundleManifest, error) {
	plaintext, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshalling content: %w", err)
	}
	return encryptRaw(plaintext, version, publishedAt, publicKeyHex)
}

// Decrypt decrypts a BundleManifest back into BundleContent.
func Decrypt(manifest *BundleManifest, publicKeyHex string) (*BundleContent, error) {
	plaintext, err := openManifest(manifest, publicKeyHex)
	if err != nil {
		return nil, err
	}
	var content BundleContent
	if err := json.Unmarshal(plaintext, &content); err != nil {
		return nil, fmt.Errorf("unmarshalling content: %w", err)
	}
	return &content, nil
}

// EncryptDigest encrypts a single BundleDigest into a BundleManifest using AES-256-GCM.
func EncryptDigest(digest *BundleDigest, publishedAt, publicKeyHex string) (*BundleManifest, error) {
	plaintext, err := json.Marshal(digest)
	if err != nil {
		return nil, fmt.Errorf("marshalling digest: %w", err)
	}
	return encryptRaw(plaintext, "1.0", publishedAt, publicKeyHex)
}

// DecryptDigest decrypts a BundleManifest back into a BundleDigest.
func DecryptDigest(manifest *BundleManifest, publicKeyHex string) (*BundleDigest, error) {
	plaintext, err := openManifest(manifest, publicKeyHex)
	if err != nil {
		return nil, err
	}
	var digest BundleDigest
	if err := json.Unmarshal(plaintext, &digest); err != nil {
		return nil, fmt.Errorf("unmarshalling digest: %w", err)
	}
	return &digest, nil
}

// EncryptSegment encrypts SegmentContent into a BundleManifest using AES-256-GCM.
func EncryptSegment(content *SegmentContent, version, publishedAt, publicKeyHex string) (*BundleManifest, error) {
	plaintext, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshalling segment content: %w", err)
	}
	return encryptRaw(plaintext, version, publishedAt, publicKeyHex)
}

// DecryptSegment decrypts a BundleManifest back into SegmentContent.
func DecryptSegment(manifest *BundleManifest, publicKeyHex string) (*SegmentContent, error) {
	sealed, err := base64.StdEncoding.DecodeString(manifest.Content)
	if err != nil {
		return nil, fmt.Errorf("decoding content: %w", err)
	}
	return openSegment(sealed, publicKeyHex)
}

// openSegment decrypts a segment's sealed content (nonce || ciphertext) in
// place and unmarshals it.
func openSegment(sealed []byte, publicKeyHex string) (*SegmentContent, error) {
	plaintext, err := openSealed(sealed, publicKeyHex)
	if err != nil {
		return nil, err
	}
	var content SegmentContent
	if err := json.Unmarshal(plaintext, &content); err != nil {
		return nil, fmt.Errorf("unmarshalling segment content: %w", err)
	}
	return &content, nil
}

// encryptRaw encrypts plaintext with AES-256-GCM into a BundleManifest whose
// content is base64(nonce || ciphertext) and whose checksum is the SHA-256 of
// the plaintext. It seals in place, so plaintext is overwritten.
func encryptRaw(plaintext []byte, version, publishedAt, publicKeyHex string) (*BundleManifest, error) {
	gcm, err := newGCM(publicKeyHex)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	checksum := fmt.Sprintf("%x", sha256.Sum256(plaintext))
	ciphertext := gcm.Seal(plaintext[:0], nonce, plaintext, nil)

	// Encode nonce || ciphertext straight into the string's buffer instead of
	// encoding to bytes and copying those into a string.
	var content strings.Builder
	content.Grow(base64.StdEncoding.EncodedLen(len(nonce) + len(ciphertext)))
	enc := base64.NewEncoder(base64.StdEncoding, &content)
	if _, err := enc.Write(nonce); err != nil {
		return nil, fmt.Errorf("encoding nonce: %w", err)
	}
	if _, err := enc.Write(ciphertext); err != nil {
		return nil, fmt.Errorf("encoding ciphertext: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("finishing bundle encoding: %w", err)
	}

	return &BundleManifest{
		Version:     version,
		PublishedAt: publishedAt,
		Checksum:    checksum,
		Content:     content.String(),
	}, nil
}

// openManifest decodes and decrypts a BundleManifest's content.
func openManifest(manifest *BundleManifest, publicKeyHex string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(manifest.Content)
	if err != nil {
		return nil, fmt.Errorf("decoding content: %w", err)
	}
	return openSealed(sealed, publicKeyHex)
}

// openSealed decrypts sealed (nonce || ciphertext) in place: the returned
// plaintext reuses sealed's memory.
func openSealed(sealed []byte, publicKeyHex string) ([]byte, error) {
	gcm, err := newGCM(publicKeyHex)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	plaintext, err := gcm.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return plaintext, nil
}

// newGCM returns the AES-256-GCM cipher keyed from publicKeyHex.
func newGCM(publicKeyHex string) (cipher.AEAD, error) {
	key, err := DeriveKey(publicKeyHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	return gcm, nil
}

// ParseBriefYAML parses a brief YAML string into a BundleBrief.
func ParseBriefYAML(yamlStr string) (*BundleBrief, error) {
	var brief BundleBrief
	if err := yaml.Unmarshal([]byte(yamlStr), &brief); err != nil {
		return nil, fmt.Errorf("parsing brief YAML: %w", err)
	}
	if brief.ID == "" {
		return nil, fmt.Errorf("brief missing required field: id")
	}
	// Every published brief passes through here, including merged drafts that
	// never re-run the validator, so list hygiene is enforced here too.
	brief.AffectedVendors = pipeline.CleanAffectedList(brief.AffectedVendors)
	brief.AffectedProducts = pipeline.CleanProductList(brief.AffectedProducts)
	brief.AffectedOS = pipeline.CleanAffectedList(brief.AffectedOS)
	brief.CPEs = pipeline.CleanCPEList(brief.CPEs)
	return &brief, nil
}

// NormalizePublicationMetadata upgrades a legacy current-snapshot brief in
// memory without changing its public URL or consumer-visible content.
func NormalizePublicationMetadata(brief BundleBrief) BundleBrief {
	if strings.TrimSpace(brief.EventID) == "" {
		brief.EventID = brief.ID
	}
	if brief.Revision < 1 {
		brief.Revision = 1
	}
	return brief
}

// MergeBriefs merges new current snapshots into an append-only publication
// history. Existing order is preserved and new IDs are appended.
func MergeBriefs(existing, incoming []BundleBrief, revisedAt time.Time) ([]BundleBrief, error) {
	byID := make(map[string]BundleBrief, len(existing))
	eventIDs := make(map[string]string, len(existing))
	slugs := make(map[string]string, len(existing))
	order := make([]string, 0, len(existing))

	register := func(b BundleBrief) error {
		if strings.TrimSpace(b.ID) == "" {
			return fmt.Errorf("brief missing immutable id")
		}
		if other, ok := eventIDs[b.EventID]; ok && other != b.ID {
			return fmt.Errorf("event_id %q already belongs to brief %q", b.EventID, other)
		}
		if b.Slug != "" {
			key := strings.ToLower(b.Slug)
			if other, ok := slugs[key]; ok && other != b.ID {
				return fmt.Errorf("slug %q already belongs to brief %q", b.Slug, other)
			}
			slugs[key] = b.ID
		}
		eventIDs[b.EventID] = b.ID
		return nil
	}

	for _, raw := range existing {
		b := NormalizePublicationMetadata(raw)
		if err := validateRevisionMetadata(b); err != nil {
			return nil, err
		}
		if _, duplicate := byID[b.ID]; duplicate {
			return nil, fmt.Errorf("duplicate existing brief id %q", b.ID)
		}
		if err := register(b); err != nil {
			return nil, err
		}
		order = append(order, b.ID)
		byID[b.ID] = b
	}

	for _, raw := range incoming {
		candidate := NormalizePublicationMetadata(raw)
		current, exists := byID[candidate.ID]
		if !exists {
			candidate.Revision = 1
			candidate.RevisionHistory = nil
			if err := register(candidate); err != nil {
				// The collision is the candidate's alone: published data is
				// intact, so the caller may drop this brief and carry on.
				return nil, &RevisionRejectedError{BriefID: raw.ID, Err: err}
			}
			order = append(order, candidate.ID)
			byID[candidate.ID] = candidate
			continue
		}

		if candidate.Slug != current.Slug {
			return nil, revisionRejected(current.ID, "brief %q changed immutable slug from %q to %q", current.ID, current.Slug, candidate.Slug)
		}
		if candidate.EventID != current.EventID {
			return nil, revisionRejected(current.ID, "brief %q changed immutable event_id from %q to %q", current.ID, current.EventID, candidate.EventID)
		}
		if !sameTimestamp(candidate.PublishedAt, current.PublishedAt) {
			return nil, revisionRejected(current.ID, "brief %q changed immutable published_at from %q to %q", current.ID, current.PublishedAt, candidate.PublishedAt)
		}
		if disjointCVEs(current.CVEs, candidate.CVEs) {
			return nil, revisionRejected(current.ID, "brief %q replaced its structured CVE set with a disjoint event", current.ID)
		}

		candidate.EventID = current.EventID
		candidate.Revision = current.Revision
		candidate.RevisionHistory = append([]BundleRevision(nil), current.RevisionHistory...)
		oldState, err := publicationStateJSON(current)
		if err != nil {
			return nil, fmt.Errorf("hashing existing brief %q: %w", current.ID, err)
		}
		newState, err := publicationStateJSON(candidate)
		if err != nil {
			return nil, fmt.Errorf("hashing incoming brief %q: %w", current.ID, err)
		}
		if string(oldState) == string(newState) {
			continue
		}

		candidate.Revision = current.Revision + 1
		checksum := sha256.Sum256(newState)
		revisionAt := revisedAt.UTC().Truncate(time.Second)
		publishedAt, err := time.Parse(time.RFC3339Nano, current.PublishedAt)
		if err != nil {
			return nil, fmt.Errorf("brief %q has invalid publication timestamp: %w", current.ID, err)
		}
		if !revisionAt.After(publishedAt) {
			revisionAt = publishedAt.UTC().Truncate(time.Second).Add(time.Second)
		}
		if n := len(candidate.RevisionHistory); n > 0 {
			previous, err := time.Parse(time.RFC3339Nano, candidate.RevisionHistory[n-1].At)
			if err != nil {
				return nil, fmt.Errorf("brief %q has invalid latest revision timestamp: %w", current.ID, err)
			}
			if !revisionAt.After(previous) {
				revisionAt = previous.UTC().Truncate(time.Second).Add(time.Second)
			}
		}
		candidate.RevisionHistory = append(candidate.RevisionHistory, BundleRevision{
			Revision:      candidate.Revision,
			At:            revisionAt.Format(time.RFC3339),
			Checksum:      "sha256:" + hex.EncodeToString(checksum[:]),
			Summary:       revisionSummary(candidate, changedPublicationFields(oldState, newState)),
			ChangedFields: changedPublicationFields(oldState, newState),
			SourceURLs:    revisionSourceURLs(candidate),
		})
		byID[candidate.ID] = candidate
	}

	merged := make([]BundleBrief, 0, len(order))
	for _, id := range order {
		merged = append(merged, byID[id])
	}
	return merged, nil
}

func validateRevisionMetadata(brief BundleBrief) error {
	if brief.Revision < 1 {
		return fmt.Errorf("brief %q has invalid revision %d", brief.ID, brief.Revision)
	}
	if len(brief.RevisionHistory) != brief.Revision-1 {
		return fmt.Errorf("brief %q revision %d has %d history entries", brief.ID, brief.Revision, len(brief.RevisionHistory))
	}
	for i, revision := range brief.RevisionHistory {
		want := i + 2
		if revision.Revision != want {
			return fmt.Errorf("brief %q revision history entry %d has revision %d, want %d", brief.ID, i, revision.Revision, want)
		}
		if _, err := time.Parse(time.RFC3339Nano, revision.At); err != nil {
			return fmt.Errorf("brief %q revision %d has invalid timestamp: %w", brief.ID, revision.Revision, err)
		}
		digest := strings.TrimPrefix(revision.Checksum, "sha256:")
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || !strings.HasPrefix(revision.Checksum, "sha256:") {
			return fmt.Errorf("brief %q revision %d has invalid checksum", brief.ID, revision.Revision)
		}
	}
	return nil
}

func sameTimestamp(a, b string) bool {
	if a == b {
		return true
	}
	at, aErr := time.Parse(time.RFC3339Nano, a)
	bt, bErr := time.Parse(time.RFC3339Nano, b)
	return aErr == nil && bErr == nil && at.Equal(bt)
}

func disjointCVEs(a, b []BundleCVE) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, cve := range a {
		if id := strings.ToUpper(strings.TrimSpace(cve.ID)); id != "" {
			seen[id] = struct{}{}
		}
	}
	for _, cve := range b {
		if _, ok := seen[strings.ToUpper(strings.TrimSpace(cve.ID))]; ok {
			return false
		}
	}
	return len(seen) > 0
}

func publicationStateJSON(brief BundleBrief) ([]byte, error) {
	brief.EventID = ""
	brief.Revision = 0
	brief.RevisionHistory = nil
	return json.Marshal(brief)
}

func changedPublicationFields(oldState, newState []byte) []string {
	var oldFields, newFields map[string]json.RawMessage
	if json.Unmarshal(oldState, &oldFields) != nil || json.Unmarshal(newState, &newFields) != nil {
		return nil
	}
	keys := make(map[string]struct{}, len(oldFields))
	for key := range oldFields {
		keys[key] = struct{}{}
	}
	for key := range newFields {
		keys[key] = struct{}{}
	}
	changed := make([]string, 0, len(keys))
	for key := range keys {
		if !reflect.DeepEqual(oldFields[key], newFields[key]) {
			changed = append(changed, key)
		}
	}
	sort.Strings(changed)
	return changed
}

func revisionSummary(brief BundleBrief, fields []string) string {
	if n := len(brief.UpdateLog); n > 0 && strings.TrimSpace(brief.UpdateLog[n-1].Summary) != "" {
		return strings.TrimSpace(brief.UpdateLog[n-1].Summary)
	}
	if len(fields) == 0 {
		return "Material revision"
	}
	return "Updated " + strings.Join(fields, ", ")
}

func revisionSourceURLs(brief BundleBrief) []string {
	if n := len(brief.UpdateLog); n > 0 {
		urls := append([]string(nil), brief.UpdateLog[n-1].SourceURLs...)
		sort.Strings(urls)
		return slicesCompact(urls)
	}
	return nil
}

func slicesCompact(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	for _, value := range values {
		if value == "" || (len(out) > 0 && out[len(out)-1] == value) {
			continue
		}
		out = append(out, value)
	}
	return out
}

// mergeDigests merges incoming digests into existing ones, deduplicating by ID.
func mergeDigests(existing, incoming []BundleDigest) []BundleDigest {
	byID := make(map[string]BundleDigest, len(existing)+len(incoming))
	order := make([]string, 0, len(existing)+len(incoming))
	for _, d := range existing {
		if _, seen := byID[d.ID]; !seen {
			order = append(order, d.ID)
		}
		byID[d.ID] = d
	}
	for _, d := range incoming {
		if _, seen := byID[d.ID]; !seen {
			order = append(order, d.ID)
		}
		byID[d.ID] = d
	}
	merged := make([]BundleDigest, 0, len(order))
	for _, id := range order {
		merged = append(merged, byID[id])
	}
	return merged
}

// bundleVersion returns the current bundle format version.
func bundleVersion() string { return "1.0" }

// bundleTimestamp returns the current time formatted for the bundle.
func bundleTimestamp() string { return time.Now().UTC().Format(time.RFC3339) }

// RevisionRejectedError reports that one incoming brief snapshot violates the
// append-only revision rules against its published version. It concerns only
// that candidate: the published data and every other brief remain valid, so
// callers may exclude BriefID and continue. Error() is the wrapped message.
type RevisionRejectedError struct {
	BriefID string
	Err     error
}

func (e *RevisionRejectedError) Error() string { return e.Err.Error() }
func (e *RevisionRejectedError) Unwrap() error { return e.Err }

func revisionRejected(briefID, format string, args ...any) error {
	return &RevisionRejectedError{BriefID: briefID, Err: fmt.Errorf(format, args...)}
}
