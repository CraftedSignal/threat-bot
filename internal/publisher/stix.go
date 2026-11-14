package publisher

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/mitre"
)

// Fixed UUID v5 namespace for deterministic STIX ID generation.
var stixNamespace = [16]byte{
	0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
}

const sharedSTIXTimestamp = "2025-01-01T00:00:00.000Z"

var producerIdentityID = stixID("identity", "craftedsignal")

var htmlTagOpenRe = regexp.MustCompile(`<(/?[a-zA-Z!])`)
var stixTimestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

func defangHTML(s string) string {
	return htmlTagOpenRe.ReplaceAllString(s, "&lt;$1")
}

type stixBundle struct {
	Type    string            `json:"type"`
	ID      string            `json:"id"`
	Objects []json.RawMessage `json:"objects"`
}

type stixIdentity struct {
	Type          string `json:"type"`
	SpecVersion   string `json:"spec_version"`
	ID            string `json:"id"`
	Created       string `json:"created"`
	Modified      string `json:"modified"`
	Name          string `json:"name"`
	IdentityClass string `json:"identity_class"`
}

type stixReport struct {
	Type            string                      `json:"type"`
	SpecVersion     string                      `json:"spec_version"`
	ID              string                      `json:"id"`
	CreatedByRef    string                      `json:"created_by_ref"`
	Created         string                      `json:"created"`
	Modified        string                      `json:"modified"`
	Name            string                      `json:"name"`
	Description     string                      `json:"description,omitempty"`
	Published       string                      `json:"published"`
	Labels          []string                    `json:"labels,omitempty"`
	ObjectRefs      []string                    `json:"object_refs"`
	ExternalRefs    []stixExternalRef           `json:"external_references"`
	Confidence      int                         `json:"confidence,omitempty"`
	BriefID         string                      `json:"x_craftedsignal_brief_id"`
	EventID         string                      `json:"x_craftedsignal_event_id"`
	Revision        int                         `json:"x_craftedsignal_revision"`
	CanonicalURL    string                      `json:"x_craftedsignal_canonical_url"`
	ActivityAt      string                      `json:"x_craftedsignal_activity_at"`
	Severity        string                      `json:"x_craftedsignal_severity"`
	BriefType       string                      `json:"x_craftedsignal_type"`
	ExploitEvidence *BundleExploitationEvidence `json:"x_craftedsignal_exploitation_evidence"`
	CVSSMax         *float64                    `json:"x_craftedsignal_cvss_max,omitempty"`
	EPSSMax         *float64                    `json:"x_craftedsignal_epss_max,omitempty"`
	KEVStatus       string                      `json:"x_craftedsignal_kev_status"`
}

type stixIndicator struct {
	Type         string   `json:"type"`
	SpecVersion  string   `json:"spec_version"`
	ID           string   `json:"id"`
	CreatedByRef string   `json:"created_by_ref"`
	Created      string   `json:"created"`
	Modified     string   `json:"modified"`
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Pattern      string   `json:"pattern"`
	PatternType  string   `json:"pattern_type"`
	ValidFrom    string   `json:"valid_from"`
	Labels       []string `json:"labels,omitempty"`
}

type stixAttackPattern struct {
	Type         string            `json:"type"`
	SpecVersion  string            `json:"spec_version"`
	ID           string            `json:"id"`
	CreatedByRef string            `json:"created_by_ref"`
	Created      string            `json:"created"`
	Modified     string            `json:"modified"`
	Name         string            `json:"name"`
	ExternalRefs []stixExternalRef `json:"external_references"`
}

type stixThreatActor struct {
	Type         string   `json:"type"`
	SpecVersion  string   `json:"spec_version"`
	ID           string   `json:"id"`
	CreatedByRef string   `json:"created_by_ref"`
	Created      string   `json:"created"`
	Modified     string   `json:"modified"`
	Name         string   `json:"name"`
	Labels       []string `json:"labels,omitempty"`
}

type stixSoftware struct {
	Type        string `json:"type"`
	SpecVersion string `json:"spec_version"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Vendor      string `json:"vendor,omitempty"`
}

type stixVulnerability struct {
	Type         string            `json:"type"`
	SpecVersion  string            `json:"spec_version"`
	ID           string            `json:"id"`
	CreatedByRef string            `json:"created_by_ref"`
	Created      string            `json:"created"`
	Modified     string            `json:"modified"`
	Name         string            `json:"name"`
	ExternalRefs []stixExternalRef `json:"external_references"`
}

type stixRelationship struct {
	Type             string `json:"type"`
	SpecVersion      string `json:"spec_version"`
	ID               string `json:"id"`
	CreatedByRef     string `json:"created_by_ref"`
	Created          string `json:"created"`
	Modified         string `json:"modified"`
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
}

type stixExternalRef struct {
	SourceName  string `json:"source_name"`
	ExternalID  string `json:"external_id,omitempty"`
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

func uuidV5(name string) string {
	h := sha1.New()
	h.Write(stixNamespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func stixID(stype, seed string) string {
	return stype + "--" + uuidV5(stype+":"+seed)
}

func iocPattern(iocType, value string) string {
	switch iocType {
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", escapePattern(value))
	case "ip":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", escapePattern(value))
	case "hash_sha256":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", escapePattern(value))
	case "hash_md5":
		return fmt.Sprintf("[file:hashes.MD5 = '%s']", escapePattern(value))
	case "url":
		return fmt.Sprintf("[url:value = '%s']", escapePattern(value))
	case "email":
		return fmt.Sprintf("[email-addr:value = '%s']", escapePattern(value))
	default:
		return fmt.Sprintf("[x-craftedsignal-indicator:value = '%s']", escapePattern(value))
	}
}

func escapePattern(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	return strings.ReplaceAll(v, "'", "\\'")
}

func severityConfidence(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 60
	case "low":
		return 40
	default:
		return 0
	}
}

func mitreURL(techniqueID string) string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(techniqueID, ".", "/")
}

type stixRegistry struct {
	byID map[string]json.RawMessage
}

func newSTIXRegistry() *stixRegistry {
	return &stixRegistry{byID: make(map[string]json.RawMessage)}
}

func (r *stixRegistry) add(object interface{}) error {
	raw, err := json.Marshal(object)
	if err != nil {
		return fmt.Errorf("marshalling STIX object: %w", err)
	}
	var header struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return fmt.Errorf("reading STIX object header: %w", err)
	}
	if header.Type == "" || header.ID == "" {
		return fmt.Errorf("STIX object missing type or id")
	}
	if existing, ok := r.byID[header.ID]; ok {
		if !bytes.Equal(existing, raw) {
			return fmt.Errorf("conflicting STIX objects reuse id %q", header.ID)
		}
		return nil
	}
	r.byID[header.ID] = append(json.RawMessage(nil), raw...)
	return nil
}

func (r *stixRegistry) sortedObjects() []json.RawMessage {
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	objects := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		objects = append(objects, r.byID[id])
	}
	return objects
}

func normalizeSTIXTimestamp(raw string) (string, time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return "", time.Time{}, fmt.Errorf("missing timestamp")
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid timestamp %q: %w", raw, err)
	}
	return parsed.UTC().Format("2006-01-02T15:04:05.000Z"), parsed.UTC(), nil
}

func reportTimes(brief BundleBrief) (created, modified string, err error) {
	created, createdAt, err := normalizeSTIXTimestamp(brief.PublishedAt)
	if err != nil {
		return "", "", fmt.Errorf("brief %q published_at: %w", brief.ID, err)
	}
	modified, modifiedAt := created, createdAt
	consider := func(label, raw string) error {
		if raw == "" {
			return nil
		}
		value, parsed, parseErr := normalizeSTIXTimestamp(raw)
		if parseErr != nil {
			return fmt.Errorf("brief %q %s: %w", brief.ID, label, parseErr)
		}
		if parsed.Before(createdAt) {
			return fmt.Errorf("brief %q %s precedes published_at", brief.ID, label)
		}
		if parsed.After(modifiedAt) {
			modified, modifiedAt = value, parsed
		}
		return nil
	}
	if err := consider("lastmod", brief.Lastmod); err != nil {
		return "", "", err
	}
	for _, revision := range brief.RevisionHistory {
		if err := consider(fmt.Sprintf("revision %d", revision.Revision), revision.At); err != nil {
			return "", "", err
		}
	}
	return created, modified, nil
}

func canonicalBriefURL(brief BundleBrief, siteURL string) string {
	slug := strings.Trim(strings.ToLower(firstNonEmpty(brief.Slug, brief.ID)), "/")
	return strings.TrimRight(siteURL, "/") + "/briefs/" + slug + "/"
}

func stableStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validSTIXURI(value string) bool {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(value))
	return err == nil && parsed.Scheme != ""
}

func aggregateRisk(brief BundleBrief) (maxCVSS, maxEPSS *float64, kevStatus string) {
	kevStatus = "unknown"
	knownFalse := false
	unknown := false
	for _, cve := range brief.CVEs {
		if cve.CVSS > 0 || strings.TrimSpace(cve.CVSSVector) != "" {
			if maxCVSS == nil || cve.CVSS > *maxCVSS {
				value := cve.CVSS
				maxCVSS = &value
			}
		}
		if cve.EPSS > 0 || cve.EPSSPercentile > 0 {
			if maxEPSS == nil || cve.EPSS > *maxEPSS {
				value := cve.EPSS
				maxEPSS = &value
			}
		}
		if cve.KEV || cve.KEVStatus == "true" {
			kevStatus = "true"
		} else if cve.KEVStatus == "false" {
			knownFalse = true
		} else {
			unknown = true
		}
	}
	if kevStatus != "true" && knownFalse && !unknown {
		kevStatus = "false"
	}
	return maxCVSS, maxEPSS, kevStatus
}

func canonicalEvidence(brief BundleBrief) (*BundleExploitationEvidence, error) {
	evidence := publicExploitationEvidence(brief)
	copy := *evidence
	copy.Status = strings.ToLower(strings.TrimSpace(copy.Status))
	copy.Confidence = strings.ToLower(strings.TrimSpace(copy.Confidence))
	switch copy.Confidence {
	case "", "low", "medium", "high":
	default:
		if copy.Status == "confirmed_active" {
			return nil, fmt.Errorf("brief %q exploitation confidence %q is invalid", brief.ID, copy.Confidence)
		}
		copy.Confidence = ""
	}
	if copy.ObservedAt != "" {
		normalized, _, err := normalizeSTIXTimestamp(copy.ObservedAt)
		if err != nil {
			return nil, fmt.Errorf("brief %q exploitation observed_at: %w", brief.ID, err)
		}
		copy.ObservedAt = normalized
	}
	return &copy, nil
}

func relationship(idSeed, relationshipType, sourceRef, targetRef, created, modified string) stixRelationship {
	return stixRelationship{
		Type: "relationship", SpecVersion: "2.1", ID: stixID("relationship", idSeed),
		CreatedByRef: producerIdentityID, Created: created, Modified: modified,
		RelationshipType: relationshipType, SourceRef: sourceRef, TargetRef: targetRef,
	}
}

// ExportSTIX converts canonical brief snapshots into deterministic STIX 2.1.
func ExportSTIX(input []BundleBrief, siteURLs ...string) ([]byte, error) {
	siteURL := "https://example.invalid"
	if len(siteURLs) > 0 && siteURLs[0] != "" {
		siteURL = siteURLs[0]
	}
	briefs := make([]BundleBrief, len(input))
	for i, brief := range input {
		briefs[i] = NormalizePublicationMetadata(brief)
	}
	sort.Slice(briefs, func(i, j int) bool { return briefs[i].ID < briefs[j].ID })
	for i := range briefs {
		if briefs[i].ID == "" {
			return nil, fmt.Errorf("STIX brief missing id")
		}
		if i > 0 && briefs[i-1].ID == briefs[i].ID {
			return nil, fmt.Errorf("duplicate canonical brief id %q", briefs[i].ID)
		}
	}

	registry := newSTIXRegistry()
	if err := registry.add(stixIdentity{
		Type: "identity", SpecVersion: "2.1", ID: producerIdentityID,
		Created: sharedSTIXTimestamp, Modified: sharedSTIXTimestamp,
		Name: "CraftedSignal", IdentityClass: "organization",
	}); err != nil {
		return nil, err
	}
	seenSoftware := make(map[string]struct{})

	for _, brief := range briefs {
		created, modified, err := reportTimes(brief)
		if err != nil {
			return nil, err
		}
		reportID := stixID("report", brief.ID)
		objectRefs := []string{producerIdentityID}

		for _, ioc := range brief.IOCs {
			if strings.TrimSpace(ioc.Type) == "" || strings.TrimSpace(ioc.Value) == "" {
				continue
			}
			indicatorID := stixID("indicator", brief.ID+":"+ioc.Type+":"+ioc.Value)
			if err := registry.add(stixIndicator{
				Type: "indicator", SpecVersion: "2.1", ID: indicatorID, CreatedByRef: producerIdentityID,
				Created: created, Modified: modified, ValidFrom: created,
				Name:        defangHTML(fmt.Sprintf("%s: %s", ioc.Type, ioc.Value)),
				Description: defangHTML(ioc.Context), Pattern: iocPattern(ioc.Type, ioc.Value), PatternType: "stix",
			}); err != nil {
				return nil, err
			}
			objectRefs = append(objectRefs, indicatorID)
			if err := registry.add(relationship(reportID+":uses:"+indicatorID, "uses", reportID, indicatorID, created, modified)); err != nil {
				return nil, err
			}
		}

		seenTechniques := make(map[string]struct{})
		for _, ttp := range brief.TTPs {
			techniqueID := strings.ToUpper(strings.TrimSpace(firstNonEmpty(ttp.SubtechniqueID, ttp.TechniqueID)))
			if techniqueID == "" {
				continue
			}
			if _, seen := seenTechniques[techniqueID]; seen {
				continue
			}
			seenTechniques[techniqueID] = struct{}{}
			canonicalName := mitre.TechniqueName(techniqueID)
			if canonicalName == "" {
				return nil, fmt.Errorf("brief %q has unknown ATT&CK technique %q", brief.ID, techniqueID)
			}
			attackID := stixID("attack-pattern", techniqueID)
			if err := registry.add(stixAttackPattern{
				Type: "attack-pattern", SpecVersion: "2.1", ID: attackID, CreatedByRef: producerIdentityID,
				Created: sharedSTIXTimestamp, Modified: sharedSTIXTimestamp, Name: canonicalName,
				ExternalRefs: []stixExternalRef{{SourceName: "mitre-attack", ExternalID: techniqueID, URL: mitreURL(techniqueID)}},
			}); err != nil {
				return nil, err
			}
			objectRefs = append(objectRefs, attackID)
			if err := registry.add(relationship(reportID+":uses:"+attackID, "uses", reportID, attackID, created, modified)); err != nil {
				return nil, err
			}
		}

		if actorName := strings.TrimSpace(brief.ThreatActor); actorName != "" {
			actorID := stixID("threat-actor", actorName)
			if err := registry.add(stixThreatActor{
				Type: "threat-actor", SpecVersion: "2.1", ID: actorID, CreatedByRef: producerIdentityID,
				Created: sharedSTIXTimestamp, Modified: sharedSTIXTimestamp, Name: actorName,
			}); err != nil {
				return nil, err
			}
			objectRefs = append(objectRefs, actorID)
			if err := registry.add(relationship(reportID+":attributed-to:"+actorID, "attributed-to", reportID, actorID, created, modified)); err != nil {
				return nil, err
			}
		}

		vendors := make([]string, 0, len(brief.AffectedVendors))
		for _, vendor := range brief.AffectedVendors {
			if !isPlaceholderValue(vendor) {
				vendors = append(vendors, strings.TrimSpace(vendor))
			}
		}
		vendors = stableStrings(vendors)
		vendor := ""
		if len(vendors) == 1 {
			vendor = vendors[0]
		}
		softwareIDs := make([]string, 0, len(brief.AffectedProducts))
		briefSoftwareIDs := make(map[string]struct{})
		for _, product := range stableStrings(brief.AffectedProducts) {
			if isPlaceholderValue(product) {
				continue
			}
			softwareID := stixID("software", strings.ToLower(vendor+":"+product))
			if _, seen := briefSoftwareIDs[softwareID]; seen {
				continue
			}
			briefSoftwareIDs[softwareID] = struct{}{}
			if _, seen := seenSoftware[softwareID]; !seen {
				if err := registry.add(stixSoftware{Type: "software", SpecVersion: "2.1", ID: softwareID, Name: product, Vendor: vendor}); err != nil {
					return nil, err
				}
				seenSoftware[softwareID] = struct{}{}
			}
			softwareIDs = append(softwareIDs, softwareID)
			objectRefs = append(objectRefs, softwareID)
		}

		seenCVEs := make(map[string]struct{})
		for _, cve := range brief.CVEs {
			cveID := strings.ToUpper(strings.TrimSpace(cve.ID))
			if cveID == "" {
				continue
			}
			if _, seen := seenCVEs[cveID]; seen {
				continue
			}
			seenCVEs[cveID] = struct{}{}
			vulnerabilityID := stixID("vulnerability", cveID)
			if err := registry.add(stixVulnerability{
				Type: "vulnerability", SpecVersion: "2.1", ID: vulnerabilityID, CreatedByRef: producerIdentityID,
				Created: sharedSTIXTimestamp, Modified: sharedSTIXTimestamp, Name: cveID,
				ExternalRefs: []stixExternalRef{{SourceName: "cve", ExternalID: cveID, URL: "https://nvd.nist.gov/vuln/detail/" + cveID}},
			}); err != nil {
				return nil, err
			}
			objectRefs = append(objectRefs, vulnerabilityID)
			for _, softwareID := range softwareIDs {
				if err := registry.add(relationship(softwareID+":has:"+vulnerabilityID, "has", softwareID, vulnerabilityID, sharedSTIXTimestamp, sharedSTIXTimestamp)); err != nil {
					return nil, err
				}
			}
		}

		canonicalURL := canonicalBriefURL(brief, siteURL)
		externalRefs := []stixExternalRef{{SourceName: "craftedsignal", ExternalID: brief.ID, URL: canonicalURL}}
		for _, ref := range stableStrings(brief.References) {
			if validSTIXURI(ref) {
				externalRefs = append(externalRefs, stixExternalRef{SourceName: "reference", URL: ref})
			}
		}
		evidence, err := canonicalEvidence(brief)
		if err != nil {
			return nil, err
		}
		maxCVSS, maxEPSS, kevStatus := aggregateRisk(brief)
		objectRefs = stableStrings(objectRefs)
		report := stixReport{
			Type: "report", SpecVersion: "2.1", ID: reportID, CreatedByRef: producerIdentityID,
			Created: created, Modified: modified, Published: created,
			Name: defangHTML(brief.Title), Description: defangHTML(brief.Content), Labels: stableStrings(brief.Tags),
			ObjectRefs: objectRefs, ExternalRefs: externalRefs, Confidence: severityConfidence(brief.Severity),
			BriefID: brief.ID, EventID: brief.EventID, Revision: brief.Revision,
			CanonicalURL: canonicalURL, ActivityAt: modified, Severity: firstNonEmpty(brief.Severity, "medium"),
			BriefType: classifyType(brief), ExploitEvidence: evidence,
			CVSSMax: maxCVSS, EPSSMax: maxEPSS, KEVStatus: kevStatus,
		}
		if err := registry.add(report); err != nil {
			return nil, err
		}
	}

	objects := registry.sortedObjects()
	hash := sha256.New()
	for _, object := range objects {
		hash.Write(object)
	}
	bundle := stixBundle{Type: "bundle", ID: stixID("bundle", hex.EncodeToString(hash.Sum(nil))), Objects: objects}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling STIX bundle: %w", err)
	}
	if err := ValidateSTIX(data, len(briefs)); err != nil {
		return nil, fmt.Errorf("validating generated STIX: %w", err)
	}
	return data, nil
}

// ValidateSTIX checks the structural and parity invariants required before a
// bundle is uploaded to the public feed.
func ValidateSTIX(data []byte, expectedReports int) error {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parsing STIX bundle: %w", err)
	}
	if bundle.Type != "bundle" || !strings.HasPrefix(bundle.ID, "bundle--") {
		return fmt.Errorf("invalid STIX bundle header")
	}

	type header struct {
		Type         string            `json:"type"`
		ID           string            `json:"id"`
		Created      string            `json:"created"`
		Modified     string            `json:"modified"`
		Published    string            `json:"published"`
		ValidFrom    string            `json:"valid_from"`
		ObjectRefs   []string          `json:"object_refs"`
		SourceRef    string            `json:"source_ref"`
		TargetRef    string            `json:"target_ref"`
		BriefID      string            `json:"x_craftedsignal_brief_id"`
		EventID      string            `json:"x_craftedsignal_event_id"`
		CanonicalURL string            `json:"x_craftedsignal_canonical_url"`
		ExternalRefs []stixExternalRef `json:"external_references"`
	}
	headers := make([]header, 0, len(bundle.Objects))
	byID := make(map[string]json.RawMessage, len(bundle.Objects))
	reportCount := 0
	producerFound := false
	for _, raw := range bundle.Objects {
		var object header
		if err := json.Unmarshal(raw, &object); err != nil {
			return fmt.Errorf("parsing STIX object: %w", err)
		}
		var untyped any
		if err := json.Unmarshal(raw, &untyped); err != nil {
			return fmt.Errorf("parsing STIX object properties: %w", err)
		}
		if property, found := firstJSONNull(untyped, ""); found {
			return fmt.Errorf("STIX object %q has forbidden null property %s", object.ID, property)
		}
		if object.Type == "" || object.ID == "" {
			return fmt.Errorf("STIX object missing type or id")
		}
		for i, ref := range object.ExternalRefs {
			if ref.URL != "" && !validSTIXURI(ref.URL) {
				return fmt.Errorf("STIX object %q external_references[%d] has invalid URL %q", object.ID, i, ref.URL)
			}
		}
		if _, duplicate := byID[object.ID]; duplicate {
			return fmt.Errorf("duplicate STIX object id %q", object.ID)
		}
		byID[object.ID] = raw
		headers = append(headers, object)
		if object.ID == producerIdentityID && object.Type == "identity" {
			producerFound = true
		}
		if object.Type == "report" {
			var properties map[string]json.RawMessage
			if err := json.Unmarshal(raw, &properties); err != nil {
				return fmt.Errorf("parsing STIX report properties: %w", err)
			}
			for _, property := range []string{"x_craftedsignal_cvss_max", "x_craftedsignal_epss_max"} {
				value, present := properties[property]
				if !present {
					continue
				}
				var number float64
				if err := json.Unmarshal(value, &number); err != nil {
					return fmt.Errorf("STIX report %q has non-numeric %s", object.ID, property)
				}
			}
			reportCount++
			if len(object.ObjectRefs) == 0 {
				return fmt.Errorf("report %q has empty object_refs", object.ID)
			}
			if object.BriefID == "" || object.EventID == "" || object.CanonicalURL == "" {
				return fmt.Errorf("report %q missing CraftedSignal identity fields", object.ID)
			}
		}
		for field, value := range map[string]string{
			"created": object.Created, "modified": object.Modified,
			"published": object.Published, "valid_from": object.ValidFrom,
		} {
			if value == "" {
				continue
			}
			if !stixTimestampRe.MatchString(value) {
				return fmt.Errorf("object %q has non-millisecond %s %q", object.ID, field, value)
			}
			if _, err := time.Parse("2006-01-02T15:04:05.000Z", value); err != nil {
				return fmt.Errorf("object %q has invalid %s: %w", object.ID, field, err)
			}
		}
		if stixRequiresCreatedModified(object.Type) && (object.Created == "" || object.Modified == "") {
			return fmt.Errorf("object %q missing created or modified", object.ID)
		}
	}
	if !producerFound {
		return fmt.Errorf("bundle missing CraftedSignal producer identity")
	}
	if reportCount != expectedReports {
		return fmt.Errorf("report parity mismatch: got %d, want %d", reportCount, expectedReports)
	}
	for _, object := range headers {
		for _, ref := range object.ObjectRefs {
			if _, ok := byID[ref]; !ok {
				return fmt.Errorf("object %q references missing object %q", object.ID, ref)
			}
		}
		for _, ref := range []string{object.SourceRef, object.TargetRef} {
			if ref != "" {
				if _, ok := byID[ref]; !ok {
					return fmt.Errorf("relationship %q references missing object %q", object.ID, ref)
				}
			}
		}
	}
	return nil
}

func firstJSONNull(value any, path string) (string, bool) {
	switch typed := value.(type) {
	case nil:
		return path, true
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := key
			if path != "" {
				child = path + "." + key
			}
			if foundAt, found := firstJSONNull(typed[key], child); found {
				return foundAt, true
			}
		}
	case []any:
		for i, item := range typed {
			if foundAt, found := firstJSONNull(item, fmt.Sprintf("%s[%d]", path, i)); found {
				return foundAt, true
			}
		}
	}
	return "", false
}

func stixRequiresCreatedModified(objectType string) bool {
	switch objectType {
	case "attack-pattern", "campaign", "course-of-action", "grouping", "identity", "incident",
		"indicator", "infrastructure", "intrusion-set", "location", "malware", "malware-analysis",
		"note", "opinion", "report", "threat-actor", "tool", "vulnerability",
		"relationship", "sighting":
		return true
	default:
		return false
	}
}
