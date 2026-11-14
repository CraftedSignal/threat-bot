package publisher

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExportSTIX_Basic(t *testing.T) {
	briefs := []BundleBrief{
		{
			ID:          "brief-001",
			Slug:        "test-brief",
			Title:       "Test Threat Brief",
			Summary:     "A test summary",
			Content:     "Detailed content about the threat.",
			Severity:    "high",
			ThreatActor: "APT29",
			PublishedAt: "2025-01-15T12:00:00Z",
			Tags:        []string{"malware", "apt"},
			References:  []string{"https://example.com/report"},
			IOCs: []BundleIOC{
				{Type: "domain", Value: "evil.example.com"},
				{Type: "ip", Value: "192.168.1.1"},
				{Type: "hash_sha256", Value: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
				{Type: "hash_md5", Value: "d41d8cd98f00b204e9800998ecf8427e"},
				{Type: "url", Value: "https://evil.example.com/payload"},
				{Type: "email", Value: "attacker@evil.example.com"},
			},
			TTPs: []BundleTTP{
				{TacticID: "TA0001", TacticName: "Initial Access", TechniqueID: "T1566", TechniqueName: "Phishing"},
				{TacticID: "TA0002", TacticName: "Execution", TechniqueID: "T1059.001", TechniqueName: "PowerShell"},
			},
		},
	}

	data, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatalf("ExportSTIX failed: %v", err)
	}

	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check bundle fields.
	if bundle["type"] != "bundle" {
		t.Errorf("expected bundle type, got %v", bundle["type"])
	}
	if !strings.HasPrefix(bundle["id"].(string), "bundle--") {
		t.Errorf("expected bundle-- prefix, got %v", bundle["id"])
	}

	objects := bundle["objects"].([]interface{})

	// Count object types.
	counts := make(map[string]int)
	for _, obj := range objects {
		m := obj.(map[string]interface{})
		counts[m["type"].(string)]++

		// Verify spec_version on SDOs.
		if sv, ok := m["spec_version"]; ok {
			if sv != "2.1" {
				t.Errorf("expected spec_version 2.1, got %v on %v", sv, m["id"])
			}
		}
	}

	// 6 IOCs → 6 indicators, 6 relationships (report→indicator)
	// 2 TTPs → 2 attack-patterns, 2 relationships (report→attack-pattern)
	// 1 threat-actor, 1 relationship (report→threat-actor)
	// 1 report
	if counts["indicator"] != 6 {
		t.Errorf("expected 6 indicators, got %d", counts["indicator"])
	}
	if counts["attack-pattern"] != 2 {
		t.Errorf("expected 2 attack-patterns, got %d", counts["attack-pattern"])
	}
	if counts["threat-actor"] != 1 {
		t.Errorf("expected 1 threat-actor, got %d", counts["threat-actor"])
	}
	if counts["report"] != 1 {
		t.Errorf("expected 1 report, got %d", counts["report"])
	}
	if counts["relationship"] != 9 {
		t.Errorf("expected 9 relationships, got %d", counts["relationship"])
	}
}

func TestCanonicalEvidenceDropsInvalidNonActiveConfidence(t *testing.T) {
	evidence, err := canonicalEvidence(BundleBrief{
		ID: "brief-invalid-non-active-confidence",
		ExploitationEvidence: &BundleExploitationEvidence{
			Status:     "not_observed",
			Confidence: "0",
		},
	})
	if err != nil {
		t.Fatalf("canonicalEvidence: %v", err)
	}
	if evidence.Confidence != "" {
		t.Fatalf("confidence = %q, want empty", evidence.Confidence)
	}
}

func TestExportSTIX_Deterministic(t *testing.T) {
	briefs := []BundleBrief{
		{
			ID:          "brief-det",
			Title:       "Determinism Test",
			PublishedAt: "2025-06-01T00:00:00Z",
			IOCs:        []BundleIOC{{Type: "domain", Value: "test.example.com"}},
		},
	}

	data1, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatal(err)
	}
	data2, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data1, data2) {
		t.Fatalf("frozen input produced different bytes:\n%s\n---\n%s", data1, data2)
	}

	// Parse both and compare object IDs too for a focused diagnostic.
	var b1, b2 map[string]interface{}
	json.Unmarshal(data1, &b1)
	json.Unmarshal(data2, &b2)

	objs1 := b1["objects"].([]interface{})
	objs2 := b2["objects"].([]interface{})

	if len(objs1) != len(objs2) {
		t.Fatalf("different object counts: %d vs %d", len(objs1), len(objs2))
	}

	for i := range objs1 {
		id1 := objs1[i].(map[string]interface{})["id"].(string)
		id2 := objs2[i].(map[string]interface{})["id"].(string)
		if id1 != id2 {
			t.Errorf("non-deterministic ID at index %d: %s vs %s", i, id1, id2)
		}
	}
}

func TestExportSTIX_CanonicalContract(t *testing.T) {
	briefs := []BundleBrief{
		{
			ID: "brief-b", Slug: "brief-b", EventID: "event-b", Revision: 1,
			Title: "Second", Severity: "medium", PublishedAt: "2026-10-19T08:00:00Z",
			TTPs: []BundleTTP{{TechniqueID: "T1059.003", TechniqueName: "Invented label"}},
			CVEs: []BundleCVE{{ID: "CVE-2026-1000", CVSS: 8.8, EPSS: 0.5, KEVStatus: "false"}},
		},
		{
			ID: "brief-a", Slug: "brief-a", EventID: "event-a", Revision: 2,
			Title: "First", Severity: "high", PublishedAt: "2026-10-19T12:34:56.789123+02:00",
			RevisionHistory:      []BundleRevision{{Revision: 2, At: "2026-10-20T11:12:13.456789+02:00"}},
			TTPs:                 []BundleTTP{{TechniqueID: "T1059.003", TechniqueName: "Also wrong"}},
			CVEs:                 []BundleCVE{{ID: "CVE-2026-1000", CVSS: 9.8, EPSS: 0.91, KEV: true, KEVStatus: "true"}},
			ExploitationEvidence: &BundleExploitationEvidence{Status: "confirmed_active", SourceURL: "https://vendor.test/advisory", ObservedAt: "2026-10-19T10:00:00Z", Confidence: "high"},
		},
	}

	data, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSTIX(data, 2); err != nil {
		t.Fatalf("ValidateSTIX: %v\n%s", err, data)
	}
	reversed, err := ExportSTIX([]BundleBrief{briefs[1], briefs[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, reversed) {
		t.Fatal("canonical STIX bytes depend on input order")
	}
	var bundle struct {
		Objects []map[string]interface{} `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	var report, attack map[string]interface{}
	for _, object := range bundle.Objects {
		counts[object["type"].(string)]++
		if object["type"] == "report" && object["x_craftedsignal_brief_id"] == "brief-a" {
			report = object
		}
		if object["type"] == "attack-pattern" {
			attack = object
		}
	}
	if counts["identity"] != 1 || counts["attack-pattern"] != 1 || counts["vulnerability"] != 1 || counts["report"] != 2 {
		t.Fatalf("shared object counts = %#v", counts)
	}
	if attack["name"] != "Windows Command Shell" {
		t.Fatalf("ATT&CK name = %v", attack["name"])
	}
	for key, want := range map[string]interface{}{
		"created":                       "2026-10-19T10:34:56.789Z",
		"modified":                      "2026-10-20T09:12:13.456Z",
		"published":                     "2026-10-19T10:34:56.789Z",
		"x_craftedsignal_brief_id":      "brief-a",
		"x_craftedsignal_event_id":      "event-a",
		"x_craftedsignal_revision":      float64(2),
		"x_craftedsignal_canonical_url": "https://example.invalid/briefs/brief-a/",
		"x_craftedsignal_activity_at":   "2026-10-20T09:12:13.456Z",
		"x_craftedsignal_kev_status":    "true",
		"x_craftedsignal_cvss_max":      float64(9.8),
		"x_craftedsignal_epss_max":      float64(0.91),
	} {
		if report[key] != want {
			t.Errorf("report[%s] = %#v, want %#v", key, report[key], want)
		}
	}
	if refs, ok := report["object_refs"].([]interface{}); !ok || len(refs) == 0 {
		t.Fatalf("report object_refs = %#v", report["object_refs"])
	}
	extRefs := report["external_references"].([]interface{})
	canonical := extRefs[0].(map[string]interface{})
	if canonical["source_name"] != "craftedsignal" || canonical["external_id"] != "brief-a" || canonical["url"] != "https://example.invalid/briefs/brief-a/" {
		t.Fatalf("canonical external reference = %#v", canonical)
	}
	if _, ok := report["x_craftedsignal_exploitation_evidence"].(map[string]interface{}); !ok {
		t.Fatalf("missing exploitation evidence: %#v", report)
	}
}

func TestExportSTIXOmitsUnavailableRiskFields(t *testing.T) {
	data, err := ExportSTIX([]BundleBrief{
		{ID: "absent-risk", Title: "Absent risk", PublishedAt: "2026-10-20T10:00:00Z"},
		{
			ID: "known-zero-risk", Title: "Known zero risk", PublishedAt: "2026-10-20T11:00:00Z",
			CVEs: []BundleCVE{{
				ID: "CVE-2026-0000", CVSS: 0, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
				EPSS: 0, EPSSPercentile: 0.01,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	reports := map[string]map[string]any{}
	for _, object := range bundle.Objects {
		if object["type"] == "report" {
			reports[object["x_craftedsignal_brief_id"].(string)] = object
		}
	}
	for _, field := range []string{"x_craftedsignal_cvss_max", "x_craftedsignal_epss_max"} {
		value, exists := reports["absent-risk"][field]
		if exists {
			t.Fatalf("absent-risk %s = %#v, want property omitted", field, value)
		}
		value, exists = reports["known-zero-risk"][field]
		if !exists || value != float64(0) {
			t.Fatalf("known-zero-risk %s = %#v (present=%v), want numeric zero", field, value, exists)
		}
	}
}

func TestExportSTIXOmitsReferencesThatAreNotURLs(t *testing.T) {
	data, err := ExportSTIX([]BundleBrief{{
		ID: "brief-1", Title: "Brief", PublishedAt: "2026-10-20T10:00:00Z",
		References: []string{"CVE-2026-67279", "https://example.com/advisory"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, object := range bundle.Objects {
		if object["type"] != "report" {
			continue
		}
		var got []string
		for _, raw := range object["external_references"].([]any) {
			ref := raw.(map[string]any)
			if value, ok := ref["url"].(string); ok {
				got = append(got, value)
			}
		}
		if strings.Contains(strings.Join(got, "\n"), "CVE-2026-67279") {
			t.Fatalf("non-URL reference was exported as a STIX URL: %#v", got)
		}
		if !strings.Contains(strings.Join(got, "\n"), "https://example.com/advisory") {
			t.Fatalf("valid URL reference was omitted: %#v", got)
		}
		return
	}
	t.Fatal("report not found")
}

func TestValidateSTIXRejectsNullRiskField(t *testing.T) {
	data, err := ExportSTIX([]BundleBrief{{ID: "brief-1", Title: "Brief", PublishedAt: "2026-10-20T10:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, object := range bundle["objects"].([]any) {
		properties := object.(map[string]any)
		if properties["type"] == "report" {
			properties["x_craftedsignal_cvss_max"] = nil
		}
	}
	broken, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSTIX(broken, 1); err == nil {
		t.Fatal("expected a report with null x_craftedsignal_cvss_max to fail validation")
	}
}

func TestValidateSTIXRejectsNestedNull(t *testing.T) {
	data, err := ExportSTIX([]BundleBrief{{ID: "brief-1", Title: "Brief", PublishedAt: "2026-10-20T10:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, object := range bundle["objects"].([]any) {
		properties := object.(map[string]any)
		if properties["type"] == "report" {
			evidence := properties["x_craftedsignal_exploitation_evidence"].(map[string]any)
			evidence["source_url"] = nil
		}
	}
	broken, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSTIX(broken, 1); err == nil {
		t.Fatal("expected a report with a nested null property to fail validation")
	}
}

func TestValidateSTIXRejectsInvalidExternalReferenceURL(t *testing.T) {
	data, err := ExportSTIX([]BundleBrief{{ID: "brief-1", Title: "Brief", PublishedAt: "2026-10-20T10:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, raw := range bundle["objects"].([]any) {
		object := raw.(map[string]any)
		if object["type"] == "report" {
			object["external_references"].([]any)[0].(map[string]any)["url"] = "CVE-2026-67279"
		}
	}
	broken, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSTIX(broken, 1); err == nil {
		t.Fatal("expected a report with a non-URL external reference to fail validation")
	}
}

func TestExportSTIXSoftwareOmitsSDOCommonProperties(t *testing.T) {
	data, err := ExportSTIX([]BundleBrief{{
		ID: "software-brief", Title: "Software brief", PublishedAt: "2026-10-20T10:00:00Z",
		AffectedVendors: []string{"Acme"}, AffectedProducts: []string{"Widget"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, object := range bundle.Objects {
		if object["type"] == "software" {
			for _, property := range []string{"created_by_ref", "created", "modified"} {
				if value, present := object[property]; present {
					t.Fatalf("software SCO unexpectedly contains %s=%#v", property, value)
				}
			}
			return
		}
	}
	t.Fatal("expected exported software object")
}

func TestValidateSTIXAcceptsSoftwareWithoutSDOTimestamps(t *testing.T) {
	data, err := ExportSTIX([]BundleBrief{{
		ID: "software-brief", Title: "Software brief", PublishedAt: "2026-10-20T10:00:00Z",
		AffectedProducts: []string{"Widget"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, object := range bundle["objects"].([]any) {
		properties := object.(map[string]any)
		if properties["type"] == "software" {
			delete(properties, "created_by_ref")
			delete(properties, "created")
			delete(properties, "modified")
		}
	}
	broken, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSTIX(broken, 1); err != nil {
		t.Fatalf("valid timestamp-less software SCO was rejected: %v", err)
	}
}

func TestExportSTIX_RejectsMissingOrInvalidTimestamp(t *testing.T) {
	for _, published := range []string{"", "not-a-time"} {
		_, err := ExportSTIX([]BundleBrief{{ID: "brief-1", PublishedAt: published}})
		if err == nil {
			t.Fatalf("published_at %q should fail", published)
		}
	}
}

func TestValidateSTIX_RejectsStructuralDefects(t *testing.T) {
	valid, err := ExportSTIX([]BundleBrief{{ID: "brief-1", PublishedAt: "2026-10-19T00:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]interface{}
	if err := json.Unmarshal(valid, &bundle); err != nil {
		t.Fatal(err)
	}
	objects := bundle["objects"].([]interface{})
	var report map[string]interface{}
	for _, raw := range objects {
		object := raw.(map[string]interface{})
		if object["type"] == "report" {
			report = object
			break
		}
	}

	t.Run("dangling object ref", func(t *testing.T) {
		report["object_refs"] = []interface{}{"identity--00000000-0000-5000-8000-000000000000"}
		data, _ := json.Marshal(bundle)
		if err := ValidateSTIX(data, 1); err == nil {
			t.Fatal("expected dangling reference error")
		}
	})

	t.Run("duplicate conflicting id", func(t *testing.T) {
		var fresh map[string]interface{}
		_ = json.Unmarshal(valid, &fresh)
		list := fresh["objects"].([]interface{})
		copyObject := map[string]interface{}{}
		for key, value := range list[0].(map[string]interface{}) {
			copyObject[key] = value
		}
		copyObject["name"] = "conflict"
		fresh["objects"] = append(list, copyObject)
		data, _ := json.Marshal(fresh)
		if err := ValidateSTIX(data, 1); err == nil {
			t.Fatal("expected duplicate object id error")
		}
	})

	t.Run("timestamp precision", func(t *testing.T) {
		var fresh map[string]interface{}
		_ = json.Unmarshal(valid, &fresh)
		for _, raw := range fresh["objects"].([]interface{}) {
			object := raw.(map[string]interface{})
			if object["type"] == "report" {
				object["modified"] = "2026-10-19T00:00:00Z"
			}
		}
		data, _ := json.Marshal(fresh)
		if err := ValidateSTIX(data, 1); err == nil {
			t.Fatal("expected millisecond timestamp error")
		}
	})

	t.Run("report missing timestamp", func(t *testing.T) {
		var fresh map[string]interface{}
		_ = json.Unmarshal(valid, &fresh)
		for _, raw := range fresh["objects"].([]interface{}) {
			object := raw.(map[string]interface{})
			if object["type"] == "report" {
				delete(object, "created")
			}
		}
		data, _ := json.Marshal(fresh)
		if err := ValidateSTIX(data, 1); err == nil {
			t.Fatal("expected timestamp-less report to fail validation")
		}
	})

	if err := ValidateSTIX(valid, 2); err == nil {
		t.Fatal("expected report parity error")
	}
}

func TestSTIXRegistryRejectsConflictingSameID(t *testing.T) {
	registry := newSTIXRegistry()
	first := stixIdentity{Type: "identity", SpecVersion: "2.1", ID: producerIdentityID, Created: sharedSTIXTimestamp, Modified: sharedSTIXTimestamp, Name: "CraftedSignal", IdentityClass: "organization"}
	if err := registry.add(first); err != nil {
		t.Fatal(err)
	}
	first.Name = "Conflicting Producer"
	if err := registry.add(first); err == nil {
		t.Fatal("expected same-ID conflicting object error")
	}
}

func TestExportSTIX_Empty(t *testing.T) {
	data, err := ExportSTIX(nil)
	if err != nil {
		t.Fatalf("ExportSTIX on nil failed: %v", err)
	}

	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bundle["type"] != "bundle" {
		t.Error("expected bundle type")
	}
}

func TestIOCPattern(t *testing.T) {
	tests := []struct {
		iocType  string
		value    string
		expected string
	}{
		{"domain", "evil.com", "[domain-name:value = 'evil.com']"},
		{"ip", "10.0.0.1", "[ipv4-addr:value = '10.0.0.1']"},
		{"hash_sha256", "abc123", "[file:hashes.'SHA-256' = 'abc123']"},
		{"hash_md5", "def456", "[file:hashes.MD5 = 'def456']"},
		{"url", "https://evil.com/x", "[url:value = 'https://evil.com/x']"},
		{"email", "a@b.com", "[email-addr:value = 'a@b.com']"},
		{"url", `file://C:\\Temp\\it's-bad`, `[url:value = 'file://C:\\\\Temp\\\\it\'s-bad']`},
	}

	for _, tt := range tests {
		got := iocPattern(tt.iocType, tt.value)
		if got != tt.expected {
			t.Errorf("iocPattern(%q, %q) = %q, want %q", tt.iocType, tt.value, got, tt.expected)
		}
	}
}

func TestAggregateRiskKeepsMixedFalseAndUnknownUnknown(t *testing.T) {
	_, _, got := aggregateRisk(BundleBrief{CVEs: []BundleCVE{
		{ID: "CVE-2026-1", KEVStatus: "false"},
		{ID: "CVE-2026-2", KEVStatus: "unknown"},
	}})
	if got != "unknown" {
		t.Fatalf("mixed false/unknown KEV status = %q, want unknown", got)
	}
}

func TestExportSTIXPrefersATTACKSubtechnique(t *testing.T) {
	raw, err := ExportSTIX([]BundleBrief{{
		ID: "brief-subtechnique", Title: "Subtechnique", PublishedAt: "2026-10-20T10:00:00Z",
		TTPs: []BundleTTP{{
			TacticID: "TA0002", TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter",
			SubtechniqueID: "T1059.003", SubtechniqueName: "Windows Command Shell",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, object := range bundle.Objects {
		if object["type"] == "attack-pattern" {
			refs, _ := object["external_references"].([]any)
			if len(refs) == 1 && refs[0].(map[string]any)["external_id"] == "T1059.003" {
				return
			}
		}
	}
	t.Fatal("STIX bundle did not emit the specific ATT&CK subtechnique")
}

func TestUUIDV5_Deterministic(t *testing.T) {
	a := uuidV5("test-input")
	b := uuidV5("test-input")
	if a != b {
		t.Errorf("uuidV5 not deterministic: %s != %s", a, b)
	}

	c := uuidV5("different-input")
	if a == c {
		t.Error("uuidV5 collision on different inputs")
	}

	// Verify format: 8-4-4-4-12 hex digits.
	parts := strings.Split(a, "-")
	if len(parts) != 5 {
		t.Fatalf("expected 5 UUID parts, got %d: %s", len(parts), a)
	}
	lengths := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != lengths[i] {
			t.Errorf("UUID part %d: expected %d chars, got %d in %s", i, lengths[i], len(p), a)
		}
	}
}

func TestExportSTIX_NoThreatActor(t *testing.T) {
	briefs := []BundleBrief{
		{
			ID:          "brief-no-ta",
			Title:       "No Actor",
			PublishedAt: "2025-01-01T00:00:00Z",
		},
	}

	data, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatal(err)
	}

	var bundle map[string]interface{}
	json.Unmarshal(data, &bundle)

	objects := bundle["objects"].([]interface{})
	for _, obj := range objects {
		m := obj.(map[string]interface{})
		if m["type"] == "threat-actor" {
			t.Error("should not have threat-actor when ThreatActor is empty")
		}
	}
}

func TestExportSTIX_AffectedSoftware(t *testing.T) {
	briefs := []BundleBrief{{
		ID:               "b1",
		Slug:             "foxit-uaf",
		Title:            "Foxit UAF",
		Content:          "c",
		Severity:         "high",
		PublishedAt:      "2026-04-01T00:00:00Z",
		AffectedVendors:  []string{"Foxit"},
		AffectedProducts: []string{"Foxit PDF Reader", "Foxit PDF Editor"},
		CVEs:             []BundleCVE{{ID: "CVE-2026-3779"}},
	}}

	data, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatalf("ExportSTIX failed: %v", err)
	}
	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	objects := bundle["objects"].([]interface{})
	counts := make(map[string]int)
	var vulnName, swVendor string
	for _, obj := range objects {
		m := obj.(map[string]interface{})
		counts[m["type"].(string)]++
		if m["type"] == "vulnerability" {
			vulnName = m["name"].(string)
		}
		if m["type"] == "software" {
			if v, ok := m["vendor"].(string); ok {
				swVendor = v
			}
		}
	}
	if counts["software"] != 2 {
		t.Errorf("software = %d, want 2", counts["software"])
	}
	if counts["vulnerability"] != 1 {
		t.Errorf("vulnerability = %d, want 1", counts["vulnerability"])
	}
	if counts["relationship"] != 2 { // 2 software --has--> 1 vulnerability
		t.Errorf("relationships = %d, want 2", counts["relationship"])
	}
	if vulnName != "CVE-2026-3779" {
		t.Errorf("vulnerability name = %q", vulnName)
	}
	if swVendor != "Foxit" {
		t.Errorf("software vendor = %q, want Foxit", swVendor)
	}
}

func TestExportSTIXDeduplicatesSoftwareCaseVariants(t *testing.T) {
	briefs := []BundleBrief{{
		ID:               "software-case-variants",
		Slug:             "software-case-variants",
		Title:            "Software case variants",
		Content:          "c",
		Severity:         "high",
		PublishedAt:      "2026-09-07T00:00:00Z",
		AffectedVendors:  []string{"N-able"},
		AffectedProducts: []string{"N-central (< 2026.3.1.14)", "N-Central (< 2026.3.1.14)", "N-central (< 2026.3.1.14)"},
	}}

	data, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatalf("ExportSTIX failed: %v", err)
	}
	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	software := 0
	for _, object := range bundle["objects"].([]interface{}) {
		if object.(map[string]interface{})["type"] == "software" {
			software++
		}
	}
	if software != 1 {
		t.Fatalf("software objects = %d, want 1", software)
	}
}

// TestExportSTIX_AffectedSoftware_PlaceholderDropped verifies that
// placeholder vendor/product values (e.g. "unknown", "unspecified") never
// leak into the STIX output: they must be filtered out before the
// "exactly one vendor" rule and the per-product dedup loop run.
func TestExportSTIX_AffectedSoftware_PlaceholderDropped(t *testing.T) {
	briefs := []BundleBrief{{
		ID:               "b2",
		Slug:             "foxit-uaf-placeholder",
		Title:            "Foxit UAF Placeholder",
		Content:          "c",
		Severity:         "high",
		PublishedAt:      "2026-04-01T00:00:00Z",
		AffectedVendors:  []string{"Foxit", "unknown"},
		AffectedProducts: []string{"Foxit PDF Reader", "unspecified"},
		CVEs:             []BundleCVE{{ID: "CVE-2026-3780"}},
	}}

	data, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatalf("ExportSTIX failed: %v", err)
	}
	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	objects := bundle["objects"].([]interface{})
	var softwareObjs []map[string]interface{}
	for _, obj := range objects {
		m := obj.(map[string]interface{})
		if m["type"] == "software" {
			softwareObjs = append(softwareObjs, m)
		}
	}
	if len(softwareObjs) != 1 {
		t.Fatalf("software = %d, want 1 (placeholder product %q must be dropped)", len(softwareObjs), "unspecified")
	}
	sw := softwareObjs[0]
	if name, _ := sw["name"].(string); name != "Foxit PDF Reader" {
		t.Errorf("software name = %q, want %q", name, "Foxit PDF Reader")
	}
	if vendor, _ := sw["vendor"].(string); vendor != "Foxit" {
		t.Errorf("software vendor = %q, want Foxit (placeholder vendor %q must be dropped)", vendor, "unknown")
	}
}

func TestExportSTIX_DefangsPayloads(t *testing.T) {
	briefs := []BundleBrief{{
		ID:          "b1",
		Slug:        "phpmyfaq-xss",
		Title:       "Stored XSS via <script>",
		Content:     "PoC: <script>alert('XSS')</script> and <img src=x onerror=alert(1)>. Affects version < 2.0.",
		Severity:    "high",
		PublishedAt: "2026-05-01T00:00:00Z",
	}}

	data, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatalf("ExportSTIX failed: %v", err)
	}
	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	var desc, name string
	for _, obj := range bundle["objects"].([]interface{}) {
		if m := obj.(map[string]interface{}); m["type"] == "report" {
			desc, _ = m["description"].(string)
			name, _ = m["name"].(string)
		}
	}
	// After JSON parsing, no live tag-opening should remain in the free text.
	for _, bad := range []string{"<script", "<img", "</script"} {
		if strings.Contains(desc, bad) {
			t.Errorf("live HTML %q survived defang in description: %q", bad, desc)
		}
	}
	if strings.Contains(name, "<script") {
		t.Errorf("live HTML survived defang in title: %q", name)
	}
	// Payload stays legible in defanged form, and a benign '<' is preserved.
	if !strings.Contains(desc, "&lt;script>alert('XSS')") {
		t.Errorf("expected defanged payload in description, got %q", desc)
	}
	if !strings.Contains(desc, "version < 2.0") {
		t.Errorf("benign '<' must be preserved, got %q", desc)
	}
}
