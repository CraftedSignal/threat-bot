package pipeline

import (
	"strings"
	"testing"
)

func TestIOCVerifier_ValidIOCs(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "hash_sha256"
    value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    context: "malware hash"
  - type: "hash_md5"
    value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    context: "malware hash"
  - type: "hash_sha1"
    value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
    context: "malware hash"
  - type: "ip"
    value: "8.8.8.8"
    context: "C2 server"
  - type: "domain"
    value: "evil.example.co"
    context: "malicious domain"
  - type: "url"
    value: "https://evil.example.co/payload"
    context: "payload URL"
`
	v := NewIOCVerifier()
	result, notes := v.Verify(yaml)
	if len(notes) > 0 {
		t.Errorf("expected no notes for valid IOCs, got: %v", notes)
	}
	if !strings.Contains(result, "8.8.8.8") {
		t.Error("expected valid IP to remain in output")
	}
}

func TestIOCVerifier_InvalidSHA256(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "hash_sha256"
    value: "tooshort"
    context: "bad hash"
`
	v := NewIOCVerifier()
	_, notes := v.Verify(yaml)
	if len(notes) == 0 {
		t.Error("expected validation note for invalid SHA-256")
	}
}

func TestIOCVerifier_InvalidMD5(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "hash_md5"
    value: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    context: "bad hash"
`
	v := NewIOCVerifier()
	_, notes := v.Verify(yaml)
	if len(notes) == 0 {
		t.Error("expected validation note for invalid MD5")
	}
}

func TestIOCVerifier_InvalidSHA1(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "hash_sha1"
    value: "abc123"
    context: "bad hash"
`
	v := NewIOCVerifier()
	_, notes := v.Verify(yaml)
	if len(notes) == 0 {
		t.Error("expected validation note for invalid SHA-1")
	}
}

func TestIOCVerifier_PrivateIP(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "ip"
    value: "192.168.1.1"
    context: "private IP"
`
	v := NewIOCVerifier()
	_, notes := v.Verify(yaml)
	if len(notes) == 0 {
		t.Error("expected validation note for private IP")
	}
}

func TestIOCVerifier_LoopbackIP(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "ip"
    value: "127.0.0.1"
    context: "loopback"
`
	v := NewIOCVerifier()
	_, notes := v.Verify(yaml)
	if len(notes) == 0 {
		t.Error("expected validation note for loopback IP")
	}
}

func TestIOCVerifier_DocumentationIP(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "ip"
    value: "192.0.2.1"
    context: "doc range"
`
	v := NewIOCVerifier()
	_, notes := v.Verify(yaml)
	if len(notes) == 0 {
		t.Error("expected validation note for documentation range IP")
	}
}

func TestIOCVerifier_InvalidDomain(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"no dot", "localhost"},
		{"is IP", "8.8.8.8"},
		{"short TLD", "evil.x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "domain"
    value: "` + tc.value + `"
    context: "bad domain"
`
			v := NewIOCVerifier()
			_, notes := v.Verify(yaml)
			if len(notes) == 0 {
				t.Errorf("expected validation note for domain %q", tc.value)
			}
		})
	}
}

func TestIOCVerifier_InvalidURL(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "url"
    value: "ftp://evil.com/payload"
    context: "bad URL"
`
	v := NewIOCVerifier()
	_, notes := v.Verify(yaml)
	if len(notes) == 0 {
		t.Error("expected validation note for non-HTTP URL")
	}
}

func TestIOCVerifier_MixedValidInvalid(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "ip"
    value: "8.8.8.8"
    context: "valid"
  - type: "ip"
    value: "192.168.1.1"
    context: "private"
  - type: "hash_md5"
    value: "abc"
    context: "too short"
`
	v := NewIOCVerifier()
	result, notes := v.Verify(yaml)
	if len(notes) != 2 {
		t.Errorf("expected 2 notes, got %d: %v", len(notes), notes)
	}
	if !strings.Contains(result, "8.8.8.8") {
		t.Error("expected valid IP to remain")
	}
	if strings.Contains(result, "192.168.1.1") {
		t.Error("expected private IP to be removed")
	}
}

func TestIOCVerifier_NoIOCs(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
`
	v := NewIOCVerifier()
	result, notes := v.Verify(yaml)
	if len(notes) > 0 {
		t.Errorf("expected no notes, got: %v", notes)
	}
	if result != yaml {
		t.Error("expected YAML to be unchanged")
	}
}

func TestIOCVerifier_RejectsGarbageTypesAndValues(t *testing.T) {
	yaml := `
id: "brief-test"
slug: "test"
title: "Test"
summary: "Test"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
content: "test"
tags: []
references: []
iocs:
  - type: "campaign"
    value: "SANDWORM_MODE"
    context: "bad type"
  - type: "string"
    value: ".npmrc tokens"
    context: "descriptive label"
  - type: "variable"
    value: "KEY"
    context: "env var name"
  - type: "domain"
    value: "github.com"
    context: "legitimate service"
  - type: "domain"
    value: "evil.example.co"
    context: "valid indicator"
`
	v := NewIOCVerifier()
	result, notes := v.Verify(yaml)
	if len(notes) != 4 {
		t.Fatalf("expected 4 removal notes, got %d: %v", len(notes), notes)
	}
	if strings.Contains(result, "SANDWORM_MODE") {
		t.Error("expected campaign-type IOC to be removed")
	}
	if strings.Contains(result, ".npmrc tokens") {
		t.Error("expected descriptive label IOC to be removed")
	}
	if strings.Contains(result, "KEY") {
		t.Error("expected env-var name IOC to be removed")
	}
	if strings.Contains(result, "github.com") {
		t.Error("expected legitimate-service domain IOC to be removed")
	}
	if !strings.Contains(result, "evil.example.co") {
		t.Error("expected valid attacker domain to remain")
	}
}
