package pipeline

import (
	"fmt"
	"strings"

	iocpkg "github.com/craftedsignal/threat-bot/pkg/ioc"
	"gopkg.in/yaml.v3"
)

// allowedIOCTypes matches the brief schema: domain, ip, hash_sha256, hash_md5,
// url, email. Unknown or invented types (campaign, string, variable, keyword,
// filename, file-path, etc.) are rejected so they cannot pollute the feed.
var allowedIOCTypes = map[string]bool{
	"domain":      true,
	"ip":          true,
	"hash_sha256": true,
	"hash_md5":    true,
	"hash_sha1":   true,
	"url":         true,
	"email":       true,
}

// garbageIOCValues are descriptive labels or non-indicator strings that the
// LLM sometimes emits as IOC values. Reject them outright.
var garbageIOCValues = map[string]bool{
	"s":                          true,
	".npmrc tokens":              true,
	"npmrc tokens":               true,
	"github api tokens":          true,
	"cryptocurrency wallet keys": true,
	"cryptocurrencyWalletKeys":   true,
	"19 malicious packages":      true,
	"19 malicious npm packages":  true,
	"stage 0 loader shim":        true,
	"carrier dependency":         true,
	"attacker-controlled cloudflare worker endpoint":                                     true,
	"environment variables matching patterns (key, secret, token, password)":             true,
	"environment variables matching distinct patterns (key, secret, token, or password)": true,
}

// genericServiceDomains are legitimate platforms that are almost never
// themselves attacker infrastructure. A specific attacker-controlled repo,
// worker subdomain, or path may be an IOC, but the apex domain is not.
var genericServiceDomains = map[string]bool{
	"github.com":            true,
	"gitlab.com":            true,
	"bitbucket.org":         true,
	"npmjs.com":             true,
	"pypi.org":              true,
	"cloudflare.com":        true,
	"google.com":            true,
	"googleapis.com":        true,
	"microsoft.com":         true,
	"azure.com":             true,
	"amazonaws.com":         true,
	"openai.com":            true,
	"anthropic.com":         true,
	"cloudflare.net":        true,
	"workers.dev":           true,
	"cloudflareworkers.com": true,
}

// IOCVerifier validates that IOCs have correct formats and removes invalid entries.
type IOCVerifier struct{}

// NewIOCVerifier creates a new IOCVerifier.
func NewIOCVerifier() *IOCVerifier {
	return &IOCVerifier{}
}

// Verify parses the brief YAML, validates IOC formats, removes invalid ones,
// and returns the (possibly modified) YAML along with validation notes.
func (v *IOCVerifier) Verify(briefStr string) (string, []string) {
	var brief briefYAML
	if err := yaml.Unmarshal([]byte(briefStr), &brief); err != nil {
		return briefStr, nil
	}

	if len(brief.IOCs) == 0 {
		return briefStr, nil
	}

	var notes []string
	var clean []briefIOC
	for _, ioc := range brief.IOCs {
		if err := validateIOCFormat(ioc); err != nil {
			notes = append(notes, fmt.Sprintf("removed IOC with invalid format: type=%s value=%q: %s", ioc.Type, ioc.Value, err))
			continue
		}
		clean = append(clean, ioc)
	}

	if len(notes) == 0 {
		return briefStr, nil
	}

	if len(clean) == 0 {
		brief.IOCs = nil
	} else {
		brief.IOCs = clean
	}

	out, err := yaml.Marshal(&brief)
	if err != nil {
		return briefStr, notes
	}
	return string(out), notes
}

// validateIOCFormat checks whether an IOC value matches the expected format
// for its type. Returns nil if valid, an error describing the problem otherwise.
func validateIOCFormat(ioc briefIOC) error {
	typ := strings.ToLower(strings.TrimSpace(ioc.Type))
	val := strings.ToLower(strings.TrimSpace(ioc.Value))

	if !allowedIOCTypes[typ] {
		return fmt.Errorf("type %q is not a valid IOC type", ioc.Type)
	}
	if garbageIOCValues[val] {
		return fmt.Errorf("value %q is a descriptive label, not an indicator", ioc.Value)
	}
	// Reject values that are just the type/category name or obvious placeholders.
	if val == typ || val == "unknown" || val == "n/a" || val == "none" || val == "null" {
		return fmt.Errorf("value %q is not a concrete indicator", ioc.Value)
	}
	// Reject single-word env-variable names that are not actual observed values.
	if typ == "variable" || (len(val) <= 8 && strings.Contains(val, "key")) {
		return fmt.Errorf("value %q is not a concrete indicator", ioc.Value)
	}
	if typ == "domain" && genericServiceDomains[val] {
		return fmt.Errorf("domain %q is a generic service, not attacker infrastructure", ioc.Value)
	}

	return iocpkg.Validate(ioc.Type, ioc.Value)
}
