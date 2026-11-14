package config

import (
	"encoding/hex"
	"fmt"
	"math"
	"net/mail"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var repoSlugPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// ValidateFor checks the configuration required by command without opening a
// database, contacting a provider, or requesting credentials over the network.
// Credentials are checked only for presence; config validation cannot establish
// that a provider model, App key, token or remote repository is usable.
func (c *Config) ValidateFor(command string) error {
	needDB, needLLM, needPublish := false, false, false
	switch command {
	case "run":
		needDB, needLLM = true, true
		needPublish = c.Pipeline.AutoPublish
	case "drafts", "sources", "efficiency":
		needDB = true
	case "check-llm":
		needLLM = true
	case "publish", "bundle":
		needPublish = true
	case "digests":
		needDB = true
	default:
		return fmt.Errorf("unknown validation command (use run, drafts, sources, check-llm, publish, bundle, digests, or efficiency)")
	}
	if needDB && strings.TrimSpace(c.DB.Path) == "" {
		return fmt.Errorf("db.path is required")
	}
	if ephemeralDB(c.DB.Path) {
		return fmt.Errorf("db.path must be persistent; :memory: is not supported by the CLI")
	}
	if err := c.LLM.Validate(needLLM); err != nil {
		return err
	}
	if err := c.GitHub.Validate(); err != nil {
		return err
	}
	if err := validateDurations(reflect.ValueOf(*c), ""); err != nil {
		return err
	}
	if math.IsNaN(c.Pipeline.QualityThreshold) || c.Pipeline.QualityThreshold < 0 || c.Pipeline.QualityThreshold > 5 {
		return fmt.Errorf("pipeline.quality_threshold must be between 0 and 5")
	}
	if c.Pipeline.MaxGroundingAttempts < 0 {
		return fmt.Errorf("pipeline.max_grounding_attempts must not be negative")
	}
	for _, score := range c.Pipeline.SourceConfidence {
		if math.IsNaN(score) || score < 0 || score > 1 {
			return fmt.Errorf("pipeline.source_confidence values must be between 0 and 1")
		}
	}
	if (c.Sources.PublicWebSocialSearch.Enabled || c.Sources.PublicWebSocialSearch.Provider != "") && c.Sources.PublicWebSocialSearch.Provider != "brave" {
		return fmt.Errorf("sources.public_web_social_search.provider must be brave")
	}
	if c.Sources.Ronin66.Enabled && strings.TrimSpace(c.Sources.Ronin66.FeedURL) == "" {
		return fmt.Errorf("sources.ronin66.feed_url is required when enabled")
	}
	if c.Notifier.URL != "" && c.Notifier.DispatchToken == "" {
		return fmt.Errorf("notifier.url requires notifier.dispatch_token or NOTIFIER_DISPATCH_TOKEN")
	}
	if c.Notifier.URL != "" {
		if c.Publish.SiteURL == "" {
			return fmt.Errorf("publish.site_url is required when notifier.url is configured")
		}
		if err := validateURL("notifier.url", c.Notifier.URL); err != nil {
			return err
		}
	}
	if c.Monitoring.PublicFeedURL != "" {
		if err := validateURL("monitoring.public_feed_url", c.Monitoring.PublicFeedURL); err != nil {
			return err
		}
	}
	configured := c.Publish.RepoSlug != "" || c.Publish.FeedPublicKey != "" || c.Publish.SiteURL != ""
	if configured || needPublish {
		if !repoSlugPattern.MatchString(c.Publish.RepoSlug) {
			return fmt.Errorf("publish.repo_slug must be owner/repository")
		}
		key, err := hex.DecodeString(c.Publish.FeedPublicKey)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("publish.feed_public_key must contain 32 hex-encoded bytes")
		}
		if err := validateURL("publish.site_url", c.Publish.SiteURL); err != nil {
			return err
		}
		if !validBranch(c.Publish.Branch) {
			return fmt.Errorf("publish.branch must be a valid Git branch name")
		}
		if strings.TrimSpace(c.Publish.AuthorName) == "" || strings.ContainsAny(c.Publish.AuthorName, "\r\n") {
			return fmt.Errorf("publish.author_name is required and must be one line")
		}
		addr, err := mail.ParseAddress(c.Publish.AuthorEmail)
		if err != nil || addr.Address != c.Publish.AuthorEmail {
			return fmt.Errorf("publish.author_email must be an email address")
		}
	}
	if needPublish && !c.GitHub.Configured() && strings.TrimSpace(os.Getenv("GITHUB_TOKEN")) == "" {
		return fmt.Errorf("publishing requires a complete GitHub App configuration or GITHUB_TOKEN")
	}
	return nil
}

func (c LLMConfig) Validate(required bool) error {
	if c.Provider == "" {
		if required {
			return fmt.Errorf("llm.provider is required (ollama or vertexai)")
		}
		return nil
	}
	if c.Provider != "ollama" && c.Provider != "vertexai" {
		return fmt.Errorf("llm.provider must be ollama or vertexai")
	}
	if required && strings.TrimSpace(c.Model) == "" {
		return fmt.Errorf("llm.model is required")
	}
	if required && c.Provider == "vertexai" && (strings.TrimSpace(c.Project) == "" || strings.TrimSpace(c.Location) == "") {
		return fmt.Errorf("llm.project and llm.location are required for vertexai")
	}
	if c.Provider == "ollama" && c.Endpoint != "" {
		return validateURL("llm.endpoint", c.Endpoint)
	}
	return nil
}

// Configured selects App auth even when the configuration is incomplete, so a
// partial App configuration never silently falls back to GITHUB_TOKEN.
func (c GitHubConfig) Configured() bool {
	return c.AppID != 0 || c.InstallationID != 0 || c.PrivateKeyPath != ""
}
func (c GitHubConfig) Validate() error {
	if c.Configured() && (c.AppID <= 0 || c.InstallationID <= 0 || strings.TrimSpace(c.PrivateKeyPath) == "") {
		return fmt.Errorf("github requires positive app_id, positive installation_id, and private_key_path together")
	}
	return nil
}

func validateURL(field, value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL without userinfo or fragment", field)
	}
	if field == "publish.site_url" && u.RawQuery != "" {
		return fmt.Errorf("publish.site_url must not contain a query")
	}
	return nil
}

func validBranch(value string) bool {
	if value == "" || value == "@" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") || strings.ContainsAny(value, " ~^:?*[\\\t\r\n") || strings.Contains(value, "..") || strings.Contains(value, "@{") || strings.Contains(value, "//") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func validateDurations(v reflect.Value, path string) error {
	durationType := reflect.TypeOf(time.Duration(0))
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		meta := v.Type().Field(i)
		name := strings.Split(meta.Tag.Get("yaml"), ",")[0]
		if name == "" {
			name = meta.Name
		}
		if path != "" {
			name = path + "." + name
		}
		if field.Type() == durationType && field.Int() < 0 {
			return fmt.Errorf("%s must not be negative", name)
		}
		if field.Kind() == reflect.Struct {
			if err := validateDurations(field, name); err != nil {
				return err
			}
		}
		if field.Kind() == reflect.Pointer && !field.IsNil() && field.Elem().Kind() == reflect.Struct {
			if err := validateDurations(field.Elem(), name); err != nil {
				return err
			}
		}
		if field.Kind() == reflect.Map && field.Type().Elem() == durationType {
			iter := field.MapRange()
			for iter.Next() {
				if iter.Value().Int() < 0 {
					return fmt.Errorf("%s values must not be negative", name)
				}
			}
		}
	}
	return nil
}

func ephemeralDB(path string) bool {
	if path == ":memory:" {
		return true
	}
	if strings.HasPrefix(path, "file:") {
		name, query, _ := strings.Cut(strings.TrimPrefix(path, "file:"), "?")
		values, err := url.ParseQuery(query)
		return name == ":memory:" || (err == nil && values.Get("mode") == "memory")
	}
	return false
}
