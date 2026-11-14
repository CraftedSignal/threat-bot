package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// BridgedSource embeds SourceToggle with yaml:",inline". If that tag stopped
// working, enabled and poll_interval would silently parse as zero values and
// the source would never register — a failure with no error to notice.
func TestLoadParsesBridgedSourceInlineFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `sources:
  ronin66:
    enabled: true
    poll_interval: 2h
    feed_url: "https://rss.app/feeds/abc.xml"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := cfg.Sources.Ronin66
	if !got.Enabled {
		t.Error("Enabled = false, want true (inline tag not honoured)")
	}
	if got.PollInterval != 2*time.Hour {
		t.Errorf("PollInterval = %v, want %v (inline tag not honoured)", got.PollInterval, 2*time.Hour)
	}
	if got.FeedURL != "https://rss.app/feeds/abc.xml" {
		t.Errorf("FeedURL = %q, want the bridge URL", got.FeedURL)
	}
}

// config.example.yaml is the only config checked into git (.gitignore excepts
// it from *.yaml), so it is what CI can verify. It ships the bridged source
// disabled with an empty feed_url.
func TestLoadParsesExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load(config.example.yaml): %v", err)
	}

	got := cfg.Sources.Ronin66
	if got.Enabled {
		t.Error("sources.ronin66.enabled = true, want false in the example config")
	}
	if got.PollInterval != 2*time.Hour {
		t.Errorf("sources.ronin66.poll_interval = %v, want 2h", got.PollInterval)
	}
	if got.FeedURL != "" {
		t.Errorf("sources.ronin66.feed_url = %q, want empty", got.FeedURL)
	}
}

func TestLoadBatchConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantErr    bool
	}{
		{"disabled", `llm: {provider: ollama}`, false},
		{"defaults", `llm: {provider: vertexai, project: prod, location: eu, model: gemini-test, batch: {enabled: true, bucket: prod-batch}}`, false},
		{"missing bucket", `llm: {provider: vertexai, project: prod, location: eu, batch: {enabled: true}}`, true},
		{"wrong provider", `llm: {provider: ollama, batch: {enabled: true, bucket: batch}}`, true},
		{"negative wait", `llm: {provider: vertexai, project: prod, location: eu, batch: {enabled: true, bucket: batch, max_wait: -1s}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Load error=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && cfg.LLM.Batch.Enabled && (cfg.LLM.Batch.MaxWait != 15*time.Minute || cfg.LLM.Batch.PollInterval != 30*time.Second) {
				t.Fatalf("unexpected defaults: %+v", cfg.LLM.Batch)
			}
		})
	}
}

func TestLoadSocialDiscoveryDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("sources: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources.BlueskyDiscovery.Enabled || cfg.Sources.MastodonDiscovery.Enabled {
		t.Fatal("social discovery must default disabled")
	}
	if cfg.Sources.BlueskyDiscovery.CandidateCap != 100 || cfg.Sources.BlueskyDiscovery.ReadWindow != 20*time.Second || cfg.Sources.BlueskyDiscovery.PollInterval != time.Minute {
		t.Fatalf("bad Bluesky defaults: %+v", cfg.Sources.BlueskyDiscovery)
	}
	if len(cfg.Sources.MastodonDiscovery.Tags) != 6 || cfg.Sources.MastodonDiscovery.CandidateCap != 100 || cfg.Sources.MastodonDiscovery.PollInterval != time.Minute {
		t.Fatalf("bad Mastodon defaults: %+v", cfg.Sources.MastodonDiscovery)
	}
	if cfg.Sources.SocialContext.ThreadDepth != 6 || cfg.Sources.SocialContext.ResponseLimit != 256<<10 || cfg.Sources.SocialContext.OEmbedURL != "https://publish.x.com/oembed" || cfg.Sources.SocialContext.LeafDailyBudget != 100 || cfg.Sources.SocialContext.ThreadDailyBudget != 20 || cfg.Sources.SocialContext.RequestInterval != 2*time.Second || cfg.Sources.SocialContext.ThreadCacheEntries != 512 {
		t.Fatalf("bad context defaults: %+v", cfg.Sources.SocialContext)
	}
	if cfg.Sources.PublicWebSocialSearch.Enabled || cfg.Sources.PublicWebSocialSearch.Limit != 25 {
		t.Fatalf("bad search defaults: %+v", cfg.Sources.PublicWebSocialSearch)
	}
}

// Catches leaking credentials into YAML or failing to resolve the configured
// environment variable before the scraper is constructed.
func TestLoadBraveSearchConfigurationFromEnvironment(t *testing.T) {
	t.Setenv("TEST_BRAVE_SEARCH_KEY", "from-env")
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `sources:
  public_web_social_search:
    enabled: true
    provider: brave
    api_key_env: TEST_BRAVE_SEARCH_KEY
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Sources.PublicWebSocialSearch
	if got.APIKey != "from-env" || got.APIKeyEnv != "TEST_BRAVE_SEARCH_KEY" {
		t.Fatalf("credentials not resolved: %+v", got)
	}
	if got.Endpoint != "https://api.search.brave.com/res/v1/web/search" || got.ResponseLimit != 256<<10 {
		t.Fatalf("bad Brave defaults: %+v", got)
	}
}

// abuse.ch rejects requests without an Auth-Key, so the key must reach the
// scraper from the environment the deployment sets, never from YAML.
func TestLoadAbuseCHAuthKeyFromEnvironment(t *testing.T) {
	t.Setenv("ABUSECH_AUTH_KEY", " from-env ")
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `sources:
  abuse_ch:
    enabled: true
    poll_interval: 4h
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Sources.AbuseCH
	if !got.Enabled || got.PollInterval != 4*time.Hour {
		t.Fatalf("toggle fields not parsed: enabled=%v poll_interval=%v", got.Enabled, got.PollInterval)
	}
	if got.APIKeyEnv != "ABUSECH_AUTH_KEY" || got.APIKey != "from-env" {
		t.Fatalf("auth key not resolved: api_key_env=%q api_key=%q", got.APIKeyEnv, got.APIKey)
	}
}

func TestLLMBatchMinPromptsDefaultsToFive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("llm:\n  provider: vertexai\n  batch:\n    enabled: true\n    bucket: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.Batch.MinPrompts != 5 {
		t.Fatalf("MinPrompts = %d, want 5", cfg.LLM.Batch.MinPrompts)
	}
}
