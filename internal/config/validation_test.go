package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRejectsUnknownKeysAndDocuments(t *testing.T) {
	for _, body := range []string{"llm: {modle: typo}", "pipeline: {auto_publsh: true}", "db: {path: a}\n---\ndb: {path: b}"} {
		if _, err := Load(writeConfig(t, body)); err == nil {
			t.Errorf("accepted invalid config %q", body)
		}
	}
}

func TestLoadDoesNotEnableProductionFreshness(t *testing.T) {
	cfg, err := Load(writeConfig(t, "{}"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Monitoring.PublicFeedURL != "" {
		t.Fatalf("implicit freshness URL %q", cfg.Monitoring.PublicFeedURL)
	}
}

func TestValidateForCommand(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	for _, tc := range []struct{ name, body, command, want string }{
		{"missing db", "llm: {provider: ollama, model: test}", "run", "db.path"},
		{"missing model", "db: {path: data/test.db}\nllm: {provider: ollama}", "run", "llm.model"},
		{"missing provider", "db: {path: data/test.db}\nllm: {model: test}", "run", "llm.provider"},
		{"unknown provider", "db: {path: data/test.db}\nllm: {provider: typo, model: test}", "run", "llm.provider"},
		{"draft reads need no llm", "db: {path: data/test.db}", "drafts", ""},
		{"model check needs no db", "llm: {provider: ollama, model: test}", "check-llm", ""},
		{"missing vertex project", "llm: {provider: vertexai, model: test}", "check-llm", "llm.project"},
		{"incomplete app", "db: {path: data/test.db}\ngithub: {installation_id: 42}", "drafts", "github"},
		{"incomplete publisher", "db: {path: data/test.db}\npublish: {repo_slug: owner/repo}", "drafts", "feed_public_key"},
		{"autopublish missing credentials", "db: {path: data/test.db}\nllm: {provider: ollama, model: test}\npipeline: {auto_publish: true}\npublish: {repo_slug: owner/repo, feed_public_key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', site_url: 'https://example.org'}", "run", "GITHUB_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, tc.body))
			if err == nil {
				err = cfg.ValidateFor(tc.command)
			}
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestExampleIsValidDraftConfiguration(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	cfg, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err = cfg.ValidateFor("run"); err != nil {
		t.Fatal(err)
	}
	if cfg.Pipeline.AutoPublish || cfg.Publish.RepoSlug != "" {
		t.Fatal("example enables publishing")
	}
	if cfg.DB.Path == "" || cfg.LLM.Model == "" {
		t.Fatal("incomplete example")
	}
}

func TestValidationUsesQualityScoreScaleAndPersistentStorage(t *testing.T) {
	for _, tc := range []struct{ extra, want string }{
		{"pipeline: {quality_threshold: 3.5}", ""},
		{"pipeline: {quality_threshold: 6}", "quality_threshold"},
		{"pipeline: {quality_threshold: .nan}", "quality_threshold"},
		{"pipeline: {source_confidence: {fixture: .inf}}", "source_confidence"},
		{"sources: {public_web_social_search: {provider: typo}}", "provider"},
	} {
		cfg, err := Load(writeConfig(t, "db: {path: ./fixture.db}\n"+tc.extra))
		if err == nil {
			err = cfg.ValidateFor("drafts")
		}
		if tc.want == "" && err != nil {
			t.Fatal(err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Fatalf("%s: error=%v", tc.extra, err)
		}
	}
	for _, path := range []string{":memory:", "file::memory:?cache=shared", "file:fixture?mode=memory"} {
		cfg, err := Load(writeConfig(t, "db: {path: '"+path+"'}"))
		if err == nil {
			err = cfg.ValidateFor("drafts")
		}
		if err == nil {
			t.Errorf("accepted ephemeral CLI database %q", path)
		}
	}
}
