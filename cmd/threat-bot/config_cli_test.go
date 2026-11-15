package main

import (
	"bytes"
	"fmt"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
)

func TestUnknownProviderFailsWithoutCreatingClient(t *testing.T) {
	if _, err := newLLMClient(config.LLMConfig{Provider: "typo", Model: "example"}, "example"); err == nil {
		t.Fatal("unknown provider silently accepted")
	}
}

func TestPartialAppNeverFallsBackToToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "BENIGN_TOKEN_SENTINEL")
	if _, err := newGitHubTokenFn(config.GitHubConfig{InstallationID: 42}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("partial App fell back to static token")
	}
}

func TestOfflineConfigValidationAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	dbpath := filepath.Join(dir, "must-not-exist.db")
	path := filepath.Join(dir, "config.yaml")
	body := "db:\n  path: " + dbpath + "\nllm: {provider: ollama, endpoint: 'http://127.0.0.1:1', model: test}\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THREAT_BOT_CONFIG", path)
	old := flagConfig
	defer func() { flagConfig = old }()
	flagConfig = ""
	var out bytes.Buffer
	if err := runConfigValidation(nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "valid") {
		t.Fatalf("output %q", out.String())
	}
	if _, err := os.Stat(dbpath); !os.IsNotExist(err) {
		t.Fatalf("validation created DB: %v", err)
	}
	flagConfig = filepath.Join(dir, "missing.yaml")
	if _, err := loadConfig(); err == nil {
		t.Fatal("explicit path did not override environment")
	}
}

func TestOfflineConfigValidationAcceptsPublisherCacheWithoutCreatingFiles(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "must-not-exist.db")
	cachePath := filepath.Join(dir, "publisher-cache")
	path := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf("db: {path: %q}\nllm: {provider: ollama, model: test}\npublish: {cache_dir: %q}\n", dbPath, cachePath)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	old := flagConfig
	flagConfig = path
	defer func() { flagConfig = old }()
	var out bytes.Buffer
	if err := runConfigValidation([]string{"--command", "run"}, &out); err != nil {
		t.Fatalf("deployed publisher cache configuration rejected: %v", err)
	}
	for _, created := range []string{dbPath, cachePath} {
		if _, err := os.Stat(created); !os.IsNotExist(err) {
			t.Fatalf("offline validation created %s: %v", created, err)
		}
	}
}

func TestLocalApprovalDoesNotInitializePublishingCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "drafts.db")
	body := fmt.Sprintf("db: {path: %q}\ngithub: {app_id: 1, installation_id: 2, private_key_path: %q}\npublish: {repo_slug: owner/feed, feed_public_key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', site_url: 'https://example.org'}", dbPath, filepath.Join(dir, "missing-key.pem"))
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CreateDraft(&storage.Draft{ID: "pending", Status: storage.StatusPending, Source: "fixture", BriefYAML: "id: pending\ntitle: Fixture\n", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := fixtureCLI(path, "drafts", "approve", "pending")
	if err != nil || strings.Contains(string(output), "GitHub auth") {
		t.Fatalf("local approval attempted publishing authentication: %v %s", err, output)
	}
	db, err = storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	draft, err := db.GetDraft("pending")
	if err != nil {
		t.Fatal(err)
	}
	if draft.Status != storage.StatusApproved {
		t.Fatalf("local approval status=%q", draft.Status)
	}
}

func TestMissingModelFailsBeforeCredentialLookup(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing-credentials.json"))
	_, err := newLLMClient(config.LLMConfig{Provider: "vertexai", Project: "fixture", Location: "fixture"}, "")
	if err == nil || !strings.Contains(err.Error(), "llm.model") {
		t.Fatalf("missing model did not fail before credentials: %v", err)
	}
}

func TestPublicationFlagsUseExecutionParsingBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name              string
		command           string
		args              []string
		wantPublish       bool
		wantArgumentError bool
	}{
		{"approve numeric", "drafts", []string{"approve", "--publish=1", "fixture"}, true, false},
		{"approve upper", "drafts", []string{"approve", "--publish=TRUE", "fixture"}, true, false},
		{"approve short", "drafts", []string{"approve", "-publish=t", "fixture"}, true, false},
		{"approve last false", "drafts", []string{"approve", "--publish", "--publish=0", "fixture"}, false, false},
		{"approve after terminator", "drafts", []string{"approve", "--", "--publish"}, false, false},
		{"approve after positional", "drafts", []string{"approve", "fixture", "--publish"}, false, false},
		{"approve invalid boolean", "drafts", []string{"approve", "--publish=maybe", "fixture"}, false, true},
		{"approve unknown flag", "drafts", []string{"approve", "--publsh", "fixture"}, false, true},
		{"amend numeric", "drafts", []string{"amend", "--id", "fixture", "--file", "replacement.yaml", "--apply=1"}, true, false},
		{"amend last false", "drafts", []string{"amend", "--id", "fixture", "--file", "replacement.yaml", "--apply", "--apply=false"}, false, false},
		{"retire short", "drafts", []string{"retire-duplicates", "--canonical-id", "keep", "--duplicate-id", "remove", "--apply=t"}, true, false},
		{"retire string value", "drafts", []string{"retire-duplicates", "--canonical-id", "keep", "--duplicate-id", "remove", "--reason", "--apply"}, false, false},
		{"digest numeric", "digests", []string{"generate", "--publish=1"}, true, false},
		{"digest last false", "digests", []string{"generate", "--publish", "--publish=F"}, false, false},
		{"digest invalid boolean", "digests", []string{"generate", "--publish=maybe"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			dbPath := filepath.Join(dir, "must-not-exist.db")
			if err := os.WriteFile(path, []byte(fmt.Sprintf("db: {path: %q}\n", dbPath)), 0600); err != nil {
				t.Fatal(err)
			}
			old := flagConfig
			flagConfig = path
			defer func() { flagConfig = old }()
			err := validateCommandConfig(tc.command, tc.args)
			if tc.wantPublish {
				if err == nil || !strings.Contains(err.Error(), "publish.repo_slug") {
					t.Fatalf("publishing requirement missed: %v", err)
				}
			} else if tc.wantArgumentError {
				if err == nil {
					t.Fatal("invalid flag accepted before database setup")
				}
			} else if err != nil {
				t.Fatalf("local operation unnecessarily requires publishing: %v", err)
			}
			if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
				t.Fatalf("preflight created database: %v", err)
			}
		})
	}
}

func TestCLIAlternatePublishingBooleansFailBeforeDatabaseCreation(t *testing.T) {
	for _, args := range [][]string{
		{"drafts", "approve", "--publish=1", "fixture"},
		{"drafts", "approve", "--publish=TRUE", "fixture"},
		{"drafts", "amend", "--id", "fixture", "--file", "replacement.yaml", "--apply=t"},
		{"digests", "generate", "--publish=1"},
		{"drafts", "approve", "--publish=maybe", "fixture"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			path, dbPath := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "must-not-exist.db")
			if err := os.WriteFile(path, []byte(fmt.Sprintf("db: {path: %q}\n", dbPath)), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := fixtureCLI(path, args...)
			if err == nil {
				t.Fatalf("invalid configuration accepted: %s", output)
			}
			if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
				t.Fatalf("invalid command created database: %v; output=%s", err, output)
			}
		})
	}
}

func TestPublishingCredentialSetupFailsBeforeDatabaseCreation(t *testing.T) {
	for _, args := range [][]string{{"drafts", "approve", "--publish=TRUE", "fixture"}, {"digests", "generate", "--publish=t"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			path, dbPath := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "must-not-exist.db")
			body := fmt.Sprintf("db: {path: %q}\ngithub: {app_id: 1, installation_id: 2, private_key_path: %q}\npublish: {repo_slug: owner/feed, feed_public_key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', site_url: 'https://example.org'}", dbPath, filepath.Join(dir, "missing-key.pem"))
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := fixtureCLI(path, args...)
			if err == nil || !strings.Contains(string(output), "GitHub auth") {
				t.Fatalf("expected explicit credential setup failure: %v %s", err, output)
			}
			if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
				t.Fatalf("failed credential setup created database: %v", err)
			}
		})
	}
}
