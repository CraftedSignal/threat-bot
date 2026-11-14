package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/github"
	"github.com/craftedsignal/threat-bot/internal/llm"
)

func runCheckLLM() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel()}))
	clients, err := buildLLMClients(cfg.LLM, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating LLM clients: %v\n", err)
		os.Exit(1)
	}
	checks := []llmCheck{{Role: "primary", Model: clients.PrimaryModel, Client: clients.Primary}}
	if clients.Fast != nil {
		checks = append(checks, llmCheck{Role: "fast", Model: clients.FastModel, Client: clients.Fast})
	}
	if err := smokeCheckLLMs(context.Background(), checks, logger); err != nil {
		fmt.Fprintf(os.Stderr, "LLM smoke check failed: %v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "LLM smoke check passed")
}

func newGitHubTokenFn(cfg config.GitHubConfig, logger *slog.Logger) (func() string, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Configured() {
		keyPEM, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("reading GitHub App private key: %w", err)
		}
		auth, err := github.NewAppAuth(cfg.AppID, cfg.InstallationID, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("creating GitHub App auth: %w", err)
		}
		logger.Info("using GitHub App for authentication", "app_id", cfg.AppID)
		return func() string {
			token, err := auth.Token()
			if err != nil {
				logger.Error("failed to get GitHub App token", "error", err)
				return ""
			}
			return token
		}, nil
	}

	// Fallback to static GITHUB_TOKEN env var.
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	return func() string { return token }, nil
}

type llmClientSet struct {
	Primary      llm.Client
	PrimaryModel string
	Fast         llm.Client
	FastModel    string
}

type llmCheck struct {
	Role   string
	Model  string
	Client llm.Client
}

func buildLLMClients(cfg config.LLMConfig, logger *slog.Logger) (llmClientSet, error) {
	primary, err := newLLMClient(cfg, cfg.Model)
	if err != nil {
		return llmClientSet{}, fmt.Errorf("creating primary LLM client: %w", err)
	}
	clients := llmClientSet{
		Primary:      primary,
		PrimaryModel: cfg.Model,
	}
	if cfg.FastModel != "" && cfg.FastModel != cfg.Model {
		fast, err := newLLMClient(cfg, cfg.FastModel)
		if err != nil {
			return llmClientSet{}, fmt.Errorf("creating fast LLM client: %w", err)
		}
		clients.Fast = fast
		clients.FastModel = cfg.FastModel
		if logger != nil {
			logger.Info("using fast model for quality gate", "model", cfg.FastModel)
		}
	}
	return clients, nil
}

func smokeCheckLLMs(parent context.Context, checks []llmCheck, logger *slog.Logger) error {
	for _, check := range checks {
		ctx, cancel := context.WithTimeout(parent, llmSmokeTimeout)
		start := time.Now()
		err := llm.SmokeCheck(ctx, check.Client)
		cancel()
		if err != nil {
			if logger != nil {
				logger.Error("llm smoke check failed", "role", check.Role, "model", check.Model, "duration", time.Since(start).Round(time.Millisecond), "error", err)
			}
			return fmt.Errorf("%s model %q: %w", check.Role, check.Model, err)
		}
		if logger != nil {
			logger.Info("llm smoke check passed", "role", check.Role, "model", check.Model, "duration", time.Since(start).Round(time.Millisecond))
		}
	}
	return nil
}

func newLLMClient(cfg config.LLMConfig, model string) (llm.Client, error) {
	cfg.Model = model
	if err := cfg.Validate(true); err != nil {
		return nil, err
	}
	switch cfg.Provider {
	case "vertexai":
		if cfg.Project == "" || cfg.Location == "" {
			return nil, fmt.Errorf("vertexai provider requires project and location in config")
		}
		return llm.NewVertexAIClient(cfg.Project, cfg.Location, model)
	case "ollama":
		if strings.TrimSpace(model) == "" {
			return nil, fmt.Errorf("llm.model is required")
		}
		return llm.NewOllamaClient(cfg.Endpoint, model), nil
	default:
		return nil, fmt.Errorf("llm.provider must be ollama or vertexai")
	}
}

func withBatchPrefetch(cfg config.LLMConfig, model string, live llm.Client, logger *slog.Logger) (llm.Client, error) {
	runner, err := llm.NewVertexBatch(cfg.Project, cfg.Location, model, cfg.Batch.Bucket, cfg.Batch.PollInterval, cfg.Batch.MaxWait, logger)
	if err != nil {
		return nil, err
	}
	return llm.NewPrefetchClient(live, runner, llm.MaxBatchRequests, logger).WithMinPrompts(cfg.Batch.MinPrompts), nil
}
