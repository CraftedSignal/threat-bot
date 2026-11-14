package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func runDrafts(args []string) {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel()}))

	needsPublisher, err := draftsNeedPublisher(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	// Set up publisher if configured.
	var pub *publisher.Publisher
	if needsPublisher && cfg.Publish.RepoSlug != "" && cfg.Publish.FeedPublicKey != "" {
		ghTokenFn, ghErr := newGitHubTokenFn(cfg.GitHub, logger)
		if ghErr != nil {
			fmt.Fprintf(os.Stderr, "error setting up GitHub auth for publishing: %v\n", ghErr)
			os.Exit(1)
		} else {
			pub = publisher.New(cfg.Publish.RepoSlug, cfg.Publish.FeedPublicKey, ghTokenFn, logger, publicationSettings(cfg))
			pub.UseSegmented = true
		}
	}

	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	handleDrafts(db, pub, args)
}

func runDigests(args []string) {
	opts, err := parseDigestOptions(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx := context.Background()
	hours, publish := &opts.hours, &opts.publish

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel()}))

	var pub *publisher.Publisher
	if *publish {
		if cfg.Publish.RepoSlug == "" || cfg.Publish.FeedPublicKey == "" {
			fmt.Fprintln(os.Stderr, "error: --publish requires publish.repo_slug and publish.feed_public_key in config")
			os.Exit(1)
		}
		ghTokenFn, ghErr := newGitHubTokenFn(cfg.GitHub, logger)
		if ghErr != nil {
			fmt.Fprintf(os.Stderr, "error setting up GitHub auth: %v\n", ghErr)
			os.Exit(1)
		}
		pub = publisher.New(cfg.Publish.RepoSlug, cfg.Publish.FeedPublicKey, ghTokenFn, logger, publicationSettings(cfg))
		pub.UseSegmented = true
	}

	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	digestCfg := publisher.DigestConfig{LookbackHours: *hours}

	if pub != nil {
		if err := pub.PublishDigest(ctx, db, digestCfg); err != nil {
			fmt.Fprintf(os.Stderr, "error publishing digest: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Digest published to feed repo.")
		return
	}

	digest, err := publisher.GenerateDigest(ctx, db, digestCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating digest: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(digest.RenderMarkdown())
}
