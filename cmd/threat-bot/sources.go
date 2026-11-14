package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func runSources(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: threat-bot sources reseed [--days N] [--source-id ID] <source>")
		fmt.Fprintln(os.Stderr, "       threat-bot sources replay [--dry-run] <source-id>... (or - to read IDs from stdin)")
		os.Exit(1)
	}
	sub := args[0]
	switch sub {
	case "reseed":
		runSourcesReseed(args[1:])
	case "replay":
		runSourcesReplay(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown sources subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runSourcesReseed(args []string) {
	fs := flag.NewFlagSet("sources reseed", flag.ExitOnError)
	days := fs.Int("days", 14, "Clear seen items newer than this many days ago")
	sourceID := fs.String("source-id", "", "Requeue only this exact source item ID")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: threat-bot sources reseed [--days N] [--source-id ID] <source>")
		os.Exit(1)
	}
	source := fs.Arg(0)

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}
	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	since := time.Now().Add(-time.Duration(*days) * 24 * time.Hour)
	n, err := db.ReseedSource(source, since, *sourceID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if *sourceID != "" && n == 0 {
		fmt.Fprintf(os.Stderr, "source item %q was not found under source %q\n", *sourceID, source)
		os.Exit(1)
	}
	fmt.Printf("requeued %d seen items for source %q (poll rewound to %s)\n", n, source, since.Format(time.RFC3339))
}
