package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

var (
	flagConfig   string
	flagLogLevel string
)

const (
	llmSmokeTimeout       = 45 * time.Second
	briefStarvationWindow = 6 * time.Hour
)

func main() {
	flag.StringVar(&flagConfig, "config", "", "Path to config file (default: config.yaml, or THREAT_BOT_CONFIG env)")
	flag.StringVar(&flagLogLevel, "log", "info", "Log level: debug, info, warn, error")
	flag.Usage = printUsage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	cmd := args[0]
	switch cmd {
	case "help":
		printUsage()
		return
	case "version":
		fmt.Printf("threat-bot %s (%s)\n", version, revision)
		return
	case "config", "validate-config":
		configArgs := args[1:]
		if cmd == "config" {
			if len(configArgs) == 0 || configArgs[0] != "validate" {
				fmt.Fprintln(os.Stderr, "Usage: threat-bot [flags] config validate [--command run]")
				os.Exit(2)
			}
			configArgs = configArgs[1:]
		}
		if err := runConfigValidation(configArgs, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			os.Exit(2)
		}
		return
	case "run", "drafts", "digests", "bundle", "sources", "check-llm":
		if (cmd == "run" || cmd == "check-llm") && len(args) > 1 {
			fmt.Fprintln(os.Stderr, "global flags must precede the command; run and check-llm take no arguments")
			os.Exit(2)
		}
		if err := validateCommandConfig(cmd, args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			os.Exit(2)
		}
	}
	switch cmd {
	case "run":
		runScraper()
	case "drafts":
		runDrafts(args[1:])
	case "digests":
		runDigests(args[1:])
	case "bundle":
		runBundle(args[1:])
	case "sources":
		runSources(args[1:])
	case "check-llm":
		runCheckLLM()
	case "canonicalize-products":
		if err := runCanonicalizeProducts(args[1:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "canonicalize-products: %v\n", err)
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: threat-bot [flags] <command>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  -config=PATH     Path to config file (default: config.yaml, or THREAT_BOT_CONFIG env)")
	fmt.Fprintln(os.Stderr, "  -log=LEVEL       Log level: debug, info, warn, error (default: info)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  version          Show version and source revision (offline)")
	fmt.Fprintln(os.Stderr, "  config validate [--command run]  Validate configuration offline; no database writes")
	fmt.Fprintln(os.Stderr, "  run              Poll sources and generate drafts (network, provider calls, database writes; optional publish)")
	fmt.Fprintln(os.Stderr, "  drafts list      List pending draft briefs")
	fmt.Fprintln(os.Stderr, "  drafts show ID   Show a draft brief")
	fmt.Fprintln(os.Stderr, "  drafts find     Find approved drafts by public slug")
	fmt.Fprintln(os.Stderr, "  drafts approve   Approve a draft brief")
	fmt.Fprintln(os.Stderr, "  drafts reject    Reject a draft brief")
	fmt.Fprintln(os.Stderr, "  drafts amend     Preview or apply one approved draft correction")
	fmt.Fprintln(os.Stderr, "  drafts retire-duplicates Remove published duplicates after canonical correction")
	fmt.Fprintln(os.Stderr, "  drafts republish Republish approved drafts (optional --id ID or --since RFC3339, --exclude-id ID)")
	fmt.Fprintln(os.Stderr, "  digests generate Generate a digest of approved briefs")
	fmt.Fprintln(os.Stderr, "  bundle migrate            Migrate legacy bundle.json to yearly segment files")
	fmt.Fprintln(os.Stderr, "  bundle repair-manifest    Rebuild segment manifest from existing segment files")
	fmt.Fprintln(os.Stderr, "  bundle backfill-markdown  Emit public Markdown for historical briefs (optional --slug list)")
	fmt.Fprintln(os.Stderr, "  bundle publish-stix       Regenerate validated immutable STIX releases and aliases")
	fmt.Fprintln(os.Stderr, "  bundle retire-briefs      Atomically remove published duplicates while preserving a canonical brief")
	fmt.Fprintln(os.Stderr, "  sources reseed [--days N] [--source-id ID] SOURCE  Re-queue source items for re-evaluation")
	fmt.Fprintln(os.Stderr, "  sources replay [--dry-run] ID...  Fetch source items and queue them in SQLite; use - for stdin")
	fmt.Fprintln(os.Stderr, "  bundle drift     Inspect segment identity drift (network)")
	fmt.Fprintln(os.Stderr, "  bundle enrich-vendors  Enrich missing vendor fields (provider calls; may publish)")
	fmt.Fprintln(os.Stderr, "  check-llm        Smoke-check configured LLM models (network, possible provider cost)")
	fmt.Fprintln(os.Stderr, "  canonicalize-products --content-dir PATH [--apply]  Dry-run product term cleanup and redirects")
	fmt.Fprintln(os.Stderr, "\nGlobal flags must precede commands. Approve/reject/amend/reseed/replay mutate SQLite; publishing commands update GitHub.\nConfiguration precedence: -config > THREAT_BOT_CONFIG > config.yaml. No implicit production endpoints.")
}

func parseLogLevel() slog.Level {
	switch strings.ToLower(flagLogLevel) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
