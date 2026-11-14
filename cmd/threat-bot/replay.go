package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// replayPollInterval is how often the service picks up items queued by
// `threat-bot sources replay`. An item the pipeline leaves unseen, after an error
// or a grounding retry, is re-emitted at this cadence until it expires, as a
// regular source re-fetches it at its own interval.
const replayPollInterval = time.Hour

// replayPlan sorts requested items by what a replay can do with them.
type replayPlan struct {
	queue   []scraper.RawItem // found and recent enough for the runner to accept
	tooOld  []string          // published before the runner's lookback, so it would skip them
	missing []string          // no enabled source returned them
}

// planReplay fetches the requested items as their sources serve them now. A
// source that can fetch items by ID does so; any other source is polled back
// to the cutoff and its items are matched by ID. Fetch errors are joined and
// returned with the plan.
func planReplay(ctx context.Context, runner *scraper.Runner, ids []string, cutoff time.Time) (replayPlan, error) {
	var sources []string
	bySource := make(map[string][]string)
	for _, id := range ids {
		source, _, _ := strings.Cut(id, ":")
		if _, ok := bySource[source]; !ok {
			sources = append(sources, source)
		}
		bySource[source] = append(bySource[source], id)
	}

	var plan replayPlan
	var errs []error
	found := make(map[string]bool, len(ids))
	for _, source := range sources {
		s, ok := runner.Scraper(source)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: no enabled source by that name", source))
			continue
		}
		var items []scraper.RawItem
		var err error
		if fetcher, ok := s.(scraper.ItemFetcher); ok {
			items, err = fetcher.FetchItems(ctx, bySource[source])
		} else {
			items, err = s.Poll(ctx, cutoff)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", source, err))
		}
		wanted := make(map[string]bool, len(bySource[source]))
		for _, id := range bySource[source] {
			wanted[id] = true
		}
		for _, item := range items {
			if !wanted[item.SourceID] || found[item.SourceID] {
				continue
			}
			found[item.SourceID] = true
			if !item.PublishedAt.IsZero() && item.PublishedAt.Before(cutoff) {
				plan.tooOld = append(plan.tooOld, item.SourceID)
				continue
			}
			plan.queue = append(plan.queue, item)
		}
	}
	for _, id := range ids {
		if !found[id] {
			plan.missing = append(plan.missing, id)
		}
	}
	return plan, errors.Join(errs...)
}

// readReplayIDs returns the source IDs given as arguments, or read one per
// line from stdin when the only argument is "-". Duplicates are dropped.
func readReplayIDs(args []string, stdin io.Reader) ([]string, error) {
	if len(args) == 1 && args[0] == "-" {
		var lines []string
		scanner := bufio.NewScanner(stdin)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		args = lines
	}
	seen := make(map[string]bool, len(args))
	var ids []string
	for _, id := range args {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

func runSourcesReplay(args []string) {
	fs := flag.NewFlagSet("sources replay", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "Fetch and report the items without queueing them")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	ids, err := readReplayIDs(fs.Args(), os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading source IDs: %v\n", err)
		os.Exit(1)
	}
	if len(ids) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: threat-bot sources replay [--dry-run] <source-id>... (or - to read IDs from stdin)")
		os.Exit(1)
	}

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
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLogLevel()}))
	ghTokenFn, err := newGitHubTokenFn(cfg.GitHub, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error setting up GitHub auth: %v\n", err)
		os.Exit(1)
	}
	runner := scraper.NewRunner(db, logger, cfg.Pipeline.InitialLookback)
	registerScrapers(runner, cfg, ghTokenFn, nil, logger)

	cutoff := time.Now().Add(-runner.Lookback())
	plan, fetchErr := planReplay(context.Background(), runner, ids, cutoff)
	if !*dryRun {
		for _, item := range plan.queue {
			itemJSON, err := json.Marshal(item)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error encoding %s: %v\n", item.SourceID, err)
				os.Exit(1)
			}
			if err := db.QueueReplay(item.Source, item.SourceID, string(itemJSON)); err != nil {
				fmt.Fprintf(os.Stderr, "error queueing %s: %v\n", item.SourceID, err)
				os.Exit(1)
			}
		}
	}

	verb := "queued"
	if *dryRun {
		verb = "would queue"
	}
	fmt.Printf("%s %d of %d items for replay\n", verb, len(plan.queue), len(ids))
	printReplayIDs("too old to replay (published before "+cutoff.Format(time.RFC3339)+")", plan.tooOld)
	printReplayIDs("not returned by their source", plan.missing)
	if fetchErr != nil {
		fmt.Printf("fetch errors:\n%v\n", fetchErr)
	}
}

func printReplayIDs(label string, ids []string) {
	if len(ids) == 0 {
		return
	}
	fmt.Printf("%s: %d\n", label, len(ids))
	for _, id := range ids {
		fmt.Printf("  %s\n", id)
	}
}
