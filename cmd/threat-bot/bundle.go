package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/publisher"
)

func runBundle(args []string) {
	if len(args) == 0 || !bundleCommandValid(args[0]) {
		fmt.Fprintln(os.Stderr, "Usage: threat-bot bundle migrate|repair-manifest|backfill-markdown [--slug a,b]|publish-stix|retire-briefs|drift|enrich-vendors")
		os.Exit(1)
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if cfg.Publish.RepoSlug == "" || cfg.Publish.FeedPublicKey == "" {
		fmt.Fprintln(os.Stderr, "error: bundle command requires publish.repo_slug and publish.feed_public_key in config")
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel()}))

	ghTokenFn, err := newGitHubTokenFn(cfg.GitHub, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error setting up GitHub auth: %v\n", err)
		os.Exit(1)
	}

	pub := publisher.New(cfg.Publish.RepoSlug, cfg.Publish.FeedPublicKey, ghTokenFn, logger, publicationSettings(cfg))

	switch args[0] {
	case "migrate":
		if err := pub.MigrateBundle(); err != nil {
			fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Migration complete.")
	case "repair-manifest":
		if err := pub.RepairManifest(); err != nil {
			fmt.Fprintf(os.Stderr, "repair failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Manifest repaired.")
	case "backfill-markdown":
		fs := flag.NewFlagSet("backfill-markdown", flag.ExitOnError)
		var slugList string
		fs.StringVar(&slugList, "slug", "", "comma-separated brief slugs or IDs (empty = all)")
		_ = fs.Parse(args[1:])
		if err := pub.BackfillMarkdownSlugs(parseSlugFilter(slugList)); err != nil {
			fmt.Fprintf(os.Stderr, "backfill failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Public Markdown backfill complete.")
	case "publish-stix":
		if err := pub.PublishSTIXBundle(); err != nil {
			fmt.Fprintf(os.Stderr, "STIX publish failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Validated STIX release published.")
	case "retire-briefs":
		pub.UseSegmented = true
		if err := runBundleRetireBriefs(pub, args[1:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "retirement failed: %v\n", err)
			os.Exit(1)
		}
	case "drift":
		drift, err := pub.CheckDriftMarkdown()
		if err != nil {
			fmt.Fprintf(os.Stderr, "drift check failed: %v\n", err)
			os.Exit(1)
		}
		if len(drift) == 0 {
			fmt.Println("No drift. Bundle and public Markdown are consistent.")
			return
		}
		fmt.Printf("Found %d drift entries:\n", len(drift))
		for _, d := range drift {
			fmt.Printf("  [%s] %s — %s\n", d.Reason, d.Path, d.BriefID)
		}
		os.Exit(2)
	case "enrich-vendors":
		fs := flag.NewFlagSet("enrich-vendors", flag.ExitOnError)
		var slugList string
		var dryRun bool
		fs.StringVar(&slugList, "slug", "", "comma-separated brief slugs to enrich (empty = all missing)")
		fs.BoolVar(&dryRun, "dry-run", false, "report changes without writing")
		_ = fs.Parse(args[1:])

		clients, err := buildLLMClients(cfg.LLM, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error building LLM client: %v\n", err)
			os.Exit(1)
		}
		pubLLM := publisher.New(cfg.Publish.RepoSlug, cfg.Publish.FeedPublicKey, ghTokenFn, logger, publicationSettings(cfg), publisher.WithLLMClient(clients.Primary))

		var slugs []string
		for _, s := range strings.Split(slugList, ",") {
			if s = strings.TrimSpace(s); s != "" {
				slugs = append(slugs, s)
			}
		}
		if err := pubLLM.EnrichVendorProduct(context.Background(), slugs, dryRun); err != nil {
			fmt.Fprintf(os.Stderr, "enrich failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Vendor/product enrichment complete.")
	}
}

type bundleRetirement struct {
	ID   string
	Slug string
}

type bundleRetirementList []bundleRetirement

func (r *bundleRetirementList) String() string {
	return fmt.Sprint(*r)
}

func (r *bundleRetirementList) Set(value string) error {
	id, slug, ok := strings.Cut(value, "=")
	id = strings.TrimSpace(id)
	slug = strings.TrimSpace(slug)
	if !ok || id == "" || slug == "" {
		return fmt.Errorf("retirement must use ID=SLUG")
	}
	*r = append(*r, bundleRetirement{ID: id, Slug: slug})
	return nil
}

type bundleRetirementPublisher interface {
	PublishedBriefExists(id string) (bool, error)
	RetireBrief(id, slug string) error
	Flush() error
}

func runBundleRetireBriefs(pub bundleRetirementPublisher, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("retire-briefs", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var survivorID string
	var retirements bundleRetirementList
	var apply bool
	fs.StringVar(&survivorID, "survivor-id", "", "published canonical brief ID that must survive")
	fs.Var(&retirements, "retire", "published duplicate in ID=SLUG form (repeatable)")
	fs.BoolVar(&apply, "apply", false, "apply the retirement; otherwise preview only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	survivorID = strings.TrimSpace(survivorID)
	if survivorID == "" {
		return fmt.Errorf("--survivor-id is required")
	}
	if len(retirements) == 0 {
		return fmt.Errorf("at least one --retire ID=SLUG is required")
	}
	seen := make(map[string]struct{}, len(retirements))
	for _, retirement := range retirements {
		if retirement.ID == survivorID {
			return fmt.Errorf("survivor %q cannot also be retired", survivorID)
		}
		if _, exists := seen[retirement.ID]; exists {
			return fmt.Errorf("duplicate retirement for %q", retirement.ID)
		}
		seen[retirement.ID] = struct{}{}
	}
	if !apply {
		if _, err := fmt.Fprintf(out, "Retirement preview: keep %s and retire %d duplicate(s). Re-run with --apply to publish.\n", survivorID, len(retirements)); err != nil {
			return err
		}
		return nil
	}
	if pub == nil {
		return fmt.Errorf("publisher is required when applying retirements")
	}
	published, err := pub.PublishedBriefExists(survivorID)
	if err != nil {
		return fmt.Errorf("checking survivor %q: %w", survivorID, err)
	}
	if !published {
		return fmt.Errorf("survivor %q is not published", survivorID)
	}
	for _, retirement := range retirements {
		if err := pub.RetireBrief(retirement.ID, retirement.Slug); err != nil {
			return fmt.Errorf("queuing retirement %q: %w", retirement.ID, err)
		}
	}
	if err := pub.Flush(); err != nil {
		return fmt.Errorf("publishing retirements: %w", err)
	}
	if _, err := fmt.Fprintf(out, "Retired %d duplicate(s); preserved %s.\n", len(retirements), survivorID); err != nil {
		return err
	}
	return nil
}

func bundleCommandValid(command string) bool {
	switch command {
	case "migrate", "repair-manifest", "backfill-markdown", "publish-stix", "drift", "enrich-vendors", "retire-briefs":
		return true
	default:
		return false
	}
}

func parseSlugFilter(raw string) []string {
	seen := make(map[string]struct{})
	var values []string
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}
