package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

// runDraftsNotifyUpdate previews, or with --send posts, the update
// notification an approved draft would send. It re-sends an update whose
// automatic dispatch was lost or reached no subscriber; the notifier queues
// it per subscription like any other update. Preview is the default.
func runDraftsNotifyUpdate(ctx context.Context, db *storage.DB, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("drafts notify-update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "approved draft ID")
	summary := fs.String("summary", "", "update summary shown to subscribers (required)")
	send := fs.Bool("send", false, "post the notification instead of previewing it")
	force := fs.Bool("force", false, "send even for a disputed or retracted brief, or within the notification cooldown")
	const usage = "usage: threat-bot drafts notify-update --id ID --summary TEXT [--send [--force]]"
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return fmt.Errorf("%s", usage)
	}
	if strings.TrimSpace(*id) == "" || strings.TrimSpace(*summary) == "" {
		return fmt.Errorf("%s", usage)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	draft, err := db.GetDraft(*id)
	if err != nil {
		return err
	}
	if draft.Status != storage.StatusApproved {
		return fmt.Errorf("draft %q is %s; only approved drafts notify", *id, draft.Status)
	}
	// The automatic path never notifies inactive rumours; neither does this
	// one without --force.
	var lifecycle struct {
		ClaimState string `yaml:"claim_state"`
	}
	_ = yaml.Unmarshal([]byte(draft.BriefYAML), &lifecycle)
	if state := strings.ToLower(strings.TrimSpace(lifecycle.ClaimState)); (state == "disputed" || state == "retracted") && !*force {
		return fmt.Errorf("draft %q is a %s claim; pass --force to notify anyway", *id, state)
	}
	// The automatic paths validate a draft before they notify; so does this
	// one. A draft that fails the publication contract cannot be the live
	// revision, so its fields may not match the page the notification links
	// to. Validation and projection are local: no token, no network.
	local := publisher.New(cfg.Publish.RepoSlug, cfg.Publish.FeedPublicKey, func() string { return "" },
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})), publicationSettings(cfg))
	if err := local.ValidatePublication(draft.BriefYAML); err != nil {
		return fmt.Errorf("draft %q fails the publication contract, so it may not be the live revision; correct it with drafts amend first: %w", *id, err)
	}
	brief, err := pipeline.UpdateNotification(draft.BriefYAML, strings.TrimSpace(*summary), cfg.Publish.SiteURL, local)
	if err != nil {
		return fmt.Errorf("building notification: %w", err)
	}
	encoded, err := json.MarshalIndent(brief, "", "  ")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "%s\n", encoded); err != nil {
		return err
	}
	cooldown := cfg.Notifier.Cooldown
	if cooldown <= 0 {
		cooldown = 6 * time.Hour
	}
	recent := false
	if draft.LastL3Dispatch != nil {
		ago := time.Since(*draft.LastL3Dispatch).Round(time.Minute)
		recent = ago < cooldown
		if _, err := fmt.Fprintf(out, "Last update notification: %s (%s ago).\n", draft.LastL3Dispatch.UTC().Format(time.RFC3339), ago); err != nil {
			return err
		}
	}
	if !*send {
		_, err := fmt.Fprintln(out, "Preview only. Rerun with --send to notify subscribers.")
		return err
	}
	if recent && !*force {
		return fmt.Errorf("an update notification for %q went out within the %s cooldown; pass --force to send again", *id, cooldown)
	}
	if err := pipeline.SendUpdateNotification(ctx, cfg.Notifier.URL, cfg.Notifier.DispatchToken, brief); err != nil {
		return fmt.Errorf("sending notification: %w", err)
	}
	if err := db.RecordL3Dispatch(draft.ID, time.Now().UTC()); err != nil {
		return fmt.Errorf("notification sent, but recording it failed: %w", err)
	}
	_, err = fmt.Fprintln(out, "Notification sent.")
	return err
}
