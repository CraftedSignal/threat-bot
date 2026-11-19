package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/pipeline"
	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/storage"
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
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return fmt.Errorf("usage: threat-bot drafts notify-update --id ID --summary TEXT [--send]")
	}
	if strings.TrimSpace(*id) == "" || strings.TrimSpace(*summary) == "" {
		return fmt.Errorf("usage: threat-bot drafts notify-update --id ID --summary TEXT [--send]")
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
	var projector *publisher.Publisher // the projection needs no publisher state
	brief, err := pipeline.UpdateNotification(draft.BriefYAML, strings.TrimSpace(*summary), cfg.Publish.SiteURL, projector)
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
	if !*send {
		_, err := fmt.Fprintln(out, "Preview only. Rerun with --send to notify subscribers.")
		return err
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
