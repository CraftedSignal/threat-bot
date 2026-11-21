package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"gopkg.in/yaml.v3"
)

func handleDrafts(db *storage.DB, pub *publisher.Publisher, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: threat-bot drafts <list|find|show|approve|reject|amend|republish|retire-duplicates|notify-update>")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		handleDraftsList(db, args[1:])
	case "notify-update":
		if err := runDraftsNotifyUpdate(context.Background(), db, args[1:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "find":
		if err := runDraftsFind(db, args[1:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "show":
		handleDraftsShow(db, args[1:])
	case "approve":
		handleDraftsApprove(db, pub, args[1:])
	case "reject":
		handleDraftsReject(db, args[1:])
	case "republish":
		handleDraftsRepublish(db, pub, args[1:])
	case "amend":
		var amendPub draftAmendPublisher
		if pub != nil {
			amendPub = pub
		}
		if err := runDraftsAmend(db, amendPub, args[1:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "retire-duplicates":
		if err := runDraftsRetireDuplicates(db, pub, args[1:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown drafts command: %s\n", args[0])
		os.Exit(1)
	}
}

type duplicateRetirementPublisher interface {
	Publish(string) error
	RetireBrief(string, string) error
	Flush() error
}

// flushRejection reports whether the publisher's last flush dropped a brief
// whose revision was rejected. Flush returns nil in that case so one bad brief
// cannot block a whole release, but callers publishing a specific brief must
// treat the drop as a failure.
func flushRejection(pub any, briefID string) error {
	r, ok := pub.(interface{ RejectedBriefIDs() []string })
	if !ok {
		return nil
	}
	if slices.Contains(r.RejectedBriefIDs(), briefID) {
		return fmt.Errorf("publisher rejected the revision of brief %s", briefID)
	}
	return nil
}

type repeatedStringFlag []string

func (f *repeatedStringFlag) String() string { return strings.Join(*f, ",") }

func (f *repeatedStringFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*f = append(*f, value)
	return nil
}

// runDraftsRetireDuplicates removes already-published duplicate identities
// while republishing the surviving canonical snapshot in the same atomic feed
// release. It previews by default because removal affects encrypted segments,
// Markdown, indexes, and STIX artifacts.
func runDraftsRetireDuplicates(db *storage.DB, pub duplicateRetirementPublisher, args []string, out io.Writer) error {
	opts, err := parseDraftRetirementOptions(args)
	if err != nil {
		return err
	}
	canonicalID, duplicateIDs := &opts.canonicalID, opts.duplicateIDs
	apply, operator, reason := &opts.apply, &opts.operator, &opts.reason
	canonical, err := db.GetDraft(*canonicalID)
	if err != nil {
		return err
	}
	if canonical.Status != storage.StatusApproved {
		return fmt.Errorf("canonical draft %q is %s, want approved", *canonicalID, canonical.Status)
	}
	canonicalBrief, err := publisher.ParseBriefYAML(canonical.BriefYAML)
	if err != nil {
		return fmt.Errorf("parsing canonical draft %q: %w", *canonicalID, err)
	}
	type retirement struct {
		draftID string
		briefID string
		slug    string
	}
	retirements := make([]retirement, 0, len(duplicateIDs))
	seen := map[string]bool{*canonicalID: true}
	for _, duplicateID := range duplicateIDs {
		if seen[duplicateID] {
			return fmt.Errorf("draft %q was supplied more than once or is the canonical draft", duplicateID)
		}
		seen[duplicateID] = true
		duplicate, err := db.GetDraft(duplicateID)
		if err != nil {
			return err
		}
		if duplicate.Status != storage.StatusApproved {
			return fmt.Errorf("duplicate draft %q is %s, want approved", duplicateID, duplicate.Status)
		}
		brief, err := publisher.ParseBriefYAML(duplicate.BriefYAML)
		if err != nil {
			return fmt.Errorf("parsing duplicate draft %q: %w", duplicateID, err)
		}
		if brief.ID == canonicalBrief.ID || brief.Slug == canonicalBrief.Slug {
			return fmt.Errorf("duplicate draft %q shares the canonical ID or slug", duplicateID)
		}
		retirements = append(retirements, retirement{draftID: duplicateID, briefID: brief.ID, slug: brief.Slug})
	}
	if _, err := fmt.Fprintf(out, "Canonical: %s (%s, %s)\n", *canonicalID, canonicalBrief.ID, canonicalBrief.Slug); err != nil {
		return err
	}
	for _, duplicate := range retirements {
		if _, err := fmt.Fprintf(out, "Retire: %s (%s, %s)\n", duplicate.draftID, duplicate.briefID, duplicate.slug); err != nil {
			return err
		}
	}
	if !*apply {
		if _, err := fmt.Fprintln(out, "Preview only. Amend the canonical brief first if needed, then rerun with --apply, --operator, and --reason."); err != nil {
			return err
		}
		return nil
	}
	if pub == nil {
		return fmt.Errorf("--apply requires publish config")
	}
	if strings.TrimSpace(*operator) == "" || strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("--operator and --reason are required with --apply")
	}
	if err := pub.Publish(canonical.BriefYAML); err != nil {
		return fmt.Errorf("buffering canonical brief: %w", err)
	}
	for _, duplicate := range retirements {
		var err error
		if durable, ok := pub.(interface {
			RetireBriefForDrafts(id, slug, canonicalID, draftID, canonicalDraftID string) error
		}); ok {
			err = durable.RetireBriefForDrafts(duplicate.briefID, duplicate.slug, canonicalBrief.ID, duplicate.draftID, *canonicalID)
		} else if favour, ok := pub.(interface {
			RetireBriefInFavourOf(id, slug, canonicalID string) error
		}); ok {
			err = favour.RetireBriefInFavourOf(duplicate.briefID, duplicate.slug, canonicalBrief.ID)
		} else {
			err = pub.RetireBrief(duplicate.briefID, duplicate.slug)
		}
		if err != nil {
			return err
		}
	}
	if err := pub.Flush(); err != nil {
		return fmt.Errorf("publishing duplicate retirement: %w", err)
	}
	if err := flushRejection(pub, canonicalBrief.ID); err != nil {
		return fmt.Errorf("canonical brief not published; duplicates left in place: %w", err)
	}
	duplicateDraftIDs := make([]string, 0, len(retirements))
	for _, duplicate := range retirements {
		duplicateDraftIDs = append(duplicateDraftIDs, duplicate.draftID)
	}
	auditReason := fmt.Sprintf("consolidated into %s by %s: %s", canonicalBrief.ID, strings.TrimSpace(*operator), strings.TrimSpace(*reason))
	if err := db.ConsolidateApprovedDrafts(*canonicalID, duplicateDraftIDs, auditReason); err != nil {
		return fmt.Errorf("feed updated but duplicate draft rows were not consolidated: %w", err)
	}
	if _, err := fmt.Fprintf(out, "Published canonical brief and retired %d duplicate(s).\n", len(retirements)); err != nil {
		return err
	}
	return nil
}

// runDraftsFind locates approved drafts by their public slug. Draft rows are
// streamed so a full feed search does not retain every YAML record in memory.
func runDraftsFind(db *storage.DB, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("drafts find", flag.ContinueOnError)
	slug := fs.String("slug", "", "Exact public brief slug")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" || len(fs.Args()) != 0 {
		return fmt.Errorf("usage: threat-bot drafts find --slug SLUG")
	}
	matches := 0
	skipped := 0
	for draft, err := range db.DraftsWithStatus(storage.StatusApproved) {
		if err != nil {
			return fmt.Errorf("listing approved drafts: %w", err)
		}
		brief, err := publisher.ParseBriefYAML(draft.BriefYAML)
		if err != nil {
			skipped++
			continue
		}
		if brief.Slug != *slug {
			continue
		}
		if _, err := fmt.Fprintf(out, "Draft ID: %s\nBrief ID: %s\nTitle: %s\nStatus: %s\n", draft.ID, brief.ID, brief.Title, draft.Status); err != nil {
			return err
		}
		matches++
	}
	if matches == 0 {
		if _, err := fmt.Fprintf(out, "No approved drafts with slug %q.\n", *slug); err != nil {
			return err
		}
	}
	if skipped > 0 {
		if _, err := fmt.Fprintf(out, "Skipped %d approved draft(s) with invalid brief YAML.\n", skipped); err != nil {
			return err
		}
	}
	return nil
}

// draftAmendPublisher keeps the amendment path testable without a GitHub
// connection. Production always supplies the configured segmented publisher.
type draftAmendPublisher interface {
	Publish(briefYAML string) error
	Flush() error
}

// runDraftsAmend previews or publishes one approved draft. The old YAML is
// backed up and the remote feed is flushed before updating SQLite. A remote
// failure leaves the stored draft unchanged, so the same edit can be retried.
func runDraftsAmend(db *storage.DB, pub draftAmendPublisher, args []string, out io.Writer) error {
	opts, err := parseDraftAmendOptions(args)
	if err != nil {
		return err
	}
	id, file, setBriefID, setSlug := &opts.id, &opts.file, &opts.setBriefID, &opts.setSlug
	apply, resolveIdentityCollision := &opts.apply, &opts.resolveIdentityCollision
	expectSHA, expectProposedSHA := &opts.expectSHA, &opts.expectProposedSHA
	backupDir, operator, reason := &opts.backupDir, &opts.operator, &opts.reason
	draft, err := db.GetDraft(*id)
	if err != nil {
		return err
	}
	if draft.Status != storage.StatusApproved {
		return fmt.Errorf("draft %q is %s; only approved drafts can be amended", *id, draft.Status)
	}
	var revisedBytes []byte
	if *file != "" {
		revisedBytes, err = os.ReadFile(*file)
		if err != nil {
			return fmt.Errorf("reading replacement YAML: %w", err)
		}
	} else {
		var document map[string]any
		if err := yaml.Unmarshal([]byte(draft.BriefYAML), &document); err != nil {
			return fmt.Errorf("parsing stored YAML for identity repair: %w", err)
		}
		document["id"] = strings.TrimSpace(*setBriefID)
		document["slug"] = strings.TrimSpace(*setSlug)
		revisedBytes, err = yaml.Marshal(document)
		if err != nil {
			return fmt.Errorf("encoding identity repair: %w", err)
		}
	}
	if strings.TrimSpace(string(revisedBytes)) == "" {
		return fmt.Errorf("replacement YAML is empty")
	}
	current, err := publisher.ParseBriefYAML(draft.BriefYAML)
	if err != nil {
		return fmt.Errorf("parsing stored brief: %w", err)
	}
	revised, err := publisher.ParseBriefYAML(string(revisedBytes))
	if err != nil {
		return fmt.Errorf("parsing replacement brief: %w", err)
	}
	idChanged := current.ID == "" || revised.ID != current.ID
	slugChanged := current.Slug == "" || revised.Slug != current.Slug
	if idChanged || slugChanged {
		if !*resolveIdentityCollision {
			if idChanged {
				return fmt.Errorf("published brief ID must remain %q (replacement %q)", current.ID, revised.ID)
			}
			return fmt.Errorf("public slug must remain %q (replacement %q)", current.Slug, revised.Slug)
		}
		if !idChanged || !slugChanged {
			return fmt.Errorf("resolving an unpublished identity collision requires changing both brief ID and public slug")
		}
		currentPublished, currentErr := time.Parse(time.RFC3339, current.PublishedAt)
		revisedPublished, revisedErr := time.Parse(time.RFC3339, revised.PublishedAt)
		if currentErr != nil || revisedErr != nil || !currentPublished.Equal(revisedPublished) {
			return fmt.Errorf("resolving an unpublished identity collision must preserve published_at %q", current.PublishedAt)
		}
	}
	if revised.Title == "" {
		return fmt.Errorf("replacement brief needs a title")
	}
	if _, err := time.Parse(time.RFC3339, revised.PublishedAt); err != nil {
		return fmt.Errorf("replacement published_at must be RFC3339: %w", err)
	}
	var revisedLastmod *time.Time
	if revised.Lastmod != "" {
		parsed, err := time.Parse(time.RFC3339, revised.Lastmod)
		if err != nil {
			return fmt.Errorf("replacement lastmod must be RFC3339: %w", err)
		}
		revisedLastmod = &parsed
	}
	lastmodForApply := revised.Lastmod
	if lastmodForApply == "" {
		lastmodForApply = "(set to apply time in UTC)"
	}
	for _, update := range revised.UpdateLog {
		if _, err := time.Parse(time.RFC3339, update.At); err != nil {
			return fmt.Errorf("replacement update timestamp must be RFC3339: %w", err)
		}
	}
	var revisedUpdateLog string
	if len(revised.UpdateLog) > 0 {
		encoded, err := json.Marshal(revised.UpdateLog)
		if err != nil {
			return fmt.Errorf("encoding replacement updates: %w", err)
		}
		revisedUpdateLog = string(encoded)
	}
	currentSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(draft.BriefYAML)))
	revisedSHA := fmt.Sprintf("%x", sha256.Sum256(revisedBytes))
	if _, err := fmt.Fprintf(out, "Draft: %s\nPublished brief: %s -> %s\nPublic slug: %s -> %s\nTitle: %s -> %s\nPublished: %s -> %s\nLastmod: %s -> %s\nUpdates: %d -> %d\nCurrent SHA256: %s\nProposed SHA256: %s\n", *id, current.ID, revised.ID, current.Slug, revised.Slug, current.Title, revised.Title, current.PublishedAt, revised.PublishedAt, current.Lastmod, lastmodForApply, len(current.UpdateLog), len(revised.UpdateLog), currentSHA, revisedSHA); err != nil {
		return err
	}
	if !*apply {
		if _, err := fmt.Fprintln(out, "Preview only. Review the YAML diff, then rerun with --apply, both SHA256 values, --backup-dir, --operator, and --reason."); err != nil {
			return err
		}
		return nil
	}
	if pub == nil {
		return fmt.Errorf("--apply requires publish config (repo_slug and feed_public_key) in config.yaml")
	}
	if *expectSHA == "" || !strings.EqualFold(*expectSHA, currentSHA) {
		return fmt.Errorf("--expect-sha256 must match the current YAML hash shown in preview")
	}
	if *expectProposedSHA == "" || !strings.EqualFold(*expectProposedSHA, revisedSHA) {
		return fmt.Errorf("--expect-proposed-sha256 must match the replacement YAML hash shown in preview")
	}
	if *backupDir == "" {
		return fmt.Errorf("--backup-dir is required with --apply")
	}
	if strings.TrimSpace(*operator) == "" || strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("--operator and --reason are required with --apply")
	}
	if currentSHA == revisedSHA {
		return fmt.Errorf("replacement YAML is identical to stored YAML")
	}
	if revised.Lastmod == "" {
		revisedBytes, err = addAmendLastmod(revisedBytes, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("setting amendment lastmod: %w", err)
		}
		revised, err = publisher.ParseBriefYAML(string(revisedBytes))
		if err != nil {
			return fmt.Errorf("parsing amended YAML with lastmod: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339, revised.Lastmod)
		if err != nil {
			return fmt.Errorf("generated lastmod is invalid: %w", err)
		}
		revisedLastmod = &parsed
	}
	// A second read narrows the race between preview validation and remote
	// publication. The final compare-and-swap in SQLite closes it locally.
	latest, err := db.GetDraft(*id)
	if err != nil {
		return err
	}
	if latest.Status != storage.StatusApproved || latest.BriefYAML != draft.BriefYAML {
		return fmt.Errorf("draft %q changed during amendment; preview it again", *id)
	}
	backupPath, err := backupDraftYAML(*backupDir, *id, draft.BriefYAML)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Original YAML backed up to %s\n", backupPath); err != nil {
		return err
	}
	if err := pub.Publish(string(revisedBytes)); err != nil {
		return fmt.Errorf("buffering corrected brief (stored YAML unchanged): %w", err)
	}
	if err := pub.Flush(); err != nil {
		return fmt.Errorf("publishing corrected brief failed; remote publication may be partial, stored YAML unchanged (backup %s): %w", backupPath, err)
	}
	if err := flushRejection(pub, revised.ID); err != nil {
		return fmt.Errorf("corrected brief was not published, stored YAML unchanged (backup %s): %w", backupPath, err)
	}
	if err := db.ApplyEditorialCorrection(storage.EditorialCorrection{
		DraftID: *id, BriefID: revised.ID, PreviousYAML: draft.BriefYAML, RevisedYAML: string(revisedBytes),
		RevisedLastmod: revisedLastmod, RevisedUpdateLog: revisedUpdateLog, RevisedUpdateCount: len(revised.UpdateLog),
		Operator: *operator, Reason: *reason, BackupPath: backupPath,
	}); err != nil {
		return fmt.Errorf("remote feed published but stored draft was not updated; inspect and retry from backup %s: %w", backupPath, err)
	}
	if _, err := fmt.Fprintf(out, "Published and saved corrected brief %s. Verify the public Markdown and encrypted bundle.\n", *id); err != nil {
		return err
	}
	return nil
}

// addAmendLastmod stamps an amended public brief without reformatting its YAML.
// The CLI hashes the operator-reviewed input before calling this helper, so a
// generated timestamp does not make preview/apply hashes drift.
func addAmendLastmod(raw []byte, at time.Time) ([]byte, error) {
	text := string(raw)
	lines := strings.SplitAfter(text, "\n")
	offset := 0
	for _, line := range lines {
		value := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.HasPrefix(value, "published_at:") {
			ending := "\n"
			if strings.HasSuffix(line, "\r\n") {
				ending = "\r\n"
			} else if !strings.HasSuffix(line, "\n") {
				ending = "\n"
			}
			insert := "lastmod: \"" + at.UTC().Format(time.RFC3339) + "\"" + ending
			if !strings.HasSuffix(line, "\n") {
				insert = ending + insert
			}
			result := make([]byte, 0, len(raw)+len(insert))
			result = append(result, raw[:offset+len(line)]...)
			result = append(result, insert...)
			result = append(result, raw[offset+len(line):]...)
			return result, nil
		}
		offset += len(line)
	}
	return nil, fmt.Errorf("replacement YAML has no top-level published_at field")
}

func backupDraftYAML(dir, id, original string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating backup directory: %w", err)
	}
	safeID := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, id)
	f, err := os.CreateTemp(dir, safeID+"-*.yaml")
	if err != nil {
		return "", fmt.Errorf("creating draft backup: %w", err)
	}
	path := filepath.Clean(f.Name())
	if _, err := io.WriteString(f, original); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("writing draft backup: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("syncing draft backup: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("closing draft backup: %w", err)
	}
	return path, nil
}

func handleDraftsList(db *storage.DB, args []string) {
	fs := flag.NewFlagSet("drafts list", flag.ExitOnError)
	status := fs.String("status", "pending", "Filter by status: pending, approved, rejected")
	_ = fs.Parse(args) // ExitOnError terminates before Parse can return an error.

	count := 0
	for d, err := range db.DraftsWithStatus(*status) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if count == 0 {
			fmt.Printf("%-40s %-8s %-15s %-20s\n", "ID", "Score", "Source", "Created")
			fmt.Println(strings.Repeat("-", 85))
		}
		count++
		title := extractYAMLField(d.BriefYAML, "title")
		fmt.Printf("%-40s %.1f     %-15s %s\n", d.ID, d.Score, d.Source, d.CreatedAt.Format("2006-01-02 15:04"))
		if title != "" {
			fmt.Printf("  %s\n", title)
		}
	}

	if count == 0 {
		fmt.Printf("No %s drafts.\n", *status)
		return
	}
	fmt.Printf("\n%d draft(s)\n", count)
}

func handleDraftsShow(db *storage.DB, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: threat-bot drafts show <draft-id>")
		os.Exit(1)
	}

	draft, err := db.GetDraft(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Draft: %s\n", draft.ID)
	fmt.Printf("Status: %s\n", draft.Status)
	fmt.Printf("Score: %.1f\n", draft.Score)
	fmt.Printf("Source: %s\n", draft.Source)
	fmt.Printf("Created: %s\n", draft.CreatedAt.Format("2006-01-02 15:04:05"))
	if draft.RejectReason != "" {
		fmt.Printf("Reject Reason: %s\n", draft.RejectReason)
	}
	if draft.ValidationNotes != "" {
		fmt.Printf("Validation Notes: %s\n", draft.ValidationNotes)
	}
	fmt.Println("\n--- Brief YAML ---")
	fmt.Println(draft.BriefYAML)
}

func handleDraftsApprove(db *storage.DB, pub *publisher.Publisher, args []string) {
	opts, err := parseDraftApproveOptions(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	allAboveScore, publish := &opts.allAboveScore, &opts.publish

	if *publish && pub == nil {
		fmt.Fprintln(os.Stderr, "error: --publish requires publish config (repo_slug and feed_public_key) in config.yaml")
		os.Exit(1)
	}

	var published int
	bufferForPublish := func(id, briefYAML string) {
		if err := pub.Publish(briefYAML); err != nil {
			fmt.Fprintf(os.Stderr, "error buffering %s for publish: %v\n", id, err)
			return
		}
		published++
		if published%publishBatchSize == 0 {
			flushPublished(pub)
		}
	}

	if *allAboveScore > 0 {
		var ids []string
		for d, err := range db.DraftsWithStatus(storage.StatusPending) {
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			if d.Score >= *allAboveScore {
				ids = append(ids, d.ID)
			}
		}
		count := 0
		for _, id := range ids {
			d, err := db.GetDraft(id)
			if err != nil || d == nil {
				fmt.Fprintf(os.Stderr, "error fetching draft %s: %v\n", id, err)
				continue
			}
			if err := db.UpdateDraftStatus(d.ID, storage.StatusApproved, ""); err != nil {
				fmt.Fprintf(os.Stderr, "error approving %s: %v\n", d.ID, err)
				continue
			}
			harvestGoldenExamples(db, d.BriefYAML, d.Source)
			title := extractYAMLField(d.BriefYAML, "title")
			fmt.Printf("Approved: %s (score: %.1f) %s\n", d.ID, d.Score, title)
			count++

			if *publish {
				bufferForPublish(d.ID, d.BriefYAML)
			}
		}
		fmt.Printf("\n%d draft(s) approved\n", count)
	} else {
		remaining := opts.ids
		if len(remaining) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: threat-bot drafts approve <draft-id> OR --all-above-score N")
			os.Exit(1)
		}

		for _, id := range remaining {
			if err := db.UpdateDraftStatus(id, storage.StatusApproved, ""); err != nil {
				fmt.Fprintf(os.Stderr, "error approving %s: %v\n", id, err)
				continue
			}
			fmt.Printf("Approved: %s\n", id)

			draft, err := db.GetDraft(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error fetching draft %s: %v\n", id, err)
				continue
			}
			harvestGoldenExamples(db, draft.BriefYAML, draft.Source)

			if *publish {
				bufferForPublish(id, draft.BriefYAML)
			}
		}
	}

	if *publish && published > 0 {
		fmt.Printf("Flushing %d brief(s) to threat-feed repo...\n", published)
		flushPublished(pub)
		fmt.Printf("Published %d brief(s) successfully.\n", published)
	}
}

// publishBatchSize bounds how many briefs the publisher buffers before a
// flush, so bulk approvals and republishes never hold every brief at once.
const publishBatchSize = 100

func flushPublished(pub *publisher.Publisher) {
	if err := pub.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "error publishing to threat-feed: %v\n", err)
		os.Exit(1)
	}
}

func handleDraftsReject(db *storage.DB, args []string) {
	ids, reason, err := parseRejectArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Usage: threat-bot drafts reject <draft-id> [--reason '...']")
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	failed := false
	for _, id := range ids {
		if err := db.UpdateDraftStatus(id, storage.StatusRejected, reason); err != nil {
			fmt.Fprintf(os.Stderr, "error rejecting %s: %v\n", id, err)
			failed = true
			continue
		}
		fmt.Printf("Rejected: %s\n", id)
	}
	if failed {
		os.Exit(1)
	}
}

func parseRejectArgs(args []string) ([]string, string, error) {
	var ids []string
	var reason string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--reason":
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" || strings.HasPrefix(args[i+1], "-") {
				return nil, "", fmt.Errorf("--reason requires a value")
			}
			i++
			reason = args[i]
		case strings.HasPrefix(args[i], "--reason="):
			reason = strings.TrimPrefix(args[i], "--reason=")
			if strings.TrimSpace(reason) == "" {
				return nil, "", fmt.Errorf("--reason requires a value")
			}
		case strings.HasPrefix(args[i], "-"):
			return nil, "", fmt.Errorf("unknown flag %q", args[i])
		default:
			ids = append(ids, args[i])
		}
	}
	if len(ids) == 0 {
		return nil, "", fmt.Errorf("at least one draft ID is required")
	}
	return ids, reason, nil
}

func handleDraftsRepublish(db *storage.DB, pub *publisher.Publisher, args []string) {
	if pub == nil {
		fmt.Fprintln(os.Stderr, "error: republish requires publish config (repo_slug and feed_public_key) in config.yaml")
		os.Exit(1)
	}
	fs := flag.NewFlagSet("drafts republish", flag.ExitOnError)
	sinceRaw := fs.String("since", "", "Republish approved drafts created at or after this RFC3339 timestamp")
	excludeID := fs.String("exclude-id", "", "Skip one approved draft ID")
	onlyID := fs.String("id", "", "Republish one approved draft ID")
	_ = fs.Parse(args) // ExitOnError terminates before Parse can return an error.
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "usage: threat-bot drafts republish [--id ID | --since RFC3339 [--exclude-id ID]]")
		os.Exit(1)
	}
	if *onlyID != "" && (*sinceRaw != "" || *excludeID != "") {
		fmt.Fprintln(os.Stderr, "error: --id cannot be combined with --since or --exclude-id")
		os.Exit(1)
	}
	var since time.Time
	if *sinceRaw != "" {
		var err error
		since, err = time.Parse(time.RFC3339, *sinceRaw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --since: %v\n", err)
			os.Exit(1)
		}
	}

	ids, err := republishDraftIDs(db, since, *excludeID, *onlyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error selecting approved drafts: %v\n", err)
		os.Exit(1)
	}

	if len(ids) == 0 {
		fmt.Println("No approved drafts to republish.")
		return
	}

	fmt.Printf("Republishing %d approved draft(s) to bundle...\n", len(ids))
	published := 0
	for _, id := range ids {
		d, err := db.GetDraft(id)
		if err != nil || d == nil {
			fmt.Fprintf(os.Stderr, "error fetching %s: %v\n", id, err)
			continue
		}
		if err := pub.Publish(d.BriefYAML); err != nil {
			fmt.Fprintf(os.Stderr, "error buffering %s: %v\n", d.ID, err)
			continue
		}
		published++
		if published%publishBatchSize == 0 {
			flushRepublished(pub)
		}
	}

	if published > 0 {
		flushRepublished(pub)
		fmt.Printf("Published %d brief(s) to bundle.\n", published)
	}
}

// republishDraftIDs limits recovery to a chosen window while preserving the
// default full republish behavior for deliberate maintenance.
func republishDraftIDs(db *storage.DB, since time.Time, excludeID, onlyID string) ([]string, error) {
	if onlyID != "" {
		draft, err := db.GetDraft(onlyID)
		if err != nil {
			return nil, err
		}
		if draft.Status != storage.StatusApproved {
			return nil, fmt.Errorf("draft %q is %s; only approved drafts can be republished", onlyID, draft.Status)
		}
		return []string{onlyID}, nil
	}
	// Collect IDs first and load one draft at a time, so neither the
	// approved set nor its briefs are held in memory at once.
	var ids []string
	rows := db.DraftsWithStatus(storage.StatusApproved)
	if !since.IsZero() {
		rows = db.ApprovedDraftsSince(since)
	}
	for d, err := range rows {
		if err != nil {
			return nil, err
		}
		if d.ID == excludeID {
			continue
		}
		ids = append(ids, d.ID)
	}
	return ids, nil
}

func flushRepublished(pub *publisher.Publisher) {
	if err := pub.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "error flushing bundle: %v\n", err)
		os.Exit(1)
	}
}

// harvestGoldenExamples records each TTP (technique, evidence) pair from an
// approved brief into the golden corpus. Best-effort: parse/store failures are
// ignored so they never block approval.
func harvestGoldenExamples(db *storage.DB, briefYAML, source string) {
	brief, err := publisher.ParseBriefYAML(briefYAML)
	if err != nil {
		return
	}
	for _, ttp := range brief.TTPs {
		if ttp.Evidence == "" || ttp.TechniqueID == "" {
			continue
		}
		_ = db.AddGoldenExample(ttp.TechniqueID, ttp.Evidence, source)
	}
}

func extractYAMLField(yamlContent, field string) string {
	for _, line := range strings.Split(yamlContent, "\n") {
		trimmed := strings.TrimSpace(line)
		prefix := field + ":"
		if strings.HasPrefix(trimmed, prefix) {
			val := strings.TrimSpace(trimmed[len(prefix):])
			val = strings.Trim(val, "\"'")
			return val
		}
	}
	return ""
}
