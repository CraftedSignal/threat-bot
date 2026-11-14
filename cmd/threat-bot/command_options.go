package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// Publication preflight and execution share these parsers so Go flag semantics
// (including every ParseBool spelling, repeated flags, and --) cannot diverge.
func commandFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

type draftApproveOptions struct {
	allAboveScore float64
	publish       bool
	ids           []string
}

func parseDraftApproveOptions(args []string) (draftApproveOptions, error) {
	var opts draftApproveOptions
	fs := commandFlagSet("drafts approve")
	fs.Float64Var(&opts.allAboveScore, "all-above-score", 0, "Approve all drafts above this score")
	fs.BoolVar(&opts.publish, "publish", false, "Publish approved drafts to the feed repo")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	opts.ids = fs.Args()
	if opts.allAboveScore <= 0 && len(opts.ids) == 0 {
		return opts, fmt.Errorf("usage: threat-bot drafts approve [--publish] <draft-id> OR --all-above-score N")
	}
	return opts, nil
}

type draftAmendOptions struct {
	id, file, setBriefID, setSlug   string
	expectSHA, expectProposedSHA    string
	backupDir, operator, reason     string
	apply, resolveIdentityCollision bool
}

func parseDraftAmendOptions(args []string) (draftAmendOptions, error) {
	var opts draftAmendOptions
	fs := commandFlagSet("drafts amend")
	fs.StringVar(&opts.id, "id", "", "Exact approved draft ID")
	fs.StringVar(&opts.file, "file", "", "Path to reviewed replacement YAML")
	fs.StringVar(&opts.setBriefID, "set-brief-id", "", "Set the public brief ID using the stored YAML as the replacement")
	fs.StringVar(&opts.setSlug, "set-slug", "", "Set the public slug using the stored YAML as the replacement")
	fs.BoolVar(&opts.apply, "apply", false, "Publish and save the amendment (default: preview only)")
	fs.StringVar(&opts.expectSHA, "expect-sha256", "", "SHA256 of current YAML shown in preview")
	fs.StringVar(&opts.expectProposedSHA, "expect-proposed-sha256", "", "SHA256 of replacement YAML shown in preview")
	fs.StringVar(&opts.backupDir, "backup-dir", "", "Directory for the original YAML backup")
	fs.StringVar(&opts.operator, "operator", "", "Operator responsible for the correction")
	fs.StringVar(&opts.reason, "reason", "", "Reason for the editorial correction")
	fs.BoolVar(&opts.resolveIdentityCollision, "resolve-unpublished-identity-collision", false, "Allow both brief ID and slug to change for a draft that never published because its generated identity collided")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	identityOnly := opts.setBriefID != "" || opts.setSlug != ""
	if opts.id == "" || fs.NArg() != 0 || (opts.file == "") == !identityOnly || (identityOnly && (opts.setBriefID == "" || opts.setSlug == "")) {
		return opts, fmt.Errorf("usage: threat-bot drafts amend --id ID (--file REVISED.yaml | --set-brief-id BRIEF_ID --set-slug SLUG) [--apply --expect-sha256 OLD_HASH --expect-proposed-sha256 NEW_HASH --backup-dir DIR --operator NAME --reason TEXT]")
	}
	return opts, nil
}

type draftRetirementOptions struct {
	canonicalID, operator, reason string
	duplicateIDs                  repeatedStringFlag
	apply                         bool
}

func parseDraftRetirementOptions(args []string) (draftRetirementOptions, error) {
	var opts draftRetirementOptions
	fs := commandFlagSet("drafts retire-duplicates")
	fs.StringVar(&opts.canonicalID, "canonical-id", "", "Approved draft ID that remains published")
	fs.Var(&opts.duplicateIDs, "duplicate-id", "Approved duplicate draft ID to retire (repeatable)")
	fs.BoolVar(&opts.apply, "apply", false, "Publish the removal and reject duplicate draft rows")
	fs.StringVar(&opts.operator, "operator", "", "Operator responsible for the consolidation")
	fs.StringVar(&opts.reason, "reason", "", "Audit reason for the consolidation")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if strings.TrimSpace(opts.canonicalID) == "" || len(opts.duplicateIDs) == 0 || fs.NArg() != 0 {
		return opts, fmt.Errorf("usage: threat-bot drafts retire-duplicates --canonical-id ID --duplicate-id ID [--duplicate-id ID] [--apply --operator NAME --reason TEXT]")
	}
	return opts, nil
}

type digestOptions struct {
	hours   int
	publish bool
}

func parseDigestOptions(args []string) (digestOptions, error) {
	var opts digestOptions
	if len(args) == 0 || args[0] != "generate" {
		return opts, fmt.Errorf("usage: threat-bot digests generate [--hours N] [--publish]")
	}
	fs := commandFlagSet("digests generate")
	fs.IntVar(&opts.hours, "hours", 24, "Lookback window in hours (default: 24)")
	fs.BoolVar(&opts.publish, "publish", false, "Publish digest to the feed repo")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, fmt.Errorf("unexpected digest arguments; flags must precede positional arguments")
	}
	return opts, nil
}
