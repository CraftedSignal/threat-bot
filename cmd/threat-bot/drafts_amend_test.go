package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/publisher"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

const amendOriginalYAML = "id: brief-1\nslug: 2024-01-example\ntitle: Old title\npublished_at: 2024-01-01T00:00:00Z\n"
const amendRevisedYAML = "id: brief-1\nslug: 2024-01-example\ntitle: Example product advisory\npublished_at: 2026-04-08T00:00:00Z\nlastmod: 2026-04-08T00:00:00Z\n"
const amendDraftID = "4df6072c-298e-4a59-86c0-c37c6e02ce05"

type amendPublisherFake struct {
	published []string
	flushes   int
	flushErr  error
}

func (f *amendPublisherFake) Publish(yaml string) error {
	f.published = append(f.published, yaml)
	return nil
}

func (f *amendPublisherFake) Flush() error {
	f.flushes++
	return f.flushErr
}

func setupAmendDraft(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "drafts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.CreateDraft(&storage.Draft{
		ID: amendDraftID, Status: storage.StatusApproved, Source: "test",
		BriefYAML: amendOriginalYAML, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

func writeAmendFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revised.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDraftAmendPreviewDoesNotPublishOrMutate(t *testing.T) {
	db := setupAmendDraft(t)
	file := writeAmendFile(t, amendRevisedYAML)
	var output bytes.Buffer
	if err := runDraftsAmend(db, nil, []string{"--id", amendDraftID, "--file", file}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Current SHA256:") || !strings.Contains(output.String(), "Example product advisory") {
		t.Fatalf("preview lacks review details: %s", output.String())
	}
	draft, err := db.GetDraft(amendDraftID)
	if err != nil || draft.BriefYAML != amendOriginalYAML {
		t.Fatalf("preview changed draft: %+v, %v", draft, err)
	}
}

func TestDraftAmendApplyBacksUpPublishesThenUpdatesSelectedDraft(t *testing.T) {
	db := setupAmendDraft(t)
	file := writeAmendFile(t, amendRevisedYAML)
	backupDir := filepath.Join(t.TempDir(), "backups")
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(amendOriginalYAML)))
	proposedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(amendRevisedYAML)))
	pub := &amendPublisherFake{}
	var output bytes.Buffer
	if err := runDraftsAmend(db, pub, []string{
		"--id", amendDraftID, "--file", file, "--apply",
		"--expect-sha256", hash, "--expect-proposed-sha256", proposedHash, "--backup-dir", backupDir,
		"--operator", "analyst@example.com", "--reason", "Correct product mapping",
	}, &output); err != nil {
		t.Fatal(err)
	}
	if len(pub.published) != 1 || pub.published[0] != amendRevisedYAML || pub.flushes != 1 {
		t.Fatalf("publisher calls: %+v", pub)
	}
	draft, err := db.GetDraft(amendDraftID)
	if err != nil || draft.BriefYAML != amendRevisedYAML {
		t.Fatalf("revised draft: %+v, %v", draft, err)
	}
	backups, err := filepath.Glob(filepath.Join(backupDir, "*.yaml"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backup files: %v, %v", backups, err)
	}
	content, err := os.ReadFile(backups[0])
	if err != nil || string(content) != amendOriginalYAML {
		t.Fatalf("backup content: %q, %v", content, err)
	}
	info, err := os.Stat(backups[0])
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup permission: %+v, %v", info, err)
	}
}

func TestDraftAmendApplySetsLastmodWhenReplacementOmitsIt(t *testing.T) {
	db := setupAmendDraft(t)
	revised := strings.Replace(amendRevisedYAML, "lastmod: 2026-04-08T00:00:00Z\n", "", 1)
	if strings.Contains(revised, "lastmod:") {
		t.Fatal("fixture must omit lastmod")
	}
	file := writeAmendFile(t, revised)
	pub := &amendPublisherFake{}
	start := time.Now().UTC().Add(-time.Second)
	var output bytes.Buffer
	if err := runDraftsAmend(db, pub, []string{
		"--id", amendDraftID, "--file", file, "--apply",
		"--expect-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(amendOriginalYAML))),
		"--expect-proposed-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(revised))),
		"--backup-dir", t.TempDir(), "--operator", "analyst", "--reason", "Correct public content",
	}, &output); err != nil {
		t.Fatal(err)
	}
	if len(pub.published) != 1 {
		t.Fatalf("published %d briefs, want 1", len(pub.published))
	}
	brief, err := publisher.ParseBriefYAML(pub.published[0])
	if err != nil {
		t.Fatal(err)
	}
	lastmod, err := time.Parse(time.RFC3339, brief.Lastmod)
	if err != nil || lastmod.Before(start) || lastmod.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("published lastmod = %q, err=%v; want current UTC time", brief.Lastmod, err)
	}
	draft, err := db.GetDraft(amendDraftID)
	if err != nil || draft.Lastmod == nil || !draft.Lastmod.Equal(lastmod) || draft.BriefYAML != pub.published[0] {
		t.Fatalf("stored lastmod/YAML do not match published correction: draft=%+v err=%v", draft, err)
	}
}

func TestDraftAmendRejectsUnsafeInputsBeforePublishing(t *testing.T) {
	cases := []struct {
		name    string
		content string
		args    []string
	}{
		{"changed id", strings.Replace(amendRevisedYAML, "id: brief-1", "id: other", 1), nil},
		{"changed slug", strings.Replace(amendRevisedYAML, "slug: 2024-01-example", "slug: other", 1), nil},
		{"unreviewed hash", amendRevisedYAML, []string{"--expect-sha256", strings.Repeat("0", 64)}},
		{"unreviewed proposed hash", amendRevisedYAML, []string{"--expect-proposed-sha256", strings.Repeat("0", 64)}},
		{"missing operator", amendRevisedYAML, []string{"--operator", ""}},
		{"missing reason", amendRevisedYAML, []string{"--reason", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupAmendDraft(t)
			file := writeAmendFile(t, tc.content)
			pub := &amendPublisherFake{}
			args := []string{"--id", amendDraftID, "--file", file, "--apply", "--backup-dir", t.TempDir(), "--expect-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(amendOriginalYAML))), "--expect-proposed-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(amendRevisedYAML))), "--operator", "analyst", "--reason", "Correct product mapping"}
			args = append(args, tc.args...)
			if err := runDraftsAmend(db, pub, args, &bytes.Buffer{}); err == nil {
				t.Fatal("expected validation error")
			}
			if len(pub.published) != 0 || pub.flushes != 0 {
				t.Fatalf("published unsafe edit: %+v", pub)
			}
		})
	}
}

func TestDraftAmendCanResolveUnpublishedIdentityCollision(t *testing.T) {
	db := setupAmendDraft(t)
	rekeyed := strings.ReplaceAll(amendOriginalYAML, "brief-1", "brief-2024-01-01-example")
	rekeyed = strings.Replace(rekeyed, "slug: 2024-01-example", "slug: 2024-01-01-example", 1)
	rekeyed = strings.Replace(rekeyed, "published_at: 2024-01-01T00:00:00Z\n", "published_at: 2024-01-01T00:00:00Z\nlastmod: 2026-04-08T00:00:00Z\n", 1)
	file := writeAmendFile(t, rekeyed)
	pub := &amendPublisherFake{}
	err := runDraftsAmend(db, pub, []string{
		"--id", amendDraftID, "--file", file, "--apply",
		"--resolve-unpublished-identity-collision",
		"--expect-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(amendOriginalYAML))),
		"--expect-proposed-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(rekeyed))),
		"--backup-dir", t.TempDir(), "--operator", "analyst",
		"--reason", "Resolve collision with an existing public brief",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pub.published) != 1 || pub.published[0] != rekeyed || pub.flushes != 1 {
		t.Fatalf("publisher calls: %+v", pub)
	}
	draft, err := db.GetDraft(amendDraftID)
	if err != nil || draft.BriefYAML != rekeyed {
		t.Fatalf("rekeyed draft: %+v, %v", draft, err)
	}
}

func TestDraftAmendCanBuildIdentityOnlyCorrectionFromStoredYAML(t *testing.T) {
	db := setupAmendDraft(t)
	var output bytes.Buffer
	if err := runDraftsAmend(db, nil, []string{
		"--id", amendDraftID,
		"--set-brief-id", "brief-2024-01-01-emudhra-ca-compromise",
		"--set-slug", "2024-01-emudhra-ca-compromise",
		"--resolve-unpublished-identity-collision",
	}, &output); err != nil {
		t.Fatal(err)
	}
	preview := output.String()
	if !strings.Contains(preview, "brief-1 -> brief-2024-01-01-emudhra-ca-compromise") ||
		!strings.Contains(preview, "2024-01-example -> 2024-01-emudhra-ca-compromise") ||
		!strings.Contains(preview, "2024-01-01T00:00:00Z -> 2024-01-01T00:00:00Z") {
		t.Fatalf("identity-only preview changed or omitted stable fields:\n%s", preview)
	}
	draft, err := db.GetDraft(amendDraftID)
	if err != nil || draft.BriefYAML != amendOriginalYAML {
		t.Fatalf("preview changed stored YAML: %+v, %v", draft, err)
	}
}

func TestDraftAmendPublishFailureKeepsAuthoritativeYAML(t *testing.T) {
	db := setupAmendDraft(t)
	file := writeAmendFile(t, amendRevisedYAML)
	pub := &amendPublisherFake{flushErr: fmt.Errorf("remote unavailable")}
	err := runDraftsAmend(db, pub, []string{
		"--id", amendDraftID, "--file", file, "--apply",
		"--expect-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(amendOriginalYAML))),
		"--expect-proposed-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(amendRevisedYAML))),
		"--backup-dir", t.TempDir(), "--operator", "analyst", "--reason", "Correct product mapping",
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "remote unavailable") {
		t.Fatalf("error = %v", err)
	}
	draft, err := db.GetDraft(amendDraftID)
	if err != nil || draft.BriefYAML != amendOriginalYAML {
		t.Fatalf("failed publish changed draft: %+v, %v", draft, err)
	}
}

func TestDraftAmendClearsContaminatedUpdateHistory(t *testing.T) {
	db := setupAmendDraft(t)
	oldYAML := amendOriginalYAML + "lastmod: 2026-10-01T01:02:03Z\nupdates:\n  - at: 2026-10-01T01:02:03Z\n    level: L1\n    summary: unrelated product update\n    sources: [test]\n"
	event := storage.UpdateEvent{At: time.Date(2026, 10, 1, 1, 2, 3, 0, time.UTC), Level: "L1", Summary: "unrelated product update", Sources: []string{"test"}}
	if err := db.RecordDraftUpdate(amendDraftID, oldYAML, event); err != nil {
		t.Fatal(err)
	}
	file := writeAmendFile(t, amendRevisedYAML)
	pub := &amendPublisherFake{}
	if err := runDraftsAmend(db, pub, []string{
		"--id", amendDraftID, "--file", file, "--apply", "--backup-dir", t.TempDir(),
		"--expect-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(oldYAML))),
		"--expect-proposed-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(amendRevisedYAML))),
		"--operator", "analyst", "--reason", "Remove unrelated update history",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	draft, err := db.GetDraft(amendDraftID)
	if err != nil || draft.BriefYAML != amendRevisedYAML || draft.Lastmod == nil || draft.Lastmod.Format(time.RFC3339) != "2026-04-08T00:00:00Z" || draft.UpdateLog != "" || draft.UpdateCount != 0 {
		t.Fatalf("contaminated update metadata retained: %+v, %v", draft, err)
	}
	if len(pub.published) != 1 || pub.published[0] != amendRevisedYAML {
		t.Fatalf("published YAML: %+v", pub.published)
	}
}

func TestDraftsFindBySlugReturnsApprovedDraftAndBriefIDs(t *testing.T) {
	db := setupAmendDraft(t)
	for _, draft := range []*storage.Draft{
		{
			ID: "malformed-approved", Status: storage.StatusApproved, Source: "test",
			BriefYAML: "not: [valid", CreatedAt: time.Now(),
		},
		{
			ID: "another-approved", Status: storage.StatusApproved, Source: "test",
			BriefYAML: "id: brief-other\nslug: 2026-10-other\ntitle: Other product advisory\n",
			CreatedAt: time.Now(),
		},
		{
			ID: "matching-pending", Status: storage.StatusPending, Source: "test",
			BriefYAML: "id: brief-pending\nslug: 2024-01-example\ntitle: Pending product advisory\n",
			CreatedAt: time.Now(),
		},
	} {
		if err := db.CreateDraft(draft); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := runDraftsFind(db, []string{"--slug", "2024-01-example"}, &out); err != nil {
		t.Fatal(err)
	}
	result := out.String()
	if !strings.Contains(result, amendDraftID) || !strings.Contains(result, "brief-1") || !strings.Contains(result, "Old title") || !strings.Contains(result, storage.StatusApproved) {
		t.Fatalf("missing match identifiers: %s", result)
	}
	if strings.Contains(result, "another-approved") || strings.Contains(result, "matching-pending") {
		t.Fatalf("included nonmatching draft: %s", result)
	}
	if !strings.Contains(result, "Skipped 1 approved draft") {
		t.Fatalf("missing malformed-draft count: %s", result)
	}
}
