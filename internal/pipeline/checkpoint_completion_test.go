package pipeline

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

// Independent review reproduced a draft saved before failed terminal cleanup,
// followed by another draft on retry. Completion must commit the saved result,
// its dedup associations and recovery intent together or leave none of them.
func TestCheckpointCompletionFailureRetriesWithoutDuplicateDraft(t *testing.T) {
	for _, mode := range []string{"manual", "auto-publish", "queue-outage"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "completion.db")
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { db.Close() }()
			conn, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Exec(`CREATE TRIGGER fail_terminal_cleanup AFTER DELETE ON processing_checkpoints BEGIN SELECT RAISE(FAIL,'terminal cleanup unavailable'); END`); err != nil {
				t.Fatal(err)
			}
			brief := strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1)
			assemblies := 0
			client := shutdownStageLLM{generate: func(context.Context, string, string) (string, error) { assemblies++; return brief, nil }, generateJSON: func(_ context.Context, _, system string, out any) error {
				if system == groundingSystem {
					out.(*GroundingResult).Grounded = true
				}
				return nil
			}}
			pub := &recoveryPublisher{fail: mode == "queue-outage"}
			cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, RetryBackoff: -time.Second, Logger: quietLogger()}
			if mode != "manual" {
				cfg.AutoPublish = true
				cfg.Publisher = pub
			}
			item := scraper.RawItem{SourceID: "completion:source", Source: "cisa-kev", Title: "Windows telemetry advisory", Content: strings.Repeat("Confirmed Windows process creation detection evidence. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
			err = New(cfg).processItem(context.Background(), item)
			if err == nil || !strings.Contains(err.Error(), "terminal cleanup unavailable") {
				t.Fatalf("failed completion not surfaced: %v", err)
			}
			if drafts := countCompletionDrafts(t, db); drafts != 0 {
				t.Fatalf("failed completion left %d drafts that a retry could duplicate", drafts)
			}
			if entries, err := db.FindBySourceID(item.SourceID); err != nil || len(entries) != 0 {
				t.Fatalf("failed completion left dedup associations: %+v %v", entries, err)
			}
			if seen, err := db.HasSeen(item.SourceID); err != nil || seen {
				t.Fatalf("failed completion consumed source: %v %v", seen, err)
			}
			if cp, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || cp == nil {
				t.Fatalf("failed completion lost candidate: %+v %v", cp, err)
			}
			if intents, err := db.ListPublicationIntents(); err != nil || len(intents) != 0 {
				t.Fatalf("failed completion leaked publication: %+v %v", intents, err)
			}
			if pub.drafts != 0 || pub.updates != 0 {
				t.Fatal("publisher ran before atomic completion committed")
			}
			if _, err := conn.Exec("DROP TRIGGER fail_terminal_cleanup"); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg.DB = db
			if err := New(cfg).processItem(context.Background(), item); err != nil {
				t.Fatal(err)
			}
			if drafts := countCompletionDrafts(t, db); drafts != 1 {
				t.Fatalf("restart created %d drafts, want1", drafts)
			}
			entries, err := db.FindBySourceID(item.SourceID)
			if err != nil || len(entries) == 0 {
				t.Fatalf("completion lost canonical source association: %+v %v", entries, err)
			}
			if entries[0].TitleHash != NormalizeTitleHash(item.Title) || entries[0].ContentHash == "" {
				t.Fatalf("completion lost dedup index fields: %+v", entries[0])
			}
			if cp, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || cp != nil {
				t.Fatalf("completed candidate retained: %+v %v", cp, err)
			}
			if seen, err := db.HasSeenRevision(item.SourceID, item.ContentRevision()); err != nil || !seen {
				t.Fatalf("completed revision not recorded: %v %v", seen, err)
			}
			if assemblies != 1 {
				t.Fatalf("retry repeated paid assembly %d times", assemblies)
			}
			if mode == "queue-outage" {
				intents, err := db.ListPublicationIntents()
				if err != nil || len(intents) != 1 || !intents[0].CompleteDraft {
					t.Fatalf("queue outage lost committed recovery intent: %+v %v", intents, err)
				}
				pub.fail = false
				if err := New(cfg).recoverPublicationIntents(); err != nil {
					t.Fatal(err)
				}
			}
			wantPublished := 0
			if mode != "manual" {
				wantPublished = 1
			}
			if pub.drafts != wantPublished || pub.updates != 0 {
				t.Fatalf("wrong publication replay count: drafts=%d updates=%d", pub.drafts, pub.updates)
			}
			if intents, err := db.ListPublicationIntents(); err != nil || len(intents) != 0 {
				t.Fatalf("accepted publication intent retained: %+v %v", intents, err)
			}
			if err := New(cfg).processItem(context.Background(), item); err != nil {
				t.Fatal(err)
			}
			if countCompletionDrafts(t, db) != 1 || pub.drafts != wantPublished || assemblies != 1 {
				t.Fatal("completed input repeated draft or publication work")
			}
		})
	}
}

func countCompletionDrafts(t *testing.T, db *storage.DB) int {
	t.Helper()
	count := 0
	for _, status := range []string{storage.StatusPending, storage.StatusApproved, storage.StatusRejected} {
		for _, err := range db.DraftsWithStatus(status) {
			if err != nil {
				t.Fatal(err)
			}
			count++
		}
	}
	return count
}

func TestGroundedCandidateSaveFailureRemainsRetryable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger string
	}{
		{"draft", `CREATE TRIGGER fail_write BEFORE INSERT ON drafts BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END`},
		{"before_grounding", `CREATE TRIGGER fail_write BEFORE UPDATE ON processing_checkpoints WHEN NEW.retry_at != '0001-01-01T00:00:00Z' BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "grounded-save.db")
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			control, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			if _, err := control.Exec(tc.trigger); err != nil {
				t.Fatal(err)
			}
			brief := strings.Replace(validWindowsPathBriefYAML, "    detection:\n", "    logsource:\n      category: process_creation\n      product: windows\n    detection:\n", 1)
			assemblies := 0
			client := shutdownStageLLM{
				generate: func(context.Context, string, string) (string, error) {
					assemblies++
					return brief, nil
				},
				generateJSON: func(_ context.Context, _, system string, out any) error {
					if system == groundingSystem {
						out.(*GroundingResult).Grounded = true
					}
					return nil
				},
			}
			cfg := Config{DB: db, LLMClient: client, QualityThreshold: 1, MaxGroundingAttempts: 1, RetryBackoff: -time.Second, Logger: quietLogger()}
			item := scraper.RawItem{SourceID: "grounded:save", Source: "cisa-kev", Title: "Windows telemetry advisory", Content: strings.Repeat("Confirmed Windows process creation detection evidence. ", 30), SigmaRule: &scraper.SigmaRule{Title: "Rule"}}
			if err := New(cfg).processItem(context.Background(), item); err == nil || !strings.Contains(err.Error(), "injected storage failure") {
				t.Errorf("grounded candidate storage failure was swallowed: %v", err)
			}
			if seen, err := db.HasSeenRevision(item.SourceID, item.ContentRevision()); err != nil || seen {
				t.Errorf("failed save consumed source revision: seen=%v err=%v", seen, err)
			}
			if reason, quarantined, err := db.PipelineQuarantineReason(item.SourceID); err != nil || quarantined {
				t.Errorf("grounded candidate mislabeled as ungrounded: reason=%q quarantined=%v err=%v", reason, quarantined, err)
			}
			if cp, err := db.GetProcessingCheckpoint(item.SourceID); err != nil || cp == nil {
				t.Errorf("failed save lost resumable candidate: checkpoint=%v err=%v", cp, err)
			}
			if _, err := control.Exec(`DROP TRIGGER fail_write`); err != nil {
				t.Fatal(err)
			}
			if err := New(cfg).processItem(context.Background(), item); err != nil {
				t.Fatal(err)
			}
			if got := countCompletionDrafts(t, db); got != 1 || assemblies != 1 {
				t.Fatalf("recovery created %d drafts with %d assembly calls, want one of each", got, assemblies)
			}
		})
	}
}
