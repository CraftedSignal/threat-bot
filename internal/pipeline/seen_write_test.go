package pipeline

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/scraper"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestProcessItemReportsFailedSeenWriteAndLeavesItemRetryable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.db")
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
	if _, err := control.Exec(`CREATE TRIGGER fail_seen BEFORE INSERT ON seen_items BEGIN SELECT RAISE(ABORT, 'injected seen write failure'); END`); err != nil {
		t.Fatal(err)
	}
	p := New(Config{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	item := scraper.RawItem{SourceID: "retryable", Source: "fixture", Title: "A short fixture", Content: "short"}
	if err := p.processItem(context.Background(), item); err == nil || !strings.Contains(err.Error(), "injected seen write failure") {
		t.Fatalf("process error = %v, want failed seen write", err)
	}
	seen, err := db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Fatal("failed write acknowledged the source")
	}
	if _, err := control.Exec(`DROP TRIGGER fail_seen`); err != nil {
		t.Fatal(err)
	}
	if err := p.processItem(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	seen, err = db.HasSeen(item.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("retry after recovery did not record source")
	}
}
