package main

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestServicePublisherBuffersToOutbox(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "threat-bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pub := newServicePublisher(cfg, func() string { return "" }, logger, nil, db)
	err = pub.Publish("id: \"brief-1\"\nslug: \"2026-02-20-one\"\ntitle: \"One\"\nsummary: \"s\"\ncontent: A security notice records suspicious host activity for analyst review.\nseverity: \"high\"\npublished_at: \"2026-02-20T10:00:00Z\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ := db.ListPublishOutbox(); len(rows) != 1 {
		t.Fatalf("service publisher did not use the outbox: %+v", rows)
	}
}

type fakeRestorer struct {
	restored   int
	restoreErr error
	flushErr   error
	flushes    int
}

func (f *fakeRestorer) RestoreOutbox() (int, error) { return f.restored, f.restoreErr }
func (f *fakeRestorer) Flush() error                { f.flushes++; return f.flushErr }

func TestFlushRestoredFlushesOnlyWhenSomethingRestored(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for name, tc := range map[string]struct {
		f     fakeRestorer
		wants int
	}{
		"nothing restored": {fakeRestorer{}, 0},
		"restored":         {fakeRestorer{restored: 2}, 1},
		"flush fails":      {fakeRestorer{restored: 2, flushErr: errors.New("boom")}, 1},
		"restore fails":    {fakeRestorer{restored: 2, restoreErr: errors.New("boom")}, 0},
	} {
		f := tc.f
		flushRestored(&f, logger)
		if f.flushes != tc.wants {
			t.Errorf("%s: flushes = %d, want %d", name, f.flushes, tc.wants)
		}
	}
}
