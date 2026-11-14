package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

type polledSource struct {
	name  string
	items []scraper.RawItem
	since time.Time
}

func (s *polledSource) Name() string { return s.name }

func (s *polledSource) Poll(_ context.Context, since time.Time) ([]scraper.RawItem, error) {
	s.since = since
	return s.items, nil
}

// fetchedSource fetches items by ID, so a replay must not poll it.
type fetchedSource struct {
	name    string
	items   map[string]scraper.RawItem
	fetched []string
}

func (s *fetchedSource) Name() string { return s.name }

func (s *fetchedSource) Poll(context.Context, time.Time) ([]scraper.RawItem, error) {
	return nil, errors.New("polled a source that fetches items by ID")
}

func (s *fetchedSource) FetchItems(_ context.Context, sourceIDs []string) ([]scraper.RawItem, error) {
	s.fetched = append(s.fetched, sourceIDs...)
	var items []scraper.RawItem
	for _, id := range sourceIDs {
		if item, ok := s.items[id]; ok {
			items = append(items, item)
		}
	}
	return items, nil
}

func TestReadReplayIDs(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		want  []string
	}{
		{name: "arguments", args: []string{"ghsa:GHSA-1", " bsi:2 ", "ghsa:GHSA-1"}, want: []string{"ghsa:GHSA-1", "bsi:2"}},
		{name: "stdin", args: []string{"-"}, stdin: "nvd:CVE-2026-1\n\n  nvd:CVE-2026-2\r\nnvd:CVE-2026-1\n", want: []string{"nvd:CVE-2026-1", "nvd:CVE-2026-2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readReplayIDs(tt.args, strings.NewReader(tt.stdin))
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("readReplayIDs = %q err=%v, want %q", got, err, tt.want)
			}
		})
	}
}

func TestPlanReplay(t *testing.T) {
	now := time.Now().UTC()
	cutoff := now.Add(-14 * 24 * time.Hour)
	bsi := &polledSource{name: "bsi", items: []scraper.RawItem{
		{SourceID: "bsi:wanted", Source: "bsi", PublishedAt: now.Add(-6 * 24 * time.Hour)},
		{SourceID: "bsi:unrequested", Source: "bsi", PublishedAt: now.Add(-6 * 24 * time.Hour)},
		{SourceID: "bsi:stale", Source: "bsi", PublishedAt: now.Add(-20 * 24 * time.Hour)},
	}}
	nvd := &fetchedSource{name: "nvd", items: map[string]scraper.RawItem{
		"nvd:CVE-2026-118252": {SourceID: "nvd:CVE-2026-118252", Source: "nvd", PublishedAt: now.Add(-7 * 24 * time.Hour)},
	}}
	runner := scraper.NewRunner(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), 14*24*time.Hour)
	runner.RegisterWithInterval(bsi, time.Hour)
	runner.RegisterWithInterval(nvd, time.Hour)

	ids := []string{"bsi:wanted", "bsi:stale", "bsi:gone", "nvd:CVE-2026-118252", "nvd:CVE-2026-999999", "elastic:rule"}
	plan, err := planReplay(context.Background(), runner, ids, cutoff)
	if err == nil || !strings.Contains(err.Error(), "elastic") {
		t.Fatalf("err = %v, want the unregistered source reported", err)
	}
	var queued []string
	for _, item := range plan.queue {
		queued = append(queued, item.SourceID)
	}
	if !slices.Equal(queued, []string{"bsi:wanted", "nvd:CVE-2026-118252"}) {
		t.Errorf("queued %q, want the requested items each source still serves", queued)
	}
	if !slices.Equal(plan.tooOld, []string{"bsi:stale"}) {
		t.Errorf("tooOld %q, want the item published before the cutoff", plan.tooOld)
	}
	if !slices.Equal(plan.missing, []string{"bsi:gone", "nvd:CVE-2026-999999", "elastic:rule"}) {
		t.Errorf("missing %q, want the items no source returned", plan.missing)
	}
	if !bsi.since.Equal(cutoff) {
		t.Errorf("bsi polled since %s, want the cutoff %s", bsi.since, cutoff)
	}
	if !slices.Equal(nvd.fetched, []string{"nvd:CVE-2026-118252", "nvd:CVE-2026-999999"}) {
		t.Errorf("nvd fetched %q, want each requested NVD item by ID", nvd.fetched)
	}
}
