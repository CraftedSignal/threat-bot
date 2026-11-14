package scraper

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func TestReplayReemitsQueuedItemsUntilSeen(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	want := RawItem{
		SourceID:    "ghsa:GHSA-rcqf-f6h2-ccg9",
		Source:      "ghsa",
		Title:       "Highcharts Dashboards parses sidebar component labels as HTML",
		URL:         "https://github.com/advisories/GHSA-rcqf-f6h2-ccg9",
		Content:     "Sidebar component labels are rendered as HTML.",
		PublishedAt: time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second),
		Metadata:    map[string]string{"ghsa": "GHSA-rcqf-f6h2-ccg9", "cve": "CVE-2026-118252", "severity": "medium"},
	}
	if err := db.MarkSeen(want.SourceID, want.Source, want.Title); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueueReplay(want.Source, want.SourceID, string(raw)); err != nil {
		t.Fatal(err)
	}

	r := NewRunner(db, testLogger(), 14*24*time.Hour)
	r.RegisterWithInterval(NewReplay(db), time.Hour)
	items, err := r.PollAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !reflect.DeepEqual(items[0], want) {
		t.Fatalf("replayed items = %+v, want [%+v]", items, want)
	}

	// Once the pipeline has processed the item, it is seen and leaves the queue.
	if err := db.MarkSeen(want.SourceID, want.Source, want.Title); err != nil {
		t.Fatal(err)
	}
	again, err := NewReplay(db).Poll(context.Background(), time.Time{})
	if err != nil || len(again) != 0 {
		t.Fatalf("replay after processing = %+v err=%v, want none", again, err)
	}
}

func TestReplayStopsReemittingAfterMaxAge(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, err := json.Marshal(RawItem{SourceID: "nvd:CVE-2026-118252", Source: "nvd", PublishedAt: time.Now().UTC().Truncate(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueueReplay("nvd", "nvd:CVE-2026-118252", string(raw)); err != nil {
		t.Fatal(err)
	}

	r := NewReplay(db)
	r.now = func() time.Time { return time.Now().Add(replayMaxAge + time.Hour) }
	items, err := r.Poll(context.Background(), time.Time{})
	if err != nil || len(items) != 0 {
		t.Fatalf("items = %+v err=%v, want none once the item outlived the max age", items, err)
	}
}
