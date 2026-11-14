package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/config"
)

func TestFetchFeedLastBuildDate(t *testing.T) {
	last := time.Date(2026, 10, 18, 2, 9, 24, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<?xml version="1.0"?><rss><channel><lastBuildDate>%s</lastBuildDate></channel></rss>`, last.Format(time.RFC1123Z))
	}))
	defer srv.Close()

	got, err := fetchFeedLastBuildDate(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchFeedLastBuildDate: %v", err)
	}
	if !got.Equal(last) {
		t.Fatalf("lastBuildDate=%s, want %s", got, last)
	}
}

func TestFetchFeedLastBuildDateDoesNotRequireEntireLargeFeed(t *testing.T) {
	last := time.Date(2026, 10, 20, 14, 42, 17, 0, time.UTC)
	largeDescription := strings.Repeat("x", maxFeedXMLBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<?xml version="1.0"?><rss><channel><lastBuildDate>%s</lastBuildDate><item><description><![CDATA[%s]]></description></item></channel></rss>`, last.Format(time.RFC1123Z), largeDescription)
	}))
	defer srv.Close()

	got, err := fetchFeedLastBuildDate(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchFeedLastBuildDate: %v", err)
	}
	if !got.Equal(last) {
		t.Fatalf("lastBuildDate=%s, want %s", got, last)
	}
}

func TestFetchFeedLastBuildDateRejectsMissingDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><rss><channel></channel></rss>`)
	}))
	defer srv.Close()

	if _, err := fetchFeedLastBuildDate(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected missing lastBuildDate to fail")
	}
}

func TestFeedBehind(t *testing.T) {
	now := time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC)
	feed := time.Date(2026, 10, 18, 2, 9, 24, 0, time.UTC)
	grace := 45 * time.Minute
	tests := []struct {
		name        string
		published   time.Time
		pushed      time.Time
		wantBehind  bool
		wantOverdue bool
	}{
		{
			// The 2026-10-18 false alarm: nothing new since 02:09, so the
			// feed is complete however old its newest brief is.
			name: "quiet period, nothing pushed since start",
		},
		{
			name:      "feed shows the newest pushed brief",
			published: feed,
			pushed:    feed.Add(20 * time.Second),
		},
		{
			name:      "sub-second publish date of a brief the feed shows",
			published: feed.Add(400 * time.Millisecond),
			pushed:    feed.Add(20 * time.Second),
		},
		{
			name:       "site still rebuilding",
			published:  now.Add(-10 * time.Minute),
			pushed:     now.Add(-10 * time.Minute),
			wantBehind: true,
		},
		{
			name:        "site never picked up the push",
			published:   now.Add(-2 * time.Hour),
			pushed:      now.Add(-2 * time.Hour),
			wantBehind:  true,
			wantOverdue: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			behind, overdue := feedBehind(feed, tt.published, tt.pushed, now, grace)
			if behind != tt.wantBehind || overdue != tt.wantOverdue {
				t.Fatalf("behind=%v overdue=%v, want behind=%v overdue=%v", behind, overdue, tt.wantBehind, tt.wantOverdue)
			}
		})
	}
}

func TestFeedFreshnessMonitorEscalatesRepeatedFetchFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	m := newFeedFreshnessMonitor(config.MonitoringConfig{PublicFeedURL: srv.URL, PublicFeedPublishGrace: 45 * time.Minute}, nil,
		slog.New(slog.NewTextHandler(&logs, nil)))
	m.client = srv.Client()

	var levels []string
	for range feedCheckFailuresBeforeError {
		logs.Reset()
		m.nextCheck = time.Time{}
		m.Check(context.Background())
		levels = append(levels, strings.Fields(strings.SplitN(logs.String(), "level=", 2)[1])[0])
	}
	want := []string{"WARN", "WARN", "ERROR"}
	if strings.Join(levels, ",") != strings.Join(want, ",") {
		t.Fatalf("levels=%v, want %v", levels, want)
	}
}
