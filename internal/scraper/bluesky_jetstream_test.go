package scraper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/craftedsignal/threat-bot/internal/config"
)

func TestBlueskyJetstreamAcceptsLegitimatePostLargerThanDefaultWebsocketLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer c.CloseNow()
		body, err := json.Marshal(map[string]any{
			"did": "did:plc:large", "time_us": int64(1793095200000000), "kind": "commit",
			"commit": map[string]any{
				"operation": "create", "collection": "app.bsky.feed.post", "rkey": "large-post",
				"record": map[string]any{
					"text":      "CVE-2026-111497: reproduced Brotli heap memory disclosure",
					"createdAt": "2026-10-27T10:00:00Z",
					"embed":     map[string]any{"alt": strings.Repeat("x", 40<<10)},
				},
			},
		})
		if err != nil {
			t.Error(err)
			return
		}
		_ = c.Write(r.Context(), websocket.MessageText, body)
	}))
	defer srv.Close()

	s := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http"), CandidateCap: 1, ReadWindow: time.Second})
	items, err := s.Poll(context.Background(), time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].SourceID != "bluesky-discovery:did:plc:large:large-post" {
		t.Fatalf("items=%+v", items)
	}
}

func TestBlueskyJetstreamDecodesFiltersAndBounds(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer c.CloseNow()
		for _, body := range []string{
			`{"did":"did:plc:alice","time_us":1793095200000000,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.post","rkey":"one","record":{"text":"CVE-2026-111497: we reproduced a heap leak","createdAt":"2026-10-27T10:00:00Z"}}}`,
			`{"did":"did:plc:bob","time_us":1793095201000000,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.post","rkey":"noise","record":{"text":"hello world","createdAt":"2026-10-27T10:00:01Z"}}}`,
		} {
			_ = c.Write(r.Context(), websocket.MessageText, []byte(body))
		}
	}))
	defer srv.Close()

	s := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http"), CandidateCap: 1, ReadWindow: time.Second})
	items, err := s.Poll(context.Background(), time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items=%d want 1", len(items))
	}
	if items[0].SourceID != "bluesky-discovery:did:plc:alice:one" || items[0].Discovery == nil || items[0].Discovery.Platform != "bluesky" {
		t.Fatalf("bad item: %+v", items[0])
	}
	if !strings.Contains(query, "wantedCollections=app.bsky.feed.post") || !strings.Contains(query, "cursor=") {
		t.Fatalf("query=%q", query)
	}
}

func TestBlueskyJetstreamHonorsCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := websocket.Accept(w, r, nil)
		defer c.CloseNow()
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http"), ReadWindow: time.Second}).Poll(ctx, time.Time{})
	if err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestBlueskyJetstreamRetriesDroppedHandshake(t *testing.T) {
	old := jetstreamDialBackoff
	jetstreamDialBackoff = func() time.Duration { return time.Millisecond }
	defer func() { jetstreamDialBackoff = old }()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close() // EOF before any handshake response
			}
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		body, _ := json.Marshal(map[string]any{
			"did": "did:plc:retry", "time_us": int64(1793095200000000), "kind": "commit",
			"commit": map[string]any{"operation": "create", "collection": "app.bsky.feed.post", "rkey": "r1",
				"record": map[string]any{"text": "CVE-2026-111497: reproduced Brotli heap memory disclosure", "createdAt": "2026-10-27T10:00:00Z"}},
		})
		_ = c.Write(r.Context(), websocket.MessageText, body)
	}))
	defer srv.Close()

	s := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http"), CandidateCap: 1, ReadWindow: time.Second})
	items, err := s.Poll(context.Background(), time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("a dropped first handshake must be retried: %v", err)
	}
	if len(items) != 1 || attempts.Load() != 2 {
		t.Fatalf("items=%d attempts=%d", len(items), attempts.Load())
	}
}

func TestBlueskyJetstreamDialRetryStopsOnCancel(t *testing.T) {
	old := jetstreamDialBackoff
	jetstreamDialBackoff = func() time.Duration { return time.Hour }
	defer func() { jetstreamDialBackoff = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	s := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http"), ReadWindow: time.Second})
	start := time.Now()
	if _, err := s.Poll(ctx, time.Time{}); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err=%v elapsed=%v; cancellation must end the backoff", err, time.Since(start))
	}
}
