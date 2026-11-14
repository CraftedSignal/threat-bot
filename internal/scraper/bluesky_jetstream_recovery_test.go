package scraper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/storage"
)

func fastJetstreamRetries(t *testing.T) {
	t.Helper()
	old := jetstreamDialBackoff
	jetstreamDialBackoff = func() time.Duration { return time.Millisecond }
	t.Cleanup(func() { jetstreamDialBackoff = old })
}

func TestBlueskyJetstreamHTTPFailuresReachRunnerHealthAndLogs(t *testing.T) {
	fastJetstreamRetries(t)
	for _, tc := range []struct {
		name     string
		status   int
		expected bool
		attempts int32
	}{
		{"gateway timeout", http.StatusGatewayTimeout, true, 3},
		{"bad request", http.StatusBadRequest, false, 1},
		{"unauthorized", http.StatusUnauthorized, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("<html>PRIVATE-UPSTREAM-HTML</html>"))
			}))
			defer srv.Close()
			db, err := storage.Open(t.TempDir() + "/scrapers.db")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var logs bytes.Buffer
			runner := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
			scraper := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http")})
			runner.RegisterWithInterval(scraper, time.Hour)
			before := time.Now()
			if items, err := runner.PollAll(context.Background()); err != nil || len(items) != 0 {
				t.Fatalf("runner should record isolated source failure: items=%d err=%v", len(items), err)
			}
			health := runner.HealthSummary()
			if len(health) != 1 || health[0].ConsecutiveErrors != 1 || health[0].LastError.IsZero() || !health[0].LastSuccess.IsZero() || health[0].LastErrorExpectedUpstream != tc.expected {
				t.Fatalf("source failure was lost or misclassified: %+v", health)
			}
			state, err := db.GetScraperState(scraper.Name())
			if err != nil || state != nil {
				t.Fatalf("failed poll advanced durable source state: state=%+v err=%v", state, err)
			}
			if runner.entries[0].lastPoll.After(before.Add(-25 * time.Minute)) {
				t.Error("failed poll lost its half-interval retry schedule")
			}
			if attempts.Load() != tc.attempts {
				t.Errorf("handshake attempts=%d, want %d", attempts.Load(), tc.attempts)
			}
			level, message := "ERROR", "scraper error"
			if tc.expected {
				level, message = "WARN", "scraper upstream unavailable"
			}
			if !strings.Contains(logs.String(), `"level":"`+level+`"`) || !strings.Contains(logs.String(), `"msg":"`+message+`"`) {
				t.Errorf("wrong source failure severity: %s", logs.String())
			}
			if strings.Contains(logs.String(), "PRIVATE-") || strings.Contains(logs.String(), "poll complete") {
				t.Errorf("failed handshake logged content or false success: %s", logs.String())
			}
		})
	}
}

func TestBlueskyJetstreamPreservesHTTPStatus(t *testing.T) {
	fastJetstreamRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer srv.Close()
	_, err := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: srv.URL}).Poll(context.Background(), time.Time{})
	if code, ok := upstreamStatus(err); !ok || code != http.StatusGatewayTimeout {
		t.Fatalf("actual handshake error lost status: code=%d ok=%v err=%v", code, ok, err)
	}
}

type jetstreamRoundTripFunc func(*http.Request) (*http.Response, error)

func (f jetstreamRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Route virtual public hosts to a real local HTTP/WebSocket server. Production
// still executes websocket.Dial and receives the actual handshake responses.
func localJetstreamTransport(t *testing.T, srv *httptest.Server, observe func(*http.Request)) {
	t.Helper()
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	old := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: jetstreamRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if observe != nil {
			observe(req)
		}
		copy := req.Clone(req.Context())
		copy.URL.Scheme, copy.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(copy)
	})}
	t.Cleanup(func() { http.DefaultClient = old })
}

func writeJetstreamRecoveryPost(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"did":"did:plc:recovered","time_us":1793095200000000,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.post","rkey":"one","record":{"text":"CVE-2026-111497: reproduced Brotli heap memory disclosure","createdAt":"2026-10-27T10:00:00Z"}}}`))
}

func TestBlueskyJetstreamFailsOverOfficialHostsWithoutLosingFilters(t *testing.T) {
	fastJetstreamRetries(t)
	for _, host := range []string{
		"jetstream1.us-east.bsky.network", "jetstream2.us-east.bsky.network",
		"jetstream1.us-west.bsky.network", "jetstream2.us-west.bsky.network",
	} {
		t.Run(host, func(t *testing.T) {
			var attempts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) == 1 {
					w.WriteHeader(http.StatusGatewayTimeout)
					return
				}
				writeJetstreamRecoveryPost(w, r)
			}))
			defer srv.Close()
			var requests []*url.URL
			localJetstreamTransport(t, srv, func(r *http.Request) {
				copy := *r.URL
				requests = append(requests, &copy)
			})
			since := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
			scraper := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{
				Endpoint:     "wss://" + host + "/subscribe?wantedDids=did:plc:recovered&wantedDids=did:plc:other",
				CandidateCap: 1, ReadWindow: time.Second,
			})
			items, err := scraper.Poll(context.Background(), since)
			if err != nil || len(items) != 1 || items[0].SourceID != "bluesky-discovery:did:plc:recovered:one" {
				t.Fatalf("transient handshake did not recover through real WebSocket: items=%+v err=%v", items, err)
			}
			if len(requests) != 2 || requests[0].Host != host || requests[1].Host == host {
				t.Fatalf("official host did not fail over: %v", requests)
			}
			allowed := map[string]bool{"jetstream1.us-east.bsky.network": true, "jetstream2.us-east.bsky.network": true, "jetstream1.us-west.bsky.network": true, "jetstream2.us-west.bsky.network": true}
			if !allowed[requests[1].Host] {
				t.Fatalf("failover escaped official hosts: %s", requests[1])
			}
			for i, request := range requests {
				wantCursor := since.UnixMicro()
				if i > 0 {
					wantCursor -= int64(5 * time.Second / time.Microsecond)
				}
				q := request.Query()
				if request.Path != "/subscribe" || q.Get("wantedCollections") != "app.bsky.feed.post" || len(q["wantedDids"]) != 2 || q.Get("cursor") != strconv.FormatInt(wantCursor, 10) {
					t.Errorf("request lost filters/cursor: %s", request)
				}
			}
		})
	}
}

func TestBlueskyJetstreamCustomEndpointsStayIsolated(t *testing.T) {
	fastJetstreamRetries(t)
	for _, endpoint := range []string{
		"wss://custom.example/subscribe",
		"wss://jetstream2.us-east.bsky.network.custom.example/subscribe",
		"wss://jetstream2.us-east.bsky.network:8443/subscribe",
		"wss://jetstream2.us-east.bsky.network/private",
		"wss://user:password@jetstream2.us-east.bsky.network/subscribe",
	} {
		t.Run(endpoint, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGatewayTimeout) }))
			defer srv.Close()
			var requests []string
			localJetstreamTransport(t, srv, func(r *http.Request) { requests = append(requests, r.URL.String()) })
			_, err := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: endpoint}).Poll(context.Background(), time.Time{})
			if code, ok := upstreamStatus(err); !ok || code != http.StatusGatewayTimeout || len(requests) != 3 {
				t.Fatalf("custom endpoint failure lost status/retry bound: attempts=%d err=%v", len(requests), err)
			}
			for _, request := range requests[1:] {
				if request != requests[0] {
					t.Error("custom endpoint escaped to another endpoint")
				}
			}
		})
	}
}

func TestBlueskyJetstreamOfficialFailoverExhaustionStaysFailedAndBounded(t *testing.T) {
	fastJetstreamRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGatewayTimeout) }))
	defer srv.Close()
	var requests []*url.URL
	localJetstreamTransport(t, srv, func(r *http.Request) {
		copy := *r.URL
		requests = append(requests, &copy)
	})
	since := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	items, err := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{}).Poll(context.Background(), since)
	if code, ok := upstreamStatus(err); !ok || code != http.StatusGatewayTimeout || len(items) != 0 || len(requests) != 3 {
		t.Fatalf("exhausted public failover lost bounded failure: requests=%v items=%d err=%v", requests, len(items), err)
	}
	hosts := make(map[string]bool)
	for i, request := range requests {
		if hosts[request.Host] {
			t.Errorf("failed public host reused during failover: %s", request.Host)
		}
		hosts[request.Host] = true
		wantCursor := since.UnixMicro()
		if i > 0 {
			wantCursor -= int64(5 * time.Second / time.Microsecond)
		}
		if request.Query().Get("cursor") != strconv.FormatInt(wantCursor, 10) {
			t.Errorf("cursor overlap accumulated across retries: %s", request)
		}
	}
}

func TestBlueskyJetstreamDroppedOfficialHandshakeFailsOver(t *testing.T) {
	fastJetstreamRetries(t)
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		writeJetstreamRecoveryPost(w, r)
	}))
	defer srv.Close()
	var hosts []string
	localJetstreamTransport(t, srv, func(r *http.Request) { hosts = append(hosts, r.URL.Host) })
	items, err := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{CandidateCap: 1}).Poll(context.Background(), time.Time{})
	if err != nil || len(items) != 1 || len(hosts) != 2 || hosts[0] == hosts[1] {
		t.Fatalf("dropped handshake did not recover on alternate: hosts=%v items=%d err=%v", hosts, len(items), err)
	}
}

func TestBlueskyJetstreamHandshakeTimeoutRetriesAndRecovers(t *testing.T) {
	fastJetstreamRetries(t)
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		writeJetstreamRecoveryPost(w, r)
	}))
	defer srv.Close()
	old := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: jetstreamRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 11*time.Second {
			return nil, fmt.Errorf("handshake lacks bounded attempt deadline")
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	t.Cleanup(func() { http.DefaultClient = old })
	scraper := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: srv.URL, CandidateCap: 1, ReadWindow: time.Second})
	start := time.Now()
	items, err := scraper.Poll(context.Background(), time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC))
	if err != nil || len(items) != 1 || attempts.Load() != 2 || time.Since(start) > 15*time.Second {
		t.Fatalf("bounded handshake did not retry/recover: attempts=%d items=%d elapsed=%v err=%v", attempts.Load(), len(items), time.Since(start), err)
	}
}

func TestBlueskyJetstreamCancelsActiveHandshake(t *testing.T) {
	started := make(chan struct{})
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		close(started)
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-started; cancel() }()
	_, err := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: srv.URL}).Poll(ctx, time.Time{})
	if !errors.Is(err, context.Canceled) || attempts.Load() != 1 {
		t.Fatalf("active handshake cancellation lost: attempts=%d err=%v", attempts.Load(), err)
	}
}
