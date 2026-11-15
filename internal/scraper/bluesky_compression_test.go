package scraper

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/craftedsignal/threat-bot/internal/config"
	"github.com/craftedsignal/threat-bot/internal/storage"
	"github.com/klauspost/compress/zstd"
)

func compressedJetstreamFixture(t *testing.T, data []byte) []byte {
	t.Helper()
	dict, err := unpackJetstreamDictionary(packedJetstreamDictionary)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderDict(dict))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(data, nil)
}

func TestBlueskyDictionaryCompressionMatchesPlainAndNegotiates(t *testing.T) {
	at := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	event := durableEvent(at, "one", "CVE-2026-111497 reproduced heap memory disclosure")
	var results [][]RawItem
	for _, compressed := range []bool{false, true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			if compressed {
				if r.URL.Query().Get("compress") != "true" {
					t.Error("official endpoint did not negotiate dictionary compression")
				}
				_ = c.Write(r.Context(), websocket.MessageBinary, compressedJetstreamFixture(t, event))
			} else {
				_ = c.Write(r.Context(), websocket.MessageText, event)
			}
		}))
		func() {
			defer srv.Close()
			endpoint := "ws" + strings.TrimPrefix(srv.URL, "http")
			if compressed {
				localJetstreamTransport(t, srv, nil)
				endpoint = "wss://jetstream2.us-east.bsky.network/subscribe"
			}
			s := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: endpoint, CandidateCap: 1, ReadWindow: time.Second})
			items, err := s.Poll(context.Background(), at.Add(-time.Hour))
			if err != nil || len(items) != 1 {
				t.Fatalf("compressed=%v items=%v err=%v", compressed, items, err)
			}
			results = append(results, items)
		}()
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Fatal("compressed and plain events differ")
	}
}

func TestBlueskyRejectsCorruptAndOversizedCompressedFrames(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"corrupt", []byte("not zstd")},
		{"oversized", compressedJetstreamFixture(t, []byte(strings.Repeat("x", (10<<20)+1)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer c.CloseNow()
				_ = c.Write(r.Context(), websocket.MessageBinary, tc.data)
				_, _, _ = c.Read(r.Context())
			}))
			defer srv.Close()
			s := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http") + "?compress=true", CandidateCap: 1, ReadWindow: time.Second})
			items, err := s.Poll(context.Background(), time.Time{})
			if err == nil || len(items) != 0 {
				t.Fatalf("unsafe compressed frame accepted: %v %v", items, err)
			}
		})
	}
}

func TestBlueskyCompressedCorruptionDoesNotAdvancePastDurablePrefix(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	first := compressedJetstreamFixture(t, durableEvent(at, "one", "CVE-2026-111497 reproduced heap memory disclosure"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		_ = c.Write(r.Context(), websocket.MessageBinary, first)
		_ = c.Write(r.Context(), websocket.MessageBinary, []byte("corrupt frame"))
		_ = c.Write(r.Context(), websocket.MessageText, durableEvent(at.Add(time.Second), "two", "CVE-2026-111498 reproduced heap memory disclosure"))
		_, _, _ = c.Read(r.Context())
	}))
	defer srv.Close()
	db, err := storage.Open(t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := durableRunner(db, "ws"+strings.TrimPrefix(srv.URL, "http")+"?compress=true", 3)
	items, err := r.PollAll(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("safe compressed prefix was lost: %v %v", items, err)
	}
	state, err := db.GetScraperState("bluesky-discovery")
	if err != nil || state == nil || !state.LastPoll.Equal(at) {
		t.Fatalf("corruption advanced past unconsumed event: %+v %v", state, err)
	}
	if r.HealthSummary()[0].ConsecutiveErrors != 1 {
		t.Fatal("corruption reported as successful window")
	}
}

func TestBlueskyCompressedStreamSurvivesOfficialFailover(t *testing.T) {
	fastJetstreamRetries(t)
	at := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	data := compressedJetstreamFixture(t, durableEvent(at, "one", "CVE-2026-111497 reproduced heap memory disclosure"))
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("compress") != "true" {
			t.Error("failover lost compression negotiation")
		}
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		_ = c.Write(r.Context(), websocket.MessageBinary, data)
	}))
	defer srv.Close()
	var hosts []string
	localJetstreamTransport(t, srv, func(r *http.Request) { hosts = append(hosts, r.URL.Host) })
	items, err := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{CandidateCap: 1}).Poll(context.Background(), at.Add(-time.Hour))
	if err != nil || len(items) != 1 || len(hosts) != 2 || hosts[0] == hosts[1] {
		t.Fatalf("compressed failover failed: hosts=%v items=%v err=%v", hosts, items, err)
	}
}

func TestBlueskyCompressedActiveReadHonorsCancellation(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	data := compressedJetstreamFixture(t, durableEvent(at, "noise", "hello world"))
	sent := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		if c.Write(r.Context(), websocket.MessageBinary, data) == nil {
			close(sent)
		}
		_, _, _ = c.Read(r.Context())
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-sent:
			cancel()
		case <-ctx.Done():
		}
	}()
	start := time.Now()
	_, err := NewBlueskyJetstream(config.BlueskyDiscoveryConfig{Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http") + "?compress=true", ReadWindow: time.Second}).Poll(ctx, time.Time{})
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("compressed active read ignored cancellation: %v", err)
	}
}

// Source packing must preserve the exact upstream dictionary and remain bounded
// before the network decoder receives it. No scanner exemption is needed.
func TestPinnedJetstreamDictionaryPacking(t *testing.T) {
	if dictionary, err := unpackJetstreamDictionary(packedJetstreamDictionary); err != nil || len(dictionary) != jetstreamDictionaryBytes {
		t.Fatalf("pinned dictionary failed validation: length=%d err=%v", len(dictionary), err)
	}
	pack := func(data []byte) []byte {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	corrupt := append([]byte(nil), packedJetstreamDictionary...)
	corrupt[len(corrupt)-8] ^= 0xff
	for _, tc := range []struct {
		name   string
		packed []byte
	}{
		{"invalid header", []byte("not gzip")},
		{"truncated", packedJetstreamDictionary[:len(packedJetstreamDictionary)-1]},
		{"corrupt checksum", corrupt},
		{"oversized", pack(make([]byte, jetstreamDictionaryBytes+1))},
		{"wrong dictionary", pack(make([]byte, jetstreamDictionaryBytes))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if dictionary, err := unpackJetstreamDictionary(tc.packed); err == nil || dictionary != nil {
				t.Fatal("invalid packed dictionary reached the network decoder")
			}
		})
	}
}
