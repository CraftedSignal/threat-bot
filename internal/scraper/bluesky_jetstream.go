package scraper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/coder/websocket"
	"github.com/craftedsignal/threat-bot/internal/config"
)

type BlueskyJetstream struct{ cfg config.BlueskyDiscoveryConfig }

// Jetstream can carry the complete post record, including embeds and facets.
// coder/websocket defaults to 32 KiB, below valid event sizes. Keep the client
// bounded at Jetstream's documented maximum message size instead.
const jetstreamMessageReadLimit = 10 << 20

func NewBlueskyJetstream(cfg config.BlueskyDiscoveryConfig) Scraper {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "wss://jetstream2.us-east.bsky.network/subscribe"
	}
	if cfg.CandidateCap <= 0 {
		cfg.CandidateCap = 100
	}
	if cfg.ReadWindow <= 0 {
		cfg.ReadWindow = 20 * time.Second
	}
	return &BlueskyJetstream{cfg: cfg}
}

// jetstreamDialRetries is how many more times a failed dial is attempted;
// Jetstream edges occasionally drop a handshake (EOF) that succeeds on retry.
const jetstreamDialRetries = 2

const jetstreamHandshakeTimeout = 10 * time.Second

// jetstreamDialBackoff is the jittered pause (1-3s) between dial attempts.
var jetstreamDialBackoff = func() time.Duration {
	return time.Second + time.Duration(rand.Int63n(int64(2*time.Second)))
}

// dialJetstream retries transient handshakes within bounded attempt deadlines.
// Official public instances can fail over; custom endpoints remain isolated.
// Exhaustion remains a failed poll so the runner retains its health/retry state.
func dialJetstream(ctx context.Context, endpoint string) (*websocket.Conn, error) {
	endpoints := jetstreamDialEndpoints(endpoint)
	var err error
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dialCtx, cancel := context.WithTimeout(ctx, jetstreamHandshakeTimeout)
		var c *websocket.Conn
		var response *http.Response
		c, response, err = websocket.Dial(dialCtx, endpoints[attempt%len(endpoints)], nil)
		cancel()
		if err == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if response != nil && response.StatusCode != http.StatusSwitchingProtocols {
			// Preserve machine-readable status without echoing proxy HTML,
			// response headers, or a configured endpoint's query/credentials.
			err = statusErrorf(response.StatusCode, "Jetstream handshake: HTTP %d", response.StatusCode)
		}
		if attempt >= jetstreamDialRetries || !transientJetstreamDialFailure(err) {
			return nil, err
		}
		timer := time.NewTimer(jetstreamDialBackoff())
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func transientJetstreamDialFailure(err error) bool {
	if code, ok := upstreamStatus(err); ok {
		// A forbidden response may be an expected source block in the runner,
		// but it is not a transient failure to route around on another host.
		return expectedUpstreamStatuses[code] && code != http.StatusForbidden
	}
	var networkError net.Error
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &networkError)
}

// jetstreamDialEndpoints only rotates the documented public v1 subscription
// endpoints. Preserve every subscription filter; time-based cursors can move
// across instances with a small overlap to avoid gaps. Poll filters old posts
// and the runner deduplicates previously processed item IDs.
// Public instance/cursor guidance: https://github.com/bluesky-social/jetstream-legacy#public-instances
func jetstreamDialEndpoints(endpoint string) []string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "wss" || u.User != nil || u.Path != "/subscribe" {
		return []string{endpoint}
	}
	hosts := []string{
		"jetstream2.us-east.bsky.network",
		"jetstream1.us-east.bsky.network",
		"jetstream2.us-west.bsky.network",
		"jetstream1.us-west.bsky.network",
	}
	for primary, host := range hosts {
		if u.Host != host {
			continue
		}
		endpoints := []string{endpoint}
		q := u.Query()
		if cursor, err := strconv.ParseInt(q.Get("cursor"), 10, 64); err == nil && cursor > 0 {
			q.Set("cursor", strconv.FormatInt(max(0, cursor-int64(5*time.Second/time.Microsecond)), 10))
		}
		u.RawQuery = q.Encode()
		for offset := 1; offset < len(hosts); offset++ {
			u.Host = hosts[(primary+offset)%len(hosts)]
			endpoints = append(endpoints, u.String())
		}
		return endpoints
	}
	return []string{endpoint}
}

func (b *BlueskyJetstream) Name() string { return "bluesky-discovery" }
func (b *BlueskyJetstream) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	window, err := b.pollWindow(ctx, since, nil, false)
	return window.Items, err
}
func (b *BlueskyJetstream) PollWindow(ctx context.Context, since time.Time, eligible func(RawItem) (bool, error)) (streamWindow, error) {
	return b.pollWindow(ctx, since, eligible, true)
}
func (b *BlueskyJetstream) pollWindow(ctx context.Context, since time.Time, eligible func(RawItem) (bool, error), overlap bool) (window streamWindow, err error) {
	if err := ctx.Err(); err != nil {
		return window, err
	}
	u, err := url.Parse(b.cfg.Endpoint)
	if err != nil {
		return window, err
	}
	q := u.Query()
	q.Set("wantedCollections", "app.bsky.feed.post")
	// Custom endpoints preserve their existing negotiation (including plain
	// fixtures); documented public endpoints support dictionary Zstd.
	if len(jetstreamDialEndpoints(b.cfg.Endpoint)) > 1 {
		q.Set("compress", "true")
	}
	if !since.IsZero() {
		cursor := since
		if overlap {
			cursor = cursor.Add(-5 * time.Second)
		}
		q.Set("cursor", strconv.FormatInt(cursor.UnixMicro(), 10))
	}
	u.RawQuery = q.Encode()
	c, err := dialJetstream(ctx, u.String())
	if err != nil {
		return window, fmt.Errorf("dialing Bluesky Jetstream: %w", err)
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(jetstreamMessageReadLimit)
	decoder, err := newJetstreamDecoder()
	if err != nil {
		return window, err
	}
	defer decoder.Close()
	readCtx, cancel := context.WithTimeout(ctx, b.cfg.ReadWindow)
	defer cancel()

	seen := map[string]bool{}
	for len(window.Items) < b.cfg.CandidateCap {
		messageType, data, err := c.Read(readCtx)
		if err != nil {
			if readCtx.Err() != nil {
				if ctx.Err() != nil {
					return window, ctx.Err()
				}
				return window, nil
			}
			return window, fmt.Errorf("reading Bluesky Jetstream: %w", err)
		}
		if messageType == websocket.MessageBinary {
			data, err = decoder.DecodeAll(data, nil)
			if err != nil {
				return window, fmt.Errorf("decompressing Jetstream event: %w", err)
			}
		}
		var ev struct {
			DID    string `json:"did"`
			TimeUS int64  `json:"time_us"`
			Kind   string `json:"kind"`
			Commit struct {
				Operation, Collection, RKey string
				Record                      struct{ Text, CreatedAt string } `json:"record"`
			} `json:"commit"`
		}
		if err := json.Unmarshal(data, &ev); err != nil {
			return window, fmt.Errorf("decoding Jetstream event: %w", err)
		}
		if ev.TimeUS <= 0 || ev.TimeUS > time.Now().Add(time.Minute).UnixMicro() {
			return window, fmt.Errorf("invalid Jetstream event timestamp")
		}
		eventTime := time.UnixMicro(ev.TimeUS)
		// Advance only after this event's candidate has been fully accepted.
		consumed := func() {
			if eventTime.After(window.Watermark) {
				window.Watermark = eventTime
			}
		}
		if ev.Kind != "commit" || ev.Commit.Operation != "create" || ev.Commit.Collection != "app.bsky.feed.post" || ev.DID == "" || ev.Commit.RKey == "" {
			consumed()
			continue
		}
		id := b.Name() + ":" + ev.DID + ":" + ev.Commit.RKey
		published, _ := time.Parse(time.RFC3339, ev.Commit.Record.CreatedAt)
		if published.IsZero() && ev.TimeUS > 0 {
			published = time.UnixMicro(ev.TimeUS)
		}
		if eventTime.Before(since) && !overlap {
			consumed()
			continue
		}
		postURL := "https://bsky.app/profile/" + url.PathEscape(ev.DID) + "/post/" + url.PathEscape(ev.Commit.RKey)
		item := RawItem{SourceID: id, Source: b.Name(), Title: ev.Commit.Record.Text, URL: postURL, Content: ev.Commit.Record.Text, PublishedAt: published, Discovery: &DiscoveryContext{Platform: "bluesky", OriginalURL: postURL, DiscoveryURL: postURL, Author: ev.DID, ContextComplete: true}}
		if IsRelevantDiscoveryCandidate(item) {
			if seen[id] {
				consumed()
				continue
			}
			seen[id] = true
			item.Revision = item.ContentRevision()
			accept := true
			if eligible != nil {
				accept, err = eligible(item)
				if err != nil {
					return window, err
				}
			}
			if accept {
				window.Items = append(window.Items, item)
			}
		}
		consumed()
	}
	return window, nil
}
