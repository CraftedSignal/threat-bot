package scraper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
	"github.com/mmcdole/gofeed"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type staticScraper struct{ name string }

func (s staticScraper) Name() string { return s.name }

func (s staticScraper) Poll(context.Context, time.Time) ([]RawItem, error) { return nil, nil }

type anchorSourceScraper struct{ item RawItem }

func (s anchorSourceScraper) Name() string { return "anchor-source" }
func (s anchorSourceScraper) Poll(context.Context, time.Time) ([]RawItem, error) {
	return []RawItem{s.item}, nil
}

type anchorObserverScraper struct{ observed []RawItem }

func (s *anchorObserverScraper) Name() string                                       { return "anchor-observer" }
func (s *anchorObserverScraper) Poll(context.Context, time.Time) ([]RawItem, error) { return nil, nil }
func (s *anchorObserverScraper) ObserveDiscoveryItems(items []RawItem) {
	s.observed = append(s.observed, items...)
}

type failingScraper struct {
	name string
	err  error
}

func (s failingScraper) Name() string { return s.name }

func (s failingScraper) Poll(context.Context, time.Time) ([]RawItem, error) {
	return nil, s.err
}

type shutdownScraper struct {
	name   string
	cancel context.CancelFunc
}

func (s shutdownScraper) Name() string { return s.name }

func (s shutdownScraper) Poll(ctx context.Context, _ time.Time) ([]RawItem, error) {
	s.cancel()
	return nil, fmt.Errorf("request interrupted: %w", ctx.Err())
}

// An unset interval must fall back to something conservative: a 1-minute
// default turned every feed into ~1,000 fetches/day and got the prod egress
// IP bot-blocked by multiple sources.
func TestRegisterWithIntervalDefaultsToOneHour(t *testing.T) {
	r := NewRunner(nil, testLogger(), 0)
	r.RegisterWithInterval(staticScraper{name: "unset"}, 0)

	if got := r.PollIntervals()["unset"]; got != time.Hour {
		t.Fatalf("default poll interval = %v, want %v", got, time.Hour)
	}
}

func TestRegisterWithIntervalKeepsExplicitInterval(t *testing.T) {
	r := NewRunner(nil, testLogger(), 0)
	r.RegisterWithInterval(staticScraper{name: "slow"}, 6*time.Hour)
	r.RegisterWithInterval(staticScraper{name: "fast"}, 5*time.Minute)

	got := r.PollIntervals()
	if got["slow"] != 6*time.Hour {
		t.Fatalf("slow interval = %v, want 6h", got["slow"])
	}
	if got["fast"] != 5*time.Minute {
		t.Fatalf("fast interval = %v, want 5m", got["fast"])
	}
}

func TestRunnerFeedsNewItemsToDiscoveryAnchorObservers(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	observer := &anchorObserverScraper{}
	r := NewRunner(db, testLogger(), 24*time.Hour)
	r.RegisterWithInterval(anchorSourceScraper{item: RawItem{SourceID: "nvd:1", Source: "nvd", Title: "CVE-2026-111497 Brotli decompression", PublishedAt: time.Now()}}, time.Hour)
	r.RegisterWithInterval(observer, time.Hour)
	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(observer.observed) != 1 || observer.observed[0].SourceID != "nvd:1" {
		t.Fatalf("observed=%+v", observer.observed)
	}
}

func TestAdaptivePollingDoublesAfterTwoEmptyPollsAndResets(t *testing.T) {
	entry := &scraperEntry{
		basePollInterval: time.Hour,
		pollInterval:     time.Hour,
		adaptiveMax:      8 * time.Hour,
	}

	updateAdaptivePolling(entry, 0)
	if entry.pollInterval != time.Hour {
		t.Fatalf("interval after one empty poll = %v", entry.pollInterval)
	}
	updateAdaptivePolling(entry, 0)
	if entry.pollInterval != 2*time.Hour {
		t.Fatalf("interval after two empty polls = %v, want 2h", entry.pollInterval)
	}
	updateAdaptivePolling(entry, 0)
	updateAdaptivePolling(entry, 0)
	if entry.pollInterval != 4*time.Hour {
		t.Fatalf("interval after four empty polls = %v, want 4h", entry.pollInterval)
	}
	updateAdaptivePolling(entry, 1)
	if entry.pollInterval != time.Hour || entry.consecutiveEmpty != 0 {
		t.Fatalf("new content did not reset interval: %+v", entry)
	}
}

func TestSetAdaptivePollingIsOptInBySource(t *testing.T) {
	r := NewRunner(nil, testLogger(), 0)
	r.RegisterWithInterval(staticScraper{name: "quiet"}, time.Hour)
	if !r.SetAdaptivePolling("quiet", 8*time.Hour) {
		t.Fatal("registered source was not configured")
	}
	if r.SetAdaptivePolling("missing", 8*time.Hour) {
		t.Fatal("unknown source reported configured")
	}
	if got := r.entries[0].adaptiveMax; got != 8*time.Hour {
		t.Fatalf("adaptive max = %v", got)
	}
}

type countingScraper struct {
	name  string
	polls atomic.Int32
}

func (s *countingScraper) Name() string { return s.name }

func (s *countingScraper) Poll(context.Context, time.Time) ([]RawItem, error) {
	s.polls.Add(1)
	return nil, nil
}

// All ~50 sources used to fire simultaneously on a cold start, tripping
// rate limits (Reddit 429s on every boot). First polls must be staggered.
func TestColdStartPollsAreStaggered(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	r := NewRunner(db, testLogger(), 0)
	scrapers := make([]*countingScraper, 4)
	for i := range scrapers {
		scrapers[i] = &countingScraper{name: fmt.Sprintf("src-%d", i)}
		r.RegisterWithInterval(scrapers[i], time.Hour)
	}

	if _, err := r.PollAll(context.Background()); err != nil {
		t.Logf("poll errors (fine): %v", err)
	}

	polled := 0
	for i, sc := range scrapers {
		t.Logf("scraper %d polls=%d", i, sc.polls.Load())
		polled += int(sc.polls.Load())
	}
	if polled != 1 {
		t.Fatalf("cold start polled %d sources immediately, want 1 (staggered)", polled)
	}
}

func TestExpectedUpstreamScraperErrorLogsWarning(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	r := NewRunner(db, logger, 0)
	r.RegisterWithInterval(failingScraper{
		name: "hackread",
		err:  statusErrorf(http.StatusForbidden, "parsing feed https://hackread.com/feed/: http error: 403 Forbidden"),
	}, time.Hour)

	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatalf("poll all: %v", err)
	}

	out := logs.String()
	if !strings.Contains(out, `"level":"WARN"`) {
		t.Fatalf("expected warning log for upstream block, got %s", out)
	}
	if strings.Contains(out, `"level":"ERROR"`) {
		t.Fatalf("did not expect error log for upstream block, got %s", out)
	}

	health := r.HealthSummary()
	if len(health) != 1 {
		t.Fatalf("expected one health entry, got %d", len(health))
	}
	if !health[0].LastErrorExpectedUpstream {
		t.Fatalf("expected upstream error flag on health entry: %+v", health[0])
	}
}

func TestDirectHTTPRateLimitScraperErrorLogsWarning(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	r := NewRunner(db, logger, 0)
	r.RegisterWithInterval(failingScraper{
		name: "reddit-netsec",
		err:  fmt.Errorf("poll: %w", gofeed.HTTPError{StatusCode: http.StatusTooManyRequests, Status: "429 Too Many Requests"}),
	}, time.Hour)

	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatalf("poll all: %v", err)
	}

	out := logs.String()
	if !strings.Contains(out, `"level":"WARN"`) {
		t.Fatalf("expected warning log for upstream rate limit, got %s", out)
	}
	if strings.Contains(out, `"level":"ERROR"`) {
		t.Fatalf("did not expect error log for upstream rate limit, got %s", out)
	}

	health := r.HealthSummary()
	if len(health) != 1 {
		t.Fatalf("expected one health entry, got %d", len(health))
	}
	if !health[0].LastErrorExpectedUpstream {
		t.Fatalf("expected upstream error flag on health entry: %+v", health[0])
	}
}

func TestTransientHTTPGatewayScraperErrorLogsWarning(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	r := NewRunner(db, logger, 0)
	r.RegisterWithInterval(failingScraper{
		name: "exploit-db",
		err:  fmt.Errorf("parsing exploit-db feed: %w", gofeed.HTTPError{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"}),
	}, time.Hour)

	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatalf("poll all: %v", err)
	}

	out := logs.String()
	if !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, `"msg":"scraper upstream unavailable"`) {
		t.Fatalf("expected warning log for transient upstream gateway failure, got %s", out)
	}
	if strings.Contains(out, `"level":"ERROR"`) || strings.Contains(out, `"msg":"scraper error"`) {
		t.Fatalf("did not expect error log for transient upstream gateway failure, got %s", out)
	}

	health := r.HealthSummary()
	if len(health) != 1 || !health[0].LastErrorExpectedUpstream {
		t.Fatalf("expected upstream error health state, got %+v", health)
	}
}

func TestCloudflareOriginFailureLogsWarningWithBoundedError(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var logs bytes.Buffer
	r := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
	r.RegisterWithInterval(failingScraper{
		name: "databreaches",
		err:  statusErrorf(523, "parsing feed: http error: 523 Origin Is Unreachable: %s", strings.Repeat("<html>failure</html>", 500)),
	}, time.Hour)

	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatalf("poll all: %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, `"level":"WARN"`) || strings.Contains(out, `"level":"ERROR"`) {
		t.Fatalf("Cloudflare origin outage should be an expected upstream warning: %s", out)
	}
	if len(out) > 1800 || !strings.Contains(out, "redacted") {
		t.Fatalf("upstream warning was not bounded for alert delivery (len=%d): %s", len(out), out)
	}
}

func TestUnexpectedScraperErrorStillLogsError(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	r := NewRunner(db, logger, 0)
	r.RegisterWithInterval(failingScraper{
		name: "internal",
		err:  errors.New("decode local cache: checksum mismatch"),
	}, time.Hour)

	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatalf("poll all: %v", err)
	}

	out := logs.String()
	if !strings.Contains(out, `"level":"ERROR"`) {
		t.Fatalf("expected error log for unexpected scraper failure, got %s", out)
	}
	if !strings.Contains(out, `"msg":"scraper error"`) {
		t.Fatalf("expected scraper error log, got %s", out)
	}
}

func TestPollAllReturnsShutdownCancellationWithoutLoggingOrHealthFailure(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var logs bytes.Buffer
	r := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
	r.RegisterWithInterval(shutdownScraper{name: "shutdown", cancel: cancel}, time.Hour)

	if _, err := r.PollAll(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("poll all error = %v, want context cancellation", err)
	}
	if out := logs.String(); strings.Contains(out, `"level":"ERROR"`) || strings.Contains(out, `"msg":"scraper error"`) {
		t.Fatalf("shutdown cancellation was logged as a scraper failure: %s", out)
	}
	if health := r.HealthSummary(); len(health) != 0 {
		t.Fatalf("shutdown cancellation changed source health: %+v", health)
	}
}

func TestPollAllTreatsChildCancellationAsScraperFailure(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var logs bytes.Buffer
	r := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
	r.RegisterWithInterval(failingScraper{name: "child", err: context.Canceled}, time.Hour)

	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatalf("poll all: %v", err)
	}
	if out := logs.String(); !strings.Contains(out, `"level":"ERROR"`) || !strings.Contains(out, `"msg":"scraper error"`) {
		t.Fatalf("child cancellation was not logged as a scraper failure: %s", out)
	}
	health := r.HealthSummary()
	if len(health) != 1 || health[0].ConsecutiveErrors != 1 {
		t.Fatalf("child cancellation health = %+v, want one consecutive error", health)
	}
}

type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

func TestIsExpectedUpstreamScraperErrorClassifiesDroppedConnections(t *testing.T) {
	wrapped := fmt.Errorf("bluesky-discovery: poll: dialing: %w", &url.Error{Op: "Get", URL: "https://x", Err: io.EOF})
	for name, err := range map[string]error{
		"eof":         io.EOF,
		"wrapped eof": wrapped,
		"unexpected":  fmt.Errorf("read: %w", io.ErrUnexpectedEOF),
		"net timeout": timeoutNetErr{},
		"wrapped to":  fmt.Errorf("poll: %w", timeoutNetErr{}),
	} {
		if !isExpectedUpstreamScraperError(err) {
			t.Errorf("%s: want expected upstream error", name)
		}
	}
	if isExpectedUpstreamScraperError(errors.New("something else broke")) {
		t.Error("unrelated error must not be expected")
	}
}

func TestPollLogDoesNotExposeCredentialURLOrResponseBody(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var logs bytes.Buffer
	r := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
	r.RegisterWithInterval(failingScraper{name: "synthetic", err: statusErrorf(503, "https://user:sentinel-password@feed.example.test/secret-path?key=sentinel-query: sentinel-body")}, time.Hour)
	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sentinel-password", "secret-path", "sentinel-query", "sentinel-body"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("log exposed %s", secret)
		}
	}
	if !strings.Contains(logs.String(), "503") {
		t.Fatal("safe log lost HTTP status")
	}
}
