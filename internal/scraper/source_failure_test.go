package scraper

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

func expiredSourceCertificate() error {
	return &url.Error{Op: "Get", URL: "https://source.example/recentvictims", Err: x509.CertificateInvalidError{
		Cert: &x509.Certificate{NotAfter: time.Date(2026, 11, 14, 20, 59, 4, 0, time.UTC)}, Reason: x509.Expired,
	}}
}

func sourceFailureLogs(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(logs.Bytes()))
	var result []map[string]any
	for {
		var entry map[string]any
		if err := decoder.Decode(&entry); errors.Is(err, io.EOF) {
			return result
		} else if err != nil {
			t.Fatal(err)
		}
		if entry["msg"] == "scraper error" || entry["msg"] == "scraper upstream unavailable" {
			result = append(result, entry)
		}
	}
}

func TestRunnerDeduplicatesSourceFailuresWithoutLosingHealth(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs bytes.Buffer
	r := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
	r.RegisterWithInterval(failingScraper{name: "ransomware-live", err: expiredSourceCertificate()}, time.Hour)
	for range 4 {
		r.entries[0].lastPoll = time.Time{}
		if _, err := r.PollAll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	failures := sourceFailureLogs(t, &logs)
	if len(failures) != 1 {
		t.Fatalf("persistent failure produced %d alerts, want one initial diagnostic: %+v", len(failures), failures)
	}
	first := failures[0]
	if first["level"] != "WARN" || first["source"] != "ransomware-live" || first["error_class"] != "tls_certificate" || first["error"] == "" || first["error"] == nil {
		t.Fatalf("TLS failure lost structured upstream diagnostics: %+v", first)
	}
	health := r.HealthSummary()
	if len(health) != 1 || health[0].ConsecutiveErrors != 4 || health[0].IsHealthy() || !health[0].LastSuccess.IsZero() {
		t.Fatalf("deduplication hid persistent source degradation: %+v", health)
	}
	if state, err := db.GetScraperState("ransomware-live"); err != nil || state != nil {
		t.Fatalf("failed source advanced durable poll state: %+v, %v", state, err)
	}
}

func TestRunnerLogsChangedFailureAndNewFailureAfterRecovery(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs bytes.Buffer
	r := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
	r.RegisterWithInterval(failingScraper{name: "source", err: expiredSourceCertificate()}, time.Hour)
	for i, failure := range []error{expiredSourceCertificate(), statusErrorf(503, "service unavailable"), errors.New("decode cache failed"), errors.New("invalid configuration")} {
		r.entries[0].scraper = failingScraper{name: "source", err: failure}
		r.entries[0].lastPoll = time.Time{}
		if _, err := r.PollAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := len(sourceFailureLogs(t, &logs)); got != i+1 {
			t.Fatalf("changed failure %d was suppressed: %s", i, logs.String())
		}
	}
	r.entries[0].scraper = staticScraper{name: "source"}
	r.entries[0].lastPoll = time.Time{}
	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.entries[0].scraper = failingScraper{name: "source", err: errors.New("invalid configuration")}
	r.entries[0].lastPoll = time.Time{}
	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(sourceFailureLogs(t, &logs)); got != 5 {
		t.Fatalf("new failure after recovery was suppressed: %s", logs.String())
	}
}

func TestRunnerDistinctFailureDiagnosticsKeepCredentialDetailsPrivate(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs bytes.Buffer
	r := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
	r.RegisterWithInterval(failingScraper{name: "source"}, time.Hour)
	for _, secret := range []string{"sentinel-first", "sentinel-second"} {
		r.entries[0].scraper = failingScraper{name: "source", err: errors.New("https://user:" + secret + "@source.example/private-path?key=" + secret)}
		r.entries[0].lastPoll = time.Time{}
		if _, err := r.PollAll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(sourceFailureLogs(t, &logs)); got != 2 {
		t.Fatalf("distinct failures sharing redacted text produced %d diagnostics, want 2", got)
	}
	for _, secret := range []string{"sentinel-first", "sentinel-second", "private-path"} {
		if strings.Contains(logs.String(), secret) || strings.Contains(r.HealthSummary()[0].LastErrorMessage, secret) {
			t.Fatal("source diagnostics retained credential-bearing error details")
		}
	}
}

func TestRunnerRemindsAboutPersistentFailuresAndClearsRecoveryDiagnostics(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/scrapers.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs bytes.Buffer
	r := NewRunner(db, slog.New(slog.NewJSONHandler(&logs, nil)), 0)
	r.RegisterWithInterval(failingScraper{name: "source", err: statusErrorf(503, "service unavailable")}, time.Hour)
	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	health := r.HealthSummary()[0]
	if health.LastErrorMessage != "upstream HTTP 503 (details redacted)" || health.LastErrorClass != "http_503" || !health.LastErrorExpectedUpstream {
		t.Fatalf("health discarded the underlying failure: %+v", health)
	}
	// Advance the diagnostic clock without waiting; poll scheduling remains
	// real and health is still updated on every failed request.
	health.lastErrorLog = time.Now().Add(-7 * time.Hour)
	r.health["source"] = health
	r.entries[0].lastPoll = time.Time{}
	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	failures := sourceFailureLogs(t, &logs)
	if len(failures) != 2 || failures[1]["consecutive_errors"] != float64(2) {
		t.Fatalf("persistent failure reminder missing: %+v", failures)
	}
	r.entries[0].scraper = staticScraper{name: "source"}
	r.entries[0].lastPoll = time.Time{}
	if _, err := r.PollAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	health = r.HealthSummary()[0]
	if health.ConsecutiveErrors != 0 || health.LastErrorMessage != "" || health.LastErrorClass != "" || health.LastErrorExpectedUpstream || !health.IsHealthy() {
		t.Fatalf("recovered health retained stale failure diagnostics: %+v", health)
	}
}

func TestCertificateVerificationFailuresRemainExpectedUpstreamErrors(t *testing.T) {
	for _, err := range []error{
		expiredSourceCertificate(),
		fmt.Errorf("poll: %w", x509.UnknownAuthorityError{}),
		fmt.Errorf("poll: %w", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "source.test"}),
	} {
		if !isExpectedUpstreamScraperError(err) {
			t.Errorf("certificate verification failure misclassified as bot defect: %v", err)
		}
	}
	if isExpectedUpstreamScraperError(errors.New("tls_certificate in unrelated local error")) {
		t.Fatal("untyped local error misclassified by message text")
	}
}

func TestRansomwareLiveRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[]`)
	}))
	server.Config.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError)
	server.StartTLS()
	defer server.Close()
	source := NewRansomwareLive()
	source.client = &http.Client{Transport: jetstreamRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		copy := req.Clone(req.Context())
		copy.URL, _ = url.Parse(server.URL)
		return http.DefaultTransport.RoundTrip(copy)
	})}
	items, err := source.Poll(context.Background(), time.Time{})
	var certErr x509.UnknownAuthorityError
	if len(items) != 0 || !errors.As(err, &certErr) {
		t.Fatalf("untrusted source was accepted: items=%d, error=%v", len(items), err)
	}
}
