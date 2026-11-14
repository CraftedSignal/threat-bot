package scraper

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A daily source spends half of each day more than 12 hours past its last
// poll; that is its cadence, not silence.
func TestLogAnomaliesUsesEachSourcesPollInterval(t *testing.T) {
	r := NewRunner(nil, testLogger(), 0)
	r.RegisterWithInterval(staticScraper{name: "daily"}, 24*time.Hour)
	r.RegisterWithInterval(staticScraper{name: "hourly"}, time.Hour)
	lastSuccess := time.Now().Add(-13 * time.Hour)
	r.health["daily"] = SourceHealth{Source: "daily", LastSuccess: lastSuccess, SilentPolls: 1}
	r.health["hourly"] = SourceHealth{Source: "hourly", LastSuccess: lastSuccess, SilentPolls: 1}

	var buf bytes.Buffer
	r.LogAnomalies(slog.New(slog.NewTextHandler(&buf, nil)))

	out := buf.String()
	if !strings.Contains(out, "sources silent past expected cadence") || !strings.Contains(out, "hourly") {
		t.Fatalf("expected the hourly source to be flagged, got %q", out)
	}
	if strings.Contains(out, "daily") {
		t.Errorf("daily source flagged within its poll interval: %q", out)
	}
}

func TestHealthSummaryUsesPollIntervalForStaleness(t *testing.T) {
	tests := []struct {
		name              string
		pollInterval      time.Duration
		lastSuccessAge    time.Duration
		consecutiveErrors int
		wantHealthy       bool
	}{
		{name: "daily before missed poll", pollInterval: 24 * time.Hour, lastSuccessAge: 25 * time.Hour, wantHealthy: true},
		{name: "daily after missed poll", pollInterval: 24 * time.Hour, lastSuccessAge: 49 * time.Hour, wantHealthy: false},
		{name: "short cadence keeps 24 hour floor", pollInterval: 12 * time.Hour, lastSuccessAge: 25 * time.Hour, wantHealthy: false},
		{name: "errors override cadence", pollInterval: 24 * time.Hour, lastSuccessAge: time.Hour, consecutiveErrors: 4, wantHealthy: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRunner(nil, testLogger(), 0)
			r.RegisterWithInterval(staticScraper{name: "source"}, tt.pollInterval)
			r.health["source"] = SourceHealth{
				Source:            "source",
				LastSuccess:       time.Now().Add(-tt.lastSuccessAge),
				ConsecutiveErrors: tt.consecutiveErrors,
			}

			health := r.HealthSummary()
			if len(health) != 1 {
				t.Fatalf("health summary length = %d, want 1", len(health))
			}
			if got := health[0].IsHealthy(); got != tt.wantHealthy {
				t.Fatalf("IsHealthy() = %t, want %t", got, tt.wantHealthy)
			}
		})
	}
}
