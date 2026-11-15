package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

func TestSourceHealthAlertsOnceForSustainedUpstreamFailureAndRecovery(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	previous := make(map[string]bool)
	health := []scraper.SourceHealth{{
		Source: "ransomware-live", ConsecutiveErrors: 4,
		LastError: time.Now(), LastErrorExpectedUpstream: true,
		LastErrorMessage: "x509: certificate has expired", LastErrorClass: "tls_certificate",
	}}
	logSourceHealthTransitions(logger, health, previous)
	logSourceHealthTransitions(logger, health, previous)
	health[0].ConsecutiveErrors = 0
	health[0].LastSuccess = time.Now()
	health[0].LastErrorMessage = ""
	health[0].LastErrorClass = ""
	logSourceHealthTransitions(logger, health, previous)
	logSourceHealthTransitions(logger, health, previous)
	decoder := json.NewDecoder(&logs)
	var outage, recovery map[string]any
	if err := decoder.Decode(&outage); err != nil {
		t.Fatal(err)
	}
	if outage["level"] != "ERROR" || outage["msg"] != "source unhealthy" || outage["source"] != "ransomware-live" || outage["error"] != "x509: certificate has expired" || outage["error_class"] != "tls_certificate" || outage["health_reason"] != "poll_errors" {
		t.Fatalf("persistent upstream outage lost actionable alert: %+v", outage)
	}
	if err := decoder.Decode(&recovery); err != nil {
		t.Fatal(err)
	}
	if recovery["level"] != "INFO" || recovery["msg"] != "source recovered" {
		t.Fatalf("recovery was not recorded: %+v", recovery)
	}
	if err := decoder.Decode(&recovery); err != io.EOF {
		t.Fatalf("duplicate transition was logged: %+v, %v", recovery, err)
	}
}

func TestStaleSourceHealthExplainsMissingSuccessfulPoll(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	logSourceHealthTransitions(logger, []scraper.SourceHealth{{Source: "stale", LastSuccess: time.Now().Add(-25 * time.Hour)}}, make(map[string]bool))
	var alert map[string]any
	if err := json.NewDecoder(&logs).Decode(&alert); err != nil {
		t.Fatal(err)
	}
	if alert["error"] == "" || alert["error"] == nil || alert["error_class"] != "stale_poll" || alert["health_reason"] != "stale_poll" {
		t.Fatalf("stale source alert lacks an explanation: %+v", alert)
	}
}
