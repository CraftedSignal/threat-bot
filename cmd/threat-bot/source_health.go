package main

import (
	"log/slog"

	"github.com/craftedsignal/threat-bot/internal/scraper"
)

// logSourceHealthTransitions reports each sustained outage and recovery once.
// Poll-level upstream warnings remain diagnostic; a sustained outage is an
// operational error even when the upstream service is responsible.
func logSourceHealthTransitions(logger *slog.Logger, health []scraper.SourceHealth, prevHealthy map[string]bool) {
	for _, h := range health {
		healthy := h.IsHealthy()
		was, seen := prevHealthy[h.Source]
		prevHealthy[h.Source] = healthy
		if (seen && was == healthy) || (!seen && healthy) {
			continue
		}
		if healthy {
			logger.Info("source recovered",
				"source", h.Source,
				"last_success", h.LastSuccess,
				"total_items", h.TotalItems,
			)
			continue
		}

		reason := "stale_poll"
		if h.ConsecutiveErrors > 3 {
			reason = "poll_errors"
		}
		message, errorClass := h.LastErrorMessage, h.LastErrorClass
		if message == "" {
			message = "no successful poll within expected source cadence"
			errorClass = "stale_poll"
			if reason == "poll_errors" {
				message = "source repeatedly failed to poll"
				errorClass = "unexpected"
			}
		}
		logger.Error("source unhealthy",
			"source", h.Source,
			"error", message,
			"error_class", errorClass,
			"health_reason", reason,
			"consecutive_errors", h.ConsecutiveErrors,
			"last_success", h.LastSuccess,
			"last_error", h.LastError,
			"last_error_expected_upstream", h.LastErrorExpectedUpstream,
			"total_items", h.TotalItems,
		)
	}
}
