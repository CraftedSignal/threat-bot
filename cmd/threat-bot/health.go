package main

import (
	"context"
	"fmt"
	"github.com/craftedsignal/threat-bot/internal/llm"
	"net/http"
	"sync/atomic"
	"time"
)

func newHealthServer(poll *atomic.Bool, monitor *llm.HealthMonitor) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if poll.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, "ok")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, "poll loop unhealthy")
		}
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		status := monitor.Status()
		if !status.OK {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "llm unhealthy: %s\n", status.Message)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})
	return &http.Server{Addr: ":8086", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
}

// shutdownHealthServer drains active probe requests within a fixed bound.
func shutdownHealthServer(srv *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
		return err
	}
	return nil
}
