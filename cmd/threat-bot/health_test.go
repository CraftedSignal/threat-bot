package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/craftedsignal/threat-bot/internal/llm"
)

func TestHealthServerHasBoundedRedactedProbesAndTimeouts(t *testing.T) {
	var poll atomic.Bool
	poll.Store(true)
	monitor := llm.NewHealthMonitor()
	monitor.Register("primary", "model")
	monitor.RecordError("primary", "model", errors.New("BENIGN_HEALTH_SENTINEL"))
	srv := newHealthServer(&poll, monitor)
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Error("health server has unbounded timeouts")
	}
	for _, tc := range []struct {
		path string
		code int
	}{{"/healthz", 200}, {"/readyz", 503}} {
		rr := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rr.Code != tc.code {
			t.Errorf("%s status %d", tc.path, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "BENIGN_HEALTH_SENTINEL") || rr.Body.Len() > 80 {
			t.Error("unsafe probe output")
		}
	}
}

func TestHealthShutdownDrainsActiveProbeAndClosesListener(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Start()
	defer srv.Close()
	response := make(chan error, 1)
	go func() {
		resp, err := srv.Client().Get(srv.URL)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe never started")
	}
	done := make(chan error, 1)
	go func() { done <- shutdownHealthServer(srv.Config) }()
	select {
	case err := <-done:
		close(release)
		t.Fatalf("shutdown did not drain active probe: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-response; err != nil {
		t.Fatalf("active probe interrupted: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if resp, err := srv.Client().Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("shutdown left probe listener open")
	}
}
