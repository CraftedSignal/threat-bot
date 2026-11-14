package publisher

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func blobTestPublisher(srv *httptest.Server) *Publisher {
	p := testPublisher(srv)
	p.blobDeadlineBase = 100 * time.Millisecond
	p.blobRate = 1 << 20
	p.blobDeadlineMax = time.Second
	p.blobBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	return p
}

func TestBlobDeadlineIsSizeAware(t *testing.T) {
	p := &Publisher{}
	if got := p.blobDeadline(0); got != 60*time.Second {
		t.Fatalf("empty = %s", got)
	}
	if got := p.blobDeadline(256 << 10 * 100); got != 160*time.Second {
		t.Fatalf("25 MiB = %s", got)
	}
	if got := p.blobDeadline(200 << 20); got != 10*time.Minute {
		t.Fatalf("200 MiB = %s, want the 10m cap", got)
	}
}

func TestFetchBlobRetriesAfterStall(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
			return
		}
		w.Write([]byte("blob"))
	}))
	defer srv.Close()
	got, err := blobTestPublisher(srv).fetchBlob("sha", 4)
	if err != nil || string(got) != "blob" || calls.Load() != 2 {
		t.Fatalf("got %q, %v after %d calls", got, err, calls.Load())
	}
}

func TestFetchBlobRetries502(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	got, err := blobTestPublisher(srv).fetchBlob("sha", 2)
	if err != nil || string(got) != "ok" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestFetchBlobGivesUpAfterThreeAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := blobTestPublisher(srv).fetchBlob("sha", 2); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestFetchBlobDoesNotRetry404(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := blobTestPublisher(srv).fetchBlob("sha", 2); err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestFetchBlobStillRejectsOversizeBody(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		chunk := make([]byte, 1<<20)
		for i := 0; i <= maxFeedFileBytes>>20; i++ {
			w.Write(chunk)
		}
	}))
	defer srv.Close()
	p := blobTestPublisher(srv)
	p.blobDeadlineBase = 30 * time.Second
	// This test exercises the byte limit, not the one-second stall/retry cap
	// used by the other fixtures. Keep the full transfer budget under -race.
	p.blobDeadlineMax = 30 * time.Second
	if _, err := p.fetchBlob("sha", 1); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("oversize body retried: %d calls", calls.Load())
	}
}
