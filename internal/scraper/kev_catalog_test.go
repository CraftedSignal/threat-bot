package scraper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// kevFixture is a trimmed copy of the live CISA catalog. CVE-2026-84869
// (ConnectWise ScreenConnect, added 2026-09-11) is in the real catalog; the
// feed had published it with kev: false because the set was never filled.
const kevFixture = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.11.10",
  "dateReleased": "2026-11-10T19:03:29.8375Z",
  "count": 2,
  "vulnerabilities": [
    {"cveID": "CVE-2026-84869", "vendorProject": "ConnectWise", "product": "ScreenConnect",
     "vulnerabilityName": "ConnectWise ScreenConnect Improper Privilege Management and Missing Authorization Vulnerability",
     "dateAdded": "2026-09-11", "shortDescription": "ScreenConnect allows unauthorized file transfer and execution.",
     "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2026-09-14",
     "knownRansomwareCampaignUse": "Unknown", "notes": ""},
    {"cveID": "cve-2021-44228 ", "vendorProject": "Apache", "product": "Log4j2",
     "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
     "dateAdded": "2021-12-10", "shortDescription": "Log4Shell.",
     "requiredAction": "Apply updates.", "dueDate": "2021-12-24",
     "knownRansomwareCampaignUse": "Known", "notes": ""}
  ]
}`

// kevServer serves body with status until swap replaces them.
type kevServer struct {
	mu     sync.Mutex
	status int
	body   string
	hits   atomic.Int32
	srv    *httptest.Server
}

func newKEVServer(t *testing.T, status int, body string) *kevServer {
	t.Helper()
	s := &kevServer{status: status, body: body}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		status, body := s.status, s.body
		s.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *kevServer) swap(status int, body string) {
	s.mu.Lock()
	s.status, s.body = status, body
	s.mu.Unlock()
}

func kevSourceFor(s *kevServer, catalog *KEVCatalog) *CISAKEV {
	c := NewCISAKEV(catalog)
	c.client = s.srv.Client()
	c.url = s.srv.URL
	return c
}

func TestKEVCatalogUnknownUntilLoaded(t *testing.T) {
	var nilCatalog *KEVCatalog
	if listed, known := nilCatalog.Lookup("CVE-2026-84869"); listed || known {
		t.Fatalf("nil catalog Lookup = (%v, %v), want unknown", listed, known)
	}
	catalog := NewKEVCatalog()
	if listed, known := catalog.Lookup("CVE-2026-84869"); listed || known {
		t.Fatalf("unloaded catalog Lookup = (%v, %v), want unknown, not \"not listed\"", listed, known)
	}
}

// Every poll of the KEV source refreshes the full set, including CVEs added
// before the poll's since window, which produce no items.
func TestCISAKEVPollFillsCatalog(t *testing.T) {
	srv := newKEVServer(t, http.StatusOK, kevFixture)
	catalog := NewKEVCatalog()
	source := kevSourceFor(srv, catalog)

	items, err := source.Poll(context.Background(), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("Poll returned %d items for entries added before since, want 0", len(items))
	}
	for _, id := range []string{"CVE-2026-84869", "cve-2026-84869", "CVE-2021-44228"} {
		if listed, known := catalog.Lookup(id); !listed || !known {
			t.Errorf("Lookup(%s) = (%v, %v), want listed", id, listed, known)
		}
	}
	if listed, known := catalog.Lookup("CVE-2026-0001"); listed || !known {
		t.Errorf("Lookup(unlisted) = (%v, %v), want known and not listed", listed, known)
	}
	if got := catalog.Len(); got != 2 {
		t.Errorf("Len = %d, want 2", got)
	}
}

// The startup load uses the same download as the poll but produces no items.
func TestCISAKEVLoadCatalogFillsSet(t *testing.T) {
	srv := newKEVServer(t, http.StatusOK, kevFixture)
	catalog := NewKEVCatalog()
	if err := kevSourceFor(srv, catalog).LoadCatalog(context.Background()); err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	if listed, known := catalog.Lookup("CVE-2026-84869"); !listed || !known {
		t.Fatalf("Lookup = (%v, %v) after LoadCatalog, want listed", listed, known)
	}
}

// A failed download, or one that lists nothing, must never wipe the set.
func TestKEVCatalogKeepsLastGoodSetWhenRefreshFails(t *testing.T) {
	srv := newKEVServer(t, http.StatusOK, kevFixture)
	catalog := NewKEVCatalog()
	source := kevSourceFor(srv, catalog)
	if err := source.LoadCatalog(context.Background()); err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	failures := []struct {
		name   string
		status int
		body   string
		is     error
	}{
		{name: "server error", status: http.StatusBadGateway, body: "bad gateway"},
		{name: "truncated JSON", status: http.StatusOK, body: kevFixture[:200]},
		{name: "empty catalog", status: http.StatusOK, body: `{"count": 0, "vulnerabilities": []}`, is: ErrKEVCatalogEmpty},
		{name: "other JSON document", status: http.StatusOK, body: `{"error": "maintenance"}`, is: ErrKEVCatalogEmpty},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			srv.swap(tc.status, tc.body)
			if _, err := source.Poll(context.Background(), time.Time{}); err == nil {
				t.Fatal("Poll succeeded, want an error")
			} else if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("Poll error = %v, want %v", err, tc.is)
			}
			if listed, known := catalog.Lookup("CVE-2026-84869"); !listed || !known {
				t.Fatalf("Lookup = (%v, %v) after failed refresh, want the last good set", listed, known)
			}
			if got := catalog.Len(); got != 2 {
				t.Fatalf("Len = %d after failed refresh, want 2", got)
			}
		})
	}
}

func TestKEVCatalogReplaceRefusesEmptySet(t *testing.T) {
	catalog := NewKEVCatalog()
	if err := catalog.Replace([]string{"CVE-2026-84869"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if err := catalog.Replace([]string{" ", ""}); !errors.Is(err, ErrKEVCatalogEmpty) {
		t.Fatalf("Replace(empty) error = %v, want ErrKEVCatalogEmpty", err)
	}
	if listed, known := catalog.Lookup("CVE-2026-84869"); !listed || !known {
		t.Fatal("Replace(empty) wiped the set")
	}
}

// Readers run concurrently with refreshes (run under -race).
func TestKEVCatalogConcurrentReaders(t *testing.T) {
	catalog := NewKEVCatalog()
	if err := catalog.Replace([]string{"CVE-2026-84869"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if listed, known := catalog.Lookup("CVE-2026-84869"); !listed || !known {
					t.Error("reader saw the set without CVE-2026-84869")
					return
				}
				_ = catalog.Len()
			}
		}()
	}
	for range 200 {
		if err := catalog.Replace([]string{"CVE-2026-84869", "CVE-2021-44228"}); err != nil {
			t.Error(err)
		}
	}
	close(stop)
	wg.Wait()
}
