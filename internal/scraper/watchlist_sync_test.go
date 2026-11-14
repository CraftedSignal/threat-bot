package scraper

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchPlatformWatchlist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/watchlist/global" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(PlatformWatchlistResponse{
			Vendors:  []string{"cisco", "fortinet"},
			Products: []string{"log4j"},
			Keywords: []string{"healthcare"},
		})
	}))
	defer server.Close()

	client := NewWatchlistSyncClient(server.URL, "test-key", &http.Client{})
	resp, err := client.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Vendors) != 2 || resp.Vendors[0] != "cisco" {
		t.Errorf("unexpected vendors: %v", resp.Vendors)
	}
}

func TestFetchPlatformWatchlist_ServerDown(t *testing.T) {
	client := NewWatchlistSyncClient("http://localhost:1", "key", &http.Client{})
	_, err := client.Fetch()
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}
