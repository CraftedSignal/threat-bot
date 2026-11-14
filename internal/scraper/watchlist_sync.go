package scraper

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type PlatformWatchlistResponse struct {
	Vendors  []string `json:"vendors"`
	Products []string `json:"products"`
	Keywords []string `json:"keywords"`
}

type WatchlistSyncClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func NewWatchlistSyncClient(baseURL, apiKey string, client *http.Client) *WatchlistSyncClient {
	return &WatchlistSyncClient{baseURL: baseURL, apiKey: apiKey, client: client}
}

func (c *WatchlistSyncClient) Fetch() (*PlatformWatchlistResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/v1/watchlist/global", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("watchlist sync: %w", err)
	}
	defer discardClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("watchlist sync: status %d", resp.StatusCode)
	}

	var result PlatformWatchlistResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("watchlist sync decode: %w", err)
	}
	return &result, nil
}
