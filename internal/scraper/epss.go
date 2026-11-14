package scraper

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/craftedsignal/threat-bot/internal/storage"
)

const epssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

// EPSSScore holds the EPSS score and percentile for a single CVE.
type EPSSScore struct {
	EPSS       float64
	Percentile float64
}

// EPSSCache serves EPSS scores from the database and refreshes them daily
// from the bulk CSV. The download is streamed into SQLite, so the full score
// set (~390k CVEs) is never held in memory.
type EPSSCache struct {
	mu        sync.RWMutex
	db        *storage.DB
	fetchedAt time.Time
	client    *http.Client
}

func NewEPSSCache(client *http.Client, db *storage.DB) *EPSSCache {
	return &EPSSCache{
		db:     db,
		client: client,
	}
}

// Lookup returns the EPSS score for a CVE, and whether it was found.
func (c *EPSSCache) Lookup(cveID string) (EPSSScore, bool) {
	row, ok, err := c.db.EPSSScore(cveID)
	if err != nil || !ok {
		return EPSSScore{}, false
	}
	return EPSSScore{EPSS: row.EPSS, Percentile: row.Percentile}, true
}

// FetchedAt returns when the cache was last refreshed.
func (c *EPSSCache) FetchedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.fetchedAt
}

// Refresh downloads the latest EPSS bulk CSV and replaces the stored scores.
func (c *EPSSCache) Refresh() error {
	resp, err := c.client.Get(epssURL)
	if err != nil {
		return fmt.Errorf("epss download: %w", err)
	}
	defer discardClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("epss download: status %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("epss gzip: %w", err)
	}
	defer discardClose(gz)
	if _, err := c.db.ReplaceEPSSScores(EPSSRows(gz)); err != nil {
		return fmt.Errorf("epss store: %w", err)
	}
	c.mu.Lock()
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

// EPSSRows streams the rows of the EPSS CSV format. The CSV has a comment
// header line starting with #, then "cve,epss,percentile". Rows whose scores
// do not parse are skipped.
func EPSSRows(r io.Reader) iter.Seq2[storage.EPSSRow, error] {
	return func(yield func(storage.EPSSRow, error) bool) {
		reader := csv.NewReader(r)
		reader.Comment = '#'
		reader.FieldsPerRecord = 3
		reader.ReuseRecord = true

		// Skip header row
		header, err := reader.Read()
		if err != nil {
			yield(storage.EPSSRow{}, fmt.Errorf("epss csv header: %w", err))
			return
		}
		if len(header) < 3 || !strings.EqualFold(header[0], "cve") {
			yield(storage.EPSSRow{}, fmt.Errorf("epss csv: unexpected header %v", header))
			return
		}

		for {
			record, err := reader.Read()
			if err == io.EOF {
				return
			}
			if err != nil {
				yield(storage.EPSSRow{}, fmt.Errorf("epss csv row: %w", err))
				return
			}
			epss, err := strconv.ParseFloat(record[1], 64)
			if err != nil {
				continue
			}
			pct, err := strconv.ParseFloat(record[2], 64)
			if err != nil {
				continue
			}
			if !yield(storage.EPSSRow{CVEID: record[0], EPSS: epss, Percentile: pct}, nil) {
				return
			}
		}
	}
}
