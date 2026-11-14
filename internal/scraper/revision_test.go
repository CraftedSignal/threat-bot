package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSemanticRevisionIgnoresDeliveryClocks(t *testing.T) {
	a := RawItem{SourceID: "rss:stable", Source: "rss", Title: "Article", Content: "Unchanged evidence", PublishedAt: time.Now()}
	b := a
	b.PublishedAt = b.PublishedAt.Add(time.Hour)

	if a.ContentRevision() != b.ContentRevision() {
		t.Fatal("delivery timestamp reprocesses identical content")
	}
	b.UpdatedAt = time.Now()
	if a.ContentRevision() == b.ContentRevision() {
		t.Fatal("real upstream revision signal ignored")
	}
	if a.EvidenceRevision() != b.EvidenceRevision() {
		t.Fatal("timestamp alone changed semantic evidence")
	}
	b.Content = "Corrected evidence"
	if a.ContentRevision() == b.ContentRevision() {
		t.Fatal("source correction ignored")
	}
}
func TestRSSUpdatedArticleIsReturnedWithOriginalPublicationDate(t *testing.T) {
	feed := `<feed xmlns="http://www.w3.org/2005/Atom"><title>Updates</title><id>feed</id><updated>2026-11-14T06:00:00Z</updated><entry><id>article</id><title>Corrected advisory</title><link href="https://vendor.example/advisory"/><published>2026-11-01T06:00:00Z</published><updated>2026-11-14T06:00:00Z</updated><content>Corrected product scope.</content></entry></feed>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, feed) }))
	defer server.Close()
	items, err := NewRSS("vendor", server.URL).Poll(context.Background(), time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC))
	if err != nil || len(items) != 1 {
		t.Fatalf("correction missing: %v %v", items, err)
	}
	if items[0].PublishedAt.Day() != 1 || items[0].UpdatedAt.Day() != 14 {
		t.Fatalf("publication history changed: %+v", items[0])
	}
}
