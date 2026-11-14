package pipeline

import "testing"

func TestWatchlistMatch_VendorInTitle(t *testing.T) {
	wl := &Watchlist{
		Vendors:  []string{"microsoft", "apache"},
		Products: []string{"exchange"},
		Keywords: []string{"ransomware"},
	}
	brief := WatchlistBrief{
		Title:   "Microsoft Exchange Zero-Day Exploitation",
		Summary: "Attackers exploit Exchange vulnerability",
		Tags:    []string{"exchange", "zero-day"},
	}
	if !wl.Matches(brief) {
		t.Error("expected match on vendor 'microsoft' in title")
	}
}

func TestWatchlistMatch_KeywordInSummary(t *testing.T) {
	wl := &Watchlist{Keywords: []string{"ransomware"}}
	brief := WatchlistBrief{
		Title:   "New Threat Actor Campaign",
		Summary: "Deploying ransomware across healthcare sector",
	}
	if !wl.Matches(brief) {
		t.Error("expected match on keyword 'ransomware' in summary")
	}
}

func TestWatchlistMatch_ProductInTags(t *testing.T) {
	wl := &Watchlist{Products: []string{"kubernetes"}}
	brief := WatchlistBrief{Tags: []string{"kubernetes", "container-escape"}}
	if !wl.Matches(brief) {
		t.Error("expected match on product 'kubernetes' in tags")
	}
}

func TestWatchlistMatch_NoMatch(t *testing.T) {
	wl := &Watchlist{
		Vendors:  []string{"microsoft"},
		Products: []string{"exchange"},
		Keywords: []string{"ransomware"},
	}
	brief := WatchlistBrief{
		Title:   "Linux Kernel Privilege Escalation",
		Summary: "New CVE in Linux kernel",
		Tags:    []string{"linux", "kernel"},
	}
	if wl.Matches(brief) {
		t.Error("expected no match")
	}
}

func TestWatchlistMatch_CaseInsensitive(t *testing.T) {
	wl := &Watchlist{Vendors: []string{"microsoft"}}
	brief := WatchlistBrief{Title: "MICROSOFT Exchange Vulnerability"}
	if !wl.Matches(brief) {
		t.Error("expected case-insensitive match")
	}
}

func TestWatchlistMatch_Empty(t *testing.T) {
	wl := &Watchlist{}
	brief := WatchlistBrief{Title: "Anything"}
	if wl.Matches(brief) {
		t.Error("empty watchlist should not match")
	}
}

func TestWatchlistMerge(t *testing.T) {
	base := &Watchlist{
		Vendors:  []string{"microsoft"},
		Products: []string{"exchange"},
	}
	platform := &Watchlist{
		Vendors:  []string{"microsoft", "cisco"},
		Products: []string{"log4j"},
		Keywords: []string{"healthcare"},
	}
	merged := MergeWatchlists(base, platform)
	if len(merged.Vendors) != 2 {
		t.Errorf("expected 2 vendors (deduped), got %d: %v", len(merged.Vendors), merged.Vendors)
	}
	if len(merged.Products) != 2 {
		t.Errorf("expected 2 products, got %d", len(merged.Products))
	}
	if len(merged.Keywords) != 1 {
		t.Errorf("expected 1 keyword, got %d", len(merged.Keywords))
	}
}
