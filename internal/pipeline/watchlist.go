package pipeline

import "strings"

// Watchlist holds vendors, products, and keywords to match against briefs.
type Watchlist struct {
	Vendors  []string
	Products []string
	Keywords []string
}

// WatchlistBrief is the subset of brief data used for watchlist matching.
type WatchlistBrief struct {
	Title       string
	Summary     string
	Tags        []string
	ThreatActor string
	Content     string
}

// Matches returns true if the brief matches any entry in the watchlist.
func (w *Watchlist) Matches(brief WatchlistBrief) bool {
	text := strings.ToLower(brief.Title + " " + brief.Summary + " " + brief.ThreatActor + " " + brief.Content)
	tagsLower := make([]string, len(brief.Tags))
	for i, t := range brief.Tags {
		tagsLower[i] = strings.ToLower(t)
	}
	tagStr := strings.Join(tagsLower, " ")

	for _, v := range w.Vendors {
		v = strings.ToLower(v)
		if strings.Contains(text, v) || strings.Contains(tagStr, v) {
			return true
		}
	}
	for _, p := range w.Products {
		p = strings.ToLower(p)
		if strings.Contains(text, p) || strings.Contains(tagStr, p) {
			return true
		}
	}
	for _, k := range w.Keywords {
		k = strings.ToLower(k)
		if strings.Contains(text, k) || strings.Contains(tagStr, k) {
			return true
		}
	}
	return false
}

// MergeWatchlists combines a base watchlist with a platform-derived one.
// Deduplicates entries (case-insensitive). Base entries cannot be removed.
func MergeWatchlists(base, platform *Watchlist) *Watchlist {
	return &Watchlist{
		Vendors:  mergeUnique(base.Vendors, platform.Vendors),
		Products: mergeUnique(base.Products, platform.Products),
		Keywords: mergeUnique(base.Keywords, platform.Keywords),
	}
}

func mergeUnique(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var result []string
	for _, lists := range [][]string{a, b} {
		for _, s := range lists {
			lower := strings.ToLower(s)
			if !seen[lower] {
				seen[lower] = true
				result = append(result, lower)
			}
		}
	}
	return result
}
