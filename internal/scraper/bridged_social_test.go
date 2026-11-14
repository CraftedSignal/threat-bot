package scraper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func bridgedItem(title, link, pubDate, description string) string {
	return fmt.Sprintf(
		`<item><title>%s</title><link>%s</link><guid>%s</guid><pubDate>%s</pubDate><description><![CDATA[%s]]></description></item>`,
		title, link, link, pubDate, description)
}

func serveBridgedFeed(t *testing.T, items ...string) *httptest.Server {
	t.Helper()
	body := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>ronin66 bridge</title><link>https://rss.app/feeds/abc.xml</link>
<description>bridge feed</description>` + strings.Join(items, "\n") + `</channel></rss>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestBridged disables shortener resolution so feed-parsing tests never
// touch the network. Resolution has its own tests below.
func newTestBridged(feedURL string) *BridgedSocial {
	b := NewBridgedSocial("ronin66", feedURL, "linkedin.com")
	b.shorteners = nil
	return b
}

func rfc1123(t time.Time) string { return t.Format(time.RFC1123Z) }

const permalink = "https://www.linkedin.com/posts/ronin66-research_activity-7443341347564052480-krVt"

// The bridge puts the LinkedIn permalink in <link>. Left there, enrichment
// re-fetches the auth wall and the item dies at the thin-content gate, so the
// outbound story link has to win.
func TestBridgedSocialPromotesBareTextLinkToURL(t *testing.T) {
	srv := serveBridgedFeed(t, bridgedItem(
		"Ronin66 Research on LinkedIn: PoCs dumped for unreported vulns",
		permalink,
		rfc1123(time.Now().Add(-time.Hour)),
		`<p>Someone is mass-dropping PoCs. None reported. https://example.com/poc-dump</p>`,
	))

	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if got := items[0].URL; got != "https://example.com/poc-dump" {
		t.Errorf("URL = %q, want the outbound story link", got)
	}
}

func TestBridgedSocialPromotesAnchorHrefToURL(t *testing.T) {
	srv := serveBridgedFeed(t, bridgedItem(
		"Ronin66 Research on LinkedIn: new campaign writeup",
		permalink,
		rfc1123(time.Now().Add(-time.Hour)),
		`<p>Worth a read <a href="https://research.example.org/campaign">here</a>.</p>`,
	))

	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if got := items[0].URL; got != "https://research.example.org/campaign" {
		t.Errorf("URL = %q, want the anchor href", got)
	}
}

// An <img src> is not the story. Regex-scanning raw HTML would return the
// bridge's tracking pixel as the article.
func TestBridgedSocialIgnoresImageSources(t *testing.T) {
	srv := serveBridgedFeed(t, bridgedItem(
		"Ronin66 Research on LinkedIn: writeup",
		permalink,
		rfc1123(time.Now().Add(-time.Hour)),
		`<p><img src="https://cdn.example.net/pixel.gif"/>Story: https://example.com/real-story</p>`,
	))

	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if got := items[0].URL; got != "https://example.com/real-story" {
		t.Errorf("URL = %q, want the story link and not the image src", got)
	}
}

func TestBridgedSocialFallsBackToPermalinkWithoutOutboundLink(t *testing.T) {
	srv := serveBridgedFeed(t, bridgedItem(
		"Ronin66 Research on LinkedIn: hiring",
		permalink,
		rfc1123(time.Now().Add(-time.Hour)),
		`<p>Commentary only, see <a href="https://www.linkedin.com/feed/hashtag/redteam">#redteam</a></p>`,
	))

	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if got := items[0].URL; got != permalink {
		t.Errorf("URL = %q, want the permalink as fallback", got)
	}
}

// The permalink must survive in Metadata: sourceURLHashesForRawItem hashes
// every metadata value, so it participates in URL dedup.
func TestBridgedSocialRecordsPermalinkAndCuratorInMetadata(t *testing.T) {
	srv := serveBridgedFeed(t, bridgedItem(
		"Ronin66 Research on LinkedIn: writeup",
		permalink,
		rfc1123(time.Now().Add(-time.Hour)),
		`<p>See https://example.com/story</p>`,
	))

	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if got := items[0].Metadata["permalink"]; got != permalink {
		t.Errorf("Metadata[permalink] = %q, want %q", got, permalink)
	}
	if got := items[0].Metadata["curator"]; got != "ronin66" {
		t.Errorf("Metadata[curator] = %q, want %q", got, "ronin66")
	}
	if want := "ronin66:" + permalink; items[0].SourceID != want {
		t.Errorf("SourceID = %q, want %q", items[0].SourceID, want)
	}
	if items[0].Source != "ronin66" {
		t.Errorf("Source = %q, want %q", items[0].Source, "ronin66")
	}
}

// Bridges prefix every title with "<Company> on LinkedIn: ". Left in place it
// defeats the NormalizeTitleHash dedup fallback, since the publisher's own
// feed carries the bare headline.
func TestBridgedSocialStripsBridgeTitlePrefix(t *testing.T) {
	srv := serveBridgedFeed(t, bridgedItem(
		"Ronin66 Research on LinkedIn: PoCs dumped for unreported vulns",
		permalink,
		rfc1123(time.Now().Add(-time.Hour)),
		`<p>See https://example.com/story</p>`,
	))

	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if got := items[0].Title; got != "PoCs dumped for unreported vulns" {
		t.Errorf("Title = %q, want the bare headline", got)
	}
}

func TestBridgedSocialKeepsContentFromFeedBody(t *testing.T) {
	srv := serveBridgedFeed(t, bridgedItem(
		"Ronin66 Research on LinkedIn: writeup",
		permalink,
		rfc1123(time.Now().Add(-time.Hour)),
		`<p>Someone is mass-dropping PoCs.</p>`,
	))

	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if !strings.Contains(items[0].Content, "mass-dropping PoCs") {
		t.Errorf("Content = %q, want it to carry the post body", items[0].Content)
	}
}

func TestBridgedSocialSkipsItemsBeforeSince(t *testing.T) {
	srv := serveBridgedFeed(t,
		bridgedItem("Ronin66 Research on LinkedIn: old", permalink+"-old",
			rfc1123(time.Now().Add(-72*time.Hour)), `<p>https://example.com/old</p>`),
		bridgedItem("Ronin66 Research on LinkedIn: new", permalink+"-new",
			rfc1123(time.Now().Add(-time.Hour)), `<p>https://example.com/new</p>`),
	)

	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1 (the old one must be filtered)", len(items))
	}
	if items[0].URL != "https://example.com/new" {
		t.Errorf("URL = %q, want the recent item", items[0].URL)
	}
}

func TestBridgedSocialClampsFutureDates(t *testing.T) {
	srv := serveBridgedFeed(t, bridgedItem(
		"Ronin66 Research on LinkedIn: scheduled",
		permalink,
		rfc1123(time.Now().Add(48*time.Hour)),
		`<p>https://example.com/story</p>`,
	))

	before := time.Now()
	items, err := newTestBridged(srv.URL).Poll(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if items[0].PublishedAt.Before(before) || items[0].PublishedAt.After(time.Now().Add(time.Minute)) {
		t.Errorf("PublishedAt = %v, want it clamped to roughly now", items[0].PublishedAt)
	}
}

func TestBridgedSocialName(t *testing.T) {
	if got := NewBridgedSocial("ronin66", "https://rss.app/x.xml", "linkedin.com").Name(); got != "ronin66" {
		t.Errorf("Name() = %q, want %q", got, "ronin66")
	}
}

func TestFirstOutboundLink(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "bare text url",
			body: `<p>Read this https://example.com/a now</p>`,
			want: "https://example.com/a",
		},
		{
			name: "anchor href",
			body: `<p><a href="https://example.com/b">link</a></p>`,
			want: "https://example.com/b",
		},
		{
			name: "first of several wins",
			body: `<p>https://example.com/first and https://example.com/second</p>`,
			want: "https://example.com/first",
		},
		{
			name: "post host rejected",
			body: `<p><a href="https://linkedin.com/posts/other">x</a></p>`,
			want: "",
		},
		{
			name: "post host subdomain rejected",
			body: `<p><a href="https://www.linkedin.com/posts/other">x</a></p>`,
			want: "",
		},
		{
			name: "post host rejected then outbound accepted",
			body: `<p><a href="https://www.linkedin.com/feed/x">x</a> https://example.com/story</p>`,
			want: "https://example.com/story",
		},
		{
			name: "bridge shim rejected",
			body: `<p><a href="https://rss.app/track/abc">x</a></p>`,
			want: "",
		},
		{
			name: "fetchrss shim rejected",
			body: `<p>https://fetchrss.com/r/abc</p>`,
			want: "",
		},
		{
			name: "feedly shim rejected",
			body: `<p>https://feedly.com/i/entry/abc</p>`,
			want: "",
		},
		{
			name: "image source ignored",
			body: `<p><img src="https://cdn.example.net/p.gif"/>https://example.com/story</p>`,
			want: "https://example.com/story",
		},
		{
			name: "non-http scheme ignored",
			body: `<p><a href="mailto:x@example.com">mail</a></p>`,
			want: "",
		},
		{
			name: "empty body",
			body: ``,
			want: "",
		},
		{
			name: "trailing punctuation trimmed",
			body: `<p>See https://example.com/story.</p>`,
			want: "https://example.com/story",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstOutboundLink(c.body, "linkedin.com"); got != c.want {
				t.Errorf("firstOutboundLink(%q) = %q, want %q", c.body, got, c.want)
			}
		})
	}
}

func TestStripBridgeTitlePrefix(t *testing.T) {
	cases := []struct {
		title string
		want  string
	}{
		{
			title: "Ronin66 Research on LinkedIn: PoCs dumped for unreported vulns",
			want:  "PoCs dumped for unreported vulns",
		},
		{
			// Case-insensitive on the platform label.
			title: "Ronin66 Research on linkedin: Something happened",
			want:  "Something happened",
		},
		{
			// A bare headline must survive untouched.
			title: "PoCs dumped for unreported vulns",
			want:  "PoCs dumped for unreported vulns",
		},
		{
			// No company prefix before " on LinkedIn: " — leave it alone.
			title: " on LinkedIn: orphaned",
			want:  "on LinkedIn: orphaned",
		},
		{
			// A colon elsewhere in the headline must not trigger a strip.
			title: "Advisory: critical RCE in Foo",
			want:  "Advisory: critical RCE in Foo",
		},
	}

	for _, c := range cases {
		if got := stripBridgeTitlePrefix(c.title, "linkedin.com"); got != c.want {
			t.Errorf("stripBridgeTitlePrefix(%q) = %q, want %q", c.title, got, c.want)
		}
	}
}

// LinkedIn rewrites outbound links to lnkd.in. Enrichment would follow the
// redirect anyway, but dedup hashes item.URL — so the shortlink has to be
// resolved here or the same article from its publisher's feed never collapses.
func TestResolveShortlinkFollowsRedirectsToCanonicalURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hop1":
			http.Redirect(w, r, "/hop2", http.StatusFound)
		case "/hop2":
			http.Redirect(w, r, "/story", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	b := NewBridgedSocial("ronin66", "unused", "linkedin.com")
	// Controlled loopback fixture; production transport accepts public destinations only.
	b.client.Transport = http.DefaultTransport
	b.shorteners = map[string]bool{mustHost(t, srv.URL): true}
	b.allowURL = func(string) bool { return true }

	got := b.resolveShortlink(context.Background(), srv.URL+"/hop1")
	if want := srv.URL + "/story"; got != want {
		t.Errorf("resolveShortlink = %q, want %q", got, want)
	}
}

func TestResolveShortlinkLeavesNonShortenerHostsAlone(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	b := NewBridgedSocial("ronin66", "unused", "linkedin.com")
	b.shorteners = map[string]bool{"lnkd.in": true}
	b.allowURL = func(string) bool { return true }

	in := srv.URL + "/article"
	if got := b.resolveShortlink(context.Background(), in); got != in {
		t.Errorf("resolveShortlink = %q, want it unchanged", got)
	}
	if hits != 0 {
		t.Errorf("made %d requests to a non-shortener host, want 0", hits)
	}
}

func TestResolveShortlinkCapsRedirectHops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("/hop%d", len(r.URL.Path)), http.StatusFound)
	}))
	defer srv.Close()

	b := NewBridgedSocial("ronin66", "unused", "linkedin.com")
	// Controlled loopback fixture; production transport accepts public destinations only.
	b.client.Transport = http.DefaultTransport
	b.shorteners = map[string]bool{mustHost(t, srv.URL): true}
	b.allowURL = func(string) bool { return true }

	in := srv.URL + "/hop"
	if got := b.resolveShortlink(context.Background(), in); got != in {
		t.Errorf("resolveShortlink = %q, want the input back once the hop cap trips", got)
	}
}

func TestResolveShortlinkRejectsNonPublicRedirectTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	b := NewBridgedSocial("ronin66", "unused", "linkedin.com")
	// Controlled loopback fixture; production transport accepts public destinations only.
	b.client.Transport = http.DefaultTransport
	b.shorteners = map[string]bool{mustHost(t, srv.URL): true}
	// Real guard: the metadata endpoint must not be followed.
	b.allowURL = func(u string) bool { return !strings.Contains(u, "169.254.169.254") }

	in := srv.URL + "/hop1"
	if got := b.resolveShortlink(context.Background(), in); got != in {
		t.Errorf("resolveShortlink = %q, want the input back when a hop is rejected", got)
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing %q: %v", rawURL, err)
	}
	return u.Hostname()
}
