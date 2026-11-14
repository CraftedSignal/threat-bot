package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// abuseCHTestNow is a fixed poll time: the middle of 2026-11-05 UTC, so the
// whole of 2026-11-04 is over and inside every fetched window.
var abuseCHTestNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func abuseCHTime(day string, clock string) string { return day + " " + clock + " UTC" }

// threatFoxIOC is one entry of a ThreatFox get_iocs response, with the field
// names the API documents.
func threatFoxIOC(id, ioc, iocType, threatType, malware, printable, firstSeen string, confidence int) map[string]any {
	return map[string]any{
		"id": id, "ioc": ioc, "ioc_type": iocType, "threat_type": threatType,
		"malware": malware, "malware_printable": printable, "malware_alias": nil,
		"malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/" + malware,
		"confidence_level": confidence, "first_seen": firstSeen, "last_seen": nil,
		"reporter": "abuse_ch", "reference": nil, "tags": []string{"c2"},
	}
}

// urlhausURL is one entry of a URLhaus recent-URLs response, with the field
// names the API documents.
func urlhausURL(id, url, host, dateAdded string, tags ...string) map[string]any {
	return map[string]any{
		"id": id, "urlhaus_reference": "https://urlhaus.abuse.ch/url/" + id + "/", "url": url,
		"url_status": "online", "host": host, "date_added": dateAdded, "threat": "malware_download",
		"blacklists": map[string]string{"spamhaus_dbl": "not listed", "surbl": "not listed"},
		"reporter":   "anonymous", "larted": "true", "tags": tags,
	}
}

func serveJSON(t *testing.T, body any, requests *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests != nil {
			raw, _ := io.ReadAll(r.Body)
			*requests = append(*requests, string(raw))
		}
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestAbuseCH(srv *httptest.Server) *AbuseCH {
	a := NewAbuseCH("test-auth-key")
	a.client = srv.Client()
	a.now = func() time.Time { return abuseCHTestNow }
	return a
}

// ThreatFox shares about 2,000 indicators a day. One item per indicator would
// cost a quality-gate call each and make one-indicator briefs, so a poll
// reports each malware family once per UTC day, after the day is over.
func TestAbuseCH_ThreatFoxReportsEachFamilyOncePerDay(t *testing.T) {
	var requests []string
	srv := serveJSON(t, map[string]any{"query_status": "ok", "data": []any{
		threatFoxIOC("103", "203.0.113.7:443", "ip:port", "botnet_cc", "win.emotet", "Emotet", abuseCHTime("2026-11-04", "21:30:00"), 100),
		threatFoxIOC("101", "198.51.100.9:8080", "ip:port", "botnet_cc", "win.emotet", "Emotet", abuseCHTime("2026-11-04", "03:12:44"), 75),
		threatFoxIOC("102", "beacon.example.net", "domain", "botnet_cc", "win.cobalt_strike", "Cobalt Strike", abuseCHTime("2026-11-04", "10:00:00"), 100),
		threatFoxIOC("104", "192.0.2.44:443", "ip:port", "botnet_cc", "win.emotet", "Emotet", abuseCHTime("2026-11-05", "09:00:00"), 100),
	}}, &requests)

	items, err := newTestAbuseCH(srv).pollThreatFoxFrom(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || !strings.Contains(requests[0], `"days":2`) {
		t.Errorf("ThreatFox request bodies = %q, want get_iocs for 2 days", requests)
	}
	byID := map[string]RawItem{}
	for _, item := range items {
		byID[item.SourceID] = item
	}
	if len(items) != 2 || len(byID) != 2 {
		t.Fatalf("got %d items %v, want Emotet and Cobalt Strike for 2026-11-04", len(items), byID)
	}
	emotet, ok := byID["abuse-ch:threatfox:win.emotet:2026-11-04"]
	if !ok {
		t.Fatalf("no Emotet item for 2026-11-04 in %v", byID)
	}
	if emotet.Source != "abuse-ch" || !emotet.Enriched {
		t.Errorf("Emotet item source=%q enriched=%v, want abuse-ch and no article fetch", emotet.Source, emotet.Enriched)
	}
	if emotet.URL != "https://threatfox.abuse.ch/browse/malware/win.emotet/" {
		t.Errorf("Emotet item URL = %q", emotet.URL)
	}
	if !strings.Contains(emotet.Title, "2 new Emotet indicators") {
		t.Errorf("Emotet title = %q", emotet.Title)
	}
	for _, want := range []string{"203.0.113.7:443", "198.51.100.9:8080", "botnet_cc", "confidence 75%"} {
		if !strings.Contains(emotet.Content, want) {
			t.Errorf("Emotet content lacks %q:\n%s", want, emotet.Content)
		}
	}
	if strings.Contains(emotet.Content, "192.0.2.44") {
		t.Errorf("Emotet item for 2026-11-04 lists an indicator first seen on 2026-11-05:\n%s", emotet.Content)
	}
	if want := time.Date(2026, 11, 4, 21, 30, 0, 0, time.UTC); !emotet.PublishedAt.Equal(want) {
		t.Errorf("Emotet PublishedAt = %v, want the newest indicator %v", emotet.PublishedAt, want)
	}
}

// A day is reported only once it is over, so a family's item lists all of
// its indicators and its source ID never covers a different set.
func TestAbuseCH_ThreatFoxWaitsUntilTheDayIsOver(t *testing.T) {
	srv := serveJSON(t, map[string]any{"query_status": "ok", "data": []any{
		threatFoxIOC("101", "198.51.100.9:8080", "ip:port", "botnet_cc", "win.emotet", "Emotet", abuseCHTime("2026-11-04", "23:59:59"), 100),
	}}, nil)
	a := newTestAbuseCH(srv)
	a.now = func() time.Time { return time.Date(2026, 11, 5, 0, 5, 0, 0, time.UTC) }

	items, err := a.pollThreatFoxFrom(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("reported %d items five minutes after midnight, want none until the day settles", len(items))
	}
}

// URLhaus items describe the URLs by tag. The item URL is the URLhaus report,
// never a listed URL: the pipeline cites it, and must never fetch malware.
func TestAbuseCH_URLhausReportsEachTagSetOncePerDay(t *testing.T) {
	srv := serveJSON(t, map[string]any{"query_status": "ok", "urls": []any{
		urlhausURL("903", "http://203.0.113.20/bins/mips", "203.0.113.20", abuseCHTime("2026-11-05", "08:00:00"), "elf", "mirai"),
		urlhausURL("902", "http://203.0.113.10/bins/arm7", "203.0.113.10", abuseCHTime("2026-11-04", "22:00:00"), "mirai", "elf"),
		urlhausURL("901", "http://198.51.100.5/x86", "198.51.100.5", abuseCHTime("2026-11-04", "04:00:00"), "elf", "mirai"),
		urlhausURL("900", "http://192.0.2.80/invoice.exe", "192.0.2.80", abuseCHTime("2026-11-04", "01:00:00")),
	}}, nil)

	items, err := newTestAbuseCH(srv).pollURLhausFrom(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]RawItem{}
	for _, item := range items {
		byID[item.SourceID] = item
	}
	if len(items) != 2 || len(byID) != 2 {
		t.Fatalf("got %d items %v, want the elf,mirai and the untagged URLs of 2026-11-04", len(items), byID)
	}
	mirai, ok := byID["abuse-ch:urlhaus:elf,mirai:2026-11-04"]
	if !ok {
		t.Fatalf("no elf,mirai item for 2026-11-04 in %v", byID)
	}
	if mirai.URL != "https://urlhaus.abuse.ch/url/902/" || !mirai.Enriched {
		t.Errorf("elf,mirai item URL=%q enriched=%v, want the newest URLhaus report and no article fetch", mirai.URL, mirai.Enriched)
	}
	if !strings.Contains(mirai.Title, "2 new malware URLs tagged elf, mirai") {
		t.Errorf("elf,mirai title = %q", mirai.Title)
	}
	for _, want := range []string{"http://203.0.113.10/bins/arm7", "http://198.51.100.5/x86", "https://urlhaus.abuse.ch/url/901/"} {
		if !strings.Contains(mirai.Content, want) {
			t.Errorf("elf,mirai content lacks %q:\n%s", want, mirai.Content)
		}
	}
	if strings.Contains(mirai.Content, "203.0.113.20") {
		t.Errorf("item for 2026-11-04 lists a URL added on 2026-11-05:\n%s", mirai.Content)
	}
	if _, ok := byID["abuse-ch:urlhaus:untagged:2026-11-04"]; !ok {
		t.Errorf("no untagged item for 2026-11-04 in %v", byID)
	}
}

// The recent endpoint returns at most the newest 1,000 URLs, which on a busy
// day reach back less than a day. Such a day is still reported once, as a
// lower bound, instead of never.
func TestAbuseCH_URLhausReportsAPartlyCoveredDayAsALowerBound(t *testing.T) {
	urls := make([]any, 0, urlhausRecentLimit)
	for i := 0; i < urlhausRecentLimit; i++ {
		added := time.Date(2026, 11, 5, 4, 39, 0, 0, time.UTC).Add(-time.Duration(i) * time.Minute)
		urls = append(urls, urlhausURL(fmt.Sprint(9000-i), fmt.Sprintf("http://203.0.113.%d/x", i%250), "203.0.113.1", added.Format("2006-01-02 15:04:05 UTC"), "mozi"))
	}
	srv := serveJSON(t, map[string]any{"query_status": "ok", "urls": urls}, nil)

	items, err := newTestAbuseCH(srv).pollURLhausFrom(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].SourceID != "abuse-ch:urlhaus:mozi:2026-11-04" {
		t.Fatalf("got %d items %+v, want one mozi item for 2026-11-04", len(items), items)
	}
	// The window reaches back to 2026-11-04 12:00, so it holds 720 of the day's URLs.
	if !strings.Contains(items[0].Title, "at least 720 new malware URLs") {
		t.Errorf("title = %q, want a lower bound", items[0].Title)
	}
	if !strings.Contains(items[0].Content, "2026-11-04 12:00:00 UTC") {
		t.Errorf("content does not say where the window starts:\n%s", items[0].Content)
	}
}

// URLhaus reports some failures in query_status with HTTP 200. Reading them
// as an empty list is how a broken feed looks quiet.
func TestAbuseCH_URLhausRejectsAFailedQueryStatus(t *testing.T) {
	srv := serveJSON(t, map[string]any{"query_status": "http_get_expected"}, nil)
	if _, err := newTestAbuseCH(srv).pollURLhausFrom(context.Background(), srv.URL); err == nil {
		t.Fatal("pollURLhaus accepted query_status http_get_expected")
	}
	empty := serveJSON(t, map[string]any{"query_status": "no_results"}, nil)
	if _, err := newTestAbuseCH(empty).pollURLhausFrom(context.Background(), empty.URL); err != nil {
		t.Fatalf("pollURLhaus rejected an empty result: %v", err)
	}
}

// An unparseable timestamp means the API changed. Failing the poll makes that
// visible; skipping the entries is how the feed stayed empty unnoticed.
func TestAbuseCH_RejectsUnparseableTimestamps(t *testing.T) {
	srv := serveJSON(t, map[string]any{"query_status": "ok", "data": []any{
		threatFoxIOC("101", "198.51.100.9:8080", "ip:port", "botnet_cc", "win.emotet", "Emotet", "2026-11-04T03:12:44Z", 100),
	}}, nil)
	if _, err := newTestAbuseCH(srv).pollThreatFoxFrom(context.Background(), srv.URL); err == nil {
		t.Fatal("pollThreatFox accepted a first_seen it cannot parse")
	}
}

// ThreatFox answers "no_result" with a message in data, and other failures
// in query_status, all with HTTP 200.
func TestAbuseCH_ThreatFoxReadsQueryStatus(t *testing.T) {
	empty := serveJSON(t, map[string]any{"query_status": "no_result", "data": "Your search did not yield any results"}, nil)
	if items, err := newTestAbuseCH(empty).pollThreatFoxFrom(context.Background(), empty.URL); err != nil || len(items) != 0 {
		t.Fatalf("no_result: items=%d err=%v, want none and no error", len(items), err)
	}
	failed := serveJSON(t, map[string]any{"query_status": "illegal_days"}, nil)
	if _, err := newTestAbuseCH(failed).pollThreatFoxFrom(context.Background(), failed.URL); err == nil {
		t.Fatal("pollThreatFox accepted query_status illegal_days")
	}
}

// A failing ThreatFox request used to be dropped, so its 401 never surfaced.
func TestAbuseCH_PollFailsWhenThreatFoxFails(t *testing.T) {
	urlhaus := serveJSON(t, map[string]any{"query_status": "no_results"}, nil)
	a := newTestAbuseCH(urlhaus)
	a.client = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "threatfox") {
			return statusTransport(http.StatusUnauthorized).RoundTrip(req)
		}
		return urlhaus.Client().Transport.RoundTrip(rewriteHost(req, urlhaus.URL))
	})}

	if _, err := a.Poll(context.Background(), abuseCHTestNow.Add(-24*time.Hour)); err == nil {
		t.Fatal("Poll succeeded although ThreatFox answered 401")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// rewriteHost sends req to the test server at base instead of its real host.
func rewriteHost(req *http.Request, base string) *http.Request {
	target, _ := url.Parse(base)
	clone := req.Clone(req.Context())
	clone.URL.Scheme, clone.URL.Host, clone.Host = target.Scheme, target.Host, target.Host
	return clone
}

// abuse.ch answers 401 {"error": "Unauthorized"} to URLhaus and ThreatFox
// requests that lack an Auth-Key header. Before URLhaus checked the status,
// that body decoded as zero URLs and every prod poll reported success.
func TestAbuseCH_SendsAuthKey(t *testing.T) {
	const key = "test-auth-key"
	requireKey := func(body map[string]any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Auth-Key") != key {
				http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(body)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/urlhaus", requireKey(map[string]any{"query_status": "ok", "urls": []any{}}))
	mux.HandleFunc("/threatfox", requireKey(map[string]any{"query_status": "ok", "data": []any{}}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := NewAbuseCH(key)
	a.client = srv.Client()

	if _, err := a.pollURLhausFrom(context.Background(), srv.URL+"/urlhaus"); err != nil {
		t.Errorf("pollURLhaus: %v", err)
	}
	if _, err := a.pollThreatFoxFrom(context.Background(), srv.URL+"/threatfox"); err != nil {
		t.Errorf("pollThreatFox: %v", err)
	}
}

// countingTransport answers like abuse.ch does without an Auth-Key and counts
// the requests it saw.
type countingTransport struct{ requests int }

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests++
	return statusTransport(http.StatusUnauthorized).RoundTrip(req)
}

// Without a key abuse.ch can only answer 401, so Poll should report the
// missing key, as the Brave provider does, without spending a request.
func TestAbuseCH_PollWithoutAuthKeyMakesNoRequest(t *testing.T) {
	transport := &countingTransport{}
	a := NewAbuseCH("")
	a.client = &http.Client{Transport: transport}

	if _, err := a.Poll(context.Background(), time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("Poll succeeded without an Auth-Key")
	}
	if transport.requests != 0 {
		t.Errorf("Poll sent %d requests without an Auth-Key, want 0", transport.requests)
	}
}
