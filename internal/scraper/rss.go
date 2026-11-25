package scraper

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mmcdole/gofeed"
)

const userAgent = "threat-bot/1.0 (threat-intelligence aggregator; +https://github.com/CraftedSignal/threat-bot)"

const maxHTTPErrorBodyBytes = 512

// browserUserAgent mimics a real browser UA for feeds behind Cloudflare Bot Management,
// which challenges or blocks non-browser UAs originating from cloud provider ASNs.
const browserUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// RSS is a generic RSS/Atom feed scraper.
type RSS struct {
	name                     string
	url                      string
	parser                   *gofeed.Parser
	validatorMu              sync.Mutex
	etag                     string
	lastModified             string
	cachedItems              []RawItem
	authoritativeArticleCVEs bool
}

func NewRSS(name, url string) *RSS {
	return newRSSWithUA(name, url, userAgent)
}

// withAuthoritativeArticleCVEs marks feeds whose entries are summaries of a
// linked first-party advisory. The pipeline must fetch the article before
// extraction, and CVEs named in that article are safe canonical identities.
func (r *RSS) withAuthoritativeArticleCVEs() *RSS {
	r.authoritativeArticleCVEs = true
	return r
}

// newRSSBrowser creates an RSS scraper that presents as a real browser.
// Use for feeds behind Cloudflare Bot Management that block cloud-provider ASNs
// when the request carries an obvious bot User-Agent.
func newRSSBrowser(name, url string) *RSS {
	return newRSSWithUA(name, url, browserUserAgent)
}

func newRSSWithUA(name, url, ua string) *RSS {
	fp := gofeed.NewParser()
	fp.Client = &http.Client{
		// http.Client.Timeout bounds the whole Do() call including retries
		// inside the transport, so the budget has to cover: initial attempt
		// + backoffs + retries. cisco-psirt alone regularly needs 45-60s
		// per attempt, so 3 minutes total leaves room for two retries.
		Timeout:   180 * time.Second,
		Transport: &uaTransport{ua: ua, rt: rssHTTPTransport()},
	}
	return &RSS{name: name, url: url, parser: fp}
}

func rssHTTPTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	transport := base.Clone()
	transport.TLSHandshakeTimeout = 30 * time.Second
	return transport
}

func (r *RSS) Name() string { return r.name }

func (r *RSS) Poll(ctx context.Context, since time.Time) ([]RawItem, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating feed request %s: %w", r.url, err)
	}
	r.validatorMu.Lock()
	etag, lastModified := r.etag, r.lastModified
	r.validatorMu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := r.parser.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching feed %s: %w", r.url, err)
	}
	defer discardClose(resp.Body)
	if resp.StatusCode == http.StatusNotModified {
		return r.cachedItemsSince(since), nil
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPErrorBodyBytes+1))
		truncated := len(body) > maxHTTPErrorBodyBytes
		if truncated {
			body = body[:maxHTTPErrorBodyBytes]
		}
		detail := strings.Join(strings.Fields(string(body)), " ")
		if truncated {
			detail += " … (truncated)"
		}
		return nil, statusErrorf(resp.StatusCode, "parsing feed %s: http error: %s: %s", r.url, resp.Status, detail)
	}

	feed, err := r.parser.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing feed %s: %w", r.url, err)
	}

	var items []RawItem
	for _, entry := range feed.Items {
		published := time.Now()
		if entry.PublishedParsed != nil {
			published = *entry.PublishedParsed
		} else if entry.UpdatedParsed != nil {
			published = *entry.UpdatedParsed
		}
		// Clamp future dates to now (scheduled/pre-published posts).
		if published.After(time.Now()) {
			published = time.Now()
		}

		updated := time.Time{}
		if entry.UpdatedParsed != nil {
			updated = *entry.UpdatedParsed

		}
		guid := entry.GUID
		if guid == "" {
			guid = entry.Link
		}

		items = append(items, RawItem{
			SourceID:            fmt.Sprintf("%s:%s", r.name, guid),
			Source:              r.name,
			Title:               entry.Title,
			URL:                 entry.Link,
			Content:             entry.Description + "\n\n" + entry.Content,
			PublishedAt:         published,
			UpdatedAt:           updated,
			NeedsFullArticle:    r.authoritativeArticleCVEs,
			BodyCVEsAreSubjects: r.authoritativeArticleCVEs,
		})
	}

	// Validators describe this retained representation, not a processing
	// acknowledgement. A 304 must replay it until durable seen state catches up.
	r.validatorMu.Lock()
	r.cachedItems = items
	r.etag = resp.Header.Get("ETag")
	r.lastModified = resp.Header.Get("Last-Modified")
	r.validatorMu.Unlock()
	return r.cachedItemsSince(since), nil
}

func (r *RSS) cachedItemsSince(since time.Time) []RawItem {
	r.validatorMu.Lock()
	defer r.validatorMu.Unlock()
	var items []RawItem
	for _, item := range r.cachedItems {
		if !itemFreshness(item).Before(since) {
			items = append(items, item)
		}
	}
	return items
}

func NewDFIRReport() *RSS {
	return NewRSS("dfir-report", "https://thedfirreport.com/feed/")
}

func NewISCStormCast() *RSS {
	// ISC dropped the old diary RSS endpoint; the StormCast daily podcast
	// feed now carries the same top-of-day security summaries we were
	// scraping before.
	return NewRSS("isc-stormcast", "https://isc.sans.edu/dailypodcast.xml")
}

// Vendor threat research blogs
func NewTalos() *RSS {
	return NewRSS("talos", "https://blog.talosintelligence.com/rss/")
}

func NewMandiant() *RSS {
	// Google Cloud publishes this as the canonical Threat Intelligence RSS
	// endpoint. The retired cloudblog.withgoogle.com URL can hang until the
	// client timeout when requested from GCP.
	return NewRSS("mandiant", "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v")
}

func NewUnit42() *RSS {
	return NewRSS("unit42", "https://unit42.paloaltonetworks.com/feed/")
}

func NewSOCRadar() *RSS {
	return NewRSS("socradar", "https://socradar.io/blog/category/cyber-threat-intelligence/feed/")
}

func NewMicrosoftThreatIntel() *RSS {
	return NewRSS("microsoft-threat-intel", "https://www.microsoft.com/en-us/security/blog/feed/")
}

func NewSophosXOps() *RSS {
	return NewRSS("sophos-xops", "https://www.sophos.com/en-us/blog/feed?id=blt6f15f4f7deaf4242")
}

func NewHuntress() *RSS {
	return NewRSS("huntress", "https://www.huntress.com/blog/rss.xml")
}

func NewArcticWolf() *RSS {
	return NewRSS("arctic-wolf", "https://arcticwolf.com/resources/category/blog/feed/")
}

func NewCheckPoint() *RSS {
	// research.checkpoint.com is behind Cloudflare Bot Management; the bot UA
	// triggers challenges from GKE IPs, so we present as a real browser instead.
	return newRSSBrowser("checkpoint", "https://research.checkpoint.com/feed/")
}

func NewCrowdStrike() *RSS {
	return NewRSS("crowdstrike", "https://www.crowdstrike.com/blog/feed/")
}

func NewESET() *RSS {
	return NewRSS("eset", "https://www.welivesecurity.com/en/rss/feed/")
}

func NewVolexity() *RSS {
	// /blog/feed/ redirects to the HTML blog page; the canonical feed is at /feed/.
	// volexity.com is behind Cloudflare — browser UA bypasses the bot challenge.
	return newRSSBrowser("volexity", "https://www.volexity.com/feed/")
}

func NewWiz() *RSS {
	return NewRSS("wiz", "https://www.wiz.io/feed/rss.xml")
}

func NewHackerNews() *RSS {
	return NewRSS("the-hacker-news", "https://feeds.feedburner.com/TheHackersNews")
}

func NewDarkReading() *RSS {
	return NewRSS("dark-reading", "https://www.darkreading.com/rss.xml")
}

// Breach / incident-focused news. These complement the
// vulnerability-feed scrapers by surfacing named-victim breach
// reporting (corporate disclosures, leaked databases, ransomware
// campaigns) which rarely carries a CVE id.
func NewDataBreaches() *RSS {
	return NewRSS("databreaches", "https://www.databreaches.net/feed/")
}

func NewHackRead() *RSS {
	return NewRSS("hackread", "https://hackread.com/feed/")
}

func NewDataBreachToday() *RSS {
	// ISMG removed RSS support from DataBreachToday entirely (confirmed 2026-05-10).
	// /feed, /rss.xml, and /rss all return HTML or 404. Keep the constructor so the
	// config field compiles; the source stays disabled in the ConfigMap.
	return NewRSS("databreachtoday", "https://www.databreachtoday.com/feed")
}

// Krebs publishes a data-breach-tagged subfeed in addition to the
// main feed; subscribing to both gives faster coverage when the
// main feed is silent for a few days.
func NewKrebsBreaches() *RSS {
	return NewRSS("krebs-breaches", "https://krebsonsecurity.com/category/data-breaches/feed/")
}

// Reputable security commentary + research feeds that surface
// disclosures and analysis the vuln-feed sources miss.
func NewSchneier() *RSS {
	return NewRSS("schneier", "https://www.schneier.com/feed/")
}

func NewSecurelist() *RSS {
	return NewRSS("securelist", "https://securelist.com/feed/")
}

// oss-security: Open Source Security mailing list via Seclists. Kernel
// CVEs, OpenSSL advisories, glibc fixes, and similar disclosures land
// here days before NVD analyst review. The thread-volume per item is
// high so the LLM extractor is selective; the actionable items still
// surface.
func NewOSSSec() *RSS {
	return NewRSS("oss-security", "https://seclists.org/rss/oss-sec.rss")
}

// WatchTowr publishes a broad threat intelligence feed with research and
// independently assessed vulnerability reporting.
func NewWatchTowr() *RSS {
	return NewRSS("watchtowr", "https://watchtowr.com/resources/feed")
}

// Mozilla's security blog publishes first-party browser and trust-store
// incident notices, including CA response details before secondary reports.
func NewMozillaSecurity() *RSS {
	return NewRSS("mozilla-security", "https://blog.mozilla.org/security/feed/")
}

// Ars Technica's security section covers major incidents, vulnerabilities,
// and security response across vendors with substantive reporting.
func NewArsSecurity() *RSS {
	return NewRSS("ars-security", "https://arstechnica.com/security/feed/")
}

// Mastodon's #cve tag on infosec.exchange aggregates security-research
// posts that mention any CVE id. Replaces the X scraping path we lost
// when Twitter killed unauthenticated access — most of the security
// researchers active on X post a Mastodon mirror, and the open RSS
// works without auth.
func NewInfosecExchangeCVE() *RSS {
	return NewRSS("infosec-exchange-cve", "https://infosec.exchange/tags/cve.rss")
}

// National CERT sources
func NewNCSC() *RSS {
	return NewRSS("ncsc-uk", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml")
}

func NewNCSCNL() *RSS {
	return NewRSS("ncsc-nl", "https://feeds.ncsc.nl/nieuws.rss")
}

func NewANSSI() *RSS {
	return NewRSS("anssi", "https://www.cert.ssi.gouv.fr/feed/")
}

func NewBSI() *RSS {
	return NewRSS("bsi", "https://wid.cert-bund.de/content/public/securityAdvisory/rss")
}

func NewCERTEU() *RSS {
	return NewRSS("cert-eu", "https://cert.europa.eu/publications/security-advisories-rss")
}

func NewJPCERT() *RSS {
	return NewRSS("jpcert", "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf")
}

// Vendor PSIRT / security advisory feeds
func NewMSRC() *RSS {
	// Microsoft Security Response Center — Patch Tuesday and out-of-band advisories.
	// Entries summarize linked first-party advisories; their article CVEs are
	// authoritative subjects for routing and roundup folding.
	return NewRSS("msrc", "https://api.msrc.microsoft.com/update-guide/rss").withAuthoritativeArticleCVEs()
}

func NewCiscoPSIRT() *RSS {
	return NewRSS("cisco-psirt", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml")
}

func NewPaloAltoNetworks() *RSS {
	return NewRSS("palo-alto-networks", "https://security.paloaltonetworks.com/rss.xml")
}

// Supply chain and vulnerability research
func NewSonatype() *RSS {
	return NewRSS("sonatype", "https://www.sonatype.com/blog/rss.xml")
}

func NewGoogleProjectZero() *RSS {
	return NewRSS("google-project-zero", "https://projectzero.google/feed.xml")
}

// Tier 1 — commercial threat research (creates new brief on novel campaign)

func NewSentinelLabs() *RSS {
	return NewRSS("sentinelone-labs", "https://www.sentinelone.com/labs/feed/")
}

// Tier 2 — commercial (enriches existing brief if campaign/actor matches)

func NewBitdefender() *RSS {
	return NewRSS("bitdefender", "https://www.bitdefender.com/blog/api/rss/labs/")
}

func NewFortiGuard() *RSS {
	return NewRSS("fortiguard", "https://feeds.fortinet.com/fortinet/blog/threat-research")
}

func NewProofpoint() *RSS {
	return NewRSS("proofpoint", "https://www.proofpoint.com/us/threat-insight-blog.xml")
}

func NewRapid7() *RSS {
	// Emergent Threat Response tag only — filters for actively-exploited CVE coverage.
	return NewRSS("rapid7", "https://www.rapid7.com/blog/tag/emergent-threat-response/rss/")
}

func NewRedCanary() *RSS {
	return NewRSS("red-canary", "https://redcanary.com/blog/feed/")
}

func NewRecordedFuture() *RSS {
	return NewRSS("recorded-future", "https://www.recordedfuture.com/feed")
}

func NewFlashpoint() *RSS {
	return NewRSS("flashpoint", "https://flashpoint.io/blog/feed/")
}

func NewIntel471() *RSS {
	return NewRSS("intel471", "https://www.intel471.com/blog/feed")
}

func NewGreyNoise() *RSS {
	return NewRSS("greynoise", "https://www.greynoise.io/blog/rss.xml")
}

func NewCofense() *RSS {
	return NewRSS("cofense", "https://cofense.com/feed/")
}

func NewAnyRun() *RSS {
	return NewRSS("any-run", "https://any.run/cybersecurity-blog/feed/")
}

func NewQualysThreatResearch() *RSS {
	// Threat-research category only — excludes general product/marketing posts.
	return NewRSS("qualys-threat-research", "https://blog.qualys.com/vulnerabilities-threat-research/feed")
}

func NewMalwareTrafficAnalysis() *RSS {
	return NewRSS("malware-traffic-analysis", "https://malware-traffic-analysis.net/blog-entries.rss")
}

func NewObjectiveSee() *RSS {
	// Patrick Wardle's macOS malware research — only dedicated high-signal macOS feed.
	return NewRSS("objective-see", "https://objective-see.org/rss.xml")
}

func NewAttackIQ() *RSS {
	return NewRSS("attackiq", "https://attackiq.com/blog/feed/")
}

// Government / CERT sources

func NewFBICyber() *RSS {
	return NewRSS("fbi-cyber", "https://www.ic3.gov/PSA/RSS")
}

func NewCCCS() *RSS {
	// Canadian Centre for Cyber Security — alerts and advisories.
	return NewRSS("cccs", "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en")
}

func NewACSC() *RSS {
	// Australian Signals Directorate / ACSC alerts feed.
	return NewRSS("acsc", "https://www.cyber.gov.au/rss/alerts")
}

func NewMSISAC() *RSS {
	// Multi-State ISAC advisories published via CIS. The old /advisory/feed
	// path now 301-redirects to a non-feed page (gofeed reports "Failed to
	// detect feed type"); the canonical feed moved to /feed/advisories.
	return NewRSS("ms-isac", "https://www.cisecurity.org/feed/advisories").withAuthoritativeArticleCVEs()
}

// Independent research

func NewGoogleTAG() *RSS {
	// Google Threat Analysis Group — government-backed attackers, 0-day in-the-wild.
	return NewRSS("google-tag", "https://blog.google/threat-analysis-group/rss/")
}

// Exploit tracking — public exploit and PoC databases
// NewExploitDB and NewSploitus are defined in exploit_db.go and sploitus.go
// respectively — they use custom scrapers that build richer content than the
// bare RSS feeds provide.

// Detection-focused research
func NewSocPrime() *RSS {
	// SOC Prime blog: detection engineering, threat hunting, and Sigma content.
	return NewRSS("socprime", "https://socprime.com/blog/feed/")
}

// Broad cybersecurity news sources
func NewBleepingComputer() *RSS {
	return NewRSS("bleepingcomputer", "https://www.bleepingcomputer.com/feed/")
}

func NewTheRecord() *RSS {
	return NewRSS("therecord", "https://therecord.media/feed")
}

func NewSecurityWeek() *RSS {
	return NewRSS("securityweek", "https://www.securityweek.com/feed/")
}

// uaTransport injects a User-Agent header into every request and retries
// transient failures (5xx responses, connection resets, EOFs) with short
// backoff so upstream hiccups don't surface as scraper errors.
type uaTransport struct {
	ua string
	rt http.RoundTripper
	// delays are the waits before each retry, so len(delays)+1 attempts at
	// most. Nil means rssRetryDelays.
	delays []time.Duration
	// onRateLimit, when set, is told when a 429 says the limit resets.
	onRateLimit func(until time.Time)
}

var rssRetryDelays = []time.Duration{1 * time.Second, 3 * time.Second}

// exploitDBRetryDelays is one quick retry. Longer outages are backed off
// across polls by ExploitDB itself, so no poll sleeps for minutes.
var exploitDBRetryDelays = []time.Duration{2 * time.Second}

const (
	defaultRateLimitPause = time.Minute
	maxRateLimitPause     = time.Hour
)

// jitterDelay spreads d over [75%, 100%] so scrapers that failed together do
// not retry together.
func jitterDelay(d time.Duration) time.Duration {
	return d - time.Duration(rand.Int63n(int64(d)/4+1))
}

// rateLimitReset returns when a 429 response says requests may resume, from
// Retry-After (seconds or an HTTP date) and x-ratelimit-reset (seconds), the
// later of the two, bounded to maxRateLimitPause.
func rateLimitReset(h http.Header, now time.Time) time.Time {
	var pause time.Duration
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if secs, err := strconv.ParseFloat(v, 64); err == nil && secs > 0 {
			pause = time.Duration(secs * float64(time.Second))
		} else if at, err := http.ParseTime(v); err == nil && at.After(now) {
			pause = at.Sub(now)
		}
	}
	if v := strings.TrimSpace(h.Get("x-ratelimit-reset")); v != "" {
		if secs, err := strconv.ParseFloat(v, 64); err == nil && secs > 0 {
			if d := time.Duration(secs * float64(time.Second)); d > pause {
				pause = d
			}
		}
	}
	if pause <= 0 {
		pause = defaultRateLimitPause
	}
	if pause > maxRateLimitPause {
		pause = maxRateLimitPause
	}
	return now.Add(pause)
}

var rssRetryableStatus = map[int]bool{
	408: true, // Request Timeout
	500: true, // Internal Server Error
	502: true, // Bad Gateway
	503: true, // Service Unavailable
	504: true, // Gateway Timeout
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.ua)
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml, */*")

	delays := t.delays
	if delays == nil {
		delays = rssRetryDelays
	}

	var lastErr error
	for attempt := 0; attempt <= len(delays); attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(jitterDelay(delays[attempt-1]))
			select {
			case <-timer.C:
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			}
		}

		resp, err := t.rt.RoundTrip(req)
		if err != nil {
			lastErr = err
			if attempt < len(delays) && isTransientNetError(err) {
				continue
			}
			return nil, err
		}

		// Retrying a 429 within seconds only extends the block; hand it to the
		// caller along with when the limit resets.
		if resp.StatusCode == http.StatusTooManyRequests && t.onRateLimit != nil {
			t.onRateLimit(rateLimitReset(resp.Header, time.Now()))
		}

		if rssRetryableStatus[resp.StatusCode] && attempt < len(delays) {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("upstream returned %d", resp.StatusCode)
			continue
		}

		return resp, nil
	}

	return nil, lastErr
}

func isTransientNetError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "no such host")
}
