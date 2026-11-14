package pipeline

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	trackingQueryParams = map[string]bool{
		"fbclid": true, "gclid": true, "dclid": true, "msclkid": true,
		"mc_cid": true, "mc_eid": true, "igshid": true, "ref": true,
		"ref_src": true, "source": true, "spm": true,
	}

	urlCandidateRe = regexp.MustCompile(`https?://[^\s<>"')\]]+`)
)

func NormalizeSourceURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		host = net.JoinHostPort(host, port)
	}

	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if decoded, err := url.PathUnescape(p); err == nil {
		p = decoded
	}
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	if p == "/" {
		p = ""
	}

	query := canonicalQuery(u.Query())
	if query != "" {
		return host + p + "?" + query
	}
	return host + p
}

func SourceURLHash(raw string) string {
	normalized := NormalizeSourceURL(raw)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("%x", sum)
}

func SourceURLHashes(values ...string) []string {
	seen := make(map[string]bool)
	var hashes []string
	for _, value := range values {
		for _, candidate := range sourceURLCandidates(value) {
			hash := SourceURLHash(candidate)
			if hash == "" || seen[hash] {
				continue
			}
			seen[hash] = true
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

func sourceURLCandidates(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return []string{trimURLCandidate(raw)}
	}
	if !strings.ContainsAny(raw, " \t\r\n") && strings.Contains(raw, ".") && !strings.Contains(raw, "@") {
		return []string{trimURLCandidate(raw)}
	}

	matches := urlCandidateRe.FindAllString(raw, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, trimURLCandidate(match))
	}
	return out
}

func trimURLCandidate(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), ".,;:)]}'\"")
}

func SourcePublishedDay(t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return t.UTC().Format("2006-01-02")
}

func canonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	clean := url.Values{}
	for key, vals := range values {
		k := strings.ToLower(strings.TrimSpace(key))
		if k == "" || strings.HasPrefix(k, "utm_") || trackingQueryParams[k] {
			continue
		}
		sort.Strings(vals)
		for _, v := range vals {
			clean.Add(k, strings.TrimSpace(v))
		}
	}
	return clean.Encode()
}
