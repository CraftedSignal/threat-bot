package scraper

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/mmcdole/gofeed"
)

// expectedUpstreamStatuses are responses that mean a source is down, blocking
// or rate limiting us, rather than that its scraper is broken.
var expectedUpstreamStatuses = map[int]bool{
	http.StatusForbidden:           true,
	http.StatusRequestTimeout:      true,
	http.StatusTooManyRequests:     true,
	http.StatusInternalServerError: true,
	http.StatusBadGateway:          true,
	http.StatusServiceUnavailable:  true,
	http.StatusGatewayTimeout:      true,
	521:                            true, // Cloudflare: origin down
	522:                            true, // Cloudflare: connection timed out
	523:                            true, // Cloudflare: origin unreachable
	524:                            true, // Cloudflare: origin timed out
}

// upstreamStatus returns the HTTP status code an error carries: ours from
// statusErrorf, or gofeed's from a feed fetched with ParseURL.
func upstreamStatus(err error) (int, bool) {
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.code, true
	}
	var feedErr gofeed.HTTPError
	if errors.As(err, &feedErr) {
		return feedErr.StatusCode, true
	}
	return 0, false
}

// httpStatusError reports an upstream response with an unsuccessful status.
// The message keeps each scraper's own wording; isExpectedUpstreamScraperError
// decides on the status code.
// ErrPollSkipped is returned by a scraper that deliberately did not contact its
// source because an earlier response told it to back off. The runner treats it
// as neither a success nor a failure for source health.
var ErrPollSkipped = errors.New("poll skipped: backing off after upstream error")

type httpStatusError struct {
	code int
	msg  string
}

func (e *httpStatusError) Error() string { return e.msg }

// statusErrorf returns an *httpStatusError for status code, with a message
// formatted as by fmt.Sprintf.
func statusErrorf(code int, format string, args ...any) error {
	return &httpStatusError{code: code, msg: fmt.Sprintf(format, args...)}
}
