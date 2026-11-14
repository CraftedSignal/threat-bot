package llm

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPErrorDoesNotExposeProviderBody(t *testing.T) {
	err := &HTTPError{StatusCode: 403, Body: "BENIGN_PROVIDER_SENTINEL"}
	if strings.Contains(err.Error(), err.Body) {
		t.Fatal("provider body exposed")
	}
	if code, ok := HTTPStatus(err); !ok || code != 403 {
		t.Fatal("lost status classification")
	}
}

func TestHealthStatusRedactsAndBoundsProviderErrors(t *testing.T) {
	m := NewHealthMonitor()
	m.Register("primary", "local-model")
	m.RecordError("primary", "local-model", errors.New(strings.Repeat("BENIGN_PROVIDER_SENTINEL", 1000)))
	status := m.Status()
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if status.OK || strings.Contains(string(data), "BENIGN_PROVIDER_SENTINEL") || len(status.Message) > 80 {
		t.Fatalf("unsafe status: length=%d", len(data))
	}
}

func TestTypedContentErrorsDoNotExposeUntrustedFields(t *testing.T) {
	for _, err := range []error{
		&FinishReasonError{Reason: "BENIGN_REASON_SENTINEL", Text: "BENIGN_TEXT_SENTINEL"},
		&OutputError{Err: errors.New("BENIGN_DECODER_SENTINEL"), Text: "BENIGN_TEXT_SENTINEL"},
	} {
		if strings.Contains(err.Error(), "SENTINEL") {
			t.Fatalf("untrusted content error field exposed: %T", err)
		}
	}
}

func TestTransportErrorsDoNotExposeURLCredentials(t *testing.T) {
	client := &http.Client{Transport: redactionRoundTripper(func(req *http.Request) (*http.Response, error) { return nil, errors.New("BENIGN_TRANSPORT_SENTINEL") })}
	req, err := http.NewRequest(http.MethodGet, "https://user:BENIGN_PASSWORD_SENTINEL@example.invalid/BENIGN_PATH_SENTINEL?key=BENIGN_QUERY_SENTINEL", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = retryDo(client, req)
	if err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("transport error not redacted: %v", err)
	}
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		t.Fatal("transport error type lost")
	}
}

type redactionRoundTripper func(*http.Request) (*http.Response, error)

func (f redactionRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
