package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPostDispatchDoesNotExposeCredentialSentinels(t *testing.T) {
	const sentinel = "harmless-notifier-credential-sentinel"
	t.Run("response body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(sentinel))
		}))
		defer server.Close()
		err := postDispatch(context.Background(), server.URL, sentinel, dispatchPayload{})
		if err == nil || strings.Contains(err.Error(), sentinel) || err.Error() != "notifier HTTP 401" {
			t.Fatalf("unsafe or missing bounded status: %v", err)
		}
	})
	t.Run("canceled credential bearing URL", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := postDispatch(ctx, "http://user:"+sentinel+"@127.0.0.1/", sentinel, dispatchPayload{})
		if err == nil || strings.Contains(err.Error(), sentinel) || !errors.Is(err, context.Canceled) {
			t.Fatalf("unsafe or missing cancellation status: %v", err)
		}
	})
	t.Run("invalid endpoint", func(t *testing.T) {
		err := postDispatch(context.Background(), "http://"+sentinel+"%invalid", sentinel, dispatchPayload{})
		if err == nil || strings.Contains(err.Error(), sentinel) {
			t.Fatalf("unsafe or missing endpoint error: %v", err)
		}
	})
}
