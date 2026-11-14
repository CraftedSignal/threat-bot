package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func generateTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func TestAppAuth_Token(t *testing.T) {
	keyPEM := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/42/access_tokens" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth == "" || len(auth) < 10 {
			t.Error("missing or short Authorization header")
		}

		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_test_installation_token",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	auth, err := NewAppAuth(123, 42, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	auth.apiURL = srv.URL

	token, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	if token != "ghs_test_installation_token" {
		t.Errorf("unexpected token: %s", token)
	}

	// Second call should return cached token.
	token2, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	if token2 != token {
		t.Error("expected cached token")
	}
}

func TestAppAuth_InvalidKey(t *testing.T) {
	_, err := NewAppAuth(123, 42, []byte("not a pem key"))
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestAppAuth_TokenRefresh(t *testing.T) {
	keyPEM := generateTestKey(t)
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_refreshed_token",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	auth, err := NewAppAuth(123, 42, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	auth.apiURL = srv.URL

	// Force expiry to trigger refresh.
	auth.token = "old_token"
	auth.expiry = time.Now().Add(-1 * time.Minute)

	token, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	if token != "ghs_refreshed_token" {
		t.Errorf("expected refreshed token, got: %s", token)
	}
	if callCount != 1 {
		t.Errorf("expected 1 API call, got %d", callCount)
	}
}
