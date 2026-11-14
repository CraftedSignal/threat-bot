package github

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AppAuth generates GitHub App installation tokens.
// Tokens are cached and auto-refreshed 5 minutes before expiry.
type AppAuth struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	apiURL         string
	httpClient     *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// NewAppAuth creates a new GitHub App authenticator.
// privateKeyPEM is the PEM-encoded RSA private key from the GitHub App settings.
func NewAppAuth(appID, installationID int64, privateKeyPEM []byte) (*AppAuth, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format as fallback.
		pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
		var ok bool
		key, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}
	return &AppAuth{
		appID:          appID,
		installationID: installationID,
		privateKey:     key,
		apiURL:         "https://api.github.com",
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Token returns a valid installation access token, refreshing if needed.
func (a *AppAuth) Token() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Now().Before(a.expiry.Add(-5*time.Minute)) {
		return a.token, nil
	}

	jwt, err := a.generateJWT()
	if err != nil {
		return "", fmt.Errorf("generating JWT: %w", err)
	}

	token, expiry, err := a.exchangeToken(jwt)
	if err != nil {
		return "", fmt.Errorf("exchanging token: %w", err)
	}

	a.token = token
	a.expiry = expiry
	return a.token, nil
}

// generateJWT creates a short-lived JWT signed with the app's private key.
func (a *AppAuth) generateJWT() (string, error) {
	now := time.Now()
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss": a.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	payload := base64URLEncode(claims)

	sigInput := header + "." + payload
	hash := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(nil, a.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return sigInput + "." + base64URLEncode(sig), nil
}

// exchangeToken exchanges a JWT for an installation access token.
func (a *AppAuth) exchangeToken(jwt string) (string, time.Time, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", a.apiURL, a.installationID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer discardClose(resp.Body)

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, fmt.Errorf("GitHub API %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, err
	}
	return result.Token, result.ExpiresAt, nil
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
