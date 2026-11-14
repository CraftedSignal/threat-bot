package scraper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRSSRequiresCurrentlyValidCertificate(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "expired"}[expired], func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			after := time.Now().Add(time.Hour)
			if expired {
				after = time.Now().Add(-time.Hour)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: after, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			pool := x509.NewCertPool()
			pool.AddCert(parsed)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			srv.StartTLS()
			defer srv.Close()
			transport := rssHTTPTransport().(*http.Transport)
			transport.TLSClientConfig = &tls.Config{RootCAs: pool}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			resp, err := client.Get(srv.URL)
			if err == nil {
				_ = resp.Body.Close()
			}
			if (err != nil) != expired {
				t.Fatalf("expired=%v request error=%v", expired, err)
			}
		})
	}
}
