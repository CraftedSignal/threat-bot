package urlsafe

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestSafeDialRejectsPrivateDNSAnswerBeforeConnecting(t *testing.T) {
	for _, raw := range []string{
		"169.254.10.20", "0.0.0.0", "100.64.0.1", "192.0.2.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe",
		"2001:2::1", "2001:db8::1", "2002:a9fe:a9fe::1", "3fff::1",
	} {
		t.Run(raw, func(t *testing.T) {
			dialed := false
			_, err := safeDialContext(
				context.Background(),
				"tcp",
				"attacker.example:443",
				func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP(raw)}}, nil
				},
				func(context.Context, string, string) (net.Conn, error) {
					dialed = true
					return nil, errors.New("unexpected dial")
				},
			)
			if err == nil {
				t.Fatal("expected non-public DNS answer to be blocked")
			}
			if dialed {
				t.Fatal("dialer was called for a non-public DNS answer")
			}
		})
	}
}
