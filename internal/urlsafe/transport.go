package urlsafe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type ipLookupFunc func(context.Context, string) ([]net.IPAddr, error)
type contextDialFunc func(context.Context, string, string) (net.Conn, error)

// NewHTTPTransport returns a transport that connects only to public IP
// addresses. It resolves hostnames itself and pins each connection to a
// validated address, preventing a second DNS lookup from rebinding the host.
func NewHTTPTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return safeDialContext(ctx, network, address, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
		},
	}
}

func safeDialContext(ctx context.Context, network, address string, lookup ipLookupFunc, dial contextDialFunc) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid outbound address: %w", err)
	}

	var addresses []net.IPAddr
	if ip := net.ParseIP(host); ip != nil {
		addresses = []net.IPAddr{{IP: ip}}
	} else {
		addresses, err = lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolving outbound host: %w", err)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("outbound host resolved to no addresses")
	}
	for _, address := range addresses {
		if len(address.IP) == 0 || !IsPublicIP(address.IP) {
			return nil, fmt.Errorf("outbound host resolved to a non-public address")
		}
	}

	var dialErrors []string
	for _, address := range addresses {
		conn, dialErr := dial(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, dialErr.Error())
	}
	return nil, fmt.Errorf("connecting to public address: %s", strings.Join(dialErrors, "; "))
}
