package urlsafe

import (
	"net"
	"testing"
)

func TestIsPublicHTTPURL(t *testing.T) {
	cases := []struct {
		url     string
		allowed bool
	}{
		{"https://example.com/article", true},
		{"http://example.com/article", true},
		{"https://feed.craftedsignal.io/briefs/foo/", true},
		// Non-HTTP schemes.
		{"ftp://example.com/file", false},
		{"file:///etc/passwd", false},
		{"javascript://alert(1)", false},
		// Loopback / private / link-local.
		{"http://localhost/path", false},
		{"http://127.0.0.1/path", false},
		{"http://10.0.0.1/path", false},
		{"http://192.168.1.1/path", false},
		{"http://169.254.169.254/latest/meta-data/", false},
		{"http://169.254.1.1/path", false},
		{"http://0.0.0.0/path", false},
		{"http://100.64.0.1/path", false},
		{"http://192.0.2.1/path", false},
		{"http://192.88.99.1/path", false},
		{"http://198.18.0.1/path", false},
		{"http://198.51.100.1/path", false},
		{"http://203.0.113.1/path", false},
		{"http://224.0.0.1/path", false},
		{"http://240.0.0.1/path", false},
		{"http://[64:ff9b::a9fe:a9fe]/path", false},
		{"http://[64:ff9b:1::a9fe:a9fe]/path", false},
		{"http://[::ffff:192.168.1.1]/path", false},
		{"http://[::192.168.1.1]/path", false},
		{"http://[100::1]/path", false},
		{"http://[2001:2::1]/path", false},
		{"http://[2001:db8::1]/path", false},
		{"http://[2002:a9fe:a9fe::1]/path", false},
		{"http://[3fff::1]/path", false},
		{"http://[fd00::1]/path", false},
		{"http://[fe80::1]/path", false},
		{"http://[ff02::1]/path", false},
		{"http://[2606:4700:4700::1111]/path", true},
		{"", false},
		{"not-a-url", false},
	}

	for _, c := range cases {
		got := IsPublicHTTPURL(c.url)
		if got != c.allowed {
			t.Errorf("IsPublicHTTPURL(%q) = %v, want %v", c.url, got, c.allowed)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip      string
		allowed bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.0.1", false},
		{"169.254.169.254", false},
		{"169.254.0.1", false},
		{"::1", false},
		{"fe80::1", false},
		{"fd00::1", false},
		{"0.0.0.0", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"192.88.99.1", false},
		{"198.18.0.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"224.0.0.1", false},
		{"240.0.0.1", false},
		{"::", false},
		{"::ffff:192.168.1.1", false},
		{"::192.168.1.1", false},
		{"64:ff9b::a9fe:a9fe", false},
		{"64:ff9b:1::a9fe:a9fe", false},
		{"100::1", false},
		{"2001:2::1", false},
		{"2001:db8::1", false},
		{"2002:a9fe:a9fe::1", false},
		{"3fff::1", false},
		{"ff02::1", false},
		{"2606:4700:4700::1111", true},
	}

	for _, c := range cases {
		got := IsPublicIP(net.ParseIP(c.ip))
		if got != c.allowed {
			t.Errorf("IsPublicIP(%q) = %v, want %v", c.ip, got, c.allowed)
		}
	}
}
