package scraper

import (
	"reflect"
	"testing"
)

func TestSecuritySignalClasses(t *testing.T) {
	tests := []struct {
		name string
		item RawItem
		want []string
	}{
		{
			name: "juliano thread has identifier mechanism and evidence",
			item: RawItem{Title: "Broccoli CVE-2026-111497 update", Content: "In our tests a malicious Brotli stream leaks heap bytes into the decompressed output."},
			want: []string{"identifier", "mechanism", "evidence"},
		},
		{
			name: "cve and poc are distinct classes",
			item: RawItem{Title: "PoC for CVE-2026-12345", Content: "Reproducer and crash trace: https://github.com/acme/repro"},
			want: []string{"identifier", "evidence", "artifact"},
		},
		{
			name: "duplicate mechanism terms count once",
			item: RawItem{Title: "heap leak memory disclosure", Content: "heap leak causes memory disclosure"},
			want: []string{"mechanism"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecuritySignalClasses(tt.item); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("SecuritySignalClasses() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRelevantDiscoveryCandidate(t *testing.T) {
	tests := []struct {
		name string
		item RawItem
		want bool
	}{
		{
			name: "juliano thread",
			item: RawItem{Title: "Broccoli CVE-2026-111497 update", Content: "In our tests a malicious Brotli stream leaks heap bytes into the decompressed output."},
			want: true,
		},
		{
			name: "product first party test and impact",
			item: RawItem{Title: "Node.js Brotli decoder", Content: "We reproduced remote code execution against Node.js 26.12.0."},
			want: true,
		},
		{
			name: "bare cve link",
			item: RawItem{Content: "https://nvd.nist.gov/vuln/detail/CVE-2026-111497"},
			want: false,
		},
		{
			name: "marketing",
			item: RawItem{Title: "Critical security webinar", Content: "Register now to learn about our vulnerability management platform."},
			want: false,
		},
		{
			name: "repost",
			item: RawItem{Title: "RT @researcher: CVE-2026-111497", Content: "PoC https://github.com/acme/repro"},
			want: false,
		},
		{
			name: "unsupported critical zero day",
			item: RawItem{Title: "CRITICAL 0day in Acme!", Content: "This is huge. Share now."},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRelevantDiscoveryCandidate(tt.item); got != tt.want {
				t.Fatalf("IsRelevantDiscoveryCandidate() = %v, want %v; classes=%v", got, tt.want, SecuritySignalClasses(tt.item))
			}
		})
	}
}
