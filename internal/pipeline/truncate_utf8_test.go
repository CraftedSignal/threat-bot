package pipeline

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateUTF8NeverSplitsRune(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		max  int
		want string
	}{
		{"cut through rune", "abc€tail", 5, "abc"},
		{"cut on rune boundary", "abc€tail", 6, "abc€"},
		{"unlimited", "abc€tail", 99, "abc€tail"},
		{"negative limit", "abc€tail", -1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateUTF8(tc.text, tc.max)
			if got != tc.want {
				t.Fatalf("truncateUTF8(%q, %d) = %q, want %q", tc.text, tc.max, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("result is invalid UTF-8: %q", got)
			}
		})
	}
}

func TestSmartTruncatePreservesUTF8(t *testing.T) {
	got := smartTruncate(strings.Repeat("é", 1000), 101)
	if !utf8.ValidString(got) {
		t.Fatalf("smartTruncate returned invalid UTF-8")
	}
	if got != strings.Repeat("é", 50) {
		t.Fatalf("smartTruncate returned %d bytes, want 100", len(got))
	}
}
