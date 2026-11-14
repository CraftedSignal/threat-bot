package publisher

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCanonicalizeProductsMarkdownChangesTaxonomyAndPreservesBody(t *testing.T) {
	input := []byte("---\nvendors:\n  - NGINX\nproducts:\n  - DSM (< 7.2.2-72806)\n  - DSM (< 7.2.2-72806)\nslug: sample\n---\n# Body\n\nKeep *all* this.\n")
	got, redirects, err := CanonicalizeProductsMarkdown(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(got), "# Body\n\nKeep *all* this.\n") {
		t.Fatalf("body changed: %q", got)
	}
	for _, want := range []string{"- DSM\n", "product_versions:", "range: < 7.2.2-72806", "product: DSM"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if len(redirects) != 1 || redirects[0].From != "/products/dsm-7.2.2-72806/" || redirects[0].To != "/products/dsm/" {
		t.Fatalf("redirects = %#v", redirects)
	}
	again, redirectsAgain, err := CanonicalizeProductsMarkdown(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(got) {
		t.Fatalf("not idempotent:\n%s\n---\n%s", got, again)
	}
	if len(redirectsAgain) != 0 {
		t.Fatalf("second pass emitted redirects: %#v", redirectsAgain)
	}
}

func TestCanonicalizeProductsMarkdownPreservesCanonicalAndUnscopedBytes(t *testing.T) {
	for _, input := range []string{
		"---\ntitle: No affected products\nslug: no-products\n---\n# Body\n",
		"---\ntitle: Canonical\nvendors: [NGINX]\nproducts: [DSM, n8n]\nproduct_versions:\n  - product: DSM\n    range: '< 7.2.2-72806'\n---\n# Body\n",
	} {
		got, redirects, err := CanonicalizeProductsMarkdown([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != input {
			t.Fatalf("semantic no-op rewrote bytes:\n%s\n---\n%s", input, got)
		}
		if len(redirects) != 0 {
			t.Fatalf("semantic no-op generated redirects: %#v", redirects)
		}
	}
}

func TestCanonicalProductScopePatternsDoNotStripModelNames(t *testing.T) {
	for _, tc := range []struct{ raw, name, scope string }{
		{"Google Pixel (8 Pro)", "Google Pixel (8 Pro)", ""},
		{"Exim (4.97 to 4.99.2)", "Exim", "4.97 to 4.99.2"},
		{"Stormshield Network Security (versions < 5.0.10)", "Stormshield Network Security", "versions < 5.0.10"},
		{"NetScaler ADC (13.1, 14.1)", "NetScaler ADC", "13.1, 14.1"},
		{"motors (n/a through 1.4.126)", "motors", "n/a through 1.4.126"},
		{"CubeCart (6.7.4)", "CubeCart", "6.7.4"},
		{"ractive (1.4.4)", "ractive", "1.4.4"},
	} {
		name, scope := CanonicalProductNameAndRange(tc.raw)
		if name != tc.name || scope != tc.scope {
			t.Errorf("split %q = (%q, %q), want (%q, %q)", tc.raw, name, scope, tc.name, tc.scope)
		}
	}
}

func TestCanonicalizeProductsSplitsMultipleBareDottedVersions(t *testing.T) {
	input := []byte("---\nproducts:\n  - DSM (1.0)\n  - DSM (2.0)\n---\n# Body\n")
	got, redirects, err := CanonicalizeProductsMarkdown(input)
	if err != nil {
		t.Fatal(err)
	}
	var fm struct {
		Products []string               `yaml:"products"`
		Versions []publicProductVersion `yaml:"product_versions"`
	}
	parts := strings.SplitN(string(got), "---\n", 3)
	if err := yaml.Unmarshal([]byte(parts[1]), &fm); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fm.Products, []string{"DSM"}) {
		t.Fatalf("products = %#v", fm.Products)
	}
	if len(fm.Versions) != 2 {
		t.Fatalf("product_versions = %#v", fm.Versions)
	}
	if len(redirects) != 2 {
		t.Fatalf("redirects = %#v, want both historical term paths", redirects)
	}
}

func TestCanonicalizeProductsDeduplicatesExistingVersionRows(t *testing.T) {
	input := []byte("---\nproducts: [DSM]\nproduct_versions:\n  - product: DSM\n    range: 1.0\n  - product: DSM\n    range: 1.0\n---\n# Body\n")
	got, _, err := CanonicalizeProductsMarkdown(input)
	if err != nil {
		t.Fatal(err)
	}
	var fm struct {
		Versions []publicProductVersion `yaml:"product_versions"`
	}
	parts := strings.SplitN(string(got), "---\n", 3)
	if err := yaml.Unmarshal([]byte(parts[1]), &fm); err != nil {
		t.Fatal(err)
	}
	if len(fm.Versions) != 1 {
		t.Fatalf("duplicate version rows remain: %#v", fm.Versions)
	}
}

func TestTermSlugMatchesHugoURLize(t *testing.T) {
	for raw, want := range map[string]string{
		"FortiGate (7.4.1)":   "fortigate-7.4.1",
		"Ångström Product":    "%C3%A5ngstr%C3%B6m-product",
		"DSM (< 7.2.2-72806)": "dsm-7.2.2-72806",
		"foo/bar":             "foo/bar",
		"C++":                 "c++",
		"foo@bar":             "foo@bar",
	} {
		if got := termSlug(raw); got != want {
			t.Errorf("termSlug(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestSameStringSetDetectsDuplicateTerms(t *testing.T) {
	if sameStringSet([]string{"DSM", "DSM"}, []string{"DSM"}) {
		t.Fatal("duplicate term was treated as canonical")
	}
}
