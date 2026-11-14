package pipeline

import "testing"

func TestProductFingerprint_VendorlessSpecificProduct(t *testing.T) {
	// Community package: the brief prompt tells the LLM to omit the vendor, so
	// a product-only key must still be produced (this is the cap-go case).
	fp1 := ProductFingerprint(nil, []string{"cap-go"})
	if fp1 == "" {
		t.Fatal("want non-empty fingerprint for vendorless specific product")
	}
	// Stable across case and empty-vendor spelling.
	fp2 := ProductFingerprint([]string{""}, []string{"Cap-go"})
	if fp1 != fp2 {
		t.Fatalf("want stable key across case/empty-vendor: %q vs %q", fp1, fp2)
	}
	// Generic platform products are NOT a safe sole merge key.
	if ProductFingerprint(nil, []string{"WordPress"}) != "" {
		t.Fatal("generic product WordPress must not produce a vendorless merge key")
	}
	if ProductFingerprint(nil, []string{"Linux"}) != "" {
		t.Fatal("generic product Linux must not produce a vendorless merge key")
	}
	if ProductFingerprint(nil, []string{"Python"}) != "" {
		t.Fatal("vendorless Python must not produce a generic merge key")
	}
	if ProductFingerprint([]string{"Python Software Foundation"}, []string{"Python"}) == "" {
		t.Fatal("upstream Python runtime advisory must produce a merge key")
	}
}
