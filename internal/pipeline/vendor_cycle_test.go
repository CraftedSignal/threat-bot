package pipeline

import (
	"testing"
	"time"
)

func TestIsPatchCycleVendor(t *testing.T) {
	for _, v := range []string{"Microsoft", "adobe", "Apple", "Oracle", "SAP", "Qualcomm"} {
		if !isPatchCycleVendor(v) {
			t.Errorf("%q should be a patch-cycle vendor", v)
		}
	}
	for _, v := range []string{"cap-go", "OpenClaw", "", "n8n GmbH"} {
		if isPatchCycleVendor(v) {
			t.Errorf("%q should NOT be a patch-cycle vendor", v)
		}
	}
}

func TestVendorCycleKey(t *testing.T) {
	ts := time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)
	if got := vendorCycleKey("Microsoft", ts); got != "microsoft|2026-07" {
		t.Fatalf("want microsoft|2026-07, got %q", got)
	}
	if vendorCycleKey("microsoft", ts) != vendorCycleKey("Microsoft", ts) {
		t.Fatal("should be case-insensitive")
	}
	if got := vendorCycleKey("SomeRandomVendor", ts); got != "" {
		t.Fatalf("want empty for non-cycle vendor, got %q", got)
	}
	if vendorCycleKey("", ts) != "" {
		t.Fatal("want empty for empty vendor")
	}
}
