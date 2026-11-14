package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalizeProductsDryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.md")
	input := []byte("---\nvendors:\n  - NGINX\nproducts:\n  - DSM (< 7.2.2-72806)\n---\n# DSM n8n NGINX\n")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runCanonicalizeProducts([]string{"--content-dir", dir}, &output); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, input) {
		t.Fatal("dry run changed content")
	}
	var report struct {
		FilesScanned   int  `json:"files_scanned"`
		FilesChanged   int  `json:"files_changed"`
		VendorsBefore  int  `json:"vendors_before"`
		VendorsAfter   int  `json:"vendors_after"`
		ProductsBefore int  `json:"products_before"`
		ProductsAfter  int  `json:"products_after"`
		Apply          bool `json:"apply"`
		Redirects      []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"redirects"`
		Examples []struct {
			Vendors  []string `json:"vendors"`
			Products []string `json:"products"`
		} `json:"examples"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || report.FilesChanged != 1 || report.Apply {
		t.Fatalf("unexpected report: %s", output.String())
	}
	if report.VendorsBefore != 1 || report.VendorsAfter != 1 || report.ProductsBefore != 1 || report.ProductsAfter != 1 {
		t.Fatalf("term counts: %#v", report)
	}
	if len(report.Redirects) != 1 || report.Redirects[0].From != "/products/dsm-7.2.2-72806/" {
		t.Fatalf("redirects: %#v", report.Redirects)
	}
	if len(report.Examples) != 1 || len(report.Examples[0].Products) != 1 || report.Examples[0].Products[0] != "DSM" || len(report.Examples[0].Vendors) != 1 || report.Examples[0].Vendors[0] != "NGINX" {
		t.Fatalf("examples: %#v", report.Examples)
	}
}

func TestCanonicalizeProductsApplyWritesOnlyFrontmatter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.md")
	input := []byte("---\nvendors:\n  - NGINX\nproducts:\n  - DSM (< 7.2.2-72806)\n---\n# Body\nkeep exactly\n")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runCanonicalizeProducts([]string{"--content-dir", dir, "--apply"}, &output); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(after), "# Body\nkeep exactly\n") {
		t.Fatalf("body changed: %s", after)
	}
	if !strings.Contains(string(after), "product_versions:") || !strings.Contains(string(after), "- DSM\n") {
		t.Fatalf("frontmatter not canonicalized: %s", after)
	}
}

func TestCanonicalizeProductsNoOpDryRunAndApplyAreByteIdentical(t *testing.T) {
	dir := t.TempDir()
	input := []byte("---\ntitle: No products\nslug: clean\n---\n# Body\nunchanged\n")
	path := filepath.Join(dir, "clean.md")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--content-dir", dir}, {"--content-dir", dir, "--apply"}} {
		var output bytes.Buffer
		if err := runCanonicalizeProducts(args, &output); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, input) {
			t.Fatalf("no-op args %v rewrote bytes:\n%s", args, after)
		}
		var report map[string]any
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report["files_changed"].(float64) != 0 {
			t.Fatalf("no-op report: %s", output.String())
		}
	}
}

func TestCanonicalizeProductsReportsRawBeforeAndCanonicalAfterCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "versions.md")
	input := []byte("---\nvendors: [Synology]\nproducts:\n  - DSM (1.0)\n  - DSM (2.0)\n---\n# Body\n")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runCanonicalizeProducts([]string{"--content-dir", dir}, &output); err != nil {
		t.Fatal(err)
	}
	var report struct {
		ProductsBefore int `json:"products_before"`
		ProductsAfter  int `json:"products_after"`
		FilesChanged   int `json:"files_changed"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.ProductsBefore != 2 || report.ProductsAfter != 1 || report.FilesChanged != 1 {
		t.Fatalf("raw/canonical report: %s", output.String())
	}
}
