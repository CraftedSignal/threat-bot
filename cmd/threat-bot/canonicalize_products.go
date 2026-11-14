package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/craftedsignal/threat-bot/internal/publisher"
	"gopkg.in/yaml.v3"
)

type canonicalizeProductsReport struct {
	FilesScanned   int                          `json:"files_scanned"`
	FilesChanged   int                          `json:"files_changed"`
	VendorsBefore  int                          `json:"vendors_before"`
	VendorsAfter   int                          `json:"vendors_after"`
	ProductsBefore int                          `json:"products_before"`
	ProductsAfter  int                          `json:"products_after"`
	Apply          bool                         `json:"apply"`
	Redirects      []publisher.TermRedirect     `json:"redirects"`
	Examples       []canonicalizeProductExample `json:"examples"`
}

type canonicalizeProductExample struct {
	File     string   `json:"file"`
	Vendors  []string `json:"vendors,omitempty"`
	Products []string `json:"products,omitempty"`
}

func runCanonicalizeProducts(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("canonicalize-products", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	contentDir := fs.String("content-dir", "", "path to local brief Markdown content directory")
	apply := fs.Bool("apply", false, "write canonical frontmatter changes to local files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *contentDir == "" {
		return errors.New("--content-dir is required")
	}
	info, err := os.Stat(*contentDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("content directory %q is not a directory", *contentDir)
	}
	report := canonicalizeProductsReport{Apply: *apply}
	redirectByFrom := map[string]publisher.TermRedirect{}
	vendorsBefore, vendorsAfter := map[string]bool{}, map[string]bool{}
	productsBefore, productsAfter := map[string]bool{}, map[string]bool{}
	var examples []canonicalizeProductExample
	err = filepath.WalkDir(*contentDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".md" {
			return nil
		}
		report.FilesScanned++
		original, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		before := rawTaxonomyTerms(original)
		updated, redirects, err := publisher.CanonicalizeProductsMarkdown(original)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		after := taxonomyTerms(updated)
		addTerms(vendorsBefore, before.Vendors)
		addTerms(vendorsAfter, after.Vendors)
		addTerms(productsBefore, before.Products)
		addTerms(productsAfter, after.Products)
		if len(before.Vendors) > 0 || len(before.Products) > 0 || len(after.Vendors) > 0 || len(after.Products) > 0 {
			examples = append(examples, canonicalizeProductExample{File: filepath.Base(path), Vendors: after.Vendors, Products: after.Products})
		}
		if string(updated) != string(original) {
			report.FilesChanged++
			if len(report.Examples) < 5 {
				report.Examples = append(report.Examples, canonicalizeExample(filepath.Base(path), updated))
			}
			if *apply {
				if err := os.WriteFile(path, updated, 0o644); err != nil {
					return err
				}
			}
		}
		for _, r := range redirects {
			redirectByFrom[r.From] = r
		}
		return nil
	})
	if err != nil {
		return err
	}
	report.VendorsBefore, report.VendorsAfter = len(vendorsBefore), len(vendorsAfter)
	report.ProductsBefore, report.ProductsAfter = len(productsBefore), len(productsAfter)
	report.Examples = representativeProductExamples(examples)
	for _, redirect := range redirectByFrom {
		report.Redirects = append(report.Redirects, redirect)
	}
	sort.Slice(report.Redirects, func(i, j int) bool { return report.Redirects[i].From < report.Redirects[j].From })
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

type taxonomyTermLists struct{ Vendors, Products []string }

func taxonomyTerms(markdown []byte) taxonomyTermLists {
	raw := rawTaxonomyTerms(markdown)
	return taxonomyTermLists{Vendors: canonicalizeTerms(raw.Vendors), Products: canonicalizeProducts(raw.Products)}
}

func rawTaxonomyTerms(markdown []byte) taxonomyTermLists {
	parts := strings.SplitN(string(markdown), "---\n", 3)
	if len(parts) != 3 {
		return taxonomyTermLists{}
	}
	var fm struct {
		Vendors          []string `yaml:"vendors"`
		Products         []string `yaml:"products"`
		AffectedProducts []string `yaml:"affected_products"`
	}
	if yaml.Unmarshal([]byte(parts[1]), &fm) != nil {
		return taxonomyTermLists{}
	}
	if len(fm.Products) == 0 {
		fm.Products = fm.AffectedProducts
	}
	return taxonomyTermLists{Vendors: uniqueRawTerms(fm.Vendors), Products: uniqueRawTerms(fm.Products)}
}

func uniqueRawTerms(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		key := strings.ToLower(item)
		if item != "" && !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

func canonicalizeTerms(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range items {
		value = publisher.CanonicalVendorName(value)
		key := strings.ToLower(value)
		if value != "" && !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

func canonicalizeProducts(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range items {
		name, _ := publisher.CanonicalProductNameAndRange(value)
		key := strings.ToLower(strings.TrimSpace(name))
		if name != "" && !seen[key] {
			seen[key] = true
			out = append(out, strings.TrimSpace(name))
		}
	}
	return out
}

func addTerms(set map[string]bool, values []string) {
	for _, value := range values {
		set[strings.ToLower(strings.TrimSpace(value))] = true
	}
}

func representativeProductExamples(all []canonicalizeProductExample) []canonicalizeProductExample {
	wanted := []string{"DSM", "n8n", "NGINX"}
	selected := make([]canonicalizeProductExample, 0, 3)
	selectedFiles := map[string]bool{}
	for _, term := range wanted {
		for _, example := range all {
			if selectedFiles[example.File] {
				continue
			}
			found := false
			for _, product := range example.Products {
				if strings.EqualFold(product, term) {
					found = true
					break
				}
			}
			for _, vendor := range example.Vendors {
				if strings.EqualFold(vendor, term) {
					found = true
					break
				}
			}
			if found {
				selected = append(selected, example)
				selectedFiles[example.File] = true
				break
			}
		}
	}
	return selected
}

func canonicalizeExample(file string, markdown []byte) canonicalizeProductExample {
	example := canonicalizeProductExample{File: file}
	parts := strings.SplitN(string(markdown), "---\n", 3)
	if len(parts) != 3 {
		return example
	}
	var fm struct {
		Vendors  []string `yaml:"vendors"`
		Products []string `yaml:"products"`
	}
	if yaml.Unmarshal([]byte(parts[1]), &fm) == nil {
		example.Vendors, example.Products = fm.Vendors, fm.Products
	}
	return example
}
