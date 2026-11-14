package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

type fakeBundleRetirementPublisher struct {
	published       bool
	publishedChecks []string
	retirements     []bundleRetirement
	flushes         int
}

func (f *fakeBundleRetirementPublisher) PublishedBriefExists(id string) (bool, error) {
	f.publishedChecks = append(f.publishedChecks, id)
	return f.published, nil
}

func (f *fakeBundleRetirementPublisher) RetireBrief(id, slug string) error {
	f.retirements = append(f.retirements, bundleRetirement{ID: id, Slug: slug})
	return nil
}

func (f *fakeBundleRetirementPublisher) Flush() error {
	f.flushes++
	return nil
}

func TestParseSlugFilter(t *testing.T) {
	got := parseSlugFilter(" first,second ,, first ")
	want := []string{"first", "second"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSlugFilter() = %#v, want %#v", got, want)
	}
}

func TestBundleCommandValidationIncludesPublishSTIX(t *testing.T) {
	if !bundleCommandValid("publish-stix") {
		t.Fatal("publish-stix must be accepted as a bundle command")
	}
	if !bundleCommandValid("retire-briefs") {
		t.Fatal("retire-briefs must be accepted as a bundle command")
	}
}

func TestRunBundleRetireBriefsPreviewDoesNotMutate(t *testing.T) {
	pub := &fakeBundleRetirementPublisher{}
	var out bytes.Buffer

	err := runBundleRetireBriefs(pub, []string{
		"--survivor-id", "brief-canonical",
		"--retire", "brief-duplicate=duplicate-slug",
	}, &out)
	if err != nil {
		t.Fatalf("runBundleRetireBriefs() error = %v", err)
	}
	if len(pub.publishedChecks) != 0 || len(pub.retirements) != 0 || pub.flushes != 0 {
		t.Fatalf("preview mutated publisher: %#v", pub)
	}
	if !strings.Contains(out.String(), "preview") {
		t.Fatalf("preview output = %q, want preview marker", out.String())
	}
}

func TestRunBundleRetireBriefsAppliesOnlyWhenSurvivorExists(t *testing.T) {
	pub := &fakeBundleRetirementPublisher{published: true}
	var out bytes.Buffer

	err := runBundleRetireBriefs(pub, []string{
		"--survivor-id", "brief-canonical",
		"--retire", "brief-duplicate-one=duplicate-one",
		"--retire", "brief-duplicate-two=duplicate-two",
		"--apply",
	}, &out)
	if err != nil {
		t.Fatalf("runBundleRetireBriefs() error = %v", err)
	}
	if !reflect.DeepEqual(pub.publishedChecks, []string{"brief-canonical"}) {
		t.Fatalf("published checks = %#v", pub.publishedChecks)
	}
	wantRetirements := []bundleRetirement{
		{ID: "brief-duplicate-one", Slug: "duplicate-one"},
		{ID: "brief-duplicate-two", Slug: "duplicate-two"},
	}
	if !reflect.DeepEqual(pub.retirements, wantRetirements) {
		t.Fatalf("retirements = %#v, want %#v", pub.retirements, wantRetirements)
	}
	if pub.flushes != 1 {
		t.Fatalf("flushes = %d, want 1", pub.flushes)
	}
}

func TestRunBundleRetireBriefsRejectsMissingSurvivor(t *testing.T) {
	pub := &fakeBundleRetirementPublisher{published: false}

	err := runBundleRetireBriefs(pub, []string{
		"--survivor-id", "brief-missing",
		"--retire", "brief-duplicate=duplicate-slug",
		"--apply",
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("runBundleRetireBriefs() error = %v, want missing survivor error", err)
	}
	if len(pub.retirements) != 0 || pub.flushes != 0 {
		t.Fatalf("missing survivor mutated publisher: %#v", pub)
	}
}

func TestRunBundleRetireBriefsRejectsSurvivorAsRetirement(t *testing.T) {
	err := runBundleRetireBriefs(&fakeBundleRetirementPublisher{}, []string{
		"--survivor-id", "brief-canonical",
		"--retire", "brief-canonical=canonical-slug",
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "survivor") {
		t.Fatalf("runBundleRetireBriefs() error = %v, want survivor validation error", err)
	}
}
