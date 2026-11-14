package publisher

import "testing"

func TestLeadingRecommendationHeadingIsPreserved(t *testing.T) {
	const content = "# FixtureWidget advisory\n\n## Recommendation\nApply the vendor's fixed release."
	const want = "## Recommendation\nApply the vendor's fixed release."
	if got := stripLeadingHeadings(content); got != want {
		t.Fatalf("semantic section heading lost: got %q, want %q", got, want)
	}
}
