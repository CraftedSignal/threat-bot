package pipeline

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var claimKeyNonWord = regexp.MustCompile(`[^a-z0-9]+`)

func ClaimKey(e *ExtractionResult) string {
	if e == nil || e.ClaimAssessment == nil || strings.TrimSpace(e.ClaimAssessment.Claim) == "" {
		return ""
	}
	cves := normalizedClaimParts(e.CVEs)
	products := normalizedClaimParts(e.AffectedProducts)
	claim := strings.Trim(claimKeyNonWord.ReplaceAllString(strings.ToLower(e.ClaimAssessment.Claim), " "), " ")
	class := strings.Trim(claimKeyNonWord.ReplaceAllString(strings.ToLower(e.VulnClass), " "), " ")
	canonical := strings.Join(cves, ",") + "|" + strings.Join(products, ",") + "|" + class + "|" + claim
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("claim:%x", sum[:16])
}
func normalizedClaimParts(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.Trim(claimKeyNonWord.ReplaceAllString(strings.ToLower(v), " "), " ")
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
