package sigma

import (
	"reflect"
	"testing"
)

func TestNormalizeModifierAliasesRewritesWholeTokens(t *testing.T) {
	det := detection(t, `
selection:
  CommandLine|regex: '^/usr/bin/(find|chmod).*-perm'
  Image|endwith: '/chmod'
  RegexField|contains: regex
  Other|contain|all: [a, b]
  Name|regexp|i: 'x'
  Path|startwith: '/tmp'
condition: selection
`)
	changed := NormalizeModifierAliases(det)
	if !changed {
		t.Fatal("expected a change")
	}
	want := detection(t, `
selection:
  CommandLine|re: '^/usr/bin/(find|chmod).*-perm'
  Image|endswith: '/chmod'
  RegexField|contains: regex
  Other|contains|all: [a, b]
  Name|re|i: 'x'
  Path|startswith: '/tmp'
condition: selection
`)
	if !reflect.DeepEqual(det, want) {
		t.Fatalf("got %v\nwant %v", det, want)
	}
	if NormalizeModifierAliases(det) {
		t.Fatal("second pass must be a no-op")
	}
}

func TestNormalizedRegexRulePassesValidation(t *testing.T) {
	det := detection(t, "selection:\n  CommandLine|regex: '^find .* -perm'\ncondition: selection\n")
	if problems, _ := CheckDetection(det); len(problems) == 0 {
		t.Skip("parser already accepts regex alias")
	}
	NormalizeModifierAliases(det)
	if problems, _ := CheckDetection(det); len(problems) != 0 {
		t.Fatalf("still invalid: %q", problems)
	}
	if got := det["selection"].(map[string]any)["CommandLine|re"]; got != "^find .* -perm" {
		t.Fatalf("value changed: %v", got)
	}
}
