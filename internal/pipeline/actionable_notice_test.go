package pipeline

import "testing"

func TestActionableBriefIncludesSourcedOperationalNotice(t *testing.T) {
	brief := `title: eMudhra certificate compromise
affected_products:
  - NSS trust store
action_plan:
  mitigation_plan:
    - action: Update affected trust stores to remove compromised intermediates
      evidence: Immediate action may be required to protect clients using your trust store.
`
	if !isActionableBrief(brief) {
		t.Fatal("grounded certificate response was dropped for having no CVE, IOC, Sigma rule, or TTP")
	}
}

func TestActionableBriefStillRejectsProductNewsWithoutSourcedAction(t *testing.T) {
	brief := `title: New security console launched
affected_products:
  - Security Console
action_plan:
  mitigation_plan:
    - action: Try the new console
`
	if isActionableBrief(brief) {
		t.Fatal("product announcement without an evidenced response passed actionability")
	}
}
