package sigma

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIndexBuild(t *testing.T) {
	dir := t.TempDir()

	rule1 := `
title: Test Process Creation Rule
id: test-rule-1
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
level: medium
`
	rule2 := `
title: Test Network Connection Rule
id: test-rule-2
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 443
    condition: selection
level: low
`
	os.MkdirAll(filepath.Join(dir, "windows", "process_creation"), 0o755)
	os.MkdirAll(filepath.Join(dir, "windows", "network"), 0o755)
	os.WriteFile(filepath.Join(dir, "windows", "process_creation", "rule1.yml"), []byte(rule1), 0o644)
	os.WriteFile(filepath.Join(dir, "windows", "network", "rule2.yml"), []byte(rule2), 0o644)

	idx, err := BuildIndex(dir)
	if err != nil {
		t.Fatal(err)
	}

	matches := idx.ByTechnique("t1059.003")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for t1059.003, got %d", len(matches))
	}
	if matches[0].Title != "Test Process Creation Rule" {
		t.Errorf("unexpected title: %s", matches[0].Title)
	}

	matches = idx.ByTactic("execution")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for execution, got %d", len(matches))
	}

	matches = idx.ByLogSource("process_creation", "windows")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for process_creation/windows, got %d", len(matches))
	}

	if idx.Count() != 2 {
		t.Errorf("expected 2 total rules, got %d", idx.Count())
	}
}
