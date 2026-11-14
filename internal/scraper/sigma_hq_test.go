package scraper

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseSigmaRule(t *testing.T) {
	raw := `
title: Change Default File Association Via Assoc
id: 3d3aa6cd-6272-44d6-8afc-7e88dfef7061
status: test
description: Detects file association changes using the builtin assoc command.
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1546.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cli:
        CommandLine|contains: 'assoc'
    condition: all of selection_*
level: low
`
	var rule SigmaRule
	if err := yaml.Unmarshal([]byte(raw), &rule); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if rule.Title != "Change Default File Association Via Assoc" {
		t.Errorf("unexpected title: %s", rule.Title)
	}
	if rule.LogSource.Category != "process_creation" {
		t.Errorf("unexpected logsource category: %s", rule.LogSource.Category)
	}

	techniques := rule.MITRETechniques()
	if len(techniques) != 1 {
		t.Fatalf("expected 1 technique, got: %v", techniques)
	}

	tactics := rule.MITRETactics()
	if len(tactics) != 2 {
		t.Fatalf("expected 2 tactics, got: %v", tactics)
	}
}
