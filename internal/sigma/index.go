package sigma

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID          string         `yaml:"id"`
	Title       string         `yaml:"title"`
	Status      string         `yaml:"status"`
	Description string         `yaml:"description"`
	Tags        []string       `yaml:"tags"`
	Level       string         `yaml:"level"`
	LogSource   LogSource      `yaml:"logsource"`
	Detection   map[string]any `yaml:"detection"`
	References  []string       `yaml:"references"`
	FilePath    string         `yaml:"-"`
	RawYAML     string         `yaml:"-"`
}

type LogSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

type Index struct {
	rules       []Rule
	byTechnique map[string][]*Rule
	byTactic    map[string][]*Rule
	byLogSource map[string][]*Rule
}

func BuildIndex(rootDir string) (*Index, error) {
	idx := &Index{
		byTechnique: make(map[string][]*Rule),
		byTactic:    make(map[string][]*Rule),
		byLogSource: make(map[string][]*Rule),
	}

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		var rule Rule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return nil // Skip unparseable files
		}
		if rule.ID == "" || rule.Title == "" {
			return nil
		}

		rule.FilePath = path
		rule.RawYAML = string(data)
		idx.rules = append(idx.rules, rule)

		r := &idx.rules[len(idx.rules)-1]

		for _, tag := range rule.Tags {
			if !strings.HasPrefix(tag, "attack.") {
				continue
			}
			rest := strings.ToLower(tag[7:])
			if len(rest) >= 2 && rest[0] == 't' && rest[1] >= '0' && rest[1] <= '9' {
				idx.byTechnique[rest] = append(idx.byTechnique[rest], r)
			} else if rest != "" {
				idx.byTactic[rest] = append(idx.byTactic[rest], r)
			}
		}

		key := strings.ToLower(rule.LogSource.Category) + ":" + strings.ToLower(rule.LogSource.Product)
		idx.byLogSource[key] = append(idx.byLogSource[key], r)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("building sigma index: %w", err)
	}
	return idx, nil
}

func (idx *Index) ByTechnique(techniqueID string) []Rule {
	ptrs := idx.byTechnique[strings.ToLower(techniqueID)]
	rules := make([]Rule, len(ptrs))
	for i, r := range ptrs {
		rules[i] = *r
	}
	return rules
}

func (idx *Index) ByTactic(tactic string) []Rule {
	ptrs := idx.byTactic[strings.ToLower(tactic)]
	rules := make([]Rule, len(ptrs))
	for i, r := range ptrs {
		rules[i] = *r
	}
	return rules
}

func (idx *Index) ByLogSource(category, product string) []Rule {
	key := strings.ToLower(category) + ":" + strings.ToLower(product)
	ptrs := idx.byLogSource[key]
	rules := make([]Rule, len(ptrs))
	for i, r := range ptrs {
		rules[i] = *r
	}
	return rules
}

func (idx *Index) Count() int {
	return len(idx.rules)
}
