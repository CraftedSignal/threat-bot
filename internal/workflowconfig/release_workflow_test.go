package workflowconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readWorkflow(t *testing.T, name string) map[string]any {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(contents, &workflow); err != nil {
		t.Fatal(err)
	}
	return workflow
}

func TestReleaseRequiresVersionTagAndValidation(t *testing.T) {
	workflow := readWorkflow(t, "release.yml")
	triggers := workflow["on"].(map[string]any)
	push, ok := triggers["push"].(map[string]any)
	if !ok {
		t.Fatal("release must be triggered by a version tag")
	}
	if _, ok := push["branches"]; ok {
		t.Fatal("release must not run on branch pushes")
	}
	tags, ok := push["tags"].([]any)
	if !ok || len(tags) != 1 || tags[0] != "v*" {
		t.Fatal("release must select version tags and validate semantic version syntax")
	}
	jobs := workflow["jobs"].(map[string]any)
	if jobs["validate"].(map[string]any)["uses"] != "./.github/workflows/ci.yml" {
		t.Fatal("release must validate exact source using public CI")
	}
	publish := jobs["publish"].(map[string]any)
	needs, ok := publish["needs"].([]any)
	if !ok || len(needs) != 2 {
		t.Fatal("publishing requires validation and artifact build")
	}
	if publish["environment"] != "public-release" {
		t.Fatal("publishing must use release environment protection")
	}
}

func TestWorkflowsUsePinnedActionsWithoutSiblingCheckouts(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	pinned := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(contents), "threat-feed") {
			t.Errorf("%s depends on sibling feed checkout", path)
		}
		var workflow map[string]any
		if err := yaml.Unmarshal(contents, &workflow); err != nil {
			t.Fatal(err)
		}
		for _, raw := range workflow["jobs"].(map[string]any) {
			job := raw.(map[string]any)
			steps, _ := job["steps"].([]any)
			for _, raw := range steps {
				step := raw.(map[string]any)
				if uses, ok := step["uses"].(string); ok && !strings.HasPrefix(uses, "./") && !pinned.MatchString(uses) {
					t.Errorf("%s has unpinned action %s", path, uses)
				}
			}
		}
	}
}

func TestDockerBuildUsesOnlyCheckoutAndPinnedToolchain(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(contents)
	if !regexp.MustCompile(`FROM --platform=\$BUILDPLATFORM golang:[0-9.]+-alpine[0-9.]+@sha256:[0-9a-f]{64} AS builder`).MatchString(dockerfile) {
		t.Fatal("Go builder must use an exact version and digest")
	}
	if strings.Contains(dockerfile, "threat-feed") || strings.Contains(dockerfile, "apk add") {
		t.Fatal("container cannot require sibling contexts or floating runtime packages")
	}
	contents, err = os.ReadFile(filepath.Join("..", "..", ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "\n**\n") {
		t.Fatal("container context must default-deny unlisted inputs")
	}
	for _, input := range []string{"!go.mod", "!go.sum", "!cmd/**/*.go", "!internal/**/*.go", "!pkg/**/*.go", "**/*_test.go"} {
		if !strings.Contains(string(contents), input) {
			t.Errorf("missing build input rule %s", input)
		}
	}
}

func TestDockerToolchainMatchesModule(t *testing.T) {
	dockerfile, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	version := regexp.MustCompile(`(?m)^go ([0-9.]+)$`).FindStringSubmatch(string(module))
	if len(version) != 2 || !strings.Contains(string(dockerfile), "golang:"+version[1]+"-") {
		t.Fatal("Docker and module/CI toolchain versions must be updated together")
	}
}
