package workflowconfig

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func releaseGuard(t *testing.T) string {
	t.Helper()
	workflow := readWorkflow(t, "release.yml")
	publish := workflow["jobs"].(map[string]any)["publish"].(map[string]any)
	guardIndex, firstWrite := -1, -1
	var code string
	for i, raw := range publish["steps"].([]any) {
		step := raw.(map[string]any)
		uses, _ := step["uses"].(string)
		if strings.Contains(uses, "actions/checkout") {
			t.Fatal("privileged publication must not check out application source")
		}
		run, _ := step["run"].(string)
		if strings.Contains(run, "docker push") && firstWrite < 0 {
			firstWrite = i
		}
		if step["name"] == "Reject existing release or image" {
			guardIndex = i
			_, python, ok := strings.Cut(run, "python3 - <<'PY'\n")
			if !ok {
				t.Fatal("guard must be inline trusted workflow Python")
			}
			code, _, ok = strings.Cut(python, "\nPY")
			if !ok {
				t.Fatal("guard Python terminator is missing")
			}
			env := step["env"].(map[string]any)
			if env["REPOSITORY_ID"] != "${{ github.repository_id }}" || env["GH_TOKEN"] != "${{ github.token }}" {
				t.Fatal("guard must bind package ownership to repository ID and use the runtime token")
			}
		}
	}
	if guardIndex < 0 || firstWrite < 0 || guardIndex >= firstWrite {
		t.Fatal("release requires an existence/ownership guard before any registry write")
	}
	return code
}

func TestReleaseGuardPrecedesRegistryWrites(t *testing.T) {
	releaseGuard(t)
}

func TestReleaseGuardRemoteStateFixtures(t *testing.T) {
	code := releaseGuard(t)
	cmd := exec.Command("python3", filepath.Join("testdata", "release_guard_cases.py"))
	cmd.Stdin = strings.NewReader(code)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("release guard fixtures: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}
