package workflowconfig

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestReleaseVersionSelection(t *testing.T) {
	cmd := exec.Command("python3", filepath.Join("..", "..", ".github", "scripts", "test-release-version.py"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release version fixtures: %v\n%s", err, output)
	}
}
