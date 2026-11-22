#!/usr/bin/env python3
"""Guard the release workflow's bounded provenance-attestation retries."""
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).parents[1] / "workflows" / "release.yml"


def step_block(workflow: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)",
        workflow,
    )
    return match.group(1) if match else ""


class ReleaseAttestationRetryTests(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text()

    def test_release_file_attestation_is_retried_once_after_failure(self):
        first = step_block(self.workflow, "Attest release files")
        delay = step_block(self.workflow, "Wait before retrying release-file attestation")
        retry = step_block(self.workflow, "Retry release-file attestation once")
        require = step_block(self.workflow, "Require release-file attestation")

        self.assertIn("id: release_files_attest_first", first)
        self.assertIn("continue-on-error: true", first)
        self.assertIn("actions/attest-build-provenance@", first)
        self.assertIn("if: steps.release_files_attest_first.outcome == 'failure'", delay)
        self.assertIn("sleep 15", delay)
        self.assertIn("if: steps.release_files_attest_first.outcome == 'failure'", retry)
        self.assertIn("continue-on-error: true", retry)
        self.assertIn("actions/attest-build-provenance@", retry)
        self.assertIn("subject-path:", retry)
        paths = re.compile(r"(?m)^          subject-path: \|\n((?:^            .+\n)+)")
        self.assertEqual(paths.findall(first), paths.findall(retry))
        self.assertIn("if: steps.release_files_attest_first.outcome != 'success' && steps.release_files_attest_retry.outcome != 'success'", require)
        self.assertIn("exit 1", require)

    def test_release_file_retry_precedes_container_attestation_and_release_creation(self):
        retry_at = self.workflow.index("Retry release-file attestation once")
        require_at = self.workflow.index("Require release-file attestation")
        container_at = self.workflow.index("Attest container provenance (attempt 1)")
        release_at = self.workflow.index("Create release")
        self.assertLess(retry_at, require_at)
        self.assertLess(require_at, container_at)
        self.assertLess(container_at, release_at)


if __name__ == "__main__":
    unittest.main()
