#!/usr/bin/env python3
"""Exercise version selection against real temporary Git histories."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("release-version.py").resolve()


class ReleaseVersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="threat-bot-version-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.env.pop("GITHUB_OUTPUT", None)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "release@example.invalid")
        self.git("config", "core.hooksPath", os.devnull)
        self.commit("Initial source")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], env=self.env, stderr=subprocess.PIPE, text=True).strip()

    def commit(self, message):
        self.git("commit", "--allow-empty", "-m", message)

    def select(self, *args):
        result = subprocess.run(["python3", str(SCRIPT), *args], cwd=self.repo, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_first_release_starts_at_zero_one(self):
        self.assertEqual(self.select(), "v0.1.0")

    def test_retry_reuses_tag_on_same_commit(self):
        self.git("tag", "v0.1.0")
        self.assertEqual(self.select(), "v0.1.0")

    def test_commit_types_choose_the_highest_bump(self):
        for message, expected in [
            ("fix: handle an empty source", "v0.1.1"),
            ("docs: clarify setup", "v0.1.1"),
            ("feat(scraper): add a source", "v0.2.0"),
            ("feat!: change the feed contract", "v1.0.0"),
            ("refactor(parser)!: change syntax", "v1.0.0"),
            ("fix: update storage\n\nBREAKING CHANGE: remove the old schema", "v1.0.0"),
            ("fix: update storage\n\nBREAKING-CHANGE: remove the old schema", "v1.0.0"),
        ]:
            with self.subTest(message=message):
                self.git("tag", "-f", "v0.1.0")
                self.commit(message)
                self.assertEqual(self.select(), expected)

    def test_all_commits_since_last_release_count(self):
        self.git("tag", "v0.1.0")
        self.commit("feat: add a source")
        self.commit("fix: handle a retry")
        self.assertEqual(self.select(), "v0.2.0")

    def test_commit_body_examples_are_not_feature_headers(self):
        self.git("tag", "v0.1.0")
        self.commit("docs: explain commit types\n\nfeat!: an example header")
        self.assertEqual(self.select(), "v0.1.1")

    def test_versions_sort_numerically(self):
        self.git("tag", "v0.9.0")
        self.commit("fix: retry")
        self.git("tag", "-a", "v0.10.0", "-m", "Release")
        self.commit("fix: retry again")
        self.assertEqual(self.select(), "v0.10.1")

    def test_unrelated_branch_tags_do_not_select_a_version(self):
        self.git("tag", "v0.1.0")
        self.git("checkout", "-b", "other")
        self.commit("feat: unrelated")
        self.git("tag", "v9.0.0")
        self.git("checkout", "main")
        self.commit("fix: retry")
        self.assertEqual(self.select(), "v0.1.1")

    def test_manual_tag_must_be_stable_and_point_at_checkout(self):
        self.git("tag", "v0.1.0")
        self.assertEqual(self.select("--tag", "v0.1.0"), "v0.1.0")
        self.commit("fix: retry")
        for tag in ("v0.1.0", "v01.2.3", "v1.2.3-rc.1", "not-a-version"):
            with self.subTest(tag=tag):
                result = subprocess.run(["python3", str(SCRIPT), "--tag", tag], cwd=self.repo, env=self.env, capture_output=True)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
