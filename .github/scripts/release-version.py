#!/usr/bin/env python3
"""Select a stable SemVer tag from the history of the checked-out commit."""
import argparse
import os
from pathlib import Path
import re
import subprocess

STABLE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def git(*args):
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()


def select_version(tag=None):
    if git("rev-parse", "--is-shallow-repository") == "true":
        raise ValueError("full Git history is required")
    head = git("rev-parse", "HEAD")
    if tag is not None:
        if not STABLE.fullmatch(tag) or git("rev-parse", "--verify", tag + "^{commit}") != head:
            raise ValueError("manual tag must be vMAJOR.MINOR.PATCH and point to this commit")
        return tag
    versions = []
    for candidate in git("tag", "--merged", "HEAD").splitlines():
        match = STABLE.fullmatch(candidate)
        if match:
            versions.append((tuple(map(int, match.groups())), candidate))
    if not versions:
        return "v0.1.0"
    (major, minor, patch), previous = max(versions)
    if git("rev-parse", previous + "^{commit}") == head:
        return previous
    messages = [message.strip() for message in git("log", "--format=%B%x00", previous + "..HEAD").split("\0")]
    if any(re.match(r"\w+(?:\([^\n]*\))?!:", message) or re.search(r"(?m)^BREAKING[ -]CHANGE:", message) for message in messages):
        return f"v{major + 1}.0.0"
    if any(re.match(r"feat(?:\([^\n]*\))?:", message) for message in messages):
        return f"v{major}.{minor + 1}.0"
    return f"v{major}.{minor}.{patch + 1}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="validate an explicitly pushed version tag")
    args = parser.parse_args()
    try:
        version = select_version(args.tag)
    except (ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Release version selection failed: {error}")
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"tag={version}\n")
    print(version)
