#!/usr/bin/env python3
"""Check Go source formatting in the current checkout, including new files."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
tracked = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "*.go"], cwd=root)
paths = sorted({p.decode() for p in tracked.split(b"\0") if p and (root / p.decode()).is_file()})
if paths:
    result = subprocess.run(["gofmt", "-l", *paths], cwd=root, check=True, text=True, capture_output=True)
    if result.stdout:
        print("Run gofmt on:\n" + result.stdout, file=sys.stderr)
        sys.exit(1)
