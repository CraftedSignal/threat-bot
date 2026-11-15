#!/usr/bin/env python3
"""Prove the Docker context excludes harmless runtime/credential sentinels."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
engine = sys.argv[1] if len(sys.argv) > 1 else "docker"
base = re.search(r"^FROM (?:--platform=\S+ )?(\S+)", (root / "Dockerfile").read_text(), re.M).group(1)
names = [".env.context-check", "runtime-context-check.db", "config.context-check.yaml",
         "internal/context-check.key", "cmd/context-check.pem", "pkg/context-check.db"]
created = []
try:
    for name in names:
        path = root / name
        with path.open("x") as f:
            f.write("harmless-build-context-sentinel\n")
        created.append(path)
    with tempfile.TemporaryDirectory(prefix="threat-bot-context-") as temp:
        probe = Path(temp) / "Dockerfile"
        checks = " && ".join(f"test ! -e /context/{name}" for name in [*names, ".git", ".superpowers", ".tools"])
        checks += " && test -s /context/internal/scraper/jetstream_zstd_dictionary.gz"
        checks += " && test -s /context/internal/scraper/jetstream_zstd_dictionary.LICENSE"
        probe.write_text(f"FROM {base}\nCOPY . /context/\nRUN test -s /context/go.mod && test -d /context/cmd/threat-bot && {checks}\n")
        subprocess.run([engine, "build", "--platform", "linux/amd64", "--no-cache", "-f", str(probe), str(root)], check=True)
finally:
    for path in created:
        path.unlink()
print("Container context excluded all runtime and credential sentinels")
