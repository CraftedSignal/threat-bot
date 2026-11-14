#!/usr/bin/env python3
"""Check local Markdown links in the public documentation without network access."""
from pathlib import Path
import re
import hashlib
import json
import sys
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[2]
files = sorted(root.glob("*.md")) + sorted((root / "docs").rglob("*.md"))
failures = []
for source in files:
    text = re.sub(r"```.*?```", "", source.read_text(), flags=re.S)
    for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", text):
        target = match.group(1).split(' "', 1)[0].strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        path = (root / unquote(parsed.path.lstrip("/"))) if parsed.path.startswith("/") else source.parent / unquote(parsed.path)
        if not path.exists():
            failures.append(f"{source.relative_to(root)}: missing local link {target}")
# Preserve original import hashes while checking intentional local adaptations.
package_provenance = json.loads((root / "pkg/provenance.json").read_text())
for entry in package_provenance["files"]:
    path = root / entry["destination"]
    expected = entry.get("adapted_sha256", entry["imported_sha256"])
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        failures.append(f"{path.relative_to(root)}: package provenance hash mismatch")
for entry in package_provenance.get("local_files", []):
    path = root / entry["path"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        failures.append(f"{path.relative_to(root)}: local package provenance hash mismatch")
# Verify the synthetic dataset's exact transformation hashes.
dataset = root / "internal/eval/testdata"
for name, expected in json.loads((dataset / "provenance.json").read_text())["files"].items():
    data = (dataset / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected["sha256"] or len(data) != expected["bytes"]:
        failures.append(f"{name}: dataset provenance hash or size mismatch")
for path in sorted((root / "examples").glob("*.json")) + sorted((root / "docs/examples").glob("*.json")):
    try:
        json.loads(path.read_text())
    except ValueError as error:
        failures.append(f"{path.relative_to(root)}: invalid JSON: {error}")
if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print(f"Checked local links in {len(files)} Markdown files")
