#!/usr/bin/env python3
"""Collect upstream notices for the supported binary; --check never writes.

This inventories source license files, not SPDX classifications or legal grants.
The certificate evidence is reviewed separately when the pinned builder changes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LICENSE_NAME = re.compile(r"^(licen[cs]e|copying|notice|copyright|patents)(?:$|[._-])", re.I)
PRIMARY_LICENSE = re.compile(r"^(licen[cs]e|copying)(?:$|[._-])", re.I)
TARGET = {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOWORK": "off"}


def run_go(*args):
    return subprocess.check_output(["go", *args], cwd=ROOT, env={**os.environ, **TARGET}, text=True)


def json_stream(raw):
    decoder = json.JSONDecoder()
    cursor = 0
    while cursor < len(raw):
        if raw[cursor].isspace():
            cursor += 1
            continue
        item, cursor = decoder.raw_decode(raw, cursor)
        yield item


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_component(value):
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not value:
        raise ValueError(f"unsafe inventory path: {value!r}")
    return path


def collect_notices(source, destination, expected):
    files = sorted(p for p in source.iterdir() if p.is_file() and LICENSE_NAME.match(p.name))
    if not any(PRIMARY_LICENSE.match(p.name) and p.stat().st_size for p in files):
        raise ValueError(f"missing upstream license for {destination}; review before distribution")
    entries = []
    for source_file in files:
        relative = destination / source_file.name
        data = source_file.read_bytes()
        expected[relative] = data
        entries.append({"path": relative.as_posix(), "sha256": sha256(data), "bytes": len(data)})
    return entries


def certificate_evidence():
    evidence_path = ROOT / "LICENSES/runtime/certificates/provenance.json"
    evidence = json.loads(evidence_path.read_text())
    dockerfile = (ROOT / "Dockerfile").read_text()
    builder = re.search(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)\s+AS\s+builder$", dockerfile, re.M | re.I)
    if not builder or builder[1] != evidence["builder_image"]:
        raise ValueError("builder changed: inspect its certificate package and refresh runtime provenance")
    runtime = re.split(r"^FROM scratch\s*$", dockerfile, flags=re.M)
    if len(runtime) != 2:
        raise ValueError("runtime base changed: review the complete runtime license inventory")
    builder_copies = re.findall(r"^COPY --from=builder.*$", runtime[1], re.M)
    if builder_copies != evidence["builder_copy_instructions"]:
        raise ValueError("builder COPY scope changed: review runtime license inventory")
    for item in evidence["notice_files"]:
        path = ROOT / safe_component(item["path"])
        if sha256(path.read_bytes()) != item["sha256"]:
            raise ValueError(f"runtime notice changed: review {item['path']} and update provenance")


def inventory():
    env = json.loads(run_go("env", "-json", "GOROOT", "GOVERSION"))
    directive = re.search(r"^go (\S+)$", (ROOT / "go.mod").read_text(), re.M)
    if not directive or env["GOVERSION"] != "go" + directive[1]:
        raise ValueError("use the exact Go version pinned by go.mod to regenerate/check notices")
    packages = list(json_stream(run_go("list", "-mod=readonly", "-deps", "-json", "-tags", "timetzdata", "./cmd/threat-bot")))
    modules = {}
    for package in packages:
        module = package.get("Module")
        if not module or module.get("Main"):
            continue
        if module.get("Replace"):
            raise ValueError(f"module replacement requires explicit license/provenance review: {module['Path']}")
        if not module.get("Version") or not module.get("Dir") or not module.get("Sum"):
            raise ValueError(f"module lacks pinned source/checksum: {module['Path']}")
        modules[module["Path"]] = module
    expected = {}
    module_records = []
    for name, module in sorted(modules.items()):
        destination = Path("LICENSES/dependencies") / safe_component(name) / safe_component(module["Version"])
        module_records.append({
            "module": name,
            "version": module["Version"],
            "go_sum": module["Sum"],
            "files": collect_notices(Path(module["Dir"]), destination, expected),
        })
    expected[Path("LICENSES/dependencies/manifest.json")] = encoded({
        "schema_version": 1,
        "command": "go list -mod=readonly -deps -json -tags timetzdata ./cmd/threat-bot",
        "target": TARGET,
        "go_version": env["GOVERSION"],
        "scope": "Root upstream license/notice files for modules contributing packages to the Linux amd64 executable; no inferred SPDX classification.",
        "modules": module_records,
    })
    goroot = Path(env["GOROOT"])
    go_destination = Path("LICENSES/runtime/go") / safe_component(env["GOVERSION"])
    go_files = []
    for source in ("LICENSE", "PATENTS", "lib/time/README"):
        data = (goroot / source).read_bytes()
        relative = go_destination / source
        expected[relative] = data
        go_files.append({"path": relative.as_posix(), "sha256": sha256(data), "bytes": len(data)})
    vendor_versions = {}
    for line in (goroot / "src/vendor/modules.txt").read_text().splitlines():
        match = re.fullmatch(r"# (\S+) (v\S+)", line)
        if match:
            vendor_versions[match[1]] = match[2]
    used_vendor = set()
    for package in packages:
        name = package["ImportPath"]
        if not package.get("Standard") or not name.startswith("vendor/"):
            continue
        name = name.removeprefix("vendor/")
        matches = [module for module in vendor_versions if name == module or name.startswith(module + "/")]
        if not matches:
            raise ValueError(f"unrecognized standard-library vendored package: {name}")
        used_vendor.add(max(matches, key=len))
    vendor_records = []
    for module in sorted(used_vendor):
        version = vendor_versions[module]
        destination = go_destination / "vendor" / safe_component(module) / safe_component(version)
        vendor_records.append({"module": module, "version": version, "files": collect_notices(goroot / "src/vendor" / module, destination, expected)})
    expected[Path("LICENSES/runtime/go/manifest.json")] = encoded({
        "schema_version": 1,
        "go_version": env["GOVERSION"],
        "target": TARGET,
        "source": "https://go.dev/dl/#" + env["GOVERSION"],
        "scope": "Go standard-library notices, embedded IANA time-zone attribution, and standard-library vendored modules used by the target executable.",
        "files": go_files,
        "vendored_modules": vendor_records,
    })
    certificate_evidence()
    return expected, len(module_records), len(vendor_records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail on drift without writing files")
    args = parser.parse_args()
    expected, module_count, vendor_count = inventory()
    owned = (ROOT / "LICENSES/dependencies", ROOT / "LICENSES/runtime/go")
    existing = {p.relative_to(ROOT) for directory in owned if directory.exists() for p in directory.rglob("*") if p.is_file()}
    changed = sorted(p for p, data in expected.items() if not (ROOT / p).is_file() or (ROOT / p).read_bytes() != data)
    stale = sorted(existing - expected.keys())
    if args.check:
        if changed or stale:
            for path in changed:
                print(f"missing or changed: {path}", file=sys.stderr)
            for path in stale:
                print(f"unexpected: {path}", file=sys.stderr)
            raise ValueError("license inventory drift; review dependencies/toolchain then run make licenses")
        print(f"License inventory verified: {module_count} binary modules, Go standard library, {vendor_count} Go-vendored modules, and pinned certificate evidence")
    else:
        for path in stale:
            (ROOT / path).unlink()
        for path in changed:
            (ROOT / path).parent.mkdir(parents=True, exist_ok=True)
            (ROOT / path).write_bytes(expected[path])
        print(f"License inventory generated: {module_count} binary modules and {vendor_count} Go-vendored modules")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"license inventory: {error}", file=sys.stderr)
        sys.exit(1)
