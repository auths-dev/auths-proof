#!/usr/bin/env python3
"""Build a source-free, hash-pinned AP-071 Airtable runner bundle.

The caller supplies built wheels and a gateway executable for this host. No
provider credential or live fixture is copied into the bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SUPPORT = (
    "airtable_resources.py", "airtable_record.py", "common.py", "resource_io.py",
    "fresh_evidence.py", "stripe_platform.py",
)
READ_FILES = (
    "installed_conformance.py", "lost_ack_agent.py", "airtable_custody.py", "recipe.json",
    "profile.lock.json",
)
WRITE_FILES = ("recipe.json", "profile.lock.json")


def _regular(path: Path, *, suffix: str | None = None) -> Path:
    if path.is_symlink() or not path.is_file() or (suffix and path.suffix != suffix):
        raise ValueError(f"bundle input is not a regular {suffix or 'file'}: {path}")
    return path


def _copy(source: Path, destination: Path) -> None:
    _regular(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _manifest(root: Path) -> bytes:
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("bundle contains a symlink")
        if path.is_file():
            data = path.read_bytes()
            files[path.relative_to(root).as_posix()] = {
                "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            }
    return (json.dumps({"schema": "auths.ap071-airtable-installed-bundle/1",
                        "files": files}, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--auths-wheel", type=Path, required=True)
    parser.add_argument("--broker-wheel", type=Path, required=True)
    parser.add_argument("--agent-wheel", type=Path, required=True)
    parser.add_argument("--dependency-wheelhouse", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.parent.is_dir():
        parser.error("output must be a new directory under an existing parent")
    wheels = [
        _regular(args.auths_wheel, suffix=".whl"),
        _regular(args.broker_wheel, suffix=".whl"),
        _regular(args.agent_wheel, suffix=".whl"),
    ]
    if (not args.dependency_wheelhouse.is_dir()
            or args.dependency_wheelhouse.is_symlink()):
        parser.error("dependency wheelhouse must be a directory")
    wheels.extend(sorted(args.dependency_wheelhouse.glob("*.whl")))
    if len({wheel.name for wheel in wheels}) != len(wheels):
        parser.error("wheel filenames must be unique")
    for wheel in wheels:
        _regular(wheel, suffix=".whl")
    gateway = _regular(args.gateway_bin)
    if gateway.stat().st_mode & 0o111 == 0:
        parser.error("gateway binary must be executable")

    output.mkdir(mode=0o700)
    try:
        _copy(gateway, output / "bin/auths-gateway")
        _copy(HERE / "run_installed_bundle.py", output / "run.py")
        for name in READ_FILES:
            _copy(HERE / name, output / "read_reference" / name)
        for name in WRITE_FILES:
            _copy(HERE.parent / "write_reference" / name,
                  output / "write_reference" / name)
        _copy(REPO / "demos/airtable-gateway/launch.py",
              output / "read_reference/launch.py")
        for name in SUPPORT:
            _copy(REPO / "qualification/reference" / name,
                  output / "read_reference" / name)
        for wheel in wheels:
            _copy(wheel, output / "wheelhouse" / wheel.name)
        manifest = _manifest(output)
        (output / "manifest.json").write_bytes(manifest)
    except Exception:
        shutil.rmtree(output)
        raise
    print(json.dumps({"bundle": str(output),
                      "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                      "wheel_count": len(wheels)}, sort_keys=True))


if __name__ == "__main__":
    main()
