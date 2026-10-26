#!/usr/bin/env python3
"""Package reviewed AP-071 Google artifacts without grants or checkout imports."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


HERE = Path(__file__).resolve().parent
DEMO = HERE.parent
REFERENCES = ("read_reference", "write_reference", "create_reference",
              "populate_reference")


def _regular(path: Path, suffix: str | None = None) -> Path:
    if (path.is_symlink() or not path.is_file()
            or suffix is not None and path.suffix != suffix):
        raise ValueError(f"bundle input is not a regular {suffix or 'file'}: {path}")
    return path


def _copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_regular(source), destination)


def _file_inventory(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("bundle contains a symlink")
        if path.is_file():
            data = path.read_bytes()
            result[path.relative_to(root).as_posix()] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--custody-bin", type=Path, required=True)
    parser.add_argument("--auths-wheel", type=Path, required=True)
    parser.add_argument("--broker-wheel", type=Path, required=True)
    parser.add_argument("--agent-wheel", type=Path, required=True)
    parser.add_argument("--dependency-wheelhouse", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.parent.is_dir():
        parser.error("output must be new under an existing directory")
    if (not args.dependency_wheelhouse.is_dir()
            or args.dependency_wheelhouse.is_symlink()):
        parser.error("dependency wheelhouse must be a regular directory")
    binaries = {
        "gateway": _regular(args.gateway_bin),
        "custody": _regular(args.custody_bin),
    }
    if any(path.stat().st_mode & 0o111 == 0 for path in binaries.values()):
        parser.error("gateway and custody binaries must be executable")
    primary = [
        _regular(args.auths_wheel, ".whl"),
        _regular(args.broker_wheel, ".whl"),
        _regular(args.agent_wheel, ".whl"),
    ]
    if len({wheel.name for wheel in primary}) != len(primary):
        parser.error("primary wheel filenames must differ")
    primary_names = {wheel.name for wheel in primary}
    dependencies = [
        _regular(wheel, ".whl")
        for wheel in sorted(args.dependency_wheelhouse.glob("*.whl"))
        if wheel.name not in primary_names
    ]
    wheels = primary + dependencies
    if len({wheel.name for wheel in wheels}) != len(wheels):
        parser.error("wheel filenames must be unique")
    output.mkdir(mode=0o700)
    try:
        for kind, binary in binaries.items():
            name = ("auths-gateway" if kind == "gateway"
                    else "auths-google-employee-custody")
            _copy(binary, output / "bin" / name)
        _copy(HERE / "prepare.py", output / "prepare.py")
        _copy(HERE / "README.md", output / "README.md")
        for reference in REFERENCES:
            for name in ("recipe.json", "profile.lock.json"):
                _copy(DEMO / reference / name,
                      output / reference / name)
        for wheel in wheels:
            _copy(wheel, output / "wheelhouse" / wheel.name)
        manifest = {
            "schema": "auths.ap071-google-installed-bundle/1",
            "primary_wheels": [wheel.name for wheel in primary],
            "files": _file_inventory(output),
        }
        raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":"))
               + "\n").encode()
        (output / "manifest.json").write_bytes(raw)
    except Exception:
        shutil.rmtree(output)
        raise
    print(json.dumps({
        "bundle": str(output),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "wheel_count": len(wheels),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
