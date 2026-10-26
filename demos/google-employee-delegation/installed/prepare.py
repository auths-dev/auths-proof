#!/usr/bin/env python3
"""Verify and install a pinned Google task bundle without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


SCHEMA = "auths.ap071-google-installed-bundle/1"


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate bundle manifest key")
        result[key] = value
    return result


def _inventory(root: Path) -> dict:
    files = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("bundle contains a symlink")
        if path.is_file() and path != root / "manifest.json":
            data = path.read_bytes()
            files[path.relative_to(root).as_posix()] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
    return files


def verify_bundle(root: Path, expected_sha256: str) -> dict:
    if (root.is_symlink() or not root.is_dir()
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef"
                   for character in expected_sha256)):
        raise ValueError("bundle or manifest pin is invalid")
    raw = (root / "manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("bundle manifest digest changed")
    manifest = json.loads(raw, object_pairs_hook=_pairs)
    if (type(manifest) is not dict
            or set(manifest) != {"schema", "primary_wheels", "files"}
            or manifest["schema"] != SCHEMA
            or type(manifest["primary_wheels"]) is not list
            or len(manifest["primary_wheels"]) != 3
            or any(type(name) is not str or not name.endswith(".whl")
                   for name in manifest["primary_wheels"])
            or len(set(manifest["primary_wheels"])) != 3
            or type(manifest["files"]) is not dict
            or manifest["files"] != _inventory(root)):
        raise ValueError("bundle file inventory changed")
    for name in manifest["primary_wheels"]:
        if f"wheelhouse/{name}" not in manifest["files"]:
            raise ValueError("primary wheel is unavailable")
    for name in ("bin/auths-gateway", "bin/auths-google-employee-custody"):
        if name not in manifest["files"] or not (root / name).stat().st_mode & 0o111:
            raise ValueError("installed binary is unavailable")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    bundle = Path(__file__).resolve().parent
    manifest = verify_bundle(bundle, args.manifest_sha256)
    root = args.root.resolve()
    if root.exists() or not root.parent.is_dir():
        parser.error("installation root must be new under an existing directory")
    root.mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"PYTHONPATH", "PYTHONHOME"}
                   and not key.startswith("PIP_")}
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    try:
        subprocess.run([sys.executable, "-m", "venv", str(root / ".venv")],
                       env=environment, check=True)
        python = root / ".venv/bin/python"
        wheels = [str(bundle / "wheelhouse" / name)
                  for name in manifest["primary_wheels"]]
        subprocess.run([
            str(python), "-m", "pip", "install", "--no-index",
            "--no-cache-dir", "--no-input", "--only-binary", ":all:",
            "--find-links", str(bundle / "wheelhouse"), *wheels,
        ], cwd=root, env=environment, check=True,
            stdout=subprocess.DEVNULL)
        probe = (
            "from pathlib import Path; "
            "import auths._native as native; "
            "from employee_read_demo import google_populate_provider_v2_owner as owner; "
            "from employee_read_agent import cli as agent; "
            "root=Path(__import__('sys').argv[1]); "
            "assert all(Path(m.__file__).is_relative_to(root) "
            "for m in (native, owner, agent)); "
            "print('installed modules imported from isolated venv')"
        )
        subprocess.run([str(python), "-I", "-c", probe,
                        str(root / ".venv")],
                       cwd=root, env=environment, check=True)
        subprocess.run([str(bundle / "bin/auths-gateway"), "--help"],
                       cwd=root, env=environment, check=True,
                       stdout=subprocess.DEVNULL)
    except Exception:
        # Preserve the incomplete, private installation for diagnosis.
        raise
    print(json.dumps({
        "schema": "auths.ap071-google-installed-preparation/1",
        "manifest_sha256": args.manifest_sha256,
        "installation": str(root),
        "python": str(python),
        "gateway": str(bundle / "bin/auths-gateway"),
        "custody": str(bundle / "bin/auths-google-employee-custody"),
        "provider_effect": "not_attempted",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
