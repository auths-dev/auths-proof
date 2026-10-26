#!/usr/bin/env python3
"""Verify and run a pinned AP-071 Airtable bundle without checkout imports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCHEMA = "auths.ap071-airtable-installed-bundle/1"


def verify_bundle(expected_manifest_sha256: str) -> dict[str, dict[str, object]]:
    manifest = ROOT / "manifest.json"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 262_144:
        raise ValueError("bundle manifest is unavailable")
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise ValueError("bundle manifest differs from the independent pin")
    data = json.loads(raw)
    if (type(data) is not dict or set(data) != {"schema", "files"}
            or data["schema"] != SCHEMA or type(data["files"]) is not dict):
        raise ValueError("bundle manifest is invalid")
    expected = data["files"]
    actual = {}
    for base, directories, filenames in os.walk(ROOT, followlinks=False):
        folder = Path(base)
        directories[:] = [name for name in directories
                          if not (folder == ROOT and name == ".venv")]
        for name in directories + filenames:
            if (folder / name).is_symlink():
                raise ValueError("bundle contains a symlink")
        for name in filenames:
            path = folder / name
            relative = path.relative_to(ROOT).as_posix()
            if relative == "manifest.json":
                continue
            body = path.read_bytes()
            actual[relative] = {
                "sha256": hashlib.sha256(body).hexdigest(), "size": len(body),
            }
    if actual != expected:
        raise ValueError("bundle files differ from the pinned manifest")
    return expected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "cleanup"))
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    for flag in ("drop-ack", "fail-before-content", "exit-after-release-entry",
                 "exit-after-content-send",
                 "revoke-before-actions",
                 "upfront-second-write", "concurrent-upfront-writes",
                 "exit-after-write-reservation",
                 "macos-agent-sandbox"):
        parser.add_argument("--" + flag, action="store_true")
    args = parser.parse_args()
    if not args.env_file.is_absolute() or not args.root.is_absolute():
        parser.error("environment file and run root must use absolute paths")
    if len(args.manifest_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in args.manifest_sha256):
        parser.error("manifest SHA-256 must be lowercase hex")
    manifest = verify_bundle(args.manifest_sha256)
    wheelhouse = ROOT / "wheelhouse"
    wheels = [name for name in manifest if name.startswith("wheelhouse/")]
    distributions = {}
    for prefix in ("auths-", "auths_google_employee_delegation_broker-",
                   "auths_google_employee_read_agent-"):
        matches = [wheel for wheel in wheels
                   if Path(wheel).name.startswith(prefix)]
        if len(matches) != 1:
            raise ValueError(f"bundle requires one {prefix} wheel")
        distributions[prefix] = ROOT / matches[0]
    environment = ROOT / ".venv"
    venv.EnvBuilder(with_pip=True, clear=True).create(environment)
    python = environment / "bin/python"
    env = {"PATH": str(environment / "bin") + os.pathsep + os.environ.get("PATH", ""),
           "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
           "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1"}
    subprocess.run([str(python), "-m", "pip", "install", "--no-index",
                    "--disable-pip-version-check", "--no-input",
                    "--find-links", str(wheelhouse),
                    *map(str, distributions.values())], env=env, check=True)
    extra = ["--" + name.replace("_", "-") for name in (
        "drop_ack", "fail_before_content", "exit_after_release_entry",
        "exit_after_content_send",
        "revoke_before_actions",
        "upfront_second_write", "concurrent_upfront_writes",
        "exit_after_write_reservation",
        "macos_agent_sandbox",
    ) if getattr(args, name)]
    command = [str(python), str(ROOT / "read_reference/installed_conformance.py"),
               args.action, "--env-file", str(args.env_file), "--root", str(args.root),
               "--gateway-bin", str(ROOT / "bin/auths-gateway"), *extra]
    raise SystemExit(subprocess.run(command, env=env, check=False).returncode)


if __name__ == "__main__":
    main()
