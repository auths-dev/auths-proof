#!/usr/bin/env python3
"""Cut over private Google pins to the generic AP-071 custody process bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path


def private_input(path: Path, maximum: int) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("pins path must be absolute and regular")
    metadata = path.stat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_size > maximum):
        raise ValueError("pins file must be owner-private and bounded")
    return path.read_bytes()


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="source", type=Path, required=True)
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.sidecar.is_absolute() or args.sidecar.is_symlink():
        parser.error("sidecar must be an absolute regular executable")
    executable = args.sidecar.stat()
    if (not stat.S_ISREG(executable.st_mode) or executable.st_mode & 0o111 == 0
            or executable.st_mode & 0o022 or executable.st_size > 32 * 1024 * 1024):
        parser.error("sidecar has unsafe executable permissions")
    original = private_input(args.source, 16_384)
    bundle = json.loads(original)
    entries = bundle.get("materializers") if isinstance(bundle, dict) else None
    if (not isinstance(bundle, dict) or set(bundle) != {"schema", "materializers"}
            or bundle["schema"] != "auths.gateway-task-materializers/1"
            or not isinstance(entries, list) or not 1 <= len(entries) <= 4
            or any(not isinstance(entry, dict) for entry in entries)):
        parser.error("expected a closed legacy Google installation bundle")
    if not args.out_dir.is_absolute():
        parser.error("output directory must be absolute")
    args.out_dir.mkdir(mode=0o700)
    pin = hashlib.sha256(args.sidecar.read_bytes()).hexdigest()
    converted = []
    for index, entry in enumerate(entries):
        provider_pins = args.out_dir / f"google-{index}.json"
        body = canonical(entry)
        write_private(provider_pins, body)
        result = subprocess.run(
            [str(args.sidecar), "--describe", "--pins", str(provider_pins)],
            capture_output=True, timeout=10, check=False, env={},
        )
        if result.returncode or len(result.stdout) > 1024:
            raise ValueError("Google sidecar refused provider pins")
        descriptor = json.loads(result.stdout)
        if (set(descriptor) != {"schema", "connection_id", "authority_digest"}
                or descriptor["schema"] != "auths.custody-process-descriptor/1"
                or descriptor["connection_id"] != entry.get("connection_id")):
            raise ValueError("Google sidecar descriptor changed")
        converted.append({
            "schema": "auths.custody-process/1",
            "connection_id": descriptor["connection_id"],
            "executable": str(args.sidecar),
            "executable_sha256": pin,
            "provider_pins": str(provider_pins),
            "provider_pins_sha256": hashlib.sha256(body).hexdigest(),
            "authority_digest": descriptor["authority_digest"],
        })
    converted.sort(key=lambda value: value["connection_id"])
    if len({item["connection_id"] for item in converted}) != len(converted):
        raise ValueError("duplicate Google connection")
    output = args.out_dir / "task-materializers.json"
    write_private(output, canonical({
        "schema": "auths.gateway-task-materializers/2",
        "materializers": converted,
    }))
    print(json.dumps({"outcome": "custody-installation-prepared",
                      "count": len(converted), "bundle": str(output)}, sort_keys=True))


if __name__ == "__main__":
    main()
