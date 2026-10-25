"""Assemble a pinned AP-SPEC-070 kit from reviewed registry digests.

This tool does not publish images or assert that Google is configured. The
publishing workflow obtains digest references from the registry first.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path


REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
STATIC_FILES = (
    ("compose.yaml", "compose.yaml"),
    ("compose.live.yaml", "compose.live.yaml"),
    ("operator-kit.md", "README.md"),
    ("evidence/live-acceptance-template.md", "evidence/live-acceptance-template.md"),
    ("isolation/agent-relay.conf", "isolation/agent-relay.conf"),
    ("isolation/browser-relay.conf", "isolation/browser-relay.conf"),
    ("isolation/model-relay.conf", "isolation/model-relay.conf"),
)


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _image_ref(value: str, *, prefix: str, role: str) -> str:
    expected = f"{prefix}-{role}@"
    if not value.startswith(expected) or not DIGEST_RE.fullmatch(value[len(expected):]):
        raise ValueError(f"{role} image must be a registry digest reference under {prefix}")
    return value


def assemble(source: Path, wheel: Path, output: Path, *, revision: str,
             image_prefix: str, broker_image: str, agent_image: str) -> dict:
    if not REVISION_RE.fullmatch(revision):
        raise ValueError("revision must be a full lowercase commit SHA")
    if not re.fullmatch(r"ghcr\.io/[a-z0-9-]+/auths-proof-google-read", image_prefix):
        raise ValueError("unexpected image registry prefix")
    broker_image = _image_ref(broker_image, prefix=image_prefix, role="broker")
    agent_image = _image_ref(agent_image, prefix=image_prefix, role="agent")
    if wheel.is_symlink() or not wheel.is_file() or not zipfile.is_zipfile(wheel):
        raise ValueError("installed SDK wheel is unavailable")
    lock_path = source / "versions.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("schema_version") != "auths.google-read-demo-lock/v1":
        raise ValueError("unsupported operator lock schema")
    if any(lock.get(key) is not None for key in (
            "installed_sdk_artifact", "broker_image_digest", "agent_image_digest")):
        raise ValueError("source lock must be an unpublished candidate")
    if not re.fullmatch(rf"auths-{re.escape(lock['auths_python'])}-[^/]+\.whl", wheel.name):
        raise ValueError("wheel version does not match the source lock")
    if output.exists():
        raise FileExistsError("release output already exists")

    output.mkdir(parents=True)
    for origin, destination in STATIC_FILES:
        source_file = source / origin
        if source_file.is_symlink() or not source_file.is_file():
            raise ValueError(f"missing or linked kit input: {origin}")
        target = output / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, target)
    sdk_target = output / "artifacts" / wheel.name
    sdk_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(wheel, sdk_target)
    lock["installed_sdk_artifact"] = {
        "filename": wheel.name,
        "sha256": _digest(sdk_target),
        "revision": revision,
        "platform": "linux/amd64",
    }
    lock["broker_image_digest"] = broker_image
    lock["agent_image_digest"] = agent_image
    (output / "versions.lock.json").write_text(
        json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (output / "REVISION").write_text(revision + "\n", encoding="ascii")
    files = sorted(path for path in output.rglob("*") if path.is_file())
    (output / "SHA256SUMS").write_text("".join(
        f"{_digest(path)}  {path.relative_to(output).as_posix()}\n" for path in files
    ), encoding="ascii")
    return lock


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--image-prefix", required=True)
    parser.add_argument("--broker-image", required=True)
    parser.add_argument("--agent-image", required=True)
    args = parser.parse_args()
    lock = assemble(args.source, args.wheel, args.output,
                    revision=args.revision, image_prefix=args.image_prefix,
                    broker_image=args.broker_image, agent_image=args.agent_image)
    print(json.dumps({"revision": args.revision,
                      "wheel_sha256": lock["installed_sdk_artifact"]["sha256"],
                      "broker_image": lock["broker_image_digest"],
                      "agent_image": lock["agent_image_digest"]}, sort_keys=True))


if __name__ == "__main__":
    main()
