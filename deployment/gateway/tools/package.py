#!/usr/bin/env python3
"""Make the operator handoff from built binaries and public deployment files."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.commit) != 40 or any(c not in "0123456789abcdef" for c in args.commit):
        parser.error("commit must be a full lowercase SHA")
    root = Path(__file__).resolve().parents[3]
    files = {
        "bin/auths-gateway": (args.gateway.read_bytes(), 0o755),
        "bin/auths-qualification": (args.qualification.read_bytes(), 0o755),
        "bin/run-with-postgres-url": ((root / "deployment/gateway/run-with-postgres-url").read_bytes(), 0o755),
        "docs/GATEWAY_PRODUCTION_RUNBOOK.md": ((root / "docs/operations/GATEWAY_PRODUCTION_RUNBOOK.md").read_bytes(), 0o644),
    }
    reference = root / "deployment/gateway"
    for path in sorted(reference.rglob("*")):
        if path.is_file() and "tools" not in path.relative_to(reference).parts and path.name != "run-with-postgres-url":
            files["reference/" + path.relative_to(reference).as_posix()] = (path.read_bytes(), 0o644)
    manifest = {
        "schema": "auths.gateway-operator-package/1",
        "source_commit": args.commit,
        "qualification_claim": "none; verify exact signed inputs separately",
        "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest()} for name, (data, _) in sorted(files.items())],
    }
    files["manifest.json"] = ((json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o644)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as destination:
        with gzip.GzipFile(fileobj=destination, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, (data, mode) in sorted(files.items()):
                    info = tarfile.TarInfo("auths-gateway-operator/" + name)
                    info.size, info.mode, info.mtime = len(data), mode, 0
                    archive.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix + ".sha256").write_text(digest + "  " + args.output.name + "\n")
    print(json.dumps({"archive": args.output.name, "sha256": digest, "files": len(files)}))


if __name__ == "__main__":
    main()
