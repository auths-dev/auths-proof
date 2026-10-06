#!/usr/bin/env python3
"""Package the native simulation harness selected from Cargo's artifact report."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    executables = []
    with args.build_report.open() as lines:
        for line in lines:
            if len(line) > 1_048_576:
                parser.error("oversized build report line")
            artifact = json.loads(line)
            if (artifact.get("reason") == "compiler-artifact"
                    and artifact.get("profile", {}).get("test") is True
                    and artifact.get("target", {}).get("kind") == ["lib"]
                    and artifact.get("executable")):
                executables.append(Path(artifact["executable"]))
    if len(executables) != 1 or not executables[0].is_file():
        parser.error("build report must select exactly one native test harness")
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("candidate kit directory must be empty")
    args.out.mkdir(parents=True, exist_ok=True)
    executable = args.out / "qualification-harness"
    shutil.copyfile(executables[0], executable)
    executable.chmod(0o755)
    with executable.open("rb") as stream:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(131_072), b""):
            hasher.update(chunk)
        digest = hasher.hexdigest()
    repository = Path(__file__).resolve().parents[2]
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repository):
        parser.error("candidate kit requires committed source")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
    (args.out / "candidate.json").write_text(json.dumps({
        "schema": "auths.qualification-simulation-candidate/1", "simulation": True,
        "source_commit": commit, "harness_sha256": digest,
        "features": ["loopback-provider"], "production_gateway": False,
    }, indent=2) + "\n")
    shutil.copyfile(repository / "qualification/simulation/run.py", args.out / "run.py")


if __name__ == "__main__":
    main()
