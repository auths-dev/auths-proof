#!/usr/bin/env python3
"""Run native qualification rehearsals; publish public simulation artifacts only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

REPORTS = (
    "stripe-refund-v1.json",
    "airtable-record-update-v1.json",
    "bootstrap/simulation.json",
    "provider-signature-verification.json",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--candidate-kit", type=Path,
                        help="run the downloaded native harness without a checkout or Rust")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    repository = None if args.candidate_kit else Path(__file__).resolve().parents[2]
    output = args.out.resolve()
    # Public rehearsal outputs must never enter the production trust or family
    # directories that the protected signing workflow consumes.
    if repository is not None and (output == repository or any(
        output.is_relative_to(repository / "qualification" / name)
        for name in ("trust", "families")
    )):
        parser.error("simulation output overlaps production inputs")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("use a new empty simulation output directory")
    if args.candidate_kit:
        kit = args.candidate_kit.resolve()
        metadata_file = kit / "candidate.json"
        if metadata_file.is_symlink() or metadata_file.stat().st_size > 4096:
            parser.error("invalid candidate metadata")
        metadata = json.loads(metadata_file.read_bytes())
        source_commit = metadata.get("source_commit")
        if (metadata.get("schema") != "auths.qualification-simulation-candidate/1"
                or metadata.get("simulation") is not True
                or metadata.get("production_gateway") is not False
                or metadata.get("features") != ["loopback-provider"]
                or not isinstance(source_commit, str)
                or not re.fullmatch(r"[0-9a-f]{40}", source_commit)):
            parser.error("invalid simulation candidate")
        harness = kit / "qualification-harness"
        if harness.is_symlink() or not harness.is_file() or harness.stat().st_size > 536_870_912:
            parser.error("invalid native harness")
        with harness.open("rb") as stream:
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(131_072), b""):
                digest.update(chunk)
            harness_sha256 = digest.hexdigest()
        if harness_sha256 != metadata.get("harness_sha256"):
            parser.error("candidate harness digest mismatch")
        source_dirty = False
        command = [str(harness), "qualification_simulation", "--nocapture"]
        verification = [str(harness), "qualification_tests::verify_simulation_reports", "--exact", "--nocapture"]
        working_directory = output
    else:
        source_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        source_dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=repository
        ))
        harness_sha256 = None
        command = [args.cargo, "test", "--locked", "-p", "auths-gateway",
            "--features", "loopback-provider", "--lib", "qualification_simulation", "--", "--nocapture"]
        verification = command[:command.index("qualification_simulation")] + [
            "qualification_tests::verify_simulation_reports", "--", "--exact", "--nocapture"]
        working_directory = repository
    # Provider and signing credentials are not needed and do not reach tests.
    environment = {
        key: value for key, value in os.environ.items()
        if key in {"PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR", "TMPDIR"}
    }
    environment["AUTHS_QUALIFICATION_SIMULATION_OUTPUT"] = str(output)
    started = time.monotonic()
    with tempfile.TemporaryFile() as log:
        for stage in (command, verification):
            result = subprocess.run(stage, cwd=working_directory, env=environment, stdout=log, stderr=subprocess.STDOUT,
                timeout=1800, check=False)
            if result.returncode:
                log.seek(0, os.SEEK_END)
                log.seek(max(0, log.tell() - 8192))
                raise SystemExit(log.read().decode("utf-8", errors="replace"))
    summaries = []
    for name in REPORTS:
        path = output / name
        if path.is_symlink() or path.stat().st_size > 1_048_576:
            raise SystemExit("invalid simulation report")
        report = json.loads(path.read_bytes())
        if report.get("simulation") is not True or report.get("stable_launch_ready") is not False:
            raise SystemExit("a rehearsal cannot publish production readiness")
        summaries.append(report)
    # The bootstrap artifacts are synthetic trust-machine fixtures. Their
    # own signed records explicitly exclude every provider-run claim.
    for path in sorted((output / "bootstrap").glob("record-*.json")):
        record = json.loads(path.read_bytes())
        if record["excluded_claims"] != ["everything: this record stands for no run"]:
            raise SystemExit("bootstrap fixture scope changed")
    # The second native stage re-reads and cryptographically verifies these
    # exact files after both family runs complete. They are detached simulation
    # signatures, with no production root or protected-run authority.
    for family in ("stripe-refund-v1", "airtable-record-update-v1"):
        signature = output / f"{family}.attestation.json"
        if signature.is_symlink() or signature.stat().st_size > 4096:
            raise SystemExit("invalid simulation signature")
    public_members = []
    for path in sorted(output.rglob("*.json")):
        if path.is_symlink() or path.stat().st_size > 1_048_576:
            raise SystemExit("invalid public artifact")
        public_members.append({"path": str(path.relative_to(output)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = {
        "schema": "auths.qualification-simulation-run/1",
        "simulation": True, "stable_launch_ready": False,
        "source_commit": source_commit, "source_dirty": source_dirty,
        "harness_sha256": harness_sha256,
        "source_free": bool(args.candidate_kit),
        "seconds": round(time.monotonic() - started, 3),
        "families": [summary.get("family") for summary in summaries[:2]],
        "provider_case_count": sum(len(summary["cases"]) for summary in summaries[:2]),
        "public_artifacts": public_members,
        "provider_reports": "detached simulation signatures verified from published bytes",
        "keys": "generated in memory and zeroized; no private key files",
        "excluded_claims": ["protected live evidence", "production qualification", "human acceptance"],
    }
    (output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"simulation": True, "provider_cases": manifest["provider_case_count"],
        "families": manifest["families"], "seconds": manifest["seconds"], "out": str(output)}))


if __name__ == "__main__":
    main()
