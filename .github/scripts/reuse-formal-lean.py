#!/usr/bin/env python3
"""Bounded same-repository/same-PR clean Lean evidence discovery.

A miss is an optimization miss: the workflow must execute the existing fresh
Lean gate. This script never accepts cached build outputs as proof evidence.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
from urllib.parse import urlencode

LIMIT = 1_048_576
WORKFLOW = ".github/workflows/ci.yml"
JOB = "formal Lean authoritative"


def positive(value):
    return type(value) is int and value > 0


def hexadecimal(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def decode_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def gh(path, archive=False):
    result = subprocess.run(["gh", "api", path], check=True, capture_output=True, timeout=60)
    if len(result.stdout) > (LIMIT if archive else 8 * LIMIT):
        raise ValueError("GitHub response exceeds finite bound")
    return result.stdout if archive else decode_json(result.stdout)


def trusted_run(run, current, number):
    repo = current["repository"]
    return (
        positive(run["id"])
        and run["id"] != current["id"]
        and positive(run["run_attempt"])
        and run["workflow_id"] == current["workflow_id"]
        and run["path"] == WORKFLOW
        and run["event"] == "pull_request"
        and run["repository"]["id"] == repo["id"]
        and run["repository"]["full_name"] == repo["full_name"]
        and run["head_repository"]["id"] == repo["id"]
        and run["head_repository"]["full_name"] == repo["full_name"]
        and run["head_branch"] == current["head_branch"]
        and hexadecimal(run["head_sha"], 40)
        # GitHub keeps this PR association but updates its head snapshot.
        # Historical source identity comes from the run/job/artifact/phase.
        and any(
            pr["number"] == number
            and pr["base"]["repo"]["id"] == repo["id"]
            and pr["head"]["repo"]["id"] == repo["id"]
            for pr in run["pull_requests"]
        )
    )


def read_phase(archive, artifact, run, attempt, environment):
    digest = artifact.get("digest", "")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("artifact has no authenticated SHA-256 metadata")
    if not hexadecimal(digest[7:], 64) or hashlib.sha256(archive).hexdigest() != digest[7:]:
        raise ValueError("artifact archive digest mismatch")
    if len(archive) > LIMIT:
        raise ValueError("archive exceeds bound")
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        entries = zipped.infolist()
        if len(entries) != 1 or entries[0].filename != "lean.json":
            raise ValueError("unexpected artifact inventory")
        if not 0 < entries[0].file_size <= LIMIT or entries[0].flag_bits & 1:
            raise ValueError("invalid phase member")
        raw = zipped.read(entries[0])
    phase = decode_json(raw)
    if not isinstance(phase, dict):
        raise ValueError("phase must be an object")
    expected = {
        "schema": "auths-proof-formal-phase-result/v1",
        "phase": "lean",
        "head_sha": run["head_sha"],
        "run_id": str(run["id"]),
        "run_attempt": str(attempt),
        "execution": "executed-clean",
        "reproduction_count": 0,
        "planned_closure_sha256": environment["AUTHS_FORMAL_PHASE_CLOSURE_SHA256"],
        "toolchain_closure_sha256": environment["AUTHS_FORMAL_TOOLCHAIN_CLOSURE_SHA256"],
        "evidence_closure_sha256": environment["AUTHS_FORMAL_EVIDENCE_CLOSURE_SHA256"],
    }
    if any(phase.get(key) != value for key, value in expected.items()):
        raise ValueError("phase does not match the successful producer/current closures")
    if phase.get("reused_from") is not None:
        raise ValueError("reuse chains are ineligible")
    for key in ["proof_inputs_sha256", "source_closure_sha256", "toolchain_lock_sha256"]:
        if not hexadecimal(phase.get(key), 64):
            raise ValueError("complete proof input attestation is absent or malformed")
    return raw


def verify_current(raw, producer, environment, directory):
    directory.mkdir(parents=True, exist_ok=True)
    phase = directory / "lean.json"
    phase.write_bytes(raw)
    env = dict(environment)
    env.update(producer)
    env["AUTHS_REUSED_LEAN_PHASE_RESULT"] = str(phase.resolve())
    return subprocess.run(
        ["cargo", "xtask", "ci", "formal-lean-reuse"], env=env, timeout=1800
    ).returncode == 0


def discover(environment, api=gh, verify=verify_current):
    repo = environment["GITHUB_REPOSITORY"]
    current_id = int(environment["GITHUB_RUN_ID"])
    number = int(environment["AUTHS_PR_NUMBER"])
    current = api(f"repos/{repo}/actions/runs/{current_id}")
    if (
        current["id"] != current_id
        or not positive(current["workflow_id"])
        or current["event"] != "pull_request"
        or current["path"] != WORKFLOW
        or current["repository"]["full_name"] != repo
        or current["head_repository"]["id"] != current["repository"]["id"]
        or not any(pr["number"] == number for pr in current["pull_requests"])
    ):
        return False
    query = urlencode({"branch": current["head_branch"], "event": "pull_request", "per_page": 50})
    runs = api(f"repos/{repo}/actions/workflows/{current['workflow_id']}/runs?{query}")["workflow_runs"]
    for run in runs[:10]:
        try:
            if not trusted_run(run, current, number):
                continue
            artifacts = api(f"repos/{repo}/actions/runs/{run['id']}/artifacts?per_page=100")["artifacts"]
            prefix = f"auths-formal-phase-lean-{run['id']}-"
            for artifact in artifacts[:100]:
                if not positive(artifact.get("id")) or artifact.get("expired") is not False:
                    continue
                if not positive(artifact.get("size_in_bytes")) or artifact["size_in_bytes"] > LIMIT:
                    continue
                name = artifact.get("name", "")
                if not isinstance(name, str) or not name.startswith(prefix):
                    continue
                suffix = name[len(prefix):]
                if not re.fullmatch(r"[1-9][0-9]*", suffix):
                    continue
                attempt = int(suffix)
                if attempt > run["run_attempt"]:
                    continue
                provenance = artifact["workflow_run"]
                if provenance["id"] != run["id"] or provenance["head_sha"] != run["head_sha"]:
                    continue
                if provenance["repository_id"] != current["repository"]["id"] or provenance["head_repository_id"] != current["repository"]["id"]:
                    continue
                jobs = api(f"repos/{repo}/actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100")["jobs"]
                successes = [job for job in jobs if job["name"] == JOB and job["status"] == "completed" and job["conclusion"] == "success" and job["head_sha"] == run["head_sha"] and positive(job["id"])]
                if len(successes) != 1:
                    continue
                raw = read_phase(api(f"repos/{repo}/actions/artifacts/{artifact['id']}/zip", archive=True), artifact, run, attempt, environment)
                producer = {
                    "AUTHS_REUSED_RUN_ID": str(run["id"]),
                    "AUTHS_REUSED_RUN_ATTEMPT": str(attempt),
                    "AUTHS_REUSED_HEAD_SHA": run["head_sha"],
                    "AUTHS_REUSED_JOB_ID": str(successes[0]["id"]),
                    "AUTHS_REUSED_ARTIFACT_ID": str(artifact["id"]),
                    "AUTHS_REUSED_ARTIFACT_SHA256": artifact["digest"][7:],
                }
                if verify(raw, producer, environment, Path("target/reused-formal/lean")):
                    print(f"Reused successful clean Lean run {run['id']} attempt {attempt}, job {successes[0]['id']}, artifact {artifact['id']}, head {run['head_sha']}")
                    return True
        except (KeyError, TypeError, ValueError, OSError, RuntimeError, subprocess.SubprocessError, zipfile.BadZipFile):
            continue
    return False


def main():
    reused = False
    try:
        reused = discover(os.environ)
    except (KeyError, TypeError, ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        print("No validated same-PR Lean producer available; fresh verification is required.")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"reused={'true' if reused else 'false'}\n")
    if not reused:
        print("Lean reuse miss: the existing fresh build and all qualification gates remain required.")


if __name__ == "__main__":
    main()
