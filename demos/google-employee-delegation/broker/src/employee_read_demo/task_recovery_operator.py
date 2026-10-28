"""Sign one joined, response-less create candidate for human recovery review.

This module runs in the private operator process. The gateway supplies the
original unknown-attempt facts; Jules's search and demo_co's blank-candidate
artifact provide independent read-only observations. The signed report is
evidence only. It neither signs as Jules nor binds a child in the gateway.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .timestamps import parse_aware_timestamp
from .demo_co_contract import ContractRejected, _unique_pairs
from .google_create_handoff import CHILD_TITLE
from .google_create_preflight import _canonical_json
from .google_create_v3_handoff import (
    CreateV3BaselinePins, CreateV3CandidateBlankPins, CreateV3NeighborPins,
    validate_create_v3_recovery_handoff,
)
from .google_create_v4_handoff import (
    CreateV4BaselinePins, CreateV4CandidateBlankPins, CreateV4NeighborPins,
    validate_create_v4_recovery_handoff,
)
from .operator_authority import OperatorDenied
from .operator_cli import _private_read, _private_write
from .task_populate_operator import _gateway, _run_gateway
from .task_write_card import _installation


SCHEMA = "auths.gateway-task-create-recovery-attestation/1"
DOMAIN = b"auths.gateway-task-create-recovery-attestation/1\0"
INPUT_SCHEMA = "auths.gateway-task-create-recovery-inputs/1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_INPUT_FIELDS = {
    "schema", "task_id", "task_commitment", "plan_commitment",
    "content_commitment", "create_operation_id", "create_recipe_digest",
    "action_commitment", "request_commitment", "populate_recipe_digest",
    "connection_id", "connection_generation", "connection_subject",
    "recovery_rule_digest", "recovery_key_sha256", "parent_id", "title",
    "marker", "plan_expires_at", "attempt_stage", "authority",
}
_RULE_MODULES = (
    "task_recovery_operator.py", "task_create_operator.py",
    "task_populate_operator.py", "task_write_card.py", "operator_cli.py",
    "google_create_preflight.py", "google_create_handoff.py",
    "google_create_v3_handoff.py", "google_create_v4_handoff.py",
    "demo_co_contract.py",
)


def current_recovery_attestation_rule_digest() -> str:
    """Commit the reviewed operator join and source validators, not semantics."""
    digest = hashlib.sha256(b"auths.ap071-google-create-recovery-rule/1\0")
    for name in _RULE_MODULES:
        source = Path(__file__).with_name(name).read_bytes()
        if len(source) > 1_048_576:
            raise ContractRejected("recovery rule source exceeds review bounds")
        digest.update(name.encode("ascii") + b"\0")
        digest.update(hashlib.sha256(source).digest())
    return digest.hexdigest()


def attest_response_less_candidate(
    inputs: dict, baseline_path: Path, candidate_path: Path,
    search_report_path: Path,
    pins: CreateV3CandidateBlankPins | CreateV4CandidateBlankPins,
    *, search_report_sha256: str, signing_key: Ed25519PrivateKey,
    now: int,
) -> bytes:
    """Return one canonical signed report after exact, independent join.

    The caller must obtain ``inputs`` from the installed gateway's private
    ``task-create-recovery-inputs`` command. It may save this result to an
    owner-private file for a later human-reviewed gateway action.
    """
    if (type(inputs) is not dict or set(inputs) != _INPUT_FIELDS
            or inputs.get("schema") != INPUT_SCHEMA
            or inputs.get("attempt_stage") != "unknown"
            or inputs.get("authority") != "none"
            or type(now) is not int
            or type(inputs.get("connection_generation")) is not int
            or inputs["connection_generation"] < 1
            or type(inputs.get("plan_expires_at")) is not int
            or inputs["plan_expires_at"] <= now
            or any(type(inputs.get(name)) is not str
                   or _DIGEST.fullmatch(inputs[name]) is None
                   for name in (
                       "task_commitment", "plan_commitment", "content_commitment",
                       "create_recipe_digest", "action_commitment",
                       "request_commitment", "populate_recipe_digest",
                       "recovery_rule_digest", "recovery_key_sha256",
                   ))
            or any(type(inputs.get(name)) is not str
                   or _ID.fullmatch(inputs[name]) is None
                   for name in ("task_id", "create_operation_id"))
            or type(search_report_sha256) is not str
            or _DIGEST.fullmatch(search_report_sha256) is None
            or not isinstance(signing_key, Ed25519PrivateKey)):
        raise ContractRejected("gateway recovery inputs are unavailable")
    pins.validate()
    public = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if (hashlib.sha256(public).hexdigest() != inputs["recovery_key_sha256"]
            or current_recovery_attestation_rule_digest()
                != inputs["recovery_rule_digest"]
            or inputs["connection_subject"] != pins.baseline.jules_subject
            or inputs["parent_id"] != pins.baseline.folder_id
            or inputs["title"] != CHILD_TITLE
            or inputs["marker"] != pins.marker
            or pins.candidate_id in {
                item.document_id for item in pins.baseline.neighbors
            }):
        raise ContractRejected("recovery signer differs from installed task pins")
    validate_handoff = (
        validate_create_v4_recovery_handoff
        if isinstance(pins, CreateV4CandidateBlankPins)
        else validate_create_v3_recovery_handoff
    )
    candidate = validate_handoff(
        baseline_path, candidate_path, search_report_path, pins,
        task_id=inputs["task_id"],
        create_operation_id=inputs["create_operation_id"],
        connection_id=inputs["connection_id"],
        connection_generation=inputs["connection_generation"],
        search_report_sha256=search_report_sha256,
    )
    try:
        search = json.loads(_private_read(search_report_path, 8192),
                            object_pairs_hook=_unique_pairs)["result"]
        observed_at = parse_aware_timestamp(candidate["observed_at"])
    except (OSError, PermissionError, KeyError, UnicodeDecodeError,
            TypeError, ValueError) as error:
        raise ContractRejected("joined recovery observations are unavailable") from error
    if (type(search["checked_at"]) is not int
            or not search["checked_at"] <= now <= search["checked_at"] + 300
            or observed_at.tzinfo is None
            or not int(observed_at.timestamp()) <= now
                    <= int(observed_at.timestamp()) + 300):
        raise ContractRejected("recovery observations are stale or future-dated")
    valid_until = min(
        now + 180, search["checked_at"] + 300,
        int(observed_at.timestamp()) + 300,
        inputs["plan_expires_at"],
    )
    if valid_until <= now:
        raise ContractRejected("recovery attestation cannot outlive the plan")
    statement = {
        "schema": SCHEMA,
        "task_id": inputs["task_id"],
        "task_commitment": inputs["task_commitment"],
        "plan_commitment": inputs["plan_commitment"],
        "content_commitment": inputs["content_commitment"],
        "create_operation_id": inputs["create_operation_id"],
        "create_recipe_digest": inputs["create_recipe_digest"],
        "action_commitment": inputs["action_commitment"],
        "request_commitment": inputs["request_commitment"],
        "candidate_id": pins.candidate_id,
        "parent_id": inputs["parent_id"],
        "title": inputs["title"],
        "marker": inputs["marker"],
        "connection_id": inputs["connection_id"],
        "connection_generation": inputs["connection_generation"],
        "connection_subject": inputs["connection_subject"],
        "recovery_rule_digest": inputs["recovery_rule_digest"],
        "search_report_sha256": search_report_sha256,
        "producer_observation_sha256": pins.observation_sha256,
        "baseline_sha256": pins.baseline.baseline_sha256,
        "candidate_metadata_sha256": search["metadata_sha256"],
        "checked_at": now,
        "valid_until": valid_until,
    }
    signature = signing_key.sign(DOMAIN + _canonical_json(statement))
    return _canonical_json({
        "statement": statement,
        "signature_b64": base64.b64encode(signature).decode("ascii").rstrip("="),
    })


def _candidate_pins(path: Path) -> (
        CreateV3CandidateBlankPins | CreateV4CandidateBlankPins):
    try:
        value = json.loads(_private_read(path, 16_384),
                           object_pairs_hook=_unique_pairs)
        if type(value) is not dict or set(value) != {
                "baseline", "observation_generation", "observation_sha256",
                "candidate_id", "marker"}:
            raise ValueError("candidate pin fields")
        baseline = value.pop("baseline")
        if type(baseline) is not dict or type(baseline.get("neighbors")) is not list:
            raise ValueError("baseline pins")
        if "source_v3_final_sha256" in baseline:
            baseline["neighbors"] = tuple(
                CreateV4NeighborPins(**item) for item in baseline["neighbors"]
            )
            baseline["prior_markers"] = tuple(baseline["prior_markers"])
            pins = CreateV4CandidateBlankPins(
                baseline=CreateV4BaselinePins(**baseline), **value,
            )
        else:
            baseline["neighbors"] = tuple(
                CreateV3NeighborPins(**item) for item in baseline["neighbors"]
            )
            pins = CreateV3CandidateBlankPins(
                baseline=CreateV3BaselinePins(**baseline), **value,
            )
        pins.validate()
        return pins
    except (OSError, PermissionError, TypeError, ValueError, KeyError,
            ContractRejected) as error:
        raise OperatorDenied("private candidate pins are unavailable") from error


def prepare_recovery_attestation(
    *, gateway_binary: Path, gateway_sha256: str,
    gateway_state_dir: Path, installation_path: Path,
    signing_seed_path: Path, baseline_path: Path,
    candidate_path: Path, search_report_path: Path,
    candidate_pins_path: Path, search_report_sha256: str,
    task_id: str, report_out: Path, now: int | None = None,
) -> dict:
    """Sign a private evidence report from gateway and two checked sources.

    This command deliberately stops before a human action or a gateway child
    binding. It cannot call create or populate.
    """
    if (type(task_id) is not str or _ID.fullmatch(task_id) is None
            or any(not path.is_absolute() for path in (
                gateway_state_dir, installation_path, signing_seed_path,
                baseline_path, candidate_path, search_report_path,
                candidate_pins_path, report_out,
            ))
            or report_out.exists() or report_out.is_symlink()
            or not report_out.parent.is_dir() or report_out.parent.is_symlink()
            or stat.S_IMODE(report_out.parent.stat().st_mode) & 0o077):
        raise OperatorDenied("private recovery attestation paths are unavailable")
    binary = _gateway(gateway_binary, gateway_sha256)
    installation = _installation(installation_path)
    pin = installation.get("recovery_attestation")
    if type(pin) is not dict:
        raise OperatorDenied("recovery attestation signer is not installed")
    try:
        seed = _private_read(signing_seed_path, 32)
        if len(seed) != 32:
            raise ValueError("seed length")
        signer = Ed25519PrivateKey.from_private_bytes(seed)
        public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        inputs = json.loads(_run_gateway(binary, [
            "task-create-recovery-inputs", "--state-dir",
            str(gateway_state_dir), "--task-id", task_id,
        ], limit=8192), object_pairs_hook=_unique_pairs)
        pins = _candidate_pins(candidate_pins_path)
    except (OSError, PermissionError, TypeError, ValueError,
            OperatorDenied) as error:
        raise OperatorDenied("private recovery inputs are unavailable") from error
    if (public.hex() != pin["public_key_hex"]
            or pin["rule_digest"] != current_recovery_attestation_rule_digest()
            or type(inputs) is not dict
            or inputs.get("recovery_key_sha256")
                != hashlib.sha256(public).hexdigest()
            or inputs.get("recovery_rule_digest") != pin["rule_digest"]):
        raise OperatorDenied("installed recovery signer differs from gateway")
    now = int(time.time()) if now is None else now
    try:
        report = attest_response_less_candidate(
            inputs, baseline_path, candidate_path, search_report_path, pins,
            search_report_sha256=search_report_sha256,
            signing_key=signer, now=now,
        )
    except ContractRejected as error:
        raise OperatorDenied("response-less candidate evidence is unavailable") from error
    _private_write(report_out, report)
    statement = json.loads(report)["statement"]
    return {
        "status": "recovery_attestation_prepared",
        "task_id": task_id,
        "candidate_id": statement["candidate_id"],
        "valid_until": statement["valid_until"],
        "report": str(report_out),
        "authority": "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--gateway-sha256", required=True)
    parser.add_argument("--gateway-state-dir", type=Path, required=True)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--signing-seed", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--search-report", type=Path, required=True)
    parser.add_argument("--candidate-pins", type=Path, required=True)
    parser.add_argument("--search-report-sha256", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    result = prepare_recovery_attestation(
        gateway_binary=args.gateway_bin,
        gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir,
        installation_path=args.installation,
        signing_seed_path=args.signing_seed,
        baseline_path=args.baseline,
        candidate_path=args.candidate,
        search_report_path=args.search_report,
        candidate_pins_path=args.candidate_pins,
        search_report_sha256=args.search_report_sha256,
        task_id=args.task_id,
        report_out=args.report_out,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
