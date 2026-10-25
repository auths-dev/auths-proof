"""Private AP-071 operator bridge from a bound child to a Jules preflight.

The gateway supplies immutable task/plan/child facts. This process performs
the credential-bearing Google GETs, signs their bounded result with an
operator-held key, and returns the report to the same private task journal.
It does not call a provider write or give the agent a credential.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import stat
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .demo_co_contract import _unique_pairs
from .google_create_handoff import CHILD_TITLE, CreatedChildMetadataPins
from .google_create_preflight import attest_jules_created_child
from .google_write_credential import WriteCredentialPins
from .operator_authority import OperatorDenied
from .operator_cli import _private_read, _private_write
from .task_write_card import _installation
from .write_handoff import WriteHandoffPins, validate_write_handoff


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_MARKER = re.compile(r"ap071_[0-9a-f]{32}\Z")
_INPUT_FIELDS = {
    "schema", "task_id", "task_commitment", "plan_commitment",
    "create_operation_id", "child_id", "populate_recipe_digest",
    "preflight_rule_digest", "connection_id", "connection_generation",
    "connection_subject", "parent_id", "title", "marker", "plan_expires_at",
}


def _gateway(binary: Path, expected_sha256: str) -> Path:
    if (not binary.is_absolute() or binary.is_symlink() or not binary.is_file()
            or not binary.stat().st_mode & stat.S_IXUSR
            or type(expected_sha256) is not str
            or _DIGEST.fullmatch(expected_sha256) is None):
        raise OperatorDenied("reviewed gateway binary is unavailable")
    digest = hashlib.sha256()
    with binary.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        raise OperatorDenied("reviewed gateway binary changed")
    return binary


def _run_gateway(binary: Path, args: list[str], *, limit: int) -> bytes:
    try:
        result = subprocess.run(
            [str(binary), *args], capture_output=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperatorDenied("gateway preflight outcome is unknown; inspect state") from error
    if result.returncode != 0 or len(result.stdout) > limit:
        raise OperatorDenied("gateway preflight outcome is unknown; inspect state")
    return result.stdout


def _credential_pins(path: Path) -> WriteCredentialPins:
    try:
        raw = json.loads(_private_read(path, 4096), object_pairs_hook=_unique_pairs)
    except (OSError, PermissionError, UnicodeDecodeError, ValueError) as error:
        raise OperatorDenied("Jules credential pins are unavailable") from error
    if (type(raw) is not dict
            or set(raw) != {"producer", "client_id", "primary_domain",
                               "connection_id", "connection_generation"}
            or type(raw["producer"]) is not dict
            or set(raw["producer"]) != {"company", "instance",
                "definition_hash", "customer_id", "jules_subject",
                "jules_email", "evidence_sha256"}):
        raise OperatorDenied("Jules credential pins are malformed")
    pins = WriteCredentialPins(
        producer=WriteHandoffPins(**raw["producer"]),
        client_id=raw["client_id"], primary_domain=raw["primary_domain"],
        connection_id=raw["connection_id"],
        connection_generation=raw["connection_generation"],
    )
    pins.validate()
    return pins


def record_jules_populate_preflight(
    *,
    gateway_binary: Path,
    gateway_sha256: str,
    gateway_state_dir: Path,
    installation_path: Path,
    write_evidence_path: Path,
    grant_path: Path,
    credential_pins_path: Path,
    signing_seed_path: Path,
    report_dir: Path,
    task_id: str,
) -> dict:
    """Record one fresh Jules report; retain its private file on uncertainty."""
    if (type(task_id) is not str or _TASK_ID.fullmatch(task_id) is None
            or not gateway_state_dir.is_absolute()
            or not report_dir.is_absolute()
            or report_dir.is_symlink() or not report_dir.is_dir()
            or stat.S_IMODE(report_dir.stat().st_mode) & 0o077):
        raise OperatorDenied("private preflight installation is unavailable")
    binary = _gateway(gateway_binary, gateway_sha256)
    installation = _installation(installation_path)
    pin = installation.get("populate_preflight")
    if type(pin) is not dict:
        raise OperatorDenied("populate preflight signer is not installed")
    seed = _private_read(signing_seed_path, 32)
    if len(seed) != 32:
        raise OperatorDenied("populate preflight signing seed is invalid")
    signer = Ed25519PrivateKey.from_private_bytes(seed)
    public_hex = signer.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    ).hex()
    if public_hex != pin["public_key_hex"]:
        raise OperatorDenied("populate preflight signing key changed")
    pins = _credential_pins(credential_pins_path)
    try:
        inputs = json.loads(_run_gateway(binary, [
            "task-populate-preflight-inputs", "--state-dir",
            str(gateway_state_dir), "--task-id", task_id,
        ], limit=8192), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError) as error:
        raise OperatorDenied("gateway preflight inputs are malformed") from error
    if (type(inputs) is not dict or set(inputs) != _INPUT_FIELDS
            or inputs["schema"] != "auths.gateway-task-populate-preflight-inputs/1"
            or inputs["task_id"] != task_id
            or any(type(inputs[field]) is not str
                   or _DIGEST.fullmatch(inputs[field]) is None
                   for field in ("task_commitment", "plan_commitment",
                                 "populate_recipe_digest", "preflight_rule_digest"))
            or type(inputs["connection_generation"]) is not int
            or type(inputs["plan_expires_at"]) is not int
            or inputs["preflight_rule_digest"] != pin["rule_digest"]
            or inputs["connection_id"] != pins.connection_id
            or inputs["connection_generation"] != pins.connection_generation
            or inputs["connection_subject"] != pins.producer.jules_subject
            or inputs["title"] != CHILD_TITLE
            or type(inputs["marker"]) is not str
            or _MARKER.fullmatch(inputs["marker"]) is None):
        raise OperatorDenied("gateway preflight inputs disagree with installation")
    evidence = validate_write_handoff(write_evidence_path, pins.producer)
    if inputs["parent_id"] != evidence["folder_id"]:
        raise OperatorDenied("created child parent differs from Project A")
    child_pins = CreatedChildMetadataPins(
        candidate_id=inputs["child_id"], parent_id=inputs["parent_id"],
        drive_id=evidence["drive_id"], title=inputs["title"],
        marker_value=inputs["marker"],
    )
    child_pins.validate()
    report = attest_jules_created_child(
        write_evidence_path, grant_path, pins, child_pins,
        connection_id=inputs["connection_id"],
        connection_generation=inputs["connection_generation"],
        task_id=task_id, task_commitment=inputs["task_commitment"],
        plan_commitment=inputs["plan_commitment"],
        create_operation_id=inputs["create_operation_id"],
        populate_recipe_digest=inputs["populate_recipe_digest"],
        rule_digest=inputs["preflight_rule_digest"],
        plan_expires_at=inputs["plan_expires_at"], signing_key=signer,
    )
    report_path = report_dir / f"populate-preflight-{task_id}-{secrets.token_hex(8)}.json"
    _private_write(report_path, report)
    outcome = _run_gateway(binary, [
        "task-record-populate-preflight", "--state-dir",
        str(gateway_state_dir), "--task-id", task_id,
        "--report", str(report_path),
    ], limit=4096)
    if outcome.strip() != b'{"outcome":"populate-preflight-recorded"}':
        raise OperatorDenied("gateway preflight outcome is unknown; inspect state")
    statement = json.loads(report)["statement"]
    return {
        "status": "populate_preflight_recorded",
        "task_id": task_id,
        "child_id": inputs["child_id"],
        "checked_at": statement["checked_at"],
        "valid_until": statement["valid_until"],
        "private_report": str(report_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Record a Jules child preflight")
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--gateway-sha256", required=True)
    parser.add_argument("--gateway-state-dir", type=Path, required=True)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--write-evidence", type=Path, required=True)
    parser.add_argument("--grant", type=Path, required=True)
    parser.add_argument("--credential-pins", type=Path, required=True)
    parser.add_argument("--signing-seed", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    args = parser.parse_args()
    result = record_jules_populate_preflight(
        gateway_binary=args.gateway_bin,
        gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir,
        installation_path=args.installation,
        write_evidence_path=args.write_evidence,
        grant_path=args.grant,
        credential_pins_path=args.credential_pins,
        signing_seed_path=args.signing_seed,
        report_dir=args.report_dir,
        task_id=args.task_id,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
