"""Enter one planned create only after a pinned producer baseline.

This development operator command does not sign for Jules or the agent. The
gateway rechecks their recorded effect plan and owns provider entry. The
baseline is retained before that entry so an ambiguous outcome cannot be
silently reissued against a newer observation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .demo_co_contract import ContractRejected, _unique_pairs
from .google_create_handoff import CHILD_TITLE
from .operator_authority import OperatorDenied
from .operator_cli import _private_read, _private_write
from .task_populate_operator import _credential_pins, _gateway
from .write_handoff import validate_write_handoff


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
_CHILD_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
_MARKER = re.compile(r"ap071_[0-9a-f]{32}\Z")
_BASELINE_FIELDS = {
    "schema_version", "company", "instance", "definition_hash", "observed_at",
    "document_id", "tab_id", "revision_id", "content_sha256",
    "content_byte_count", "original_marker_count",
}


def _baseline(path: Path, expected_sha256: str, *, evidence: dict,
              now: int) -> tuple[int, dict]:
    if (type(expected_sha256) is not str or _DIGEST.fullmatch(expected_sha256) is None
            or path.name != "google-write-observation.json"
            or (match := _GENERATION.fullmatch(path.parent.name)) is None
            or int(match.group(1)) < 2):
        raise OperatorDenied("pre-create producer baseline is unavailable")
    try:
        if path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
            raise ValueError("private observation directory")
        raw = _private_read(path, 4096)
        observation = json.loads(raw, object_pairs_hook=_unique_pairs)
        observed = datetime.fromisoformat(observation["observed_at"])
    except (OSError, PermissionError, ValueError, KeyError, TypeError) as error:
        raise OperatorDenied("pre-create producer baseline is unavailable") from error
    if (hashlib.sha256(raw).hexdigest() != expected_sha256
            or type(observation) is not dict or set(observation) != _BASELINE_FIELDS
            or observation["schema_version"] != "demo-co/google-write-observation/v1"
            or any(observation[field] != evidence[field]
                   for field in ("company", "instance", "definition_hash", "document_id"))
            or type(observation["tab_id"]) is not str
            or not 1 <= len(observation["tab_id"].encode()) <= 64
            or type(observation["revision_id"]) is not str
            or not 1 <= len(observation["revision_id"].encode()) <= 128
            or type(observation["content_sha256"]) is not str
            or _DIGEST.fullmatch(observation["content_sha256"]) is None
            or type(observation["content_byte_count"]) is not int
            or not 1 <= observation["content_byte_count"] <= 16_384
            or type(observation["original_marker_count"]) is not int
            or not 0 <= observation["original_marker_count"] <= 10
            or observed.tzinfo is None or observed.utcoffset() is None
            or not timedelta(0) <= datetime.fromtimestamp(now, timezone.utc) - observed
            <= timedelta(minutes=5)):
        raise OperatorDenied("pre-create producer baseline is stale or disagrees with pins")
    return int(match.group(1)), observation


def submit_planned_create(*, gateway_binary: Path, gateway_sha256: str,
                          gateway_state_dir: Path, task_dir: Path, task_id: str,
                          write_evidence_path: Path, credential_pins_path: Path,
                          baseline_path: Path, baseline_sha256: str,
                          now: int | None = None) -> dict:
    """Record the sole baseline, then submit the immutable human effect plan once."""
    if (type(task_id) is not str or _TASK_ID.fullmatch(task_id) is None
            or not gateway_state_dir.is_absolute() or not task_dir.is_absolute()
            or task_dir.name != task_id or task_dir.is_symlink()
            or not task_dir.is_dir() or stat.S_IMODE(task_dir.stat().st_mode) & 0o077):
        raise OperatorDenied("private planned create task is unavailable")
    binary = _gateway(gateway_binary, gateway_sha256)
    pins = _credential_pins(credential_pins_path)
    try:
        evidence = validate_write_handoff(write_evidence_path, pins.producer)
    except (ContractRejected, OSError, ValueError) as error:
        raise OperatorDenied("pinned Project A write evidence is unavailable") from error
    now = int(time.time()) if now is None else now
    generation, observation = _baseline(
        baseline_path, baseline_sha256, evidence=evidence, now=now,
    )
    try:
        card = json.loads(_private_read(task_dir / "task-card.json", 16_384),
                          object_pairs_hook=_unique_pairs)
        for name, limit in (("agent.proof", 4 * 1024 * 1024),
                            ("agent.action", 64 * 1024),
                            ("effect-plan.proof", 4 * 1024 * 1024),
                            ("effect-plan.action", 64 * 1024)):
            if not _private_read(task_dir / name, limit):
                raise ValueError("empty signed action")
    except (OSError, PermissionError, ValueError, TypeError) as error:
        raise OperatorDenied("signed create and effect plan are unavailable") from error
    pending = card.get("pending_child") if type(card) is dict else None
    if (type(card) is not dict or card.get("task_id") != task_id
            or card.get("company_id") != pins.producer.company
            or type(pending) is not dict
            or pending.get("parent_handle") != evidence["folder_id"]
            or pending.get("title") != CHILD_TITLE
            or type(pending.get("marker")) is not str
            or _MARKER.fullmatch(pending["marker"]) is None
            or type(pending.get("create_recipe_digest")) is not str
            or _DIGEST.fullmatch(pending["create_recipe_digest"]) is None
            or type(pending.get("create_operation_id")) is not str
            or not 1 <= len(pending["create_operation_id"]) <= 32
            or card.get("connection_subject") != pins.producer.jules_subject
            or card.get("connection_id") != pins.connection_id
            or card.get("connection_generation") != pins.connection_generation):
        raise OperatorDenied("signed create task disagrees with Project A pins")
    record = {
        "schema": "auths.ap071-pre-create-baseline/1",
        "task_id": task_id,
        "create_operation_id": pending["create_operation_id"],
        "marker": pending["marker"],
        "generation": generation,
        "observation_sha256": baseline_sha256,
        "observed_at": observation["observed_at"],
    }
    # Exclusive creation is the one-shot handoff. Even an IPC failure after
    # this point needs task/attempt inspection before an operator may proceed.
    try:
        _private_write(task_dir / "pre-create-baseline.json", json.dumps(
            record, sort_keys=True, separators=(",", ":"),
        ).encode())
    except FileExistsError as error:
        raise OperatorDenied(
            "planned create already handed off; inspect gateway state",
        ) from error
    except OSError as error:
        raise OperatorDenied("private pre-create baseline could not be recorded") from error
    try:
        result = subprocess.run([
            str(binary), "task-submit", "--state-dir", str(gateway_state_dir),
            "--task-id", task_id,
            "--recipe-digest", pending["create_recipe_digest"],
            "--agent-proof", str(task_dir / "agent.proof"),
            "--agent-action", str(task_dir / "agent.action"),
            "--recorded-effect-plan",
        ], capture_output=True, check=False, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperatorDenied("planned create outcome is unknown; inspect state") from error
    if result.returncode != 0 or len(result.stdout) > 8192:
        raise OperatorDenied("planned create outcome is unknown; inspect state")
    try:
        outcome = json.loads(result.stdout, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError) as error:
        raise OperatorDenied("planned create outcome is unknown; inspect state") from error
    if type(outcome) is not dict or outcome.get("outcome") not in {
            "denied", "indeterminate", "not-entered", "unknown",
            "response-recorded", "observed", "observed-by-provider"}:
        raise OperatorDenied("planned create outcome is unknown; inspect state")
    return {
        "task_id": task_id, "baseline_generation": generation,
        "baseline_sha256": baseline_sha256, "gateway_outcome": outcome["outcome"],
    }


def reconcile_planned_child(*, gateway_binary: Path, gateway_sha256: str,
                            gateway_state_dir: Path, task_dir: Path,
                            task_id: str) -> dict:
    """Bind only a recorded create-response child, never repeat create."""
    if (type(task_id) is not str or _TASK_ID.fullmatch(task_id) is None
            or not gateway_state_dir.is_absolute() or not task_dir.is_absolute()
            or task_dir.name != task_id or task_dir.is_symlink()
            or not task_dir.is_dir() or stat.S_IMODE(task_dir.stat().st_mode) & 0o077):
        raise OperatorDenied("private planned create task is unavailable")
    binary = _gateway(gateway_binary, gateway_sha256)
    try:
        baseline = json.loads(_private_read(
            task_dir / "pre-create-baseline.json", 4096,
        ), object_pairs_hook=_unique_pairs)
        card = json.loads(_private_read(
            task_dir / "task-card.json", 16_384,
        ), object_pairs_hook=_unique_pairs)
        for name, limit in (("agent.proof", 4 * 1024 * 1024),
                            ("agent.action", 64 * 1024)):
            if not _private_read(task_dir / name, limit):
                raise ValueError("empty signed create")
    except (OSError, PermissionError, ValueError, TypeError) as error:
        raise OperatorDenied("recorded create handoff is unavailable") from error
    pending = card.get("pending_child") if type(card) is dict else None
    if (type(baseline) is not dict
            or set(baseline) != {"schema", "task_id", "create_operation_id",
                                 "marker", "generation", "observation_sha256",
                                 "observed_at"}
            or baseline["schema"] != "auths.ap071-pre-create-baseline/1"
            or baseline["task_id"] != task_id
            or type(baseline["generation"]) is not int
            or baseline["generation"] < 2
            or type(baseline["observation_sha256"]) is not str
            or _DIGEST.fullmatch(baseline["observation_sha256"]) is None
            or type(pending) is not dict
            or pending.get("create_operation_id") != baseline["create_operation_id"]
            or pending.get("marker") != baseline["marker"]
            or type(pending.get("create_recipe_digest")) is not str
            or _DIGEST.fullmatch(pending["create_recipe_digest"]) is None):
        raise OperatorDenied("recorded create baseline disagrees with signed task")
    try:
        result = subprocess.run([
            str(binary), "task-reconcile-child", "--state-dir", str(gateway_state_dir),
            "--task-id", task_id,
            "--recipe-digest", pending["create_recipe_digest"],
            "--agent-proof", str(task_dir / "agent.proof"),
            "--agent-action", str(task_dir / "agent.action"),
        ], capture_output=True, check=False, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperatorDenied("created-child reconciliation is uncertain; inspect state") from error
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise OperatorDenied("created-child reconciliation is uncertain; inspect state")
    try:
        outcome = json.loads(result.stdout, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError) as error:
        raise OperatorDenied("created-child reconciliation is uncertain; inspect state") from error
    if (type(outcome) is not dict
            or set(outcome) != {"schema", "outcome", "child_id"}
            or outcome["schema"] != "auths.gateway-child-reconciliation/1"
            or outcome["outcome"] != "child-bound"
            or type(outcome["child_id"]) is not str
            or _CHILD_ID.fullmatch(outcome["child_id"]) is None):
        raise OperatorDenied("created-child reconciliation is uncertain; inspect state")
    return {
        "task_id": task_id, "child_id": outcome["child_id"],
        "baseline_generation": baseline["generation"],
        "baseline_sha256": baseline["observation_sha256"],
    }


def submit_planned_population(*, gateway_binary: Path, gateway_sha256: str,
                              gateway_state_dir: Path, task_dir: Path,
                              task_id: str, preflight_path: Path,
                              now: int | None = None) -> dict:
    """Submit one agent-signed population under the recorded Jules plan."""
    if (type(task_id) is not str or _TASK_ID.fullmatch(task_id) is None
            or not gateway_state_dir.is_absolute() or not task_dir.is_absolute()
            or task_dir.name != task_id or task_dir.is_symlink()
            or not task_dir.is_dir() or stat.S_IMODE(task_dir.stat().st_mode) & 0o077):
        raise OperatorDenied("private planned population task is unavailable")
    binary = _gateway(gateway_binary, gateway_sha256)
    now = int(time.time()) if now is None else now
    try:
        baseline = json.loads(_private_read(task_dir / "pre-create-baseline.json", 4096),
                              object_pairs_hook=_unique_pairs)
        plan = json.loads(_private_read(task_dir / "effect-plan.json", 4096),
                          object_pairs_hook=_unique_pairs)
        package = json.loads(_private_read(
            task_dir / "agent-companion-write-package.json", 262_144,
        ), object_pairs_hook=_unique_pairs)
        preflight_raw = _private_read(preflight_path, 8192)
        report = json.loads(preflight_raw, object_pairs_hook=_unique_pairs)
        for name, limit in (("populate.proof", 4 * 1024 * 1024),
                            ("populate.action", 64 * 1024)):
            if not _private_read(task_dir / name, limit):
                raise ValueError("empty agent population action")
        inputs_result = subprocess.run([
            str(binary), "task-populate-preflight-inputs", "--state-dir",
            str(gateway_state_dir), "--task-id", task_id,
        ], capture_output=True, check=False, timeout=30)
        if inputs_result.returncode != 0 or len(inputs_result.stdout) > 8192:
            raise ValueError("gateway child inputs unavailable")
        inputs = json.loads(inputs_result.stdout, object_pairs_hook=_unique_pairs)
    except (OSError, PermissionError, ValueError, TypeError,
            subprocess.TimeoutExpired) as error:
        raise OperatorDenied("planned population inputs are unavailable") from error
    statement = report.get("statement") if type(report) is dict else None
    create = plan.get("create") if type(plan) is dict else None
    if (type(baseline) is not dict
            or set(baseline) != {"schema", "task_id", "create_operation_id",
                                 "marker", "generation", "observation_sha256",
                                 "observed_at"}
            or baseline.get("schema") != "auths.ap071-pre-create-baseline/1"
            or baseline.get("task_id") != task_id
            or type(baseline.get("generation")) is not int
            or baseline["generation"] < 2
            or type(baseline.get("observation_sha256")) is not str
            or _DIGEST.fullmatch(baseline["observation_sha256"]) is None
            or type(plan) is not dict or plan.get("schema") != "auths.agent-effect-plan/1"
            or plan.get("task_id") != task_id
            or type(create) is not dict
            or create.get("operation_id") != baseline.get("create_operation_id")
            or type(package) is not dict
            or package.get("schema") != "auths.ap071-agent-write-package/1"
            or package.get("task_id") != task_id
            or package.get("recipe_digest") != plan.get("populate_recipe_digest")
            or type(inputs) is not dict
            or inputs.get("schema") != "auths.gateway-task-populate-preflight-inputs/1"
            or inputs.get("task_id") != task_id
            or inputs.get("task_commitment") != plan.get("task_commitment")
            or inputs.get("create_operation_id") != create.get("operation_id")
            or inputs.get("populate_recipe_digest") != plan.get("populate_recipe_digest")
            or type(inputs.get("child_id")) is not str
            or _CHILD_ID.fullmatch(inputs["child_id"]) is None
            or type(statement) is not dict
            or statement.get("schema") != "auths.gateway-task-populate-preflight/1"
            or any(statement.get(field) != inputs.get(field) for field in (
                "task_id", "task_commitment", "plan_commitment",
                "create_operation_id", "child_id", "populate_recipe_digest",
                "preflight_rule_digest", "connection_id", "connection_generation",
                "connection_subject"))
            or type(statement.get("valid_until")) is not int
            or type(plan.get("expires_at")) is not int
            or type(plan.get("populate_operation_id")) is not str
            or _TASK_ID.fullmatch(plan["populate_operation_id"]) is None
            or not now < min(statement["valid_until"], plan["expires_at"])):
        raise OperatorDenied("planned population differs from recorded task and Jules preflight")
    entry = {
        "schema": "auths.ap071-populate-entry/1",
        "task_id": task_id,
        "child_id": inputs["child_id"],
        "populate_operation_id": plan["populate_operation_id"],
        "baseline_sha256": baseline["observation_sha256"],
        "preflight_sha256": hashlib.sha256(preflight_raw).hexdigest(),
    }
    try:
        _private_write(task_dir / "populate-entry.json", json.dumps(
            entry, sort_keys=True, separators=(",", ":"),
        ).encode())
    except FileExistsError as error:
        raise OperatorDenied("planned population already handed off; inspect state") from error
    except OSError as error:
        raise OperatorDenied("private population entry could not be recorded") from error
    try:
        result = subprocess.run([
            str(binary), "task-submit", "--state-dir", str(gateway_state_dir),
            "--task-id", task_id,
            "--recipe-digest", plan["populate_recipe_digest"],
            "--agent-proof", str(task_dir / "populate.proof"),
            "--agent-action", str(task_dir / "populate.action"),
            "--recorded-effect-plan",
        ], capture_output=True, check=False, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperatorDenied("planned population outcome is unknown; inspect state") from error
    if result.returncode != 0 or len(result.stdout) > 8192:
        raise OperatorDenied("planned population outcome is unknown; inspect state")
    try:
        outcome = json.loads(result.stdout, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError) as error:
        raise OperatorDenied("planned population outcome is unknown; inspect state") from error
    if type(outcome) is not dict or outcome.get("outcome") not in {
            "denied", "indeterminate", "not-entered", "unknown",
            "response-recorded", "observed", "observed-by-provider"}:
        raise OperatorDenied("planned population outcome is unknown; inspect state")
    return {
        "task_id": task_id, "child_id": inputs["child_id"],
        "gateway_outcome": outcome["outcome"],
        "baseline_sha256": baseline["observation_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--gateway-sha256", required=True)
    parser.add_argument("--gateway-state-dir", type=Path, required=True)
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--write-evidence", type=Path, required=True)
    parser.add_argument("--credential-pins", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--baseline-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(submit_planned_create(
        gateway_binary=args.gateway_bin, gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir, task_dir=args.task_dir,
        task_id=args.task_id, write_evidence_path=args.write_evidence,
        credential_pins_path=args.credential_pins, baseline_path=args.baseline,
        baseline_sha256=args.baseline_sha256,
    ), sort_keys=True))
    return 0


def reconcile_main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile one planned Google child")
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--gateway-sha256", required=True)
    parser.add_argument("--gateway-state-dir", type=Path, required=True)
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    args = parser.parse_args()
    print(json.dumps(reconcile_planned_child(
        gateway_binary=args.gateway_bin, gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir, task_dir=args.task_dir,
        task_id=args.task_id,
    ), sort_keys=True))
    return 0


def populate_main() -> int:
    parser = argparse.ArgumentParser(description="Submit one planned Google population")
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--gateway-sha256", required=True)
    parser.add_argument("--gateway-state-dir", type=Path, required=True)
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(submit_planned_population(
        gateway_binary=args.gateway_bin, gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir, task_dir=args.task_dir,
        task_id=args.task_id, preflight_path=args.preflight,
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
