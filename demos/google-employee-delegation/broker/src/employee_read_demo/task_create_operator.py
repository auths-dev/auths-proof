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
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path

from .demo_co_contract import ContractRejected, _unique_pairs
from .google_create_handoff import CHILD_TITLE
from .google_create_preflight import search_jules_created_child
from .google_create_v2_handoff import (
    CreateV2BaselinePins, validate_create_v2_precreate_baseline,
)
from .google_create_v3_handoff import (
    CreateV3BaselinePins, CreateV3NeighborPins,
    validate_create_v3_precreate_baseline,
)
from .operator_authority import OperatorDenied
from .operator_cli import _private_read, _private_write
from .task_populate_operator import _credential_pins, _gateway, _run_gateway
from .write_handoff import validate_current_write_observation, validate_write_handoff


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
_CHILD_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
_MARKER = re.compile(r"ap071_[0-9a-f]{32}\Z")
_BASELINE_RECORD_FIELDS = {
    "schema", "task_id", "create_operation_id", "marker", "generation",
    "observation_sha256", "observed_at",
}
_RECOVERY_REPORT_NAME = re.compile(r"recovery-search-[A-Za-z0-9_-]{1,32}\.json\Z")


def _recorded_baseline_is_valid(record: object, task_id: str) -> bool:
    if type(record) is not dict or record.get("task_id") != task_id:
        return False
    if record.get("schema") in (
            "auths.ap071-pre-create-baseline/1",
            "auths.ap071-pre-create-baseline/3"):
        expected = _BASELINE_RECORD_FIELDS
    elif record.get("schema") == "auths.ap071-pre-create-baseline/2":
        expected = _BASELINE_RECORD_FIELDS | {"preserved_blank_sha256"}
        if (type(record.get("preserved_blank_sha256")) is not str
                or _DIGEST.fullmatch(record["preserved_blank_sha256"]) is None):
            return False
    else:
        return False
    return (set(record) == expected
            and type(record.get("generation")) is int
            and record["generation"] >= 2
            and type(record.get("observation_sha256")) is str
            and _DIGEST.fullmatch(record["observation_sha256"]) is not None)


def _baseline(path: Path, expected_sha256: str, *, evidence: dict,
              now: int, preserved_blank_path: Path | None = None,
              v2_pins: CreateV2BaselinePins | None = None,
              v3_pins: CreateV3BaselinePins | None = None,
              ) -> tuple[int, dict, str]:
    if path.name == "google-create-v3-baseline.json":
        if (v3_pins is None or v2_pins is not None
                or preserved_blank_path is not None
                or type(expected_sha256) is not str
                or expected_sha256 != v3_pins.baseline_sha256
                or (match := _GENERATION.fullmatch(path.parent.name)) is None
                or int(match.group(1)) != v3_pins.baseline_generation
                or not path.parent.is_dir() or path.parent.is_symlink()
                or path.parent.stat().st_mode & 0o077
                or not path.is_file() or path.is_symlink()
                or path.stat().st_mode & 0o077
                or any(getattr(v3_pins, field) != evidence[field]
                       for field in ("company", "instance", "definition_hash",
                                     "customer_id", "jules_subject", "drive_id",
                                     "folder_id"))
                or v3_pins.neighbors[0].document_id != evidence["document_id"]):
            raise OperatorDenied("v3 pre-create producer baseline disagrees with pins")
        try:
            observation = validate_create_v3_precreate_baseline(
                path, v3_pins, now=now,
            )
        except (ContractRejected, OSError, ValueError) as error:
            raise OperatorDenied("v3 pre-create producer baseline is unavailable") from error
        return int(match.group(1)), observation, "v3"
    if path.name == "google-create-v2-baseline.json":
        if (v2_pins is None or v3_pins is not None
                or preserved_blank_path is None
                or type(expected_sha256) is not str
                or expected_sha256 != v2_pins.baseline_sha256
                or (match := _GENERATION.fullmatch(path.parent.name)) is None
                or int(match.group(1)) != v2_pins.baseline_generation
                or preserved_blank_path.name
                    != "google-preserved-blank-observation.json"
                or (blank_match := _GENERATION.fullmatch(
                    preserved_blank_path.parent.name)) is None
                or int(blank_match.group(1))
                    != v2_pins.preserved_blank_generation
                or not path.parent.is_dir()
                or not preserved_blank_path.parent.is_dir()
                or path.parent.is_symlink() or preserved_blank_path.parent.is_symlink()
                or path.parent.stat().st_mode & 0o077
                or preserved_blank_path.parent.stat().st_mode & 0o077
                or not path.is_file() or not preserved_blank_path.is_file()
                or path.stat().st_mode & 0o077
                or preserved_blank_path.stat().st_mode & 0o077
                or any(getattr(v2_pins, field) != evidence[field]
                       for field in ("company", "instance", "definition_hash",
                                     "customer_id", "jules_subject", "drive_id",
                                     "folder_id"))
                or v2_pins.working_document_id != evidence["document_id"]):
            raise OperatorDenied("v2 pre-create producer baseline disagrees with pins")
        try:
            observation = validate_create_v2_precreate_baseline(
                preserved_blank_path, path, v2_pins, now=now,
            )
        except (ContractRejected, OSError, ValueError) as error:
            raise OperatorDenied("v2 pre-create producer baseline is unavailable") from error
        return int(match.group(1)), observation, "v2"
    if any(value is not None for value in (preserved_blank_path, v2_pins,
                                           v3_pins)):
        raise OperatorDenied("versioned pins cannot be used with a v1 baseline")
    try:
        generation, observation = validate_current_write_observation(
            path, expected_sha256, evidence=evidence, now=now,
            maximum_age=timedelta(minutes=5),
        )
    except (ContractRejected, OSError, ValueError) as error:
        raise OperatorDenied("pre-create producer baseline is stale or disagrees with pins") from error
    return generation, observation, "v1"


def submit_planned_create(*, gateway_binary: Path, gateway_sha256: str,
                          gateway_state_dir: Path, task_dir: Path, task_id: str,
                          write_evidence_path: Path, credential_pins_path: Path,
                          baseline_path: Path, baseline_sha256: str,
                          preserved_blank_path: Path | None = None,
                          v2_pins_path: Path | None = None,
                          v3_pins_path: Path | None = None,
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
    v2_pins = None
    v3_pins = None
    if v2_pins_path is not None and v3_pins_path is not None:
        raise OperatorDenied("only one producer baseline version may be pinned")
    if v2_pins_path is not None:
        try:
            v2_pins = CreateV2BaselinePins(**json.loads(
                _private_read(v2_pins_path, 4096), object_pairs_hook=_unique_pairs,
            ))
            v2_pins.validate()
        except (OSError, PermissionError, ValueError, TypeError) as error:
            raise OperatorDenied("private v2 baseline pins are unavailable") from error
        if v2_pins.source_verification_sha256 != pins.producer.evidence_sha256:
            raise OperatorDenied("v2 source verification differs from installed producer")
    if v3_pins_path is not None:
        try:
            document = json.loads(_private_read(v3_pins_path, 8192),
                                  object_pairs_hook=_unique_pairs)
            neighbors = tuple(CreateV3NeighborPins(**item)
                              for item in document.pop("neighbors"))
            v3_pins = CreateV3BaselinePins(neighbors=neighbors, **document)
            v3_pins.validate()
        except (OSError, PermissionError, ValueError, TypeError,
                AttributeError, KeyError) as error:
            raise OperatorDenied("private v3 baseline pins are unavailable") from error
        if v3_pins.source_verification_sha256 != pins.producer.evidence_sha256:
            raise OperatorDenied("v3 source verification differs from installed producer")
    now = int(time.time()) if now is None else now
    generation, observation, baseline_version = _baseline(
        baseline_path, baseline_sha256, evidence=evidence, now=now,
        preserved_blank_path=preserved_blank_path, v2_pins=v2_pins,
        v3_pins=v3_pins,
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
        "schema": ("auths.ap071-pre-create-baseline/3" if baseline_version == "v3"
                   else "auths.ap071-pre-create-baseline/2" if baseline_version == "v2"
                   else "auths.ap071-pre-create-baseline/1"),
        "task_id": task_id,
        "create_operation_id": pending["create_operation_id"],
        "marker": pending["marker"],
        "generation": generation,
        "observation_sha256": baseline_sha256,
        "observed_at": observation["observed_at"],
    }
    if v2_pins is not None:
        record["preserved_blank_sha256"] = v2_pins.preserved_blank_sha256
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
    if (not _recorded_baseline_is_valid(baseline, task_id)
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


def search_planned_created_child(*, gateway_binary: Path, gateway_sha256: str,
                                 gateway_state_dir: Path, task_dir: Path,
                                 task_id: str, write_evidence_path: Path,
                                 grant_path: Path, credential_pins_path: Path,
                                 report_path: Path, now: int | None = None) -> dict:
    """Search the original task marker after one claimed create; bind nothing.

    The private report distinguishes zero, one and multiple candidates. Even
    one rechecked candidate is only input to an independent producer check and
    a fresh human-signed recovery action; it never authorizes population or a
    create retry.
    """
    if (type(task_id) is not str or _TASK_ID.fullmatch(task_id) is None
            or not gateway_state_dir.is_absolute() or not task_dir.is_absolute()
            or task_dir.name != task_id or task_dir.is_symlink()
            or not task_dir.is_dir() or stat.S_IMODE(task_dir.stat().st_mode) & 0o077
            or not report_path.is_absolute() or report_path.parent != task_dir
            or _RECOVERY_REPORT_NAME.fullmatch(report_path.name) is None
            or report_path.exists() or report_path.is_symlink()):
        raise OperatorDenied("private planned-create recovery path is unavailable")
    binary = _gateway(gateway_binary, gateway_sha256)
    pins = _credential_pins(credential_pins_path)
    try:
        evidence = validate_write_handoff(write_evidence_path, pins.producer)
        baseline = json.loads(_private_read(task_dir / "pre-create-baseline.json", 4096),
                              object_pairs_hook=_unique_pairs)
        card = json.loads(_private_read(task_dir / "task-card.json", 16_384),
                          object_pairs_hook=_unique_pairs)
        plan = json.loads(_private_read(task_dir / "effect-plan.json", 4096),
                          object_pairs_hook=_unique_pairs)
        for name, limit in (("agent.proof", 4 * 1024 * 1024),
                            ("agent.action", 64 * 1024),
                            ("effect-plan.proof", 4 * 1024 * 1024),
                            ("effect-plan.action", 64 * 1024)):
            if not _private_read(task_dir / name, limit):
                raise ValueError("empty signed action")
        status = json.loads(_run_gateway(binary, [
            "task-status", "--state-dir", str(gateway_state_dir),
            "--task-id", task_id,
        ], limit=8192), object_pairs_hook=_unique_pairs)
    except (OSError, PermissionError, ValueError, TypeError, ContractRejected) as error:
        raise OperatorDenied("planned-create recovery inputs are unavailable") from error
    pending = card.get("pending_child") if type(card) is dict else None
    create = plan.get("create") if type(plan) is dict else None
    if (not _recorded_baseline_is_valid(baseline, task_id)
            or type(card) is not dict or card.get("task_id") != task_id
            or card.get("company_id") != pins.producer.company
            or card.get("connection_id") != pins.connection_id
            or card.get("connection_generation") != pins.connection_generation
            or card.get("connection_subject") != pins.producer.jules_subject
            or type(pending) is not dict
            or pending.get("create_operation_id") != baseline["create_operation_id"]
            or pending.get("marker") != baseline["marker"]
            or pending.get("parent_handle") != evidence["folder_id"]
            or pending.get("title") != CHILD_TITLE
            or type(plan) is not dict or plan.get("schema") != "auths.agent-effect-plan/1"
            or plan.get("task_id") != task_id or type(create) is not dict
            or create.get("operation_id") != baseline["create_operation_id"]
            or create.get("resource_handle") != evidence["folder_id"]
            or create.get("recipe_digest") != pending.get("create_recipe_digest")
            or create.get("connection_id") != pins.connection_id
            or create.get("connection_generation") != pins.connection_generation
            or create.get("connection_subject") != pins.producer.jules_subject
            or type(status) is not dict
            or status.get("schema") != "auths.gateway-agent-task-status/1"
            or status.get("task_id") != task_id or status.get("writes") != 1
            or status.get("write_operations") != [baseline["create_operation_id"]]):
        raise OperatorDenied("planned-create recovery differs from claimed task")
    now = int(time.time()) if now is None else now
    try:
        result = search_jules_created_child(
            write_evidence_path, grant_path, pins, baseline["marker"],
            connection_id=pins.connection_id,
            connection_generation=pins.connection_generation, now=now,
        )
    except ContractRejected as error:
        raise OperatorDenied("Jules recovery search is incomplete or invalid") from error
    if (result.marker_value != baseline["marker"]
            or result.parent_id != evidence["folder_id"]
            or result.drive_id != evidence["drive_id"]
            or result.connection_id != pins.connection_id
            or result.connection_generation != pins.connection_generation
            or result.connection_subject != pins.producer.jules_subject
            or result.checked_at != now):
        raise OperatorDenied("Jules recovery search changed task pins")
    report = {
        "schema": "auths.ap071-create-recovery-search/1",
        "task_id": task_id,
        "create_operation_id": baseline["create_operation_id"],
        "baseline_sha256": baseline["observation_sha256"],
        "result": asdict(result) | {"status": result.status},
        "authority": "none",
    }
    try:
        _private_write(report_path, json.dumps(
            report, sort_keys=True, separators=(",", ":"),
        ).encode())
    except OSError as error:
        raise OperatorDenied("private recovery search report could not be recorded") from error
    return {"task_id": task_id, "status": result.status,
            "candidate_count": result.candidate_count,
            "report": str(report_path), "authority": "none"}


def submit_planned_population(*, gateway_binary: Path, gateway_sha256: str,
                              gateway_state_dir: Path, task_dir: Path,
                              task_id: str, preflight_path: Path,
                              now: int | None = None,
                              recover_pre_entry_denial: bool = False) -> dict:
    """Submit one population, or recover a proven pre-entry denial once."""
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
    if (not _recorded_baseline_is_valid(baseline, task_id)
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
    result_path = task_dir / (
        "populate-recovery-result.json" if recover_pre_entry_denial
        else "populate-result.json"
    )
    if recover_pre_entry_denial:
        try:
            original = json.loads(_private_read(task_dir / "populate-entry.json", 4096),
                                  object_pairs_hook=_unique_pairs)
            prior = json.loads(_private_read(task_dir / "populate-result.json", 4096),
                               object_pairs_hook=_unique_pairs)
            status_result = subprocess.run([
                str(binary), "task-status", "--state-dir", str(gateway_state_dir),
                "--task-id", task_id,
            ], capture_output=True, check=False, timeout=30)
            if status_result.returncode != 0 or len(status_result.stdout) > 8192:
                raise ValueError("gateway status unavailable")
            status = json.loads(status_result.stdout, object_pairs_hook=_unique_pairs)
        except (OSError, PermissionError, ValueError, TypeError,
                subprocess.TimeoutExpired) as error:
            raise OperatorDenied("pre-entry population denial cannot be proved") from error
        if (type(original) is not dict or type(prior) is not dict
                or type(status) is not dict
                or any(original.get(field) != entry[field] for field in (
                    "schema", "task_id", "child_id", "populate_operation_id",
                    "baseline_sha256"))
                or original.get("preflight_sha256") == entry["preflight_sha256"]
                or prior != {
                    "schema": "auths.ap071-populate-result/1",
                    "task_id": task_id,
                    "populate_operation_id": plan["populate_operation_id"],
                    "outcome": "denied",
                }
                or status.get("schema") != "auths.gateway-agent-task-status/1"
                or status.get("task_id") != task_id
                or status.get("writes") != 1
                or status.get("write_operations") != [create["operation_id"]]):
            raise OperatorDenied("population may have entered; recovery refused")
        try:
            _private_write(task_dir / "populate-recovery-entry.json", json.dumps(
                entry, sort_keys=True, separators=(",", ":"),
            ).encode())
        except FileExistsError as error:
            raise OperatorDenied("planned population recovery already handed off") from error
        except OSError as error:
            raise OperatorDenied("private population recovery could not be recorded") from error
    else:
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
    try:
        _private_write(result_path, json.dumps({
            "schema": "auths.ap071-populate-result/1",
            "task_id": task_id,
            "populate_operation_id": plan["populate_operation_id"],
            "outcome": outcome["outcome"],
        }, sort_keys=True, separators=(",", ":")).encode())
    except OSError as error:
        raise OperatorDenied("planned population result could not be recorded; inspect state") from error
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
    parser.add_argument("--preserved-blank", type=Path)
    parser.add_argument("--v2-pins", type=Path)
    parser.add_argument("--v3-pins", type=Path)
    args = parser.parse_args()
    print(json.dumps(submit_planned_create(
        gateway_binary=args.gateway_bin, gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir, task_dir=args.task_dir,
        task_id=args.task_id, write_evidence_path=args.write_evidence,
        credential_pins_path=args.credential_pins, baseline_path=args.baseline,
        baseline_sha256=args.baseline_sha256,
        preserved_blank_path=args.preserved_blank, v2_pins_path=args.v2_pins,
        v3_pins_path=args.v3_pins,
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


def recovery_search_main() -> int:
    parser = argparse.ArgumentParser(description="Search a claimed Google create without binding it")
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--gateway-sha256", required=True)
    parser.add_argument("--gateway-state-dir", type=Path, required=True)
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--write-evidence", type=Path, required=True)
    parser.add_argument("--grant", type=Path, required=True)
    parser.add_argument("--credential-pins", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(search_planned_created_child(
        gateway_binary=args.gateway_bin, gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir, task_dir=args.task_dir,
        task_id=args.task_id, write_evidence_path=args.write_evidence,
        grant_path=args.grant, credential_pins_path=args.credential_pins,
        report_path=args.report,
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
    parser.add_argument("--recover-pre-entry-denial", action="store_true")
    args = parser.parse_args()
    print(json.dumps(submit_planned_population(
        gateway_binary=args.gateway_bin, gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir, task_dir=args.task_dir,
        task_id=args.task_id, preflight_path=args.preflight,
        recover_pre_entry_denial=args.recover_pre_entry_denial,
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
