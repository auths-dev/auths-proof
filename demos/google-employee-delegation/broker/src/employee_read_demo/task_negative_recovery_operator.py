"""Record installed create-recovery refusals without binding any child.

This development operator path joins a signed task and durable gateway state
to a source-pinned scratch folder. demo_co's later observation is separately
validated and cannot stand in for these Auths refusal facts.
"""

from __future__ import annotations

import argparse
import json
import stat
import time
from pathlib import Path

from .demo_co_contract import ContractRejected, _unique_pairs
from .google_create_handoff import CHILD_TITLE
from .google_create_negative_handoff import (
    CreateNegativePins, load_v4_final_pins,
    validate_create_recovery_negative_observation,
    validate_negative_precreate_baseline,
)
from .google_create_preflight import search_jules_created_child
from .operator_authority import OperatorDenied
from .operator_cli import _private_read, _private_write
from .task_create_operator import _recorded_baseline_is_valid
from .task_populate_operator import _credential_pins, _gateway, _run_gateway


def _gateway_json(binary: Path, state_dir: Path, task_id: str,
                  command: str) -> dict:
    try:
        document = json.loads(_run_gateway(binary, [
            command, "--state-dir", str(state_dir), "--task-id", task_id,
        ], limit=8192), object_pairs_hook=_unique_pairs)
    except (OSError, ValueError, TypeError) as error:
        raise OperatorDenied(f"negative {command} unavailable") from error
    if type(document) is not dict:
        raise OperatorDenied(f"negative {command} is malformed")
    return document


def record_negative_create_refusal(
    *,
    gateway_binary: Path,
    gateway_sha256: str,
    gateway_state_dir: Path,
    task_dir: Path,
    task_id: str,
    write_evidence_path: Path,
    credential_pins_path: Path,
    grant_path: Path,
    source_v4_paths: tuple[Path, Path, Path],
    v4_pins_path: Path,
    setup_path: Path,
    setup_sha256: str,
    baseline_path: Path,
    baseline_sha256: str,
    inject_incomplete_search_for_test: bool = False,
    now: int | None = None,
) -> dict:
    """Search once, refuse zero/multiple/incomplete and save one private report."""
    if (not gateway_state_dir.is_absolute() or not task_dir.is_absolute()
            or task_dir.name != task_id or task_dir.is_symlink()
            or not task_dir.is_dir()
            or stat.S_IMODE(task_dir.stat().st_mode) & 0o077
            or len(source_v4_paths) != 3
            or (task_dir / "negative-refusal.json").exists()
            or (task_dir / "negative-refusal.json").is_symlink()):
        raise OperatorDenied("negative task directory or source paths are invalid")
    now = int(time.time()) if now is None else now
    binary = _gateway(gateway_binary, gateway_sha256)
    credential = _credential_pins(credential_pins_path)
    try:
        target, generation, _ = validate_negative_precreate_baseline(
            *source_v4_paths, setup_path, setup_sha256,
            baseline_path, baseline_sha256, load_v4_final_pins(v4_pins_path),
            now=now,
        )
        recorded = json.loads(_private_read(
            task_dir / "pre-create-baseline.json", 4096,
        ), object_pairs_hook=_unique_pairs)
        card = json.loads(_private_read(task_dir / "task-card.json", 16_384),
                          object_pairs_hook=_unique_pairs)
        plan = json.loads(_private_read(task_dir / "effect-plan.json", 4096),
                          object_pairs_hook=_unique_pairs)
    except (ContractRejected, OSError, ValueError, TypeError) as error:
        raise OperatorDenied("negative task or producer baseline is unavailable") from error
    pending = card.get("pending_child") if type(card) is dict else None
    create = plan.get("create") if type(plan) is dict else None
    if (not _recorded_baseline_is_valid(recorded, task_id)
            or recorded["schema"] != "auths.ap071-pre-create-baseline-negative/1"
            or recorded["generation"] != generation
            or recorded["observation_sha256"] != baseline_sha256
            or type(pending) is not dict or type(create) is not dict
            or pending.get("parent_handle") != target.parent_id
            or pending.get("title") != CHILD_TITLE
            or pending.get("marker") != target.marker
            or pending.get("create_operation_id")
                != recorded["create_operation_id"]
            or create.get("operation_id") != recorded["create_operation_id"]
            or create.get("resource_handle") != target.parent_id
            or create.get("connection_id") != credential.connection_id
            or create.get("connection_generation")
                != credential.connection_generation
            or create.get("connection_subject")
                != credential.producer.jules_subject
            or card.get("connection_subject")
                != credential.producer.jules_subject):
        raise OperatorDenied("negative signed plan differs from scratch pins")
    if inject_incomplete_search_for_test != (target.case == "incomplete"):
        raise OperatorDenied("negative search fault differs from signed case")
    expected_writes = 0 if target.case == "zero" else 1
    expected_operations = ([] if expected_writes == 0 else
                           [recorded["create_operation_id"]])
    before = _gateway_json(binary, gateway_state_dir, task_id, "task-status")
    if (before.get("schema") != "auths.gateway-agent-task-status/1"
            or before.get("task_id") != task_id
            or before.get("writes") != expected_writes
            or before.get("write_operations") != expected_operations):
        raise OperatorDenied("negative gateway attempt count differs")
    recovery_inputs = None
    if expected_writes:
        recovery_inputs = _gateway_json(
            binary, gateway_state_dir, task_id, "task-create-recovery-inputs",
        )
        if (recovery_inputs.get("schema")
                != "auths.gateway-task-create-recovery-inputs/1"
                or recovery_inputs.get("task_id") != task_id
                or recovery_inputs.get("attempt_stage") != "unknown"
                or recovery_inputs.get("authority") != "none"
                or recovery_inputs.get("parent_id") != target.parent_id
                or recovery_inputs.get("marker") != target.marker
                or recovery_inputs.get("title") != CHILD_TITLE
                or recovery_inputs.get("create_operation_id")
                    != recorded["create_operation_id"]
                or recovery_inputs.get("connection_subject")
                    != credential.producer.jules_subject):
            raise OperatorDenied("negative recovery is not one unknown create")
    try:
        search = search_jules_created_child(
            write_evidence_path, grant_path, credential, target.marker,
            connection_id=credential.connection_id,
            connection_generation=credential.connection_generation,
            pinned_parent_id=target.parent_id,
            inject_incomplete_search_for_test=inject_incomplete_search_for_test,
            now=now,
        )
    except ContractRejected as error:
        if target.case != "incomplete" or "incomplete" not in str(error):
            raise OperatorDenied("negative recovery search failed unexpectedly") from error
        status = "injected-incomplete"
        candidate_count = None
        page_sha256: list[str] = []
    else:
        status = search.status
        candidate_count = search.candidate_count
        page_sha256 = list(search.page_sha256)
        if (status != target.case or search.candidate_id is not None
                or candidate_count != (0 if status == "zero" else 2)
                or search.parent_id != target.parent_id
                or search.marker_value != target.marker
                or search.connection_subject
                    != credential.producer.jules_subject):
            raise OperatorDenied("negative search did not establish refusal")
    after = _gateway_json(binary, gateway_state_dir, task_id, "task-status")
    if (after.get("writes") != expected_writes
            or after.get("write_operations") != expected_operations
            or after.get("provider_calls") != before.get("provider_calls")
            or after.get("releases") != before.get("releases")):
        raise OperatorDenied("negative search changed task budgets")
    report = {
        "schema": "auths.ap071-create-negative-refusal/1",
        "task_id": task_id, "case": target.case, "run_id": target.run_id,
        "marker": target.marker, "parent_id": target.parent_id,
        "create_operation_id": recorded["create_operation_id"],
        "baseline_generation": generation,
        "baseline_sha256": baseline_sha256,
        "setup_generation": target.setup_generation,
        "setup_sha256": target.setup_sha256,
        "gateway_write_count": expected_writes,
        "gateway_write_operations": expected_operations,
        "gateway_unknown_create": recovery_inputs is not None,
        "search_status": status, "candidate_count": candidate_count,
        "search_page_sha256": page_sha256,
        "injected_incomplete_search": inject_incomplete_search_for_test,
        "child_bound": False, "populate_submitted": False,
        "authority": "none",
    }
    try:
        _private_write(task_dir / "negative-refusal.json", json.dumps(
            report, sort_keys=True, separators=(",", ":"),
        ).encode())
    except FileExistsError as error:
        raise OperatorDenied("negative refusal already recorded") from error
    return report


def join_negative_refusal_observation(
    *, task_dir: Path, task_id: str,
    source_v4_paths: tuple[Path, Path, Path],
    setup_path: Path, baseline_path: Path, observation_path: Path,
    pins: CreateNegativePins,
) -> dict:
    """Join independent provider inventory to the prior Auths refusal."""
    if (not task_dir.is_absolute() or task_dir.name != task_id
            or (task_dir / "negative-joined.json").exists()
            or (task_dir / "negative-joined.json").is_symlink()
            or len(source_v4_paths) != 3):
        raise OperatorDenied("negative join path is unavailable")
    try:
        refusal = json.loads(_private_read(
            task_dir / "negative-refusal.json", 8192,
        ), object_pairs_hook=_unique_pairs)
        provider = validate_create_recovery_negative_observation(
            *source_v4_paths, setup_path, baseline_path, observation_path,
            pins,
        )
    except (ContractRejected, OSError, ValueError, TypeError) as error:
        raise OperatorDenied("negative refusal or producer observation is unavailable") from error
    if (type(refusal) is not dict
            or refusal.get("schema") != "auths.ap071-create-negative-refusal/1"
            or refusal.get("task_id") != task_id
            or refusal.get("case") != pins.case
            or refusal.get("run_id") != pins.run_id
            or refusal.get("marker") != pins.marker
            or refusal.get("parent_id") != pins.run_folder_id
            or refusal.get("setup_generation") != pins.setup_generation
            or refusal.get("setup_sha256") != pins.setup_sha256
            or refusal.get("baseline_generation") != pins.baseline_generation
            or refusal.get("baseline_sha256") != pins.baseline_sha256
            or refusal.get("authority") != "none"
            or refusal.get("child_bound") is not False
            or refusal.get("populate_submitted") is not False
            or provider.get("case") != pins.case
            or provider.get("run_id") != pins.run_id
            or provider.get("authority") != "none"):
        raise OperatorDenied("negative provider state differs from Auths refusal")
    if pins.case == "incomplete":
        if (refusal.get("search_status") != "injected-incomplete"
                or refusal.get("candidate_count") is not None
                or refusal.get("injected_incomplete_search") is not True):
            raise OperatorDenied("incomplete search was not an Auths fault")
    elif (refusal.get("search_status") != pins.case
          or refusal.get("candidate_count") != provider["provider_match_count"]
          or refusal.get("injected_incomplete_search") is not False):
        raise OperatorDenied("negative search count differs from provider")
    joined = {
        "schema": "auths.ap071-create-negative-joined/1",
        "task_id": task_id, "run_id": pins.run_id, "case": pins.case,
        "provider_match_count": provider["provider_match_count"],
        "new_child_ids": provider["new_child_ids"],
        "gateway_write_count": refusal["gateway_write_count"],
        "search_status": refusal["search_status"],
        "create_retry_count": 0, "populate_count": 0,
        "authority": "none",
        "provider_attribution": "provider_state_only",
    }
    try:
        _private_write(task_dir / "negative-joined.json", json.dumps(
            joined, sort_keys=True, separators=(",", ":"),
        ).encode())
    except FileExistsError as error:
        raise OperatorDenied("negative provider observation already joined") from error
    return joined


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--gateway-sha256", required=True)
    parser.add_argument("--gateway-state-dir", type=Path, required=True)
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--write-evidence", type=Path, required=True)
    parser.add_argument("--credential-pins", type=Path, required=True)
    parser.add_argument("--grant", type=Path, required=True)
    parser.add_argument("--v4-baseline", type=Path, required=True)
    parser.add_argument("--v4-candidate", type=Path, required=True)
    parser.add_argument("--v4-final", type=Path, required=True)
    parser.add_argument("--v4-pins", type=Path, required=True)
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--setup-sha256", required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--inject-incomplete-search-for-test", action="store_true")
    args = parser.parse_args()
    print(json.dumps(record_negative_create_refusal(
        gateway_binary=args.gateway_bin,
        gateway_sha256=args.gateway_sha256,
        gateway_state_dir=args.gateway_state_dir,
        task_dir=args.task_dir, task_id=args.task_id,
        write_evidence_path=args.write_evidence,
        credential_pins_path=args.credential_pins, grant_path=args.grant,
        source_v4_paths=(args.v4_baseline, args.v4_candidate,
                         args.v4_final),
        v4_pins_path=args.v4_pins, setup_path=args.setup,
        setup_sha256=args.setup_sha256, baseline_path=args.baseline,
        baseline_sha256=args.baseline_sha256,
        inject_incomplete_search_for_test=(
            args.inject_incomplete_search_for_test),
    ), sort_keys=True))
    return 0


def join_main() -> int:
    parser = argparse.ArgumentParser(description="Join Auths refusal and producer state")
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--v4-baseline", type=Path, required=True)
    parser.add_argument("--v4-candidate", type=Path, required=True)
    parser.add_argument("--v4-final", type=Path, required=True)
    parser.add_argument("--v4-pins", type=Path, required=True)
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    args = parser.parse_args()
    try:
        pin_document = json.loads(_private_read(args.pins, 8192),
                                  object_pairs_hook=_unique_pairs)
        pins = CreateNegativePins(
            v4=load_v4_final_pins(args.v4_pins), **pin_document,
        )
    except (OSError, ValueError, TypeError) as error:
        raise OperatorDenied("private negative observation pins are invalid") from error
    print(json.dumps(join_negative_refusal_observation(
        task_dir=args.task_dir, task_id=args.task_id,
        source_v4_paths=(args.v4_baseline, args.v4_candidate,
                         args.v4_final),
        setup_path=args.setup, baseline_path=args.baseline,
        observation_path=args.observation, pins=pins,
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
