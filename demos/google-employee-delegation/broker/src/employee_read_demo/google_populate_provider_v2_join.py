"""Join a task's one planned population to independent Google after-state.

The caller must obtain task activity from the pinned gateway executable and
the provider verdict from ``validate_populate_provider_final_v2``. This join
never turns a response or provider observation into retry authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from .contracts import commitment
from .demo_co_contract import ContractRejected, _unique_pairs
from .google_create_handoff import CHILD_TITLE
from .google_populate_failure_handoff import HEX64, _identifier
from .task_write_proofs import task_commitment


_PREFLIGHT = re.compile(r"populate-preflight-[A-Za-z0-9_-]{1,32}-[0-9a-f]{16}\.json\Z")
_CREATE_STAGES = {"unknown", "response-recorded", "observed"}
_POPULATE_STAGES = {"unknown", "response-recorded", "observed", "observed-by-provider"}
_POPULATE_RESULTS = _POPULATE_STAGES


def _private_json(path: Path, limit: int) -> tuple[dict, bytes]:
    if (path.is_symlink() or not path.is_file()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or path.stat().st_size > limit):
        raise ContractRejected("private task record is unavailable")
    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError) as error:
        raise ContractRejected("private task record is malformed") from error
    if type(value) is not dict:
        raise ContractRejected("private task record is malformed")
    return value, raw


def join_populate_provider_final_v2(
    task_dir: Path, preflight_path: Path,
    activity: dict, lineage: dict, provider: dict,
) -> dict:
    """Return a redacted correlation only for one exact task/effect lineage."""
    if (task_dir.is_symlink() or not task_dir.is_dir()
            or task_dir.stat().st_uid != os.getuid()
            or stat.S_IMODE(task_dir.stat().st_mode) & 0o077
            or not _identifier(task_dir.name)
            or preflight_path.parent != task_dir
            or _PREFLIGHT.fullmatch(preflight_path.name) is None):
        raise ContractRejected("private task lineage is unavailable")
    task_id = task_dir.name
    card, _ = _private_json(task_dir / "task-card.json", 32_768)
    plan, _ = _private_json(task_dir / "effect-plan.json", 64_000)
    baseline, _ = _private_json(task_dir / "pre-create-baseline.json", 8_192)
    entry, _ = _private_json(task_dir / "populate-entry.json", 8_192)
    result, _ = _private_json(task_dir / "populate-result.json", 8_192)
    preflight, preflight_raw = _private_json(preflight_path, 8_192)
    if any((task_dir / name).exists() for name in (
            "populate-recovery-entry.json", "populate-recovery-result.json")):
        raise ContractRejected("provider v2 join cannot hide a second population handoff")
    pending = card.get("pending_child")
    create = plan.get("create")
    statement = preflight.get("statement")
    task = activity.get("task") if type(activity) is dict else None
    writes = activity.get("write_attempts") if type(activity) is dict else None
    required_provider = (
        "company_id", "jules_subject", "source_document_id", "run_folder_id",
        "marker", "child_id", "tab_id", "precreate_sha256",
        "precreate_observed_at", "setup_sha256", "final_sha256",
        "expected_raw_sha256",
    )
    if (type(provider) is not dict
            or any(type(provider.get(key)) is not str or not provider[key]
                   for key in required_provider)):
        raise ContractRejected("provider v2 verdict is incomplete")
    if type(plan.get("initial_text")) is not str:
        raise ContractRejected("provider v2 plan has no exact content")
    try:
        planned_raw = b"\xef\xbb\xbf" + plan["initial_text"].encode("utf-8")
    except UnicodeEncodeError as error:
        raise ContractRejected("provider v2 plan content is not UTF-8") from error
    if (type(provider) is not dict
            or provider.get("schema") != "auths.ap071-populate-provider-final-join/1"
            or provider.get("authority") != "provider_state_only"
            or provider.get("status") != "exact_populated"
            or provider.get("content_matches") is not True
            or provider.get("retry_authorized") is not False
            or type(provider.get("source_raw_byte_count")) is not int
            or type(card) is not dict
            or card.get("schema") != "auths.agent-task/2"
            or card.get("task_id") != task_id
            or card.get("company_id") != provider.get("company_id")
            or card.get("write_approval_mode") != "exact"
            or not _identifier(card.get("human_principal"))
            or not _identifier(card.get("agent_principal"))
            or card.get("human_principal") == card.get("agent_principal")
            or card.get("max_provider_calls") != 1
            or card.get("max_releases") != 1
            or card.get("max_writes") != 2
            or type(card.get("max_release_bytes")) is not int
            or card["max_release_bytes"] < provider.get("source_raw_byte_count", -1)
            or card.get("connection_subject") != provider.get("jules_subject")
            or type(card.get("read_scopes")) is not list
            or len(card["read_scopes"]) != 1
            or type(card["read_scopes"][0]) is not dict
            or card["read_scopes"][0].get("handle")
                != provider.get("source_document_id")
            or card["read_scopes"][0].get("connection_subject")
                != card.get("connection_subject")
            or type(card.get("write_scopes")) is not list
            or len(card["write_scopes"]) != 1
            or type(card["write_scopes"][0]) is not dict
            or type(pending) is not dict
            or pending.get("parent_handle") != provider.get("run_folder_id")
            or pending.get("marker") != provider.get("marker")
            or card["write_scopes"][0].get("handle")
                != pending.get("parent_handle")
            or card["write_scopes"][0].get("verb") != "create"
            or card["write_scopes"][0].get("recipe_digest")
                != pending.get("create_recipe_digest")
            or pending.get("title") != CHILD_TITLE
            or type(plan) is not dict
            or plan.get("schema") != "auths.agent-effect-plan/1"
            or plan.get("task_id") != task_id
            or type(provider.get("expected_raw_byte_count")) is not int
            or len(planned_raw) != provider["expected_raw_byte_count"]
            or provider["expected_raw_sha256"] != hashlib.sha256(planned_raw).hexdigest()
            or type(create) is not dict
            or create.get("task_id") != task_id
            or not _identifier(create.get("operation_id"))
            or create.get("operation_id") != pending.get("create_operation_id")
            or create.get("recipe_digest") != pending.get("create_recipe_digest")
            or create.get("resource_handle") != pending.get("parent_handle")
            or create.get("verb") != "create"
            or create.get("connection_id") != card.get("connection_id")
            or create.get("connection_generation")
                != card.get("connection_generation")
            or create.get("connection_subject")
                != card.get("connection_subject")
            or plan.get("populate_recipe_digest")
                != pending.get("populate_recipe_digest")
            or type(plan.get("populate_operation_id")) is not str
            or not _identifier(plan["populate_operation_id"])):
        raise ContractRejected("provider v2 task and plan differ from exact effect")
    try:
        actual_task_commitment = task_commitment(card)
        actual_plan_commitment = commitment("auths.agent-effect-plan.v1", plan)
    except (RuntimeError, TypeError, ValueError) as error:
        raise ContractRejected("provider v2 native commitments are unavailable") from error
    if plan.get("task_commitment") != actual_task_commitment:
        raise ContractRejected("provider v2 plan is not bound to task card")
    if (baseline != {
            "schema": "auths.ap071-pre-create-baseline-populate-failure/1",
            "task_id": task_id,
            "create_operation_id": create["operation_id"],
            "marker": provider["marker"],
            "generation": provider.get("precreate_generation"),
            "observation_sha256": provider.get("precreate_sha256"),
            "observed_at": provider.get("precreate_observed_at"),
            "parent_id": provider["run_folder_id"],
            "setup_generation": provider.get("setup_generation"),
            "setup_sha256": provider.get("setup_sha256"),
        }
            or entry != {
                "schema": "auths.ap071-populate-entry/1",
                "task_id": task_id,
                "child_id": provider["child_id"],
                "populate_operation_id": plan["populate_operation_id"],
                "baseline_sha256": provider["precreate_sha256"],
                "preflight_sha256": hashlib.sha256(preflight_raw).hexdigest(),
            }
            or result != {
                "schema": "auths.ap071-populate-result/1",
                "task_id": task_id,
                "populate_operation_id": plan["populate_operation_id"],
                "outcome": result.get("outcome"),
            }
            or result["outcome"] not in _POPULATE_RESULTS):
        raise ContractRejected("provider v2 private handoff differs from plan")
    values = statement.get("provider_values") if type(statement) is dict else None
    digests = statement.get("evidence_digests") if type(statement) is dict else None
    if (type(statement) is not dict
            or statement.get("schema") != "auths.gateway-task-populate-preflight/2"
            or statement.get("task_id") != task_id
            or statement.get("task_commitment") != plan.get("task_commitment")
            or statement.get("plan_commitment") != actual_plan_commitment
            or statement.get("create_operation_id") != create["operation_id"]
            or statement.get("child_id") != provider["child_id"]
            or statement.get("populate_recipe_digest")
                != plan["populate_recipe_digest"]
            or statement.get("connection_id") != card.get("connection_id")
            or statement.get("connection_generation")
                != card.get("connection_generation")
            or statement.get("connection_subject")
                != card.get("connection_subject")
            or set(preflight) != {"statement", "signature_b64"}
            or type(preflight["signature_b64"]) is not str
            or not 80 <= len(preflight["signature_b64"]) <= 90
            or type(values) is not dict
            or set(values) != {"tab_id", "required_revision_id"}
            or values.get("tab_id") != provider.get("tab_id")
            or not _identifier(values.get("required_revision_id"))
            or type(digests) is not dict
            or set(digests) != {"metadata", "capability", "document"}
            or any(type(value) is not str or HEX64.fullmatch(value) is None
                   for value in digests.values())):
        raise ContractRejected("provider v2 Jules preflight differs from bound child")
    try:
        signature = base64.b64decode(
            preflight["signature_b64"] + "==", validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise ContractRejected("provider v2 preflight signature is malformed") from error
    if (len(signature) != 64
            or type(lineage) is not dict
            or lineage != {
                "schema": "auths.gateway-task-population-lineage/1",
                "task_id": task_id,
                "plan_commitment": actual_plan_commitment,
                "create_operation_id": create["operation_id"],
                "populate_operation_id": plan["populate_operation_id"],
                "child_id": provider["child_id"],
                "preflight_signature_sha256": hashlib.sha256(signature).hexdigest(),
            }):
        raise ContractRejected("provider v2 gateway preflight lineage differs")
    if (type(activity) is not dict
            or activity.get("schema") != "auths.gateway-agent-task-activity/1"
            or type(task) is not dict
            or task.get("schema") != "auths.gateway-agent-task-status/1"
            or task.get("task_id") != task_id
            or task.get("provider_calls") != 1
            or task.get("releases") != 1
            or task.get("released_bytes") != provider.get("source_raw_byte_count")
            or task.get("writes") != 2
            or task.get("max_provider_calls") != 1
            or task.get("max_releases") != 1
            or task.get("max_writes") != 2
            or task.get("write_operations") != [
                create["operation_id"], plan["populate_operation_id"]]
            or type(task.get("reads")) is not list
            or len(task["reads"]) != 1
            or type(task["reads"][0]) is not dict
            or task["reads"][0].get("stage") != "agent-acknowledged"
            or task["reads"][0].get("released_bytes")
                != provider.get("source_raw_byte_count")
            or type(writes) is not list or len(writes) != 2
            or any(type(item) is not dict for item in writes)):
        raise ContractRejected("provider v2 gateway activity differs from task")
    by_operation = {item.get("operation_id"): item for item in writes}
    if (len(by_operation) != 2
            or set(by_operation) != {create["operation_id"],
                                     plan["populate_operation_id"]}
            or by_operation[create["operation_id"]].get("stage")
                not in _CREATE_STAGES
            or by_operation[plan["populate_operation_id"]].get("stage")
                not in _POPULATE_STAGES
            or by_operation[plan["populate_operation_id"]].get("stage")
                == "claimed-no-attempt"
            or result["outcome"] == "unknown"
                and by_operation[plan["populate_operation_id"]].get("stage")
                    != "unknown"
            or result["outcome"] == "response-recorded"
                and by_operation[plan["populate_operation_id"]].get("stage")
                    not in {"response-recorded", "observed"}
            or result["outcome"] == "observed"
                and by_operation[plan["populate_operation_id"]].get("stage")
                    != "observed"
            or result["outcome"] == "observed-by-provider"
                and by_operation[plan["populate_operation_id"]].get("stage")
                    != "observed-by-provider"):
        raise ContractRejected("provider v2 attempt lineage differs from task")
    populate_attempt = by_operation[plan["populate_operation_id"]]
    stage = populate_attempt["stage"]
    status = populate_attempt.get("response_status")
    observed = populate_attempt.get("observation_match")
    if (stage == "unknown" and (status is not None or observed is not None)
            or stage != "unknown" and (type(status) is not int or not 200 <= status < 300)
            or stage == "observed" and observed is not True
            or stage == "response-recorded" and observed is not None):
        raise ContractRejected("provider v2 population attempt is not a successful response")
    return {
        "schema": "auths.ap071-populate-task-provider-join/1",
        "status": "joined",
        "task_id": task_id,
        "child_id": provider["child_id"],
        "create_operation_id": create["operation_id"],
        "populate_operation_id": plan["populate_operation_id"],
        "population_outcome": result["outcome"],
        "provider_state": "exact_populated",
        "provider_final_generation": provider["final_generation"],
        "provider_final_sha256": provider["final_sha256"],
        "retry_authorized": False,
    }
