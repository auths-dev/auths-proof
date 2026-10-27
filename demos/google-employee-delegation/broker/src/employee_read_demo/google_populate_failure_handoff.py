"""Pin demo_co's isolated population-failure setup before issuing a task.

The producer setup identifies a disposable run folder and marker. It grants no
create, child-binding or population authority; those remain signed Auths facts.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from importlib.resources import files
from pathlib import Path

from .timestamps import parse_aware_timestamp
from .contracts import commitment
from .demo_co_contract import ContractRejected, _load, _unique_pairs
from .google_create_handoff import CHILD_TITLE, MARKER
from .google_create_v4_handoff import (
    CreateV4FinalPins, validate_create_v4_observation,
)


SETUP_SCHEMA = "google-populate-failure-setup-v1.schema.json"
SETUP_SCHEMA_SHA256 = "443b92143dbae4beea74be280655eecd7296becef28cf8107ff146bdf1ec7bce"
PRECREATE_SCHEMA = "google-populate-precreate-baseline-v1.schema.json"
PRECREATE_SCHEMA_SHA256 = "48bcc13a3242b0e2641a97f6e656402ed45d66b2ae936ed7402cca325fb97625"
BLANK_SCHEMA = "google-populate-blank-baseline-v1.schema.json"
BLANK_SCHEMA_SHA256 = "c3e77c807c7ce4dbfb911ee72dbd8275570636d04a6cede0a9ae301ed476c1a5"
DENIAL_SCHEMA = "google-populate-denial-v1.schema.json"
DENIAL_SCHEMA_SHA256 = "64070c9319310aba683d0a4431475c315d45c714d3d857381c557aa1dfbd7815"
RECOVERY_SCHEMA = "google-populate-denial-recovery-v1.schema.json"
RECOVERY_SCHEMA_SHA256 = "c8322bd0a082c7fe40e0118c86633c357b7abfac0fc1990d29b2c2555dec7329"
POST_ENTRY_SCHEMA = "google-populate-post-entry-observation-v1.schema.json"
POST_ENTRY_SCHEMA_SHA256 = "8ef317accf40827a67e5fb40b55d070271124c0be184e430edf2d3dea103b898"
BLANK_SHA256 = "f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
RUN_ID = re.compile(r"[a-z][a-z0-9-]{1,40}\Z")


@dataclass(frozen=True)
class PopulateFailureTarget:
    run_id: str
    marker: str
    parent_id: str
    setup_generation: int
    setup_sha256: str
    case: str = "populate-failure"


def _identifier(value: object) -> bool:
    return (type(value) is str and 1 <= len(value) <= 256
            and not any(character.isspace() for character in value))


def _timestamp(value: object) -> datetime:
    if type(value) is not str:
        raise ContractRejected("populate setup time is invalid")
    try:
        result = parse_aware_timestamp(value)
    except ValueError as error:
        raise ContractRejected("populate setup time is invalid") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ContractRejected("populate setup time lacks timezone")
    return result


def validate_populate_failure_setup(
    source_v4_baseline_path: Path,
    source_v4_candidate_path: Path,
    source_v4_final_path: Path,
    setup_path: Path,
    setup_sha256: str,
    v4: CreateV4FinalPins,
) -> PopulateFailureTarget:
    """Accept only a frozen setup for a new, isolated Project A scratch run."""
    v4.validate()
    validate_create_v4_observation(source_v4_baseline_path,
                                   source_v4_candidate_path,
                                   source_v4_final_path, v4)
    location = GENERATION.fullmatch(setup_path.parent.name)
    if (location is None or setup_path.name != "google-populate-failure-setup.json"
            or setup_path.parent.is_symlink() or not setup_path.parent.is_dir()
            or stat.S_IMODE(setup_path.parent.stat().st_mode) & 0o077
            or setup_path.is_symlink() or not setup_path.is_file()
            or stat.S_IMODE(setup_path.stat().st_mode) & 0o077
            or type(setup_sha256) is not str
            or HEX64.fullmatch(setup_sha256) is None):
        raise ContractRejected("populate setup location or digest is invalid")
    schema = files("employee_read_demo").joinpath("schemas", SETUP_SCHEMA).read_bytes()
    if hashlib.sha256(schema).hexdigest() != SETUP_SCHEMA_SHA256:
        raise ContractRejected("populate setup schema differs from reviewed bytes")
    setup, raw = _load(setup_path, SETUP_SCHEMA)
    if hashlib.sha256(raw).hexdigest() != setup_sha256:
        raise ContractRejected("populate setup differs from pinned bytes")
    source = v4.candidate.baseline
    if (setup.get("schema_version") != "demo-co/google-populate-failure-setup/v1"
            or setup.get("status") != "ready"
            or setup.get("attribution") != "producer_setup_only"
            or setup.get("company") != source.company
            or setup.get("instance") != source.instance
            or setup.get("definition_hash") != source.definition_hash
            or setup.get("drive_id") != source.drive_id
            or setup.get("project_a_folder_id") != source.folder_id
            or setup.get("jules_subject") != source.jules_subject
            or setup.get("source_v4_baseline_generation")
                != source.baseline_generation
            or setup.get("source_v4_baseline_sha256")
                != source.baseline_sha256
            or setup.get("source_v4_final_generation")
                != v4.observation_generation
            or setup.get("source_v4_final_sha256")
                != v4.observation_sha256
            or type(setup.get("run_id")) is not str
            or RUN_ID.fullmatch(setup["run_id"]) is None
            or type(setup.get("marker")) is not str
            or MARKER.fullmatch(setup["marker"]) is None
            or not _identifier(setup.get("scratch_root_id"))
            or not _identifier(setup.get("run_folder_id"))
            or len({source.folder_id, setup["scratch_root_id"],
                    setup["run_folder_id"]}) != 3
            or setup["marker"] in (*source.prior_markers,
                                   v4.candidate.marker)):
        raise ContractRejected("populate setup differs from frozen v4 source")
    _timestamp(setup.get("observed_at"))
    generation = int(location.group(1))
    if generation <= v4.observation_generation:
        raise ContractRejected("populate setup predates v4 final observation")
    return PopulateFailureTarget(setup["run_id"], setup["marker"],
                                 setup["run_folder_id"], generation,
                                 setup_sha256)


def validate_populate_precreate_baseline(
    source_v4_baseline_path: Path,
    source_v4_candidate_path: Path,
    source_v4_final_path: Path,
    setup_path: Path,
    setup_sha256: str,
    baseline_path: Path,
    baseline_sha256: str,
    v4: CreateV4FinalPins,
    *,
    now: int,
) -> tuple[PopulateFailureTarget, int, dict]:
    """Require a complete, recent zero-match check after the signed plan."""
    target = validate_populate_failure_setup(
        source_v4_baseline_path, source_v4_candidate_path,
        source_v4_final_path, setup_path, setup_sha256, v4,
    )
    location = GENERATION.fullmatch(baseline_path.parent.name)
    if (location is None
            or int(location.group(1)) <= target.setup_generation
            or baseline_path.name != "google-populate-precreate-baseline.json"
            or baseline_path.parent.is_symlink()
            or not baseline_path.parent.is_dir()
            or stat.S_IMODE(baseline_path.parent.stat().st_mode) & 0o077
            or baseline_path.is_symlink() or not baseline_path.is_file()
            or stat.S_IMODE(baseline_path.stat().st_mode) & 0o077
            or type(baseline_sha256) is not str
            or HEX64.fullmatch(baseline_sha256) is None):
        raise ContractRejected("populate pre-create baseline location is invalid")
    schema = files("employee_read_demo").joinpath("schemas", PRECREATE_SCHEMA).read_bytes()
    if hashlib.sha256(schema).hexdigest() != PRECREATE_SCHEMA_SHA256:
        raise ContractRejected("populate pre-create schema differs from reviewed bytes")
    baseline, raw = _load(baseline_path, PRECREATE_SCHEMA)
    if hashlib.sha256(raw).hexdigest() != baseline_sha256:
        raise ContractRejected("populate pre-create baseline differs from pin")
    setup, _ = _load(setup_path, SETUP_SCHEMA)
    source = v4.candidate.baseline
    if (baseline.get("schema_version")
            != "demo-co/google-populate-precreate-baseline/v1"
            or baseline.get("status") != "ready"
            or baseline.get("attribution") != "provider_state_only"
            or baseline.get("setup_generation") != target.setup_generation
            or baseline.get("setup_sha256") != target.setup_sha256
            or baseline.get("company") != source.company
            or baseline.get("instance") != source.instance
            or baseline.get("definition_hash") != source.definition_hash
            or baseline.get("drive_id") != source.drive_id
            or baseline.get("project_a_folder_id") != source.folder_id
            or baseline.get("scratch_root_id") != setup["scratch_root_id"]
            or baseline.get("run_folder_id") != target.parent_id
            or baseline.get("run_id") != target.run_id
            or baseline.get("marker") != target.marker
            or baseline.get("project_a_direct_child_count") != 8
            or baseline.get("provider_search_complete") is not True
            or baseline.get("provider_match_count") != 0
            or baseline.get("run_child_count") != 0
            or any(baseline.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged", "jules_project_b_write_denied"))):
        raise ContractRejected("populate pre-create baseline differs from setup")
    setup_time = _timestamp(setup.get("observed_at"))
    baseline_time = _timestamp(baseline.get("observed_at"))
    age = datetime.fromtimestamp(now, tz=baseline_time.tzinfo) - baseline_time
    if not setup_time <= baseline_time or not timedelta(0) <= age <= timedelta(minutes=5):
        raise ContractRejected("populate pre-create baseline is stale or reordered")
    return target, int(location.group(1)), baseline


def _pinned_observation(path: Path, digest: str, name: str,
                        schema_name: str, schema_digest: str) -> tuple[int, dict]:
    location = GENERATION.fullmatch(path.parent.name)
    if (location is None or path.name != name or path.parent.is_symlink()
            or not path.parent.is_dir()
            or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
            or path.is_symlink() or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or type(digest) is not str or HEX64.fullmatch(digest) is None):
        raise ContractRejected("populate observation location or digest is invalid")
    schema = files("employee_read_demo").joinpath("schemas", schema_name).read_bytes()
    if hashlib.sha256(schema).hexdigest() != schema_digest:
        raise ContractRejected("populate observation schema differs from reviewed bytes")
    document, raw = _load(path, schema_name)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ContractRejected("populate observation differs from pinned bytes")
    return int(location.group(1)), document


def validate_populate_denial_recovery(
    source_v4_paths: tuple[Path, Path, Path],
    setup_path: Path, setup_sha256: str,
    precreate_path: Path, precreate_sha256: str,
    blank_path: Path, blank_sha256: str,
    denial_path: Path, denial_sha256: str,
    recovery_path: Path, recovery_sha256: str,
    v4: CreateV4FinalPins, *, expected_text: str,
) -> dict:
    """Join four immutable provider observations; grant no Auths authority."""
    if type(expected_text) is not str or not 1 <= len(expected_text.encode()) <= 16_384:
        raise ContractRejected("approved population text is unavailable")
    target, precreate_generation, precreate = validate_populate_precreate_baseline(
        *source_v4_paths, setup_path, setup_sha256,
        precreate_path, precreate_sha256, v4,
        now=int(_timestamp(_pinned_observation(
            blank_path, blank_sha256, "google-populate-blank-baseline.json",
            BLANK_SCHEMA, BLANK_SCHEMA_SHA256,
        )[1]["observed_at"]).timestamp()),
    )
    blank_generation, blank = _pinned_observation(
        blank_path, blank_sha256, "google-populate-blank-baseline.json",
        BLANK_SCHEMA, BLANK_SCHEMA_SHA256,
    )
    denial_generation, denial = _pinned_observation(
        denial_path, denial_sha256, "google-populate-denial.json",
        DENIAL_SCHEMA, DENIAL_SCHEMA_SHA256,
    )
    recovery_generation, recovery = _pinned_observation(
        recovery_path, recovery_sha256, "google-populate-denial-recovery.json",
        RECOVERY_SCHEMA, RECOVERY_SCHEMA_SHA256,
    )
    setup, _ = _load(setup_path, SETUP_SCHEMA)
    common = {
        "company": setup["company"], "instance": setup["instance"],
        "definition_hash": setup["definition_hash"],
        "drive_id": setup["drive_id"], "run_id": target.run_id,
        "run_folder_id": target.parent_id, "marker": target.marker,
    }
    if (not precreate_generation < blank_generation < denial_generation
            < recovery_generation
            or any(any(document.get(key) != value for key, value in common.items())
                   for document in (blank, denial, recovery))
            or any(any(document.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged", "jules_project_b_write_denied"))
                   for document in (blank, denial, recovery))
            or any(document.get("project_a_direct_child_count") != 8
                   or document.get("marker_match_count") != 1
                   or document.get("run_child_count") != 1
                   or document.get("attribution") != "provider_state_only"
                   for document in (blank, denial, recovery))):
        raise ContractRejected("populate observations crossed run identity")
    child = blank.get("child_id")
    created_at = _timestamp(blank.get("child_created_at"))
    before_time = _timestamp(precreate["observed_at"])
    blank_time = _timestamp(blank["observed_at"])
    denial_time = _timestamp(denial["observed_at"])
    recovery_time = _timestamp(recovery["observed_at"])
    if (not _identifier(child) or blank.get("child_title") != CHILD_TITLE
            or blank.get("setup_generation") != target.setup_generation
            or blank.get("setup_sha256") != target.setup_sha256
            or blank.get("status") != "ready"
            or blank.get("raw_byte_count") != 3
            or blank.get("raw_sha256") != BLANK_SHA256
            or not before_time <= created_at <= blank_time <= denial_time <= recovery_time
            or created_at - before_time > timedelta(minutes=5)
            or any(document.get("child_id") != child
                   or document.get("child_created_at") != blank["child_created_at"]
                   or document.get("tab_id") != blank.get("tab_id")
                   for document in (denial, recovery))):
        raise ContractRejected("populate blank child or observation order changed")
    if (denial.get("blank_baseline_generation") != blank_generation
            or denial.get("blank_baseline_sha256") != blank_sha256
            or denial.get("status") != "blank_unchanged_after_gateway_denial"
            or denial.get("denial_mechanism") != "gateway_denied_before_provider_entry"
            or denial.get("gateway_denial_attested") is not False
            or denial.get("provider_entry_attested") is not False
            or denial.get("unchanged_admin_revision_id") != blank.get("admin_revision_id")
            or denial.get("unchanged_raw_byte_count") != 3
            or denial.get("unchanged_raw_sha256") != BLANK_SHA256):
        raise ContractRejected("populate denial provider state changed")
    expected = b"\xef\xbb\xbf" + expected_text.encode()
    expected_sha256 = hashlib.sha256(expected).hexdigest()
    if (recovery.get("denial_generation") != denial_generation
            or recovery.get("denial_sha256") != denial_sha256
            or recovery.get("failure_generation") != denial_generation
            or recovery.get("failure_sha256") != denial_sha256
            or recovery.get("status") != "populated_same_child"
            or recovery.get("exact_expected_content") is not True
            or recovery.get("expected_raw_byte_count") != len(expected)
            or recovery.get("expected_raw_sha256") != expected_sha256
            or recovery.get("final_admin_revision_id") == blank.get("admin_revision_id")):
        raise ContractRejected("populate recovery differs from approved bytes")
    return {
        "run_id": target.run_id, "run_folder_id": target.parent_id,
        "marker": target.marker, "child_id": child,
        "precreate_generation": precreate_generation,
        "precreate_sha256": precreate_sha256,
        "blank_generation": blank_generation,
        "denial_generation": denial_generation,
        "recovery_generation": recovery_generation,
        "expected_raw_sha256": expected_sha256,
        "expected_raw_byte_count": len(expected),
        "authority": "provider_state_only",
    }


def validate_populate_post_entry(
    source_v4_paths: tuple[Path, Path, Path],
    setup_path: Path, setup_sha256: str,
    precreate_path: Path, precreate_sha256: str,
    blank_path: Path, blank_sha256: str,
    post_path: Path, post_sha256: str,
    v4: CreateV4FinalPins, *, expected_text: str,
    bounded_observation_generation: int,
    bounded_observation_sha256: str,
) -> dict:
    """Join immutable Google observations after an entered population response is lost.

    This proves provider state only. Auths's separate attempt and one-use fault
    records establish entry and response loss; this verdict never permits retry.
    """
    if (type(expected_text) is not str
            or not 1 <= len(expected_text.encode("utf-8")) <= 16_384
            or type(bounded_observation_generation) is not int
            or bounded_observation_generation < 1
            or type(bounded_observation_sha256) is not str
            or HEX64.fullmatch(bounded_observation_sha256) is None):
        raise ContractRejected("post-entry content or bounded pin is invalid")
    blank_generation, blank = _pinned_observation(
        blank_path, blank_sha256, "google-populate-blank-baseline.json",
        BLANK_SCHEMA, BLANK_SCHEMA_SHA256,
    )
    target, precreate_generation, precreate = validate_populate_precreate_baseline(
        *source_v4_paths, setup_path, setup_sha256,
        precreate_path, precreate_sha256, v4,
        now=int(_timestamp(blank.get("observed_at")).timestamp()),
    )
    post_generation, post = _pinned_observation(
        post_path, post_sha256, "google-populate-post-entry-observation.json",
        POST_ENTRY_SCHEMA, POST_ENTRY_SCHEMA_SHA256,
    )
    setup, _ = _load(setup_path, SETUP_SCHEMA)
    source = v4.candidate.baseline
    expected = b"\xef\xbb\xbf" + expected_text.encode("utf-8")
    expected_digest = hashlib.sha256(expected).hexdigest()
    child = blank.get("child_id")
    common = {
        "company": source.company, "instance": source.instance,
        "definition_hash": source.definition_hash, "drive_id": source.drive_id,
        "run_id": target.run_id, "run_folder_id": target.parent_id,
        "marker": target.marker,
    }
    if (not precreate_generation < blank_generation < post_generation
            or any(any(document.get(key) != value for key, value in common.items())
                   for document in (blank, post))
            or any(any(document.get(key) is not True for key in (
                "original_seven_unchanged", "canonical_project_a_unchanged",
                "canonical_project_b_unchanged"))
                   for document in (blank, post))
            or blank.get("schema_version")
                != "demo-co/google-populate-blank-baseline/v1"
            or blank.get("status") != "ready"
            or blank.get("attribution") != "provider_state_only"
            or blank.get("setup_generation") != target.setup_generation
            or blank.get("setup_sha256") != target.setup_sha256
            or blank.get("child_title") != CHILD_TITLE
            or blank.get("marker_match_count") != 1
            or blank.get("run_child_count") != 1
            or blank.get("raw_byte_count") != 3
            or blank.get("raw_sha256") != BLANK_SHA256
            or not _identifier(child)
            or not _identifier(blank.get("tab_id"))
            or not _identifier(blank.get("admin_revision_id"))
            or post.get("schema_version")
                != "demo-co/google-populate-post-entry-observation/v1"
            or post.get("status") != "exact_populated"
            or post.get("attribution") != "provider_state_only"
            or post.get("project_a_folder_id") != source.folder_id
            or post.get("scratch_root_id") != setup["scratch_root_id"]
            or post.get("child_id") != child
            or post.get("child_created_at") != blank.get("child_created_at")
            or post.get("tab_id") != blank.get("tab_id")
            or post.get("blank_baseline_generation") != blank_generation
            or post.get("blank_baseline_sha256") != blank_sha256
            or post.get("blank_admin_revision_id") != blank.get("admin_revision_id")
            or post.get("blank_raw_sha256") != BLANK_SHA256
            or post.get("observed_admin_revision_id") == blank.get("admin_revision_id")
            or post.get("revision_changed") is not True
            or post.get("provider_match_count") != 1
            or post.get("run_child_count") != 1
            or post.get("exact_scratch_root_children") is not True
            or post.get("bounded_document_unchanged") is not True
            or post.get("bounded_observation_generation")
                != bounded_observation_generation
            or post.get("bounded_observation_sha256")
                != bounded_observation_sha256
            or post.get("exact_expected_content") is not True
            or post.get("still_exactly_blank") is not False
            or post.get("provider_entry_attested") is not False
            or post.get("retry_authorized") is not False
            or post.get("run_marker_occurrences_in_content") != 0
            or post.get("expected_raw_byte_count") != len(expected)
            or post.get("observed_raw_byte_count") != len(expected)
            or post.get("expected_raw_sha256") != expected_digest
            or post.get("observed_raw_sha256") != expected_digest):
        raise ContractRejected("post-entry observation differs from approved run")
    before = _timestamp(precreate["observed_at"])
    created = _timestamp(blank["child_created_at"])
    blank_time = _timestamp(blank["observed_at"])
    after = _timestamp(post["observed_at"])
    if not before <= created <= blank_time < after:
        raise ContractRejected("post-entry observation order changed")
    return {
        "authority": "provider_state_only", "retry_authorized": False,
        "run_id": target.run_id, "run_folder_id": target.parent_id,
        "marker": target.marker, "child_id": child,
        "precreate_generation": precreate_generation,
        "precreate_sha256": precreate_sha256,
        "blank_generation": blank_generation,
        "blank_sha256": blank_sha256,
        "post_generation": post_generation,
        "post_sha256": post_sha256,
        "expected_raw_sha256": expected_digest,
        "expected_raw_byte_count": len(expected),
        "status": "exact_populated",
    }


def join_populate_post_entry(
    task_dir: Path, gateway_status: dict, support_bundle: dict,
    consumed_arm: dict, population_review: dict, provider: dict,
    *, gateway_sha256: str,
) -> dict:
    """Join one unknown Auths attempt to independent exact Google after-state."""
    if (task_dir.is_symlink() or not task_dir.is_dir()
            or stat.S_IMODE(task_dir.stat().st_mode) & 0o077):
        raise ContractRejected("private post-entry task journal is unavailable")

    def read(name: str) -> dict:
        path = task_dir / name
        if (path.is_symlink() or not path.is_file()
                or stat.S_IMODE(path.stat().st_mode) & 0o077
                or path.stat().st_size > 16_384):
            raise ContractRejected("post-entry task record is unavailable")
        try:
            value = json.loads(path.read_bytes(), object_pairs_hook=_unique_pairs)
        except (OSError, ValueError) as error:
            raise ContractRejected("post-entry task record is malformed") from error
        if type(value) is not dict:
            raise ContractRejected("post-entry task record is malformed")
        return value

    if any((task_dir / name).exists() for name in (
            "populate-recovery-entry.json", "populate-recovery-result.json")):
        raise ContractRejected("an unknown population cannot use pre-entry recovery")
    task_id = task_dir.name
    card = read("task-card.json")
    plan = read("effect-plan.json")
    baseline = read("pre-create-baseline.json")
    entry = read("populate-entry.json")
    result = read("populate-result.json")
    create = plan.get("create") if type(plan) is dict else None
    pop_id = plan.get("populate_operation_id")
    attempts = support_bundle.get("attempts") if type(support_bundle) is dict else None
    pending = card.get("pending_child") if type(card) is dict else None
    arguments = (population_review.get("arguments")
                 if type(population_review) is dict else None)
    request = (population_review.get("request")
               if type(population_review) is dict else None)
    if (type(arguments) is not dict or type(request) is not dict
            or population_review.get("schema")
                != "auths.gateway-submission-review/1"
            or population_review.get("actors") != [card.get("agent_principal")]
            or arguments.get("task_id") != task_id
            or arguments.get("operation_id") != pop_id
            or arguments.get("document_id") != provider.get("child_id")
            or arguments.get("text") != plan.get("initial_text")
            or request.get("method") != "POST"
            or type(request.get("url")) is not str
            or provider.get("child_id") not in request["url"]
            or type(request.get("content_type")) is not str
            or type(request.get("headers")) is not list
            or type(request.get("body")) is not str):
        raise ContractRejected("native population review differs from plan")
    request_commitment = commitment("auths.agent-write-request.v1", {
        "method": request["method"], "url": request["url"],
        "content_type": request["content_type"],
        "headers": request["headers"],
        "body_hex": request["body"].encode("utf-8").hex(),
    })
    if (type(create) is not dict
            or type(pending) is not dict
            or card.get("task_id") != task_id
            or pending.get("parent_handle") != provider.get("run_folder_id")
            or pending.get("marker") != provider.get("marker")
            or create.get("resource_handle") != pending.get("parent_handle")
            or create.get("operation_id") != pending.get("create_operation_id")
            or plan.get("populate_recipe_digest")
                != pending.get("populate_recipe_digest")
            or plan.get("schema") != "auths.agent-effect-plan/1"
            or plan.get("task_id") != task_id
            or type(plan.get("initial_text")) is not str
            or not _identifier(create.get("operation_id"))
            or not _identifier(pop_id)
            or baseline.get("schema")
                != "auths.ap071-pre-create-baseline-populate-failure/1"
            or baseline.get("task_id") != task_id
            or baseline.get("create_operation_id") != create["operation_id"]
            or baseline.get("generation") != provider.get("precreate_generation")
            or baseline.get("observation_sha256") != provider.get("precreate_sha256")
            or baseline.get("parent_id") != provider.get("run_folder_id")
            or baseline.get("marker") != provider.get("marker")
            or entry != {
                "schema": "auths.ap071-populate-entry/1", "task_id": task_id,
                "child_id": provider.get("child_id"),
                "populate_operation_id": pop_id,
                "baseline_sha256": provider.get("precreate_sha256"),
                "preflight_sha256": entry.get("preflight_sha256"),
            }
            or type(entry.get("preflight_sha256")) is not str
            or HEX64.fullmatch(entry["preflight_sha256"]) is None
            or result != {
                "schema": "auths.ap071-populate-result/1", "task_id": task_id,
                "populate_operation_id": pop_id, "outcome": "unknown",
            }
            or provider.get("authority") != "provider_state_only"
            or provider.get("retry_authorized") is not False
            or provider.get("status") != "exact_populated"
            or provider.get("expected_raw_sha256") != hashlib.sha256(
                b"\xef\xbb\xbf" + plan["initial_text"].encode()).hexdigest()
            or consumed_arm.get("schema")
                != "auths.development-populate-response-loss-arm/1"
            or consumed_arm.get("task_id") != task_id
            or consumed_arm.get("operation_id") != pop_id
            or consumed_arm.get("request_commitment")
                != request_commitment):
        raise ContractRejected("post-entry Auths records differ from provider lineage")
    if (type(gateway_status) is not dict
            or gateway_status.get("schema") != "auths.gateway-agent-task-status/1"
            or gateway_status.get("task_id") != task_id
            or gateway_status.get("revoked") is not True
            or gateway_status.get("provider_calls") != 1
            or gateway_status.get("releases") != 1
            or gateway_status.get("released_bytes") != 51
            or gateway_status.get("writes") != 2
            or gateway_status.get("write_operations")
                != [create["operation_id"], pop_id]
            or support_bundle.get("schema") != "auths.gateway-support-bundle/1"
            or support_bundle.get("build_sha256") != gateway_sha256
            or type(attempts) is not dict
            or attempts.get("listed") != 2
            or attempts.get("truncated") is not False
            or attempts.get("by_stage") != {"observed": 1, "unknown": 1}
            or type(attempts.get("identifiers")) is not list
            or len(attempts["identifiers"]) != 2
            or {item.get("stage") for item in attempts["identifiers"]
                    if type(item) is dict} != {"observed", "unknown"}):
        raise ContractRejected("gateway ledger does not prove one entered unknown population")
    return {
        "schema": "auths.ap071-populate-post-entry-join/1",
        "status": "accepted", "task_id": task_id,
        "child_id": provider["child_id"],
        "create_operation_id": create["operation_id"],
        "populate_operation_id": pop_id,
        "provider_generation": provider["post_generation"],
        "create_attempts": 1, "population_attempts": 1,
        "population_outcome": "unknown",
        "provider_state": "exact_populated",
        "retry_authorized": False,
    }


def join_populate_denial_recovery(
    task_dir: Path, gateway_status: dict, claim_records: list[dict],
    provider: dict,
) -> dict:
    """Join producer state to the one Auths task, denial and two entered writes."""
    if (task_dir.is_symlink() or not task_dir.is_dir()
            or stat.S_IMODE(task_dir.stat().st_mode) & 0o077):
        raise ContractRejected("private population task journal is unavailable")
    def read(name: str) -> dict:
        path = task_dir / name
        if (path.is_symlink() or not path.is_file()
                or stat.S_IMODE(path.stat().st_mode) & 0o077
                or path.stat().st_size > 16_384):
            raise ContractRejected("population task record is unavailable")
        try:
            result = json.loads(
                path.read_bytes(), object_pairs_hook=_unique_pairs,
            )
        except (OSError, ValueError) as error:
            raise ContractRejected("population task record is malformed") from error
        if type(result) is not dict:
            raise ContractRejected("population task record is malformed")
        return result
    plan = read("effect-plan.json")
    baseline = read("pre-create-baseline.json")
    first_entry = read("populate-entry.json")
    first_result = read("populate-result.json")
    recovery_entry = read("populate-recovery-entry.json")
    recovery_result = read("populate-recovery-result.json")
    task_id = task_dir.name
    create = plan.get("create")
    if (type(create) is not dict or type(plan.get("initial_text")) is not str
            or not _identifier(create.get("operation_id"))
            or plan.get("schema") != "auths.agent-effect-plan/1"
            or plan.get("task_id") != task_id
            or provider.get("authority") != "provider_state_only"
            or provider.get("child_id") != first_entry.get("child_id")
            or provider.get("precreate_generation") != baseline.get("generation")
            or provider.get("precreate_sha256")
                != baseline.get("observation_sha256")
            or provider.get("run_folder_id") != baseline.get("parent_id")
            or provider.get("marker") != baseline.get("marker")
            or provider.get("expected_raw_sha256") != hashlib.sha256(
                b"\xef\xbb\xbf" + plan["initial_text"].encode()).hexdigest()
            or create.get("operation_id") != baseline.get("create_operation_id")
            or create.get("resource_handle") != baseline.get("parent_id")
            or baseline.get("schema")
                != "auths.ap071-pre-create-baseline-populate-failure/1"
            or baseline.get("task_id") != task_id
            or baseline.get("observation_sha256")
                != first_entry.get("baseline_sha256")
            or baseline.get("marker") is None):
        raise ContractRejected("population task differs from provider lineage")
    pop_id = plan.get("populate_operation_id")
    entry_fields = {"schema", "task_id", "child_id", "populate_operation_id",
                    "baseline_sha256", "preflight_sha256"}
    if (not _identifier(pop_id)
            or set(first_entry) != entry_fields
            or set(recovery_entry) != entry_fields
            or any(first_entry.get(key) != recovery_entry.get(key)
                   for key in entry_fields - {"preflight_sha256"})
            or first_entry["preflight_sha256"]
                == recovery_entry["preflight_sha256"]
            or first_entry.get("schema") != "auths.ap071-populate-entry/1"
            or first_entry.get("task_id") != task_id
            or first_entry.get("populate_operation_id") != pop_id
            or first_result != {
                "schema": "auths.ap071-populate-result/1", "task_id": task_id,
                "populate_operation_id": pop_id, "outcome": "denied",
            }
            or recovery_result != {
                "schema": "auths.ap071-populate-result/1", "task_id": task_id,
                "populate_operation_id": pop_id, "outcome": "response-recorded",
            }):
        raise ContractRejected("population denial or one-time recovery changed")
    operation_ids = {create["operation_id"], pop_id}
    if (type(gateway_status) is not dict
            or gateway_status.get("schema") != "auths.gateway-agent-task-status/1"
            or gateway_status.get("task_id") != task_id
            or gateway_status.get("revoked") is not True
            or gateway_status.get("provider_calls") != 1
            or gateway_status.get("releases") != 1
            or gateway_status.get("released_bytes") != 51
            or gateway_status.get("writes") != 2
            or type(gateway_status.get("write_operations")) is not list
            or len(gateway_status["write_operations"]) != 2
            or any(type(item) is not str
                   for item in gateway_status["write_operations"])
            or set(gateway_status["write_operations"]) != operation_ids
            or type(claim_records) is not list or len(claim_records) != 2
            or any(type(item) is not dict for item in claim_records)
            or any(type(item.get("operation_id")) is not str
                   for item in claim_records)
            or {item.get("operation_id") for item in claim_records} != operation_ids
            or any(item.get("stage") not in {"observed", "response-recorded"}
                   or item.get("response_status") != 200
                   for item in claim_records)):
        raise ContractRejected("gateway ledger does not prove one create and population")
    return {
        "schema": "auths.ap071-populate-denial-recovery-join/1",
        "task_id": task_id, "child_id": provider["child_id"],
        "create_operation_id": create["operation_id"],
        "populate_operation_id": pop_id,
        "denied_population_provider_entries": 0,
        "successful_population_provider_entries": 1,
        "create_provider_entries": 1,
        "provider_generation": provider["recovery_generation"],
        "status": "accepted",
    }
