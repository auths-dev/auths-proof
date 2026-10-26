"""Pinned producer baseline and choices for the isolated upfront negative run."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

from .demo_co_contract import ContractRejected, _load
from .edit_rerun_handoff import EditRerunTarget, OPTION_A, OPTION_B
from .write_handoff import WriteHandoffPins


BASELINE_SCHEMA = "google-bounded-negative-baseline-v1.schema.json"
BASELINE_SCHEMA_SHA256 = "5ac9a8c6ac0b3721e27d8f3ad2817e76f3ea3283a2edee073be233c1013654fc"
CHOICES_SCHEMA = "google-bounded-negative-choices-v1.schema.json"
CHOICES_SCHEMA_SHA256 = "cce25d418c2df14c3cffd95e053dcf133eddf874bd68e31b5053e1438090bb64"
OBSERVATION_SCHEMA = "google-bounded-negative-observation-v1.schema.json"
OBSERVATION_SCHEMA_SHA256 = "ff8c25aea56cef6aca7dc91881d9d055990dae7eb70654c9a7e64af3731aa8f3"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
_MARKER = re.compile(r"AP071-NEG-[0-9a-f]{24}\Z")


@dataclass(frozen=True)
class BoundedNegativePins:
    producer: WriteHandoffPins
    baseline_sha256: str
    choices_sha256: str
    scratch_root_id: str
    scratch_plan_sha256: str
    v4_baseline_sha256: str
    v4_final_sha256: str

    def validate(self) -> None:
        self.producer.validate()
        if (any(type(value) is not str or _HEX64.fullmatch(value) is None
                for value in (self.baseline_sha256, self.choices_sha256,
                              self.scratch_plan_sha256,
                              self.v4_baseline_sha256, self.v4_final_sha256))
                or type(self.scratch_root_id) is not str
                or not 1 <= len(self.scratch_root_id) <= 128
                or any(char.isspace() for char in self.scratch_root_id)):
            raise ContractRejected("bounded negative pins are invalid")


@dataclass(frozen=True)
class BoundedNegativeObservation:
    sha256: str
    raw_sha256: str
    raw_byte_count: int
    observed_at: int


def _private_generation(path: Path, filename: str) -> int:
    match = _GENERATION.fullmatch(path.parent.name)
    if (path.name != filename or match is None
            or path.is_symlink() or path.parent.is_symlink()
            or not path.is_file() or not path.parent.is_dir()
            or path.stat().st_size > 8192
            or path.stat().st_uid != os.getuid()
            or path.parent.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or stat.S_IMODE(path.parent.stat().st_mode) & 0o077):
        raise ContractRejected("bounded negative observation is unavailable")
    return int(match.group(1))


def _observed_time(value: object, now: int) -> int:
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ContractRejected("bounded negative observation time is invalid") from error
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ContractRejected("bounded negative observation time is invalid")
    instant = int(observed.astimezone(timezone.utc).timestamp())
    if not 0 <= now - instant <= 3600:
        raise ContractRejected("bounded negative observation is stale")
    return instant


def validate_bounded_negative(
    baseline_path: Path, choices_path: Path, pins: BoundedNegativePins,
    *, source_evidence: dict, now: int,
) -> EditRerunTarget:
    """Accept a fresh marker-only scratch Doc and exact A/B after-states."""
    pins.validate()
    if type(now) is not int:
        raise ContractRejected("bounded negative clock is invalid")
    baseline_generation = _private_generation(
        baseline_path, "google-bounded-negative-baseline.json")
    choices_generation = _private_generation(
        choices_path, "google-bounded-negative-choices.json")
    if choices_generation != baseline_generation + 1:
        raise ContractRejected("bounded negative choices are not next generation")
    for name, expected in ((BASELINE_SCHEMA, BASELINE_SCHEMA_SHA256),
                           (CHOICES_SCHEMA, CHOICES_SCHEMA_SHA256)):
        actual = hashlib.sha256(files("employee_read_demo").joinpath(
            "schemas", name).read_bytes()).hexdigest()
        if actual != expected:
            raise ContractRejected("bounded negative schema changed")
    baseline, baseline_raw = _load(baseline_path, BASELINE_SCHEMA)
    choices, choices_raw = _load(choices_path, CHOICES_SCHEMA)
    if (hashlib.sha256(baseline_raw).hexdigest() != pins.baseline_sha256
            or hashlib.sha256(choices_raw).hexdigest() != pins.choices_sha256):
        raise ContractRejected("bounded negative artifact digest changed")
    if _observed_time(baseline.get("observed_at"), now) > _observed_time(
            choices.get("observed_at"), now):
        raise ContractRejected("bounded negative choices preceded baseline")
    identity = (pins.producer.company, pins.producer.instance,
                pins.producer.definition_hash)
    if ((baseline["company"], baseline["instance"],
         baseline["definition_hash"]) != identity
            or (choices["company"], choices["instance"],
                choices["definition_hash"]) != identity
            or baseline["jules_subject"] != pins.producer.jules_subject
            or baseline["drive_id"] != source_evidence["drive_id"]
            or baseline["project_a_folder_id"] != source_evidence["folder_id"]
            or baseline["document_id"] == source_evidence["document_id"]
            or baseline["scratch_root_id"] != pins.scratch_root_id
            or baseline["source_scratch_plan_generation"] != 38
            or baseline["source_scratch_plan_sha256"] != pins.scratch_plan_sha256
            or baseline["source_v4_baseline_generation"] != 21
            or baseline["source_v4_baseline_sha256"] != pins.v4_baseline_sha256
            or baseline["source_v4_final_generation"] != 23
            or baseline["source_v4_final_sha256"] != pins.v4_final_sha256):
        raise ContractRejected("bounded negative fixture identity changed")
    if (baseline["schema_version"] != "demo-co/google-bounded-negative-baseline/v1"
            or baseline["status"] != "ready"
            or baseline["attribution"] != "provider_state_only"
            or baseline["logical_id"] != "ap071-bounded-upfront-negative-doc"
            or baseline["exact_scratch_root_children"] is not True
            or baseline["scratch_root_child_count"] != 5
            or baseline["original_seven_unchanged"] is not True
            or baseline["canonical_project_a_unchanged"] is not True
            or baseline["canonical_project_b_unchanged"] is not True
            or baseline["jules_can_edit"] is not True
            or baseline["marker_count"] != 1
            or baseline["tab_id"] != "t.0"
            or _MARKER.fullmatch(baseline["marker"]) is None):
        raise ContractRejected("bounded negative baseline is not ready")
    raw_before = b"\xef\xbb\xbf" + baseline["marker"].encode("utf-8")
    if (baseline["raw_byte_count"] != len(raw_before)
            or baseline["raw_sha256"] != hashlib.sha256(raw_before).hexdigest()):
        raise ContractRejected("bounded negative raw baseline differs")
    if (choices["schema_version"] != "demo-co/google-bounded-negative-choices/v1"
            or choices["status"] != "ready"
            or choices["attribution"] != "precommitted_provider_expectation"
            or choices["baseline_generation"] != baseline_generation
            or choices["baseline_sha256"] != pins.baseline_sha256
            or choices["baseline_raw_sha256"] != baseline["raw_sha256"]
            or choices["baseline_raw_byte_count"] != len(raw_before)
            or choices["document_id"] != baseline["document_id"]
            or choices["marker"] != baseline["marker"]
            or choices["replacement_rule"] !=
                "replace_single_marker_in_exact_raw_export/v1"):
        raise ContractRejected("bounded negative choices differ from baseline")
    for letter, text in (("a", OPTION_A), ("b", OPTION_B)):
        payload = text.encode("utf-8")
        raw = b"\xef\xbb\xbf" + payload
        if (choices[f"option_{letter}_text_byte_count"] != len(payload)
                or choices[f"option_{letter}_text_sha256"] !=
                    hashlib.sha256(payload).hexdigest()
                or choices[f"option_{letter}_expected_raw_byte_count"] != len(raw)
                or choices[f"option_{letter}_expected_raw_sha256"] !=
                    hashlib.sha256(raw).hexdigest()):
            raise ContractRejected("bounded negative choice commitment changed")
    return EditRerunTarget(
        baseline["document_id"], baseline["document_title"],
        baseline["scratch_root_id"], baseline["drive_id"],
        baseline["tab_id"], baseline["jules_revision_id"],
        baseline["marker"], baseline["raw_sha256"], baseline["raw_byte_count"],
    )


def validate_bounded_negative_observation(
    observation_path: Path, *, observation_sha256: str,
    baseline_path: Path, choices_path: Path, pins: BoundedNegativePins,
    target: EditRerunTarget, task_not_before: int, now: int,
) -> BoundedNegativeObservation:
    """Accept independent provider state only; gateway causality is separate."""
    pins.validate()
    if (type(observation_sha256) is not str
            or _HEX64.fullmatch(observation_sha256) is None
            or type(task_not_before) is not int or type(now) is not int):
        raise ContractRejected("bounded negative observation pins are invalid")
    baseline_generation = _private_generation(
        baseline_path, "google-bounded-negative-baseline.json")
    choices_generation = _private_generation(
        choices_path, "google-bounded-negative-choices.json")
    observation_generation = _private_generation(
        observation_path, "google-bounded-negative-observation.json")
    if (choices_generation != baseline_generation + 1
            or observation_generation != choices_generation + 1):
        raise ContractRejected("bounded negative observation generation changed")
    baseline, baseline_raw = _load(baseline_path, BASELINE_SCHEMA)
    if (hashlib.sha256(baseline_raw).hexdigest() != pins.baseline_sha256
            or hashlib.sha256(choices_path.read_bytes()).hexdigest() !=
                pins.choices_sha256):
        raise ContractRejected("bounded negative observation source changed")
    schema_sha = hashlib.sha256(files("employee_read_demo").joinpath(
        "schemas", OBSERVATION_SCHEMA).read_bytes()).hexdigest()
    if schema_sha != OBSERVATION_SCHEMA_SHA256:
        raise ContractRejected("bounded negative observation schema changed")
    observation, raw = _load(observation_path, OBSERVATION_SCHEMA)
    if hashlib.sha256(raw).hexdigest() != observation_sha256:
        raise ContractRejected("bounded negative observation digest changed")
    observed_at = _observed_time(observation.get("observed_at"), now)
    if observed_at < task_not_before:
        raise ContractRejected("bounded negative observation preceded task")
    expected = b"\xef\xbb\xbf" + OPTION_A.encode("utf-8")
    expected_sha = hashlib.sha256(expected).hexdigest()
    if ((observation["company"], observation["instance"],
         observation["definition_hash"]) != (
             pins.producer.company, pins.producer.instance,
             pins.producer.definition_hash)
            or observation["baseline_generation"] != baseline_generation
            or observation["baseline_sha256"] != pins.baseline_sha256
            or observation["choices_generation"] != choices_generation
            or observation["choices_sha256"] != pins.choices_sha256
            or observation["drive_id"] != target.drive_id
            or observation["project_a_folder_id"] !=
                baseline["project_a_folder_id"]):
        raise ContractRejected("bounded negative observation identity changed")
    if (observation["document_id"] != target.document_id
            or observation["scratch_root_id"] != target.folder_id
            or observation["tab_id"] != target.tab_id
            or observation["marker"] != target.marker
            or observation["selected_choice"] != "A"
            or observation["status"] != "option_a_exact"
            or observation["attribution"] != "provider_state_only"
            or observation["provider_entry_attested"] is not False
            or observation["exact_expected_content"] is not True
            or observation["jules_export_matches_admin"] is not True
            or observation["revision_changed_from_baseline"] is not True
            or observation["final_jules_revision_id"] == target.revision_id
            or observation["raw_sha256"] != expected_sha
            or observation["raw_byte_count"] != len(expected)
            or observation["original_marker_count"] != 0
            or observation["scratch_root_child_count"] != 5
            or any(observation[field] is not True for field in (
                "exact_scratch_root_children", "original_seven_unchanged",
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged"))):
        raise ContractRejected("bounded negative complete after-state did not match")
    return BoundedNegativeObservation(
        observation_sha256, expected_sha, len(expected), observed_at,
    )
