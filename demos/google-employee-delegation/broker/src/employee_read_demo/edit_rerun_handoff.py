"""Pinned producer baseline and precommitted choices for an upfront edit rerun."""

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
from .write_handoff import WriteHandoffPins


BASELINE_SCHEMA = "google-edit-rerun-baseline-v1.schema.json"
BASELINE_SCHEMA_SHA256 = "28a0f067d7592e01e85b2e1298c40e969c2d0bfec77f4b197fc14e21ffc5a79f"
CHOICES_SCHEMA = "google-edit-rerun-choices-v1.schema.json"
CHOICES_SCHEMA_SHA256 = "43fe66f9a0e57d5349e5e97c601eba74cbfc0c88199a1cfaa4236d73f85e11e3"
OPTION_A = "Project A update: agent selected approved option A for the AP-071 upfront delegation test."
OPTION_B = "Project A update: agent selected approved option B for the AP-071 upfront delegation test."
LOGICAL_ID = "ap071-project-a-clean-edit-rerun"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"generation-([0-9]{4,})\Z")


@dataclass(frozen=True)
class EditRerunPins:
    producer: WriteHandoffPins
    previous_working_observation_sha256: str
    baseline_sha256: str
    choices_sha256: str

    def validate(self) -> None:
        self.producer.validate()
        for value in (self.previous_working_observation_sha256,
                      self.baseline_sha256, self.choices_sha256):
            if type(value) is not str or _HEX64.fullmatch(value) is None:
                raise ContractRejected("edit rerun pins are invalid")


@dataclass(frozen=True)
class EditRerunTarget:
    document_id: str
    document_title: str
    folder_id: str
    drive_id: str
    tab_id: str
    revision_id: str
    marker: str
    baseline_sha256: str
    baseline_byte_count: int

    def allowed_arguments(self) -> list[dict]:
        return [{
            "document_id": self.document_id,
            "marker": self.marker,
            "replacement": replacement,
            "required_revision_id": self.revision_id,
            "tab_id": self.tab_id,
        } for replacement in (OPTION_A, OPTION_B)]


def _private_generation(path: Path, filename: str, *, after: int = 1) -> int:
    generation = _GENERATION.fullmatch(path.parent.name)
    if (path.name != filename or generation is None
            or int(generation.group(1)) <= after
            or path.is_symlink() or path.parent.is_symlink()
            or not path.is_file() or not path.parent.is_dir()
            or path.stat().st_size > 8192
            or path.stat().st_uid != os.getuid()
            or path.parent.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or stat.S_IMODE(path.parent.stat().st_mode) & 0o077):
        raise ContractRejected("edit rerun producer observation is unavailable")
    return int(generation.group(1))


def _time(value: object, now: int) -> int:
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ContractRejected("edit rerun observation time is malformed") from error
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ContractRejected("edit rerun observation time is malformed")
    instant = int(observed.astimezone(timezone.utc).timestamp())
    if not 0 <= now - instant <= 3600:
        raise ContractRejected("edit rerun producer observation is stale")
    return instant


def validate_edit_rerun(baseline_path: Path, choices_path: Path,
                        pins: EditRerunPins, *, source_evidence: dict,
                        now: int) -> EditRerunTarget:
    """Accept only a reconstructable marker-only baseline and both choices."""
    pins.validate()
    if type(now) is not int:
        raise ContractRejected("edit rerun clock is invalid")
    baseline_generation = _private_generation(
        baseline_path, "google-edit-rerun-baseline.json")
    choices_generation = _private_generation(
        choices_path, "google-edit-rerun-choices.json", after=baseline_generation)
    if choices_generation != baseline_generation + 1:
        raise ContractRejected("edit rerun choices are not the next producer generation")
    for name, digest in ((BASELINE_SCHEMA, BASELINE_SCHEMA_SHA256),
                         (CHOICES_SCHEMA, CHOICES_SCHEMA_SHA256)):
        if hashlib.sha256(files("employee_read_demo").joinpath(
                "schemas", name).read_bytes()).hexdigest() != digest:
            raise ContractRejected("edit rerun schema changed")
    baseline, baseline_raw = _load(baseline_path, BASELINE_SCHEMA)
    choices, choices_raw = _load(choices_path, CHOICES_SCHEMA)
    if (hashlib.sha256(baseline_raw).hexdigest() != pins.baseline_sha256
            or hashlib.sha256(choices_raw).hexdigest() != pins.choices_sha256):
        raise ContractRejected("edit rerun observation digest disagrees with pin")
    baseline_time = _time(baseline.get("observed_at"), now)
    choices_time = _time(choices.get("observed_at"), now)
    if choices_time < baseline_time:
        raise ContractRejected("edit rerun choices preceded their baseline")
    identity = (pins.producer.company, pins.producer.instance,
                pins.producer.definition_hash, pins.producer.jules_subject)
    if ((baseline["company"], baseline["instance"],
         baseline["definition_hash"], baseline["jules_subject"]) != identity
            or (choices["company"], choices["instance"],
                choices["definition_hash"]) != identity[:3]
            or baseline["customer_id"] != pins.producer.customer_id
            or baseline["source_write_verification_sha256"] !=
                pins.producer.evidence_sha256
            or baseline["source_working_observation_sha256"] !=
                pins.previous_working_observation_sha256
            or baseline["folder_id"] != source_evidence["folder_id"]
            or baseline["drive_id"] != source_evidence["drive_id"]
            or baseline["document_id"] == source_evidence["document_id"]):
        raise ContractRejected("edit rerun producer identity or location changed")
    if (baseline["schema_version"] != "demo-co/google-edit-rerun-baseline/v1"
            or baseline["status"] != "ready"
            or baseline["attribution"] != "provider_state_only"
            or baseline["expected_after_rule"] !=
                "replace_single_marker_in_exact_raw_export/v1"
            or baseline["baseline_exactly_one_marker"] is not True
            or baseline["jules_can_edit"] is not True
            or baseline["direct_child_count"] != 5
            or any(baseline[field] is not True for field in (
                "canonical_project_a_unchanged", "canonical_project_b_unchanged",
                "jules_probe_unchanged", "preserved_child_unchanged",
                "second_child_unchanged", "working_document_unchanged"))):
        raise ContractRejected("edit rerun baseline is not ready")
    if (type(baseline["document_id"]) is not str
            or not 1 <= len(baseline["document_id"].encode()) <= 64
            or type(baseline["document_title"]) is not str
            or not 1 <= len(baseline["document_title"].encode()) <= 256
            or type(baseline["tab_id"]) is not str
            or not 1 <= len(baseline["tab_id"].encode()) <= 16
            or type(baseline["jules_revision_id"]) is not str
            or not 1 <= len(baseline["jules_revision_id"].encode()) <= 128
            or type(baseline["marker"]) is not str
            or not 1 <= len(baseline["marker"].encode()) <= 48):
        raise ContractRejected("edit rerun target exceeds recipe bounds")
    raw_before = b"\xef\xbb\xbf" + baseline["marker"].encode("utf-8")
    raw_a = b"\xef\xbb\xbf" + OPTION_A.encode("utf-8")
    raw_b = b"\xef\xbb\xbf" + OPTION_B.encode("utf-8")
    if (baseline["baseline_raw_byte_count"] != len(raw_before)
            or baseline["baseline_raw_sha256"] != hashlib.sha256(raw_before).hexdigest()
            or baseline["approved_option_a_byte_count"] != len(OPTION_A.encode())
            or baseline["approved_option_a_sha256"] !=
                hashlib.sha256(OPTION_A.encode()).hexdigest()
            or baseline["expected_after_raw_byte_count"] != len(raw_a)
            or baseline["expected_after_raw_sha256"] !=
                hashlib.sha256(raw_a).hexdigest()):
        raise ContractRejected("edit rerun baseline is not exactly reconstructable")
    if (choices["schema_version"] != "demo-co/google-edit-rerun-choices/v1"
            or choices["status"] != "ready"
            or choices["attribution"] != "precommitted_provider_expectation"
            or choices["replacement_rule"] != baseline["expected_after_rule"]
            or choices["baseline_generation"] != baseline_generation
            or choices["baseline_sha256"] != pins.baseline_sha256
            or choices["baseline_raw_sha256"] != baseline["baseline_raw_sha256"]
            or choices["baseline_raw_byte_count"] != len(raw_before)
            or choices["document_id"] != baseline["document_id"]
            or choices["marker"] != baseline["marker"]
            or choices["direct_child_count"] != 5):
        raise ContractRejected("edit rerun choices differ from baseline")
    for letter, text, raw in (("a", OPTION_A, raw_a), ("b", OPTION_B, raw_b)):
        if (choices[f"option_{letter}_text_byte_count"] != len(text.encode())
                or choices[f"option_{letter}_text_sha256"] !=
                    hashlib.sha256(text.encode()).hexdigest()
                or choices[f"option_{letter}_expected_raw_byte_count"] != len(raw)
                or choices[f"option_{letter}_expected_raw_sha256"] !=
                    hashlib.sha256(raw).hexdigest()):
            raise ContractRejected("edit rerun choice commitment changed")
    return EditRerunTarget(
        baseline["document_id"], baseline["document_title"],
        baseline["folder_id"], baseline["drive_id"], baseline["tab_id"],
        baseline["jules_revision_id"], baseline["marker"],
        baseline["baseline_raw_sha256"], baseline["baseline_raw_byte_count"],
    )
