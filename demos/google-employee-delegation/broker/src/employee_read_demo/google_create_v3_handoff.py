"""Strict consumer of demo_co's frozen five-to-six-child Project A evidence.

These checks compare producer observations with owner-private operator pins.
They do not infer that Auths caused the observed Google state.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path

from .demo_co_contract import ContractRejected, _load
from .google_create_handoff import CHILD_TITLE, MARKER


SCHEMA_SHA256 = {
    "google-create-v3-baseline-v1.schema.json":
        "78298880d6b6bcfb0efcc06a6080e93ac5b16804f3286b8e2b6a50b481e946ee",
    "google-create-observation-v3.schema.json":
        "13f2b6f54740036e2fcf907078fc974dfba98b7fb0ca7b9513991b10c8b175d1",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
ROLES = ("working", "jules_probe", "preserved_first", "second_auths",
         "clean_edit")


@dataclass(frozen=True)
class CreateV3NeighborPins:
    role: str
    document_id: str
    raw_content_sha256: str
    raw_content_byte_count: int

    def validate(self) -> None:
        if (self.role not in ROLES
                or type(self.document_id) is not str
                or not 1 <= len(self.document_id) <= 256
                or any(character.isspace() for character in self.document_id)
                or type(self.raw_content_sha256) is not str
                or HEX64.fullmatch(self.raw_content_sha256) is None
                or type(self.raw_content_byte_count) is not int
                or not 0 <= self.raw_content_byte_count <= 100_000):
            raise ContractRejected("v3 neighbor operator pin is invalid")


@dataclass(frozen=True)
class CreateV3BaselinePins:
    company: str
    instance: str
    definition_hash: str
    customer_id: str
    jules_subject: str
    drive_id: str
    folder_id: str
    source_verification_sha256: str
    source_v2_final_sha256: str
    source_edit_final_sha256: str
    source_working_observation_sha256: str
    baseline_generation: int
    baseline_sha256: str
    neighbors: tuple[CreateV3NeighborPins, ...]
    preserved_marker: str
    second_marker: str

    def validate(self) -> None:
        hashes = (self.definition_hash, self.source_verification_sha256,
                  self.source_v2_final_sha256, self.source_edit_final_sha256,
                  self.source_working_observation_sha256, self.baseline_sha256)
        labels = (self.company, self.instance, self.customer_id,
                  self.jules_subject, self.drive_id, self.folder_id)
        if (any(type(value) is not str or HEX64.fullmatch(value) is None
                for value in hashes)
                or any(type(value) is not str or not 1 <= len(value) <= 256
                       or any(character.isspace() for character in value)
                       for value in labels)
                or type(self.baseline_generation) is not int
                or self.baseline_generation < 1
                or type(self.neighbors) is not tuple
                or len(self.neighbors) != 5
                or any(type(item) is not CreateV3NeighborPins
                       for item in self.neighbors)
                or tuple(item.role for item in self.neighbors) != ROLES
                or len({item.document_id for item in self.neighbors}) != 5
                or type(self.preserved_marker) is not str
                or MARKER.fullmatch(self.preserved_marker) is None
                or type(self.second_marker) is not str
                or MARKER.fullmatch(self.second_marker) is None
                or self.preserved_marker == self.second_marker):
            raise ContractRejected("v3 baseline operator pins are invalid")
        for item in self.neighbors:
            item.validate()


@dataclass(frozen=True)
class CreateV3FinalPins:
    baseline: CreateV3BaselinePins
    observation_generation: int
    observation_sha256: str
    new_child_id: str
    new_marker: str
    new_content_sha256: str
    new_content_byte_count: int

    def validate(self) -> None:
        self.baseline.validate()
        if (type(self.observation_generation) is not int
                or self.observation_generation
                    <= self.baseline.baseline_generation
                or any(type(value) is not str or HEX64.fullmatch(value) is None
                for value in (self.observation_sha256,
                              self.new_content_sha256))
                or type(self.new_child_id) is not str
                or not 1 <= len(self.new_child_id) <= 256
                or any(character.isspace() for character in self.new_child_id)
                or self.new_child_id in {
                    item.document_id for item in self.baseline.neighbors
                }
                or type(self.new_marker) is not str
                or MARKER.fullmatch(self.new_marker) is None
                or self.new_marker in (self.baseline.preserved_marker,
                                       self.baseline.second_marker)
                or type(self.new_content_byte_count) is not int
                or not 0 < self.new_content_byte_count <= 100_000):
            raise ContractRejected("v3 final operator pins are invalid")


def _checked(path: Path, schema_name: str, digest: str) -> dict:
    schema = files("employee_read_demo").joinpath("schemas", schema_name).read_bytes()
    if hashlib.sha256(schema).hexdigest() != SCHEMA_SHA256[schema_name]:
        raise ContractRejected("v3 producer schema differs from reviewed bytes")
    document, raw = _load(path, schema_name)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ContractRejected("v3 producer artifact differs from operator pin")
    return document


def _time(document: dict, name: str) -> datetime:
    try:
        value = datetime.fromisoformat(document[name])
    except (KeyError, TypeError, ValueError) as error:
        raise ContractRejected("v3 producer time is invalid") from error
    if value.tzinfo is None or value.utcoffset() is None:
        raise ContractRejected("v3 producer time lacks timezone")
    return value


def validate_create_v3_precreate_baseline(
    path: Path, pins: CreateV3BaselinePins, *, now: int,
) -> dict:
    """Accept a fresh, exact five-child producer baseline before create entry."""
    pins.validate()
    if (type(now) is not int
            or path.name != "google-create-v3-baseline.json"
            or (match := GENERATION.fullmatch(path.parent.name)) is None
            or int(match.group(1)) != pins.baseline_generation):
        raise ContractRejected("v3 baseline location or time is invalid")
    baseline = _checked(path, "google-create-v3-baseline-v1.schema.json",
                        pins.baseline_sha256)
    common = {
        "company": pins.company, "instance": pins.instance,
        "definition_hash": pins.definition_hash,
        "customer_id": pins.customer_id,
        "jules_subject": pins.jules_subject,
        "drive_id": pins.drive_id, "folder_id": pins.folder_id,
        "source_verification_sha256": pins.source_verification_sha256,
        "source_v2_final_sha256": pins.source_v2_final_sha256,
        "source_edit_final_sha256": pins.source_edit_final_sha256,
        "source_working_observation_sha256":
            pins.source_working_observation_sha256,
    }
    if (any(baseline.get(name) != value for name, value in common.items())
            or baseline.get("schema_version")
                != "demo-co/google-create-v3-baseline/v1"
            or baseline.get("status") != "ready"
            or baseline.get("attribution") != "provider_state_only"
            or baseline.get("direct_child_count") != 5
            or baseline.get("canonical_project_a_unchanged") is not True
            or baseline.get("canonical_project_b_unchanged") is not True
            or baseline.get("preserved_marker") != pins.preserved_marker
            or baseline.get("second_marker") != pins.second_marker
            or baseline.get("neighbors") != [asdict(item) for item in pins.neighbors]):
        raise ContractRejected("v3 baseline differs from reviewed fixture pins")
    observed_at = _time(baseline, "observed_at")
    current = datetime.fromtimestamp(now, timezone.utc)
    if not observed_at <= current <= observed_at + timedelta(minutes=5):
        raise ContractRejected("v3 pre-create baseline is stale or future-dated")
    return baseline


def validate_create_v3_observation(
    baseline_path: Path, final_path: Path, pins: CreateV3FinalPins,
) -> None:
    """Compare the six-child observation with its pinned five-child baseline."""
    pins.validate()
    baseline = _checked(
        baseline_path, "google-create-v3-baseline-v1.schema.json",
        pins.baseline.baseline_sha256,
    )
    final = _checked(final_path, "google-create-observation-v3.schema.json",
                     pins.observation_sha256)
    if (baseline_path.name != "google-create-v3-baseline.json"
            or (match := GENERATION.fullmatch(baseline_path.parent.name)) is None
            or int(match.group(1)) != pins.baseline.baseline_generation
            or final_path.name != "google-create-observation-v3.json"
            or (final_match := GENERATION.fullmatch(final_path.parent.name)) is None
            or int(final_match.group(1)) != pins.observation_generation):
        raise ContractRejected("v3 final artifact location differs from pins")
    common = {
        "company": pins.baseline.company,
        "instance": pins.baseline.instance,
        "definition_hash": pins.baseline.definition_hash,
        "customer_id": pins.baseline.customer_id,
        "jules_subject": pins.baseline.jules_subject,
        "drive_id": pins.baseline.drive_id,
        "folder_id": pins.baseline.folder_id,
    }
    if (any(any(document.get(name) != value for name, value in common.items())
            for document in (baseline, final))
            or baseline.get("neighbors")
                != [asdict(item) for item in pins.baseline.neighbors]
            or baseline.get("schema_version")
                != "demo-co/google-create-v3-baseline/v1"
            or baseline.get("status") != "ready"
            or baseline.get("attribution") != "provider_state_only"
            or baseline.get("direct_child_count") != 5
            or any(baseline.get(name) is not True for name in (
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged",
            ))
            or any(baseline.get(name) != getattr(pins.baseline, name)
                   for name in (
                       "source_verification_sha256",
                       "source_v2_final_sha256",
                       "source_edit_final_sha256",
                       "source_working_observation_sha256",
                   ))
            or baseline.get("preserved_marker")
                != pins.baseline.preserved_marker
            or baseline.get("second_marker") != pins.baseline.second_marker
            or final.get("schema_version")
                != "demo-co/google-create-observation/v3"
            or final.get("status") != "ready"
            or final.get("attribution") != "provider_state_only"
            or final.get("baseline_generation")
                != pins.baseline.baseline_generation
            or final.get("baseline_sha256")
                != pins.baseline.baseline_sha256
            or final.get("baseline_observed_at") != baseline.get("observed_at")
            or final.get("direct_child_count") != 6
            or final.get("new_child_id") != pins.new_child_id
            or final.get("new_child_title") != CHILD_TITLE
            or final.get("new_marker") != pins.new_marker
            or final.get("new_content_sha256") != pins.new_content_sha256
            or final.get("new_content_byte_count")
                != pins.new_content_byte_count
            or any(final.get(name) is not True for name in (
                "neighbors_match_baseline",
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged",
                "jules_project_b_write_denied",
            ))
            or any(final.get(name) != 1 for name in (
                "new_marker_match_count",
                "preserved_marker_match_count",
                "second_marker_match_count",
            ))
            or any(type(final.get(name)) is not str or not final[name]
                   for name in ("new_tab_id", "new_admin_revision_id"))):
        raise ContractRejected("v3 final observation differs from run pins")
    baseline_at = _time(baseline, "observed_at")
    created_at = _time(final, "new_child_created_at")
    final_at = _time(final, "observed_at")
    if (not baseline_at < created_at <= final_at
            or created_at - baseline_at > timedelta(minutes=5)):
        raise ContractRejected("v3 create falls outside pinned five-minute window")
