"""Strict Auths consumer for demo_co's versioned second-create observations.

The producer observes Google state with its own credential. This module checks
the exact versioned exports against private operator pins; it cannot prove
that an Auths task caused the observed provider effect.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path

from .demo_co_contract import ContractRejected, _load
from .google_create_handoff import CHILD_TITLE, MARKER


SCHEMA_SHA256 = {
    "google-preserved-blank-observation-v1.schema.json":
        "7e1f16313bfd8d7c6a5cfa3eab5ac70e5780e776e726180e66b78277c82f3b46",
    "google-create-v2-baseline-v1.schema.json":
        "e0bc21d72378913e5af8036f55c1dfecfeac5baa87f2d9883de91835dde13669",
    "google-create-observation-v2.schema.json":
        "3fbf76db47200f4727fb8b7d6411d076a536720e7d6da93e30c8daaaa51e0492",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class CreateV2BaselinePins:
    """Operator-reviewed identity and historical-child pins before a new create."""

    company: str
    instance: str
    definition_hash: str
    customer_id: str
    jules_subject: str
    source_verification_sha256: str
    drive_id: str
    folder_id: str
    working_document_id: str
    original_baseline_generation: int
    original_baseline_sha256: str
    preserved_blank_generation: int
    preserved_blank_sha256: str
    baseline_generation: int
    baseline_sha256: str
    preserved_child_id: str
    preserved_marker: str

    def validate(self) -> None:
        hashes = (self.definition_hash, self.source_verification_sha256,
                  self.original_baseline_sha256, self.preserved_blank_sha256,
                  self.baseline_sha256)
        labels = (self.company, self.instance, self.customer_id,
                  self.jules_subject, self.drive_id, self.folder_id,
                  self.working_document_id, self.preserved_child_id)
        if (any(type(value) is not str or HEX64.fullmatch(value) is None
                for value in hashes)
                or any(type(value) is not str or not 1 <= len(value) <= 256
                       or any(character.isspace() for character in value)
                       for value in labels)
                or type(self.original_baseline_generation) is not int
                or type(self.preserved_blank_generation) is not int
                or type(self.baseline_generation) is not int
                or not 2 <= self.original_baseline_generation
                    < self.preserved_blank_generation < self.baseline_generation
                or type(self.preserved_marker) is not str
                or MARKER.fullmatch(self.preserved_marker) is None):
            raise ContractRejected("v2 pre-create baseline pins are invalid")


def validate_create_v2_precreate_baseline(
    blank_export: Path, baseline_export: Path, pins: CreateV2BaselinePins,
    *, now: int,
) -> dict:
    """Accept a fresh three-child baseline before any second provider create.

    The old blank observation remains historical evidence. The fresh baseline
    fixes the preserved child's *current* state and the working Doc so a v2
    final observation can prove that the second create changed neither.
    """
    pins.validate()
    if type(now) is not int:
        raise ContractRejected("v2 pre-create time is invalid")
    blank = _checked(blank_export,
                     "google-preserved-blank-observation-v1.schema.json",
                     pins.preserved_blank_sha256)
    baseline = _checked(baseline_export,
                        "google-create-v2-baseline-v1.schema.json",
                        pins.baseline_sha256)
    common = {
        "company": pins.company, "instance": pins.instance,
        "definition_hash": pins.definition_hash,
        "customer_id": pins.customer_id,
        "jules_subject": pins.jules_subject,
        "source_verification_sha256": pins.source_verification_sha256,
        "drive_id": pins.drive_id, "folder_id": pins.folder_id,
    }
    if any(any(document.get(name) != value for name, value in common.items())
           or document.get("attribution") != "provider_state_only"
           for document in (blank, baseline)):
        raise ContractRejected("v2 pre-create identity differs from pins")
    if (blank.get("schema_version")
            != "demo-co/google-preserved-blank-observation/v1"
            or blank.get("status") != "observed_blank"
            or blank.get("original_baseline_generation")
                != pins.original_baseline_generation
            or blank.get("original_baseline_sha256")
                != pins.original_baseline_sha256
            or blank.get("preserved_child_id") != pins.preserved_child_id
            or blank.get("preserved_child_title") != CHILD_TITLE
            or blank.get("preserved_marker") != pins.preserved_marker
            or blank.get("blank_export_byte_count") != 3
            or blank.get("blank_export_sha256")
                != hashlib.sha256(b"\xef\xbb\xbf").hexdigest()
            or blank.get("blank_layout")
                != "section-break-then-newline-paragraph/v1"
            or blank.get("direct_child_count") != 3
            or not all(blank.get(name) is True for name in (
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged"))):
        raise ContractRejected("v2 historical blank observation differs")
    if (baseline.get("schema_version")
            != "demo-co/google-create-v2-baseline/v1"
            or baseline.get("status") != "ready"
            or baseline.get("preserved_blank_generation")
                != pins.preserved_blank_generation
            or baseline.get("preserved_blank_sha256")
                != pins.preserved_blank_sha256
            or baseline.get("working_document_id")
                != pins.working_document_id
            or baseline.get("working_content_sha256")
                != blank.get("working_document_sha256")
            or baseline.get("preserved_child_id") != pins.preserved_child_id
            or baseline.get("preserved_child_title") != CHILD_TITLE
            or baseline.get("preserved_child_created_at")
                != blank.get("preserved_child_created_at")
            or baseline.get("preserved_marker") != pins.preserved_marker
            or baseline.get("direct_child_count") != 3
            or baseline.get("preserved_state") not in ("blank", "populated")
            or not all(baseline.get(name) is True for name in (
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged"))):
        raise ContractRejected("v2 current pre-create baseline differs")
    preserved_bytes = baseline.get("preserved_content_byte_count")
    preserved_sha = baseline.get("preserved_content_sha256")
    if (type(preserved_bytes) is not int
            or type(preserved_sha) is not str
            or HEX64.fullmatch(preserved_sha) is None
            or (baseline["preserved_state"] == "blank" and
                (preserved_bytes != 3
                 or preserved_sha != hashlib.sha256(b"\xef\xbb\xbf").hexdigest()))
            or (baseline["preserved_state"] == "populated"
                and preserved_bytes <= 3)):
        raise ContractRejected("v2 preserved-child content state disagrees")
    original_at = _time(blank, "original_baseline_observed_at")
    created_at = _time(blank, "preserved_child_created_at")
    blank_at = _time(blank, "observed_at")
    baseline_at = _time(baseline, "observed_at")
    current = datetime.fromtimestamp(now, timezone.utc)
    if (not original_at <= created_at <= blank_at <= baseline_at <= current
            or created_at - original_at > timedelta(minutes=5)
            or current - baseline_at > timedelta(minutes=5)):
        raise ContractRejected("v2 pre-create observation is stale or unordered")
    return baseline


@dataclass(frozen=True)
class CreateV2Pins:
    company: str
    instance: str
    definition_hash: str
    customer_id: str
    jules_subject: str
    source_verification_sha256: str
    original_baseline_generation: int
    original_baseline_sha256: str
    preserved_blank_generation: int
    preserved_blank_sha256: str
    v2_baseline_generation: int
    v2_baseline_sha256: str
    observation_sha256: str
    drive_id: str
    folder_id: str
    working_document_id: str
    preserved_child_id: str
    preserved_marker: str
    new_child_id: str
    new_marker: str
    new_content_sha256: str
    new_content_byte_count: int

    def validate(self) -> None:
        hashes = (
            self.definition_hash, self.source_verification_sha256,
            self.original_baseline_sha256, self.preserved_blank_sha256,
            self.v2_baseline_sha256, self.observation_sha256,
            self.new_content_sha256,
        )
        labels = (
            self.company, self.instance, self.customer_id, self.jules_subject,
            self.drive_id, self.folder_id, self.working_document_id,
            self.preserved_child_id,
            self.new_child_id,
        )
        if (any(type(value) is not str or HEX64.fullmatch(value) is None
                for value in hashes)
                or any(type(value) is not str or not 1 <= len(value) <= 256
                       or any(character.isspace() for character in value)
                       for value in labels)
                or type(self.original_baseline_generation) is not int
                or type(self.preserved_blank_generation) is not int
                or type(self.v2_baseline_generation) is not int
                or not 2 <= self.original_baseline_generation
                    < self.preserved_blank_generation
                    < self.v2_baseline_generation
                or self.new_child_id == self.preserved_child_id
                or type(self.new_content_byte_count) is not int
                or not 0 < self.new_content_byte_count <= 100_000
                or type(self.preserved_marker) is not str
                or type(self.new_marker) is not str
                or MARKER.fullmatch(self.preserved_marker) is None
                or MARKER.fullmatch(self.new_marker) is None
                or self.new_marker == self.preserved_marker):
            raise ContractRejected("v2 create operator pins are invalid")


def _checked(path: Path, schema_name: str, digest: str) -> dict:
    schema = files("employee_read_demo").joinpath("schemas", schema_name).read_bytes()
    if hashlib.sha256(schema).hexdigest() != SCHEMA_SHA256[schema_name]:
        raise ContractRejected("v2 producer schema differs from reviewed bytes")
    document, raw = _load(path, schema_name)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ContractRejected("v2 producer artifact differs from operator pin")
    return document


def _time(document: dict, name: str) -> datetime:
    try:
        value = datetime.fromisoformat(document[name])
    except (KeyError, TypeError, ValueError) as error:
        raise ContractRejected("v2 producer time is invalid") from error
    if value.tzinfo is None or value.utcoffset() is None:
        raise ContractRejected("v2 producer time lacks timezone")
    return value


def validate_create_v2_observation(
    blank_export: Path, baseline_export: Path, observation_export: Path,
    pins: CreateV2Pins,
) -> None:
    """Require all three independent stages and exact run-specific pins."""
    pins.validate()
    blank = _checked(
        blank_export, "google-preserved-blank-observation-v1.schema.json",
        pins.preserved_blank_sha256,
    )
    baseline = _checked(
        baseline_export, "google-create-v2-baseline-v1.schema.json",
        pins.v2_baseline_sha256,
    )
    final = _checked(
        observation_export, "google-create-observation-v2.schema.json",
        pins.observation_sha256,
    )
    common = {
        "company": pins.company, "instance": pins.instance,
        "definition_hash": pins.definition_hash,
        "customer_id": pins.customer_id,
        "jules_subject": pins.jules_subject,
        "source_verification_sha256": pins.source_verification_sha256,
        "drive_id": pins.drive_id, "folder_id": pins.folder_id,
    }
    for document in (blank, baseline, final):
        if any(document.get(name) != value for name, value in common.items()):
            raise ContractRejected("v2 producer identity or fixture differs from pins")
        if document.get("attribution") != "provider_state_only":
            raise ContractRejected("v2 producer attribution is unsupported")
    if (blank.get("schema_version") != "demo-co/google-preserved-blank-observation/v1"
            or blank.get("status") != "observed_blank"
            or blank.get("original_baseline_generation")
                != pins.original_baseline_generation
            or blank.get("original_baseline_sha256")
                != pins.original_baseline_sha256
            or blank.get("preserved_child_id") != pins.preserved_child_id
            or blank.get("preserved_child_title") != CHILD_TITLE
            or blank.get("preserved_marker") != pins.preserved_marker
            or blank.get("blank_export_sha256")
                != hashlib.sha256(b"\xef\xbb\xbf").hexdigest()
            or blank.get("blank_export_byte_count") != 3
            or blank.get("blank_layout")
                != "section-break-then-newline-paragraph/v1"
            or blank.get("direct_child_count") != 3
            or not all(blank.get(name) is True for name in (
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged",
            ))):
        raise ContractRejected("preserved-child historical blank state differs")
    if (baseline.get("schema_version") != "demo-co/google-create-v2-baseline/v1"
            or baseline.get("status") != "ready"
            or baseline.get("preserved_blank_generation")
                != pins.preserved_blank_generation
            or baseline.get("preserved_blank_sha256")
                != pins.preserved_blank_sha256
            or baseline.get("working_document_id")
                != pins.working_document_id
            or baseline.get("working_content_sha256")
                != blank.get("working_document_sha256")
            or type(baseline.get("working_content_byte_count")) is not int
            or baseline["working_content_byte_count"] < 0
            or baseline.get("preserved_child_id") != pins.preserved_child_id
            or baseline.get("preserved_child_title") != CHILD_TITLE
            or baseline.get("preserved_marker") != pins.preserved_marker
            or baseline.get("preserved_child_created_at")
                != blank.get("preserved_child_created_at")
            or baseline.get("direct_child_count") != 3
            or baseline.get("preserved_state") not in ("blank", "populated")
            or not all(baseline.get(name) is True for name in (
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged",
            ))):
        raise ContractRejected("v2 pre-create baseline differs from preserved child")
    if (final.get("schema_version") != "demo-co/google-create-observation/v2"
            or final.get("status") != "ready"
            or final.get("preserved_blank_generation")
                != pins.preserved_blank_generation
            or final.get("preserved_blank_sha256")
                != pins.preserved_blank_sha256
            or final.get("v2_baseline_generation")
                != pins.v2_baseline_generation
            or final.get("v2_baseline_sha256")
                != pins.v2_baseline_sha256
            or final.get("new_child_id") != pins.new_child_id
            or final.get("new_child_title") != CHILD_TITLE
            or final.get("new_marker") != pins.new_marker
            or final.get("new_content_sha256")
                != pins.new_content_sha256
            or final.get("new_content_byte_count")
                != pins.new_content_byte_count
            or final.get("preserved_child_id") != pins.preserved_child_id
            or final.get("preserved_child_title") != CHILD_TITLE
            or final.get("preserved_child_created_at")
                != blank.get("preserved_child_created_at")
            or final.get("preserved_marker") != pins.preserved_marker
            or final.get("preserved_content_sha256")
                != baseline.get("preserved_content_sha256")
            or final.get("preserved_content_byte_count")
                != baseline.get("preserved_content_byte_count")
            or final.get("preserved_state") != baseline.get("preserved_state")
            or final.get("working_document_sha256")
                != baseline.get("working_content_sha256")
            or final.get("direct_child_count") != 4
            or final.get("new_marker_match_count") != 1
            or final.get("preserved_marker_match_count") != 1
            or not all(final.get(name) is True for name in (
                "preserved_original_blank",
                "preserved_matches_precreate_baseline",
                "working_document_matches_precreate_baseline",
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged",
                "jules_project_b_write_denied",
            ))):
        raise ContractRejected("v2 final observation differs from run pins")
    original_baseline_at = _time(blank, "original_baseline_observed_at")
    preserved_created_at = _time(blank, "preserved_child_created_at")
    blank_at = _time(blank, "observed_at")
    baseline_at = _time(baseline, "observed_at")
    new_created_at = _time(final, "new_child_created_at")
    final_at = _time(final, "observed_at")
    if (not original_baseline_at <= preserved_created_at <= blank_at <= baseline_at
            <= new_created_at <= final_at
            or preserved_created_at - original_baseline_at > timedelta(minutes=5)
            or new_created_at - baseline_at > timedelta(minutes=5)
            or final.get("v2_baseline_observed_at") != baseline.get("observed_at")):
        raise ContractRejected("v2 producer stages are outside pinned run windows")
