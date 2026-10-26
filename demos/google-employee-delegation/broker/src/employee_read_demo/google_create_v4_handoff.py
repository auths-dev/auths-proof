"""Strict, test-only consumer of demo_co's frozen six-to-seven-child evidence."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path

from .demo_co_contract import ContractRejected, _load, _unique_pairs
from .google_create_handoff import CHILD_TITLE, MARKER, MAX_RECOVERY_PAGES


SCHEMA_SHA256 = {
    "google-create-v4-baseline-v1.schema.json":
        "0532aaa734fc0d0ff80fdc2f190bffbcfb6b157bd06311c2a862491cce677e4a",
    "google-create-v4-candidate-blank-v1.schema.json":
        "1faaf0a27b7585bc73e740fe3767d551a57a3c5ebfedee7ca32e9ca2b390d9ec",
    "google-create-observation-v4.schema.json":
        "e62d06be69358da61baef197dc5c2c360e7bff6674e94bbd38279a6f6a6e656b",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
ROLES = ("working", "jules_probe", "preserved_first", "second_auths",
         "clean_edit", "recovered_first")
COMMON = ("company", "instance", "definition_hash", "customer_id",
          "jules_subject", "drive_id", "folder_id")


@dataclass(frozen=True)
class CreateV4NeighborPins:
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
            raise ContractRejected("v4 neighbor pin is invalid")


@dataclass(frozen=True)
class CreateV4BaselinePins:
    company: str
    instance: str
    definition_hash: str
    customer_id: str
    jules_subject: str
    drive_id: str
    folder_id: str
    source_verification_sha256: str
    source_v3_baseline_generation: int
    source_v3_baseline_sha256: str
    source_v3_final_generation: int
    source_v3_final_sha256: str
    baseline_generation: int
    baseline_sha256: str
    neighbors: tuple[CreateV4NeighborPins, ...]
    prior_markers: tuple[str, str, str]

    def validate(self) -> None:
        hashes = (self.definition_hash, self.source_verification_sha256,
                  self.source_v3_baseline_sha256, self.source_v3_final_sha256,
                  self.baseline_sha256)
        labels = (self.company, self.instance, self.customer_id,
                  self.jules_subject, self.drive_id, self.folder_id)
        if (any(type(value) is not str or HEX64.fullmatch(value) is None
                for value in hashes)
                or any(type(value) is not str or not 1 <= len(value) <= 256
                       or any(character.isspace() for character in value)
                       for value in labels)
                or any(type(value) is not int or value < 1 for value in (
                    self.source_v3_baseline_generation,
                    self.source_v3_final_generation, self.baseline_generation,
                ))
                or self.source_v3_final_generation
                    <= self.source_v3_baseline_generation
                or type(self.neighbors) is not tuple
                or len(self.neighbors) != 6
                or any(type(item) is not CreateV4NeighborPins
                       for item in self.neighbors)
                or tuple(item.role for item in self.neighbors) != ROLES
                or len({item.document_id for item in self.neighbors}) != 6
                or type(self.prior_markers) is not tuple
                or len(self.prior_markers) != 3
                or any(type(marker) is not str or MARKER.fullmatch(marker) is None
                       for marker in self.prior_markers)
                or len(set(self.prior_markers)) != 3):
            raise ContractRejected("v4 baseline pins are invalid")
        for item in self.neighbors:
            item.validate()


@dataclass(frozen=True)
class CreateV4CandidateBlankPins:
    baseline: CreateV4BaselinePins
    observation_generation: int
    observation_sha256: str
    candidate_id: str
    marker: str

    def validate(self) -> None:
        self.baseline.validate()
        if (type(self.observation_generation) is not int
                or self.observation_generation <= self.baseline.baseline_generation
                or type(self.observation_sha256) is not str
                or HEX64.fullmatch(self.observation_sha256) is None
                or type(self.candidate_id) is not str
                or not 1 <= len(self.candidate_id) <= 256
                or any(character.isspace() for character in self.candidate_id)
                or self.candidate_id in {
                    item.document_id for item in self.baseline.neighbors
                }
                or type(self.marker) is not str
                or MARKER.fullmatch(self.marker) is None
                or self.marker in self.baseline.prior_markers):
            raise ContractRejected("v4 candidate pins are invalid")


@dataclass(frozen=True)
class CreateV4FinalPins:
    candidate: CreateV4CandidateBlankPins
    observation_generation: int
    observation_sha256: str
    new_content_sha256: str
    new_content_byte_count: int

    def validate(self) -> None:
        self.candidate.validate()
        if (type(self.observation_generation) is not int
                or self.observation_generation
                    <= self.candidate.observation_generation
                or any(type(value) is not str or HEX64.fullmatch(value) is None
                       for value in (self.observation_sha256,
                                     self.new_content_sha256))
                or type(self.new_content_byte_count) is not int
                or not 3 < self.new_content_byte_count <= 100_000):
            raise ContractRejected("v4 final pins are invalid")


def _checked(path: Path, schema_name: str, digest: str) -> dict:
    schema = files("employee_read_demo").joinpath("schemas", schema_name).read_bytes()
    if hashlib.sha256(schema).hexdigest() != SCHEMA_SHA256[schema_name]:
        raise ContractRejected("v4 producer schema differs from reviewed bytes")
    document, raw = _load(path, schema_name)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ContractRejected("v4 producer artifact differs from operator pin")
    return document


def _at(document: dict, name: str) -> datetime:
    try:
        value = datetime.fromisoformat(document[name])
    except (KeyError, TypeError, ValueError) as error:
        raise ContractRejected("v4 producer time is invalid") from error
    if value.tzinfo is None or value.utcoffset() is None:
        raise ContractRejected("v4 producer time lacks timezone")
    return value


def _location(path: Path, name: str, generation: int) -> bool:
    match = GENERATION.fullmatch(path.parent.name)
    return (path.name == name and match is not None
            and int(match.group(1)) == generation)


def _baseline(path: Path, pins: CreateV4BaselinePins) -> dict:
    pins.validate()
    if not _location(path, "google-create-v4-baseline.json",
                     pins.baseline_generation):
        raise ContractRejected("v4 baseline location differs from pins")
    baseline = _checked(path, "google-create-v4-baseline-v1.schema.json",
                        pins.baseline_sha256)
    expected = {
        **{name: getattr(pins, name) for name in COMMON},
        "source_verification_sha256": pins.source_verification_sha256,
        "source_v3_baseline_generation": pins.source_v3_baseline_generation,
        "source_v3_baseline_sha256": pins.source_v3_baseline_sha256,
        "source_v3_final_generation": pins.source_v3_final_generation,
        "source_v3_final_sha256": pins.source_v3_final_sha256,
        "neighbors": [asdict(item) for item in pins.neighbors],
        "prior_markers": list(pins.prior_markers),
    }
    if (any(baseline.get(name) != value for name, value in expected.items())
            or baseline.get("schema_version")
                != "demo-co/google-create-v4-baseline/v1"
            or baseline.get("status") != "ready"
            or baseline.get("attribution") != "provider_state_only"
            or baseline.get("direct_child_count") != 6
            or any(baseline.get(name) is not True for name in (
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged",
                "jules_project_b_write_denied",
            ))):
        raise ContractRejected("v4 baseline differs from reviewed pins")
    return baseline


def validate_create_v4_precreate_baseline(
    path: Path, pins: CreateV4BaselinePins, *, now: int,
) -> dict:
    """Accept one fresh six-child producer snapshot before provider entry."""
    if type(now) is not int:
        raise ContractRejected("v4 pre-create time is invalid")
    baseline = _baseline(path, pins)
    observed = _at(baseline, "observed_at")
    current = datetime.fromtimestamp(now, timezone.utc)
    if not observed <= current <= observed + timedelta(minutes=5):
        raise ContractRejected("v4 pre-create baseline is stale or future-dated")
    return baseline


def validate_create_v4_candidate_blank(
    baseline_path: Path, candidate_path: Path, pins: CreateV4CandidateBlankPins,
) -> dict:
    """Accept independent blank-child evidence; this grants no authority."""
    pins.validate()
    baseline = _baseline(baseline_path, pins.baseline)
    if not _location(candidate_path, "google-create-v4-candidate-blank.json",
                     pins.observation_generation):
        raise ContractRejected("v4 candidate location differs from pins")
    candidate = _checked(candidate_path,
                         "google-create-v4-candidate-blank-v1.schema.json",
                         pins.observation_sha256)
    expected = {
        **{name: getattr(pins.baseline, name) for name in COMMON},
        "baseline_generation": pins.baseline.baseline_generation,
        "baseline_sha256": pins.baseline.baseline_sha256,
        "baseline_observed_at": baseline["observed_at"],
        "candidate_id": pins.candidate_id,
        "candidate_title": CHILD_TITLE,
        "candidate_marker": pins.marker,
    }
    if (any(candidate.get(name) != value for name, value in expected.items())
            or candidate.get("schema_version")
                != "demo-co/google-create-v4-candidate-blank/v1"
            or candidate.get("status") != "observed_blank"
            or candidate.get("attribution") != "provider_state_only"
            or candidate.get("direct_child_count") != 7
            or candidate.get("candidate_marker_match_count") != 1
            or candidate.get("blank_export_byte_count") != 3
            or candidate.get("blank_export_sha256")
                != hashlib.sha256(b"\xef\xbb\xbf").hexdigest()
            or candidate.get("blank_layout")
                != "section-break-then-newline-paragraph/v1"
            or any(candidate.get(name) is not True for name in (
                "neighbors_match_baseline",
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged",
                "jules_project_b_write_denied",
            ))
            or any(type(candidate.get(name)) is not str or not candidate[name]
                   for name in ("candidate_tab_id", "candidate_admin_revision_id"))):
        raise ContractRejected("v4 blank candidate differs from run pins")
    first = _at(baseline, "observed_at")
    created = _at(candidate, "candidate_created_at")
    observed = _at(candidate, "observed_at")
    if not first < created <= observed or created - first > timedelta(minutes=5):
        raise ContractRejected("v4 blank candidate falls outside create window")
    return candidate


def validate_create_v4_recovery_handoff(
    baseline_path: Path, candidate_path: Path, search_report_path: Path,
    pins: CreateV4CandidateBlankPins, *, task_id: str,
    create_operation_id: str, connection_id: str,
    connection_generation: int, search_report_sha256: str,
) -> dict:
    """Join a single Jules search result and independent producer observation."""
    pins.validate()
    if (type(task_id) is not str or not 1 <= len(task_id) <= 128
            or type(create_operation_id) is not str
            or not 1 <= len(create_operation_id) <= 128
            or type(connection_id) is not str
            or not 1 <= len(connection_id) <= 256
            or type(connection_generation) is not int
            or connection_generation < 1
            or type(search_report_sha256) is not str
            or HEX64.fullmatch(search_report_sha256) is None
            or not search_report_path.is_file() or search_report_path.is_symlink()
            or stat.S_IMODE(search_report_path.stat().st_mode) & 0o077
            or search_report_path.stat().st_size > 8192):
        raise ContractRejected("private v4 recovery handoff pins are invalid")
    raw = search_report_path.read_bytes()
    if len(raw) > 8192 or hashlib.sha256(raw).hexdigest() != search_report_sha256:
        raise ContractRejected("v4 search report differs from operator pin")
    try:
        report = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError) as error:
        raise ContractRejected("v4 search report is malformed") from error
    if (type(report) is not dict
            or set(report) != {"schema", "task_id", "create_operation_id",
                               "baseline_sha256", "result", "authority"}
            or report.get("schema") != "auths.ap071-create-recovery-search/1"
            or report.get("task_id") != task_id
            or report.get("create_operation_id") != create_operation_id
            or report.get("baseline_sha256") != pins.baseline.baseline_sha256
            or report.get("authority") != "none"):
        raise ContractRejected("v4 search report differs from task pins")
    result = report["result"]
    if (type(result) is not dict
            or set(result) != {
                "candidate_id", "candidate_count", "parent_id", "drive_id",
                "marker_value", "page_sha256", "metadata_sha256",
                "checked_at", "connection_id", "connection_generation",
                "connection_subject", "status",
            }
            or result["status"] != "single"
            or result["candidate_count"] != 1
            or result["candidate_id"] != pins.candidate_id
            or result["parent_id"] != pins.baseline.folder_id
            or result["drive_id"] != pins.baseline.drive_id
            or result["marker_value"] != pins.marker
            or result["connection_id"] != connection_id
            or result["connection_generation"] != connection_generation
            or result["connection_subject"] != pins.baseline.jules_subject
            or type(result["checked_at"]) is not int
            or type(result["page_sha256"]) is not list
            or not 1 <= len(result["page_sha256"]) <= MAX_RECOVERY_PAGES
            or any(type(value) is not str or HEX64.fullmatch(value) is None
                   for value in result["page_sha256"])
            or type(result["metadata_sha256"]) is not str
            or HEX64.fullmatch(result["metadata_sha256"]) is None):
        raise ContractRejected("v4 search lacks one exact Jules candidate")
    return validate_create_v4_candidate_blank(baseline_path, candidate_path, pins)


def validate_create_v4_observation(
    baseline_path: Path, candidate_path: Path, final_path: Path,
    pins: CreateV4FinalPins,
) -> None:
    """Compare the seventh child's exact final content with both earlier pins."""
    pins.validate()
    baseline = _baseline(baseline_path, pins.candidate.baseline)
    candidate = validate_create_v4_candidate_blank(
        baseline_path, candidate_path, pins.candidate,
    )
    if not _location(final_path, "google-create-observation-v4.json",
                     pins.observation_generation):
        raise ContractRejected("v4 final location differs from pins")
    final = _checked(final_path, "google-create-observation-v4.schema.json",
                     pins.observation_sha256)
    expected = {
        **{name: getattr(pins.candidate.baseline, name) for name in COMMON},
        "baseline_generation": pins.candidate.baseline.baseline_generation,
        "baseline_sha256": pins.candidate.baseline.baseline_sha256,
        "candidate_generation": pins.candidate.observation_generation,
        "candidate_sha256": pins.candidate.observation_sha256,
        "baseline_observed_at": baseline["observed_at"],
        "new_child_id": pins.candidate.candidate_id,
        "new_child_title": CHILD_TITLE,
        "new_child_created_at": candidate["candidate_created_at"],
        "new_marker": pins.candidate.marker,
        "new_content_sha256": pins.new_content_sha256,
        "new_content_byte_count": pins.new_content_byte_count,
    }
    if (any(final.get(name) != value for name, value in expected.items())
            or final.get("schema_version")
                != "demo-co/google-create-observation/v4"
            or final.get("status") != "ready"
            or final.get("attribution") != "provider_state_only"
            or final.get("direct_child_count") != 7
            or final.get("new_marker_match_count") != 1
            or any(final.get(name) is not True for name in (
                "exact_expected_content", "neighbors_match_baseline",
                "canonical_project_a_unchanged",
                "canonical_project_b_unchanged",
                "jules_project_b_write_denied",
            ))
            or any(type(final.get(name)) is not str or not final[name]
                   for name in ("new_tab_id", "new_admin_revision_id"))):
        raise ContractRejected("v4 final observation differs from run pins")
    created = _at(final, "new_child_created_at")
    observed = _at(final, "observed_at")
    if created > observed:
        raise ContractRejected("v4 final observation predates create")
