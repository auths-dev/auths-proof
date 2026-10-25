"""Pinned, read-only consumer of demo_co's new-child observation.

The producer reports provider state only. This shim does not turn a public
marker or an operator-supplied child ID into Auths task authority, and it
never performs a create, populate or cleanup request.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Mapping
from urllib.parse import quote

from .demo_co_contract import ContractRejected, _load

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MARKER = re.compile(r"ap071_[0-9a-f]{32}\Z")
DRIVE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
CHILD_TITLE = "Auths AP-071 Project A handoff"
CHILD_MIME_TYPE = "application/vnd.google-apps.document"
CHILD_FIELDS = "id,name,mimeType,parents,driveId,properties,trashed,createdTime"


def prepare_create_inputs(parent_id: str, *, pinned_folder_id: str) -> dict[str, str]:
    """Choose the first-run title and fresh marker before human review.

    The caller must still put these values in the signed agent action and
    exact human confirmation. This function confers no provider authority.
    """
    if (type(parent_id) is not str or type(pinned_folder_id) is not str
            or not parent_id or parent_id != pinned_folder_id
            or len(parent_id) > 64 or any(character.isspace() for character in parent_id)):
        raise ContractRejected("create parent differs from the pinned Project A folder")
    return {
        "parent_id": parent_id,
        "title": CHILD_TITLE,
        "recovery_marker": "ap071_" + secrets.token_hex(16),
    }


@dataclass(frozen=True)
class CreatedChildMetadataPins:
    """Exact signed create fields and operator-pinned shared Drive context.

    The candidate ID must come from the durable Auths attempt journal. These
    pins alone cannot attribute creation to an agent or authorize population.
    """

    candidate_id: str
    parent_id: str
    drive_id: str
    title: str
    marker_value: str

    def validate(self) -> None:
        if (not all(type(value) is str and DRIVE_ID.fullmatch(value)
                    for value in (self.candidate_id, self.parent_id, self.drive_id))
                or type(self.title) is not str or self.title != CHILD_TITLE
                or type(self.marker_value) is not str
                or MARKER.fullmatch(self.marker_value) is None):
            raise ContractRejected("created-child metadata pins are invalid")


def created_child_metadata_url(pins: CreatedChildMetadataPins) -> str:
    """Build the fixed Google metadata GET for the response-derived child."""
    pins.validate()
    return ("https://www.googleapis.com/drive/v3/files/"
            + quote(pins.candidate_id, safe="")
            + "?supportsAllDrives=true&fields=" + quote(CHILD_FIELDS, safe=","))


def validate_created_child_metadata(metadata: Mapping[str, object],
                                    pins: CreatedChildMetadataPins) -> datetime:
    """Check a bounded files.get result as a test-only Google vertical oracle.

    The caller must separately pin the OAuth UserInfo subject, task action,
    response journal, and connection generation. A matching public marker is
    never child permission. The returned aware timestamp is correlation only.
    """
    pins.validate()
    if (not isinstance(metadata, Mapping)
            or metadata.get("id") != pins.candidate_id
            or metadata.get("name") != pins.title
            or metadata.get("mimeType") != CHILD_MIME_TYPE
            or metadata.get("parents") != [pins.parent_id]
            or metadata.get("driveId") != pins.drive_id
            or metadata.get("trashed") is not False
            or not isinstance(metadata.get("properties"), dict)
            or metadata["properties"].get("auths_operation_marker") != pins.marker_value):
        raise ContractRejected("created-child metadata differs from signed and operator pins")
    try:
        timestamp = metadata["createdTime"]
        if type(timestamp) is not str or len(timestamp) > 40:
            raise ValueError("invalid timestamp shape")
        created = datetime.fromisoformat(
            timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ContractRejected("created-child creation time is invalid") from error
    if created.tzinfo is None or created.utcoffset() is None:
        raise ContractRejected("created-child creation time has no timezone")
    return created


@dataclass(frozen=True)
class CreateObservationPins:
    company: str
    instance: str
    definition_hash: str
    customer_id: str
    jules_subject: str
    source_verification_sha256: str
    working_baseline_generation: int
    working_baseline_sha256: str
    drive_id: str
    folder_id: str
    child_id: str
    marker_value: str
    expected_content_sha256: str
    expected_content_byte_count: int
    observation_sha256: str

    def validate(self) -> None:
        hashes = (self.definition_hash, self.source_verification_sha256,
                  self.working_baseline_sha256, self.expected_content_sha256,
                  self.observation_sha256)
        labels = (self.company, self.instance, self.customer_id,
                  self.jules_subject, self.drive_id, self.folder_id, self.child_id)
        if (not all(type(value) is str and HEX64.fullmatch(value) for value in hashes)
                or not all(type(value) is str and 1 <= len(value) <= 256
                           and not any(character.isspace() for character in value)
                           for value in labels)
                or type(self.working_baseline_generation) is not int
                or self.working_baseline_generation < 2
                or type(self.expected_content_byte_count) is not int
                or not 0 < self.expected_content_byte_count <= 100_000
                or type(self.marker_value) is not str
                or MARKER.fullmatch(self.marker_value) is None):
            raise ContractRejected("create observation operator pins are invalid")


@dataclass(frozen=True)
class CreateObservationStatus:
    contract: str
    status: str
    attribution: str
    observation_sha256: str | None = None
    reason: str | None = None


def validate_create_observation(export: Path, pins: CreateObservationPins) -> None:
    """Check one exact producer observation against private Auths run pins.

    This checks the observed content and isolation, but no signed Auths
    response-ID binding exists yet. Callers must not infer agent attribution.
    """
    pins.validate()
    observation, raw = _load(export, "google-create-observation-v1.schema.json")
    if hashlib.sha256(raw).hexdigest() != pins.observation_sha256:
        raise ContractRejected("create observation digest disagrees with operator pin")
    if (observation["schema_version"] != "demo-co/google-create-observation/v1"
            or observation["status"] != "ready"
            or observation["attribution"] != "provider_state_only"):
        raise ContractRejected("create observation has unsupported provenance")
    expected = {
        "company": pins.company,
        "instance": pins.instance,
        "definition_hash": pins.definition_hash,
        "customer_id": pins.customer_id,
        "jules_subject": pins.jules_subject,
        "source_verification_sha256": pins.source_verification_sha256,
        "working_baseline_generation": pins.working_baseline_generation,
        "working_baseline_sha256": pins.working_baseline_sha256,
        "drive_id": pins.drive_id,
        "folder_id": pins.folder_id,
        "child_id": pins.child_id,
        "child_title": CHILD_TITLE,
        "marker_key": "auths_operation_marker",
        "marker_value": pins.marker_value,
        "content_sha256": pins.expected_content_sha256,
        "content_byte_count": pins.expected_content_byte_count,
    }
    if any(observation.get(name) != value for name, value in expected.items()):
        raise ContractRejected("create observation disagrees with Auths run pins")
    if not all(observation.get(name) is True for name in (
            "child_parent_exact", "canonical_project_a_unchanged",
            "canonical_project_b_unchanged", "working_document_matches_expected",
            "jules_project_b_write_denied")):
        raise ContractRejected("create observation lacks independent isolation checks")
    if observation.get("marker_match_count") != 1 or observation.get("direct_child_count") != 3:
        raise ContractRejected("create observation has ambiguous child inventory")
    try:
        baseline = datetime.fromisoformat(observation["working_baseline_observed_at"])
        created = datetime.fromisoformat(observation["child_created_at"])
        observed = datetime.fromisoformat(observation["observed_at"])
    except (TypeError, ValueError) as error:
        raise ContractRejected("create observation has invalid times") from error
    if (any(value.tzinfo is None for value in (baseline, created, observed))
            or not baseline <= created <= observed
            or created - baseline > timedelta(minutes=5)):
        raise ContractRejected("create observation is outside the pinned run window")


def inspect_create_observation(export: Path | None = None,
                               pins: CreateObservationPins | None = None,
                               ) -> CreateObservationStatus:
    """Expose a redacted handoff result without claiming Auths attribution."""
    if export is None or pins is None:
        return CreateObservationStatus(
            "auths.demo-co-google-create-handoff-status/v1", "not_configured",
            "unproven", reason="producer observation and run pins are both required",
        )
    try:
        validate_create_observation(export, pins)
    except (ContractRejected, OSError, ValueError) as error:
        return CreateObservationStatus(
            "auths.demo-co-google-create-handoff-status/v1", "producer_rejected",
            "unproven", reason=str(error),
        )
    return CreateObservationStatus(
        "auths.demo-co-google-create-handoff-status/v1", "provider_state_observed",
        "provider_state_only", observation_sha256=pins.observation_sha256,
        reason="Auths task and create-response child binding have not been proved",
    )
