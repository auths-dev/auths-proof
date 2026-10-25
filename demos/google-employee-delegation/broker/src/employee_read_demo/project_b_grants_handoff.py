"""Pinned consumer of demo_co's separate Jules Project B grant probes.

This records provider access for two different Google grants. It does not
turn an Auths task-excluded read into an admitted provider request.
"""

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


SCHEMA = "google-project-b-jules-grants-v1.schema.json"
SCHEMA_SHA256 = "17482aeba82f8dd0be56c57bcfa5ea98b4fe4c73be64d33e683d661b4a558ce4"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
_FIELDS = {
    "schema_version", "attribution", "company", "instance",
    "definition_hash", "observed_at", "resource_id", "document_id",
    "drive_id", "jules_subject", "admin_owned_document_observed",
    "admin_export_matches_fixture", "read_grant_kind",
    "read_grant_http_status", "read_grant_export_matches_fixture",
    "read_grant_denial_leaked_fixture", "write_grant_kind",
    "write_grant_http_status", "write_grant_export_matches_fixture",
    "write_grant_denial_leaked_fixture",
}


@dataclass(frozen=True)
class ProjectBGrantPins:
    company: str
    instance: str
    definition_hash: str
    jules_subject: str
    document_id: str
    drive_id: str
    evidence_sha256: str

    def validate(self) -> None:
        labels = (self.company, self.instance, self.jules_subject,
                  self.document_id, self.drive_id)
        if (any(type(value) is not str or not 1 <= len(value) <= 256
                or any(character.isspace() for character in value)
                for value in labels)
                or type(self.definition_hash) is not str
                or _HEX64.fullmatch(self.definition_hash) is None
                or type(self.evidence_sha256) is not str
                or _HEX64.fullmatch(self.evidence_sha256) is None):
            raise ContractRejected("Project B grant pins are invalid")


@dataclass(frozen=True)
class ProjectBGrantObservation:
    document_id: str
    drive_id: str
    observed_at: int
    read_grant_status: int
    write_grant_status: int


def validate_project_b_grants(path: Path, pins: ProjectBGrantPins, *, now: int,
                              maximum_age_seconds: int = 3600) -> ProjectBGrantObservation:
    """Accept only the fresh, private, hash-pinned two-grant provider probe."""
    pins.validate()
    generation = _GENERATION.fullmatch(path.parent.name)
    if (type(now) is not int or type(maximum_age_seconds) is not int
            or not 1 <= maximum_age_seconds <= 86_400
            or path.name != "google-project-b-jules-grants.json"
            or generation is None or int(generation.group(1)) < 16
            or path.is_symlink() or path.parent.is_symlink()
            or not path.is_file() or not path.parent.is_dir()
            or path.stat().st_size > 4096
            or path.stat().st_uid != os.getuid()
            or path.parent.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or stat.S_IMODE(path.parent.stat().st_mode) & 0o077):
        raise ContractRejected("Project B grant observation is unavailable")
    schema = files("employee_read_demo").joinpath("schemas", SCHEMA).read_bytes()
    if hashlib.sha256(schema).hexdigest() != SCHEMA_SHA256:
        raise ContractRejected("Project B grant schema changed")
    observation, raw = _load(path, SCHEMA)
    if hashlib.sha256(raw).hexdigest() != pins.evidence_sha256:
        raise ContractRejected("Project B grant digest disagrees with pin")
    if (set(observation) != _FIELDS
            or observation["schema_version"] != "demo-co/google-project-b-jules-grants/v1"
            or observation["attribution"] != "provider_state_only"
            or (observation["company"], observation["instance"],
                observation["definition_hash"], observation["jules_subject"],
                observation["document_id"], observation["drive_id"]) != (
                    pins.company, pins.instance, pins.definition_hash,
                    pins.jules_subject, pins.document_id, pins.drive_id)
            or observation["resource_id"] != "doc-project-b-plan"
            or observation["admin_owned_document_observed"] is not True
            or observation["admin_export_matches_fixture"] is not True
            or observation["read_grant_kind"] != "google-person-jules-drive-readonly"
            or observation["read_grant_http_status"] != 200
            or observation["read_grant_export_matches_fixture"] is not True
            or observation["read_grant_denial_leaked_fixture"] is not False
            or observation["write_grant_kind"] != "google-write-person-jules-drive-file"
            or observation["write_grant_http_status"] not in (403, 404)
            or observation["write_grant_export_matches_fixture"] is not False
            or observation["write_grant_denial_leaked_fixture"] is not False):
        raise ContractRejected("Project B grant probe differs from pinned fixture")
    try:
        observed = datetime.fromisoformat(
            observation["observed_at"].replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ContractRejected("Project B grant observation time is malformed") from error
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ContractRejected("Project B grant observation time is malformed")
    instant = int(observed.astimezone(timezone.utc).timestamp())
    if not 0 <= now - instant <= maximum_age_seconds:
        raise ContractRejected("Project B grant observation is stale or in the future")
    return ProjectBGrantObservation(
        pins.document_id, pins.drive_id, instant,
        observation["read_grant_http_status"],
        observation["write_grant_http_status"],
    )
