"""Pinned consumer of demo_co's focused Google finance-access probe.

The observation proves provider state before an Auths test. It does not prove
that an agent action passed task admission or entered Google under Jules.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import timezone
from importlib.resources import files
from pathlib import Path

from .timestamps import parse_aware_timestamp
from .demo_co_contract import ContractRejected, _load


SCHEMA = "google-finance-denial-v1.schema.json"
SCHEMA_SHA256 = "d2cec86f3f32e22d88f80749671cc21e71842c8acce4e0534be7968975ad84fd"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
_FIELDS = {
    "schema_version", "status", "attribution", "company", "instance",
    "definition_hash", "observed_at", "customer_id", "jules_subject",
    "resource_id", "document_id", "admin_file_observed",
    "admin_content_matches_fixture", "jules_metadata_http_status",
    "jules_export_http_status", "metadata_response_leaked_fixture",
    "export_response_leaked_fixture",
}


@dataclass(frozen=True)
class FinanceDenialPins:
    company: str
    instance: str
    definition_hash: str
    customer_id: str
    jules_subject: str
    document_id: str
    evidence_sha256: str

    def validate(self) -> None:
        labels = (self.company, self.instance, self.customer_id,
                  self.jules_subject, self.document_id)
        if (any(type(value) is not str or not 1 <= len(value) <= 256
                or any(character.isspace() for character in value)
                for value in labels)
                or type(self.definition_hash) is not str
                or _HEX64.fullmatch(self.definition_hash) is None
                or type(self.evidence_sha256) is not str
                or _HEX64.fullmatch(self.evidence_sha256) is None):
            raise ContractRejected("finance denial pins are invalid")


def validate_finance_denial(path: Path, pins: FinanceDenialPins, *, now: int,
                            maximum_age_seconds: int = 3600) -> dict:
    """Accept only a fresh, private, hash-pinned direct Jules denial probe."""
    pins.validate()
    match = _GENERATION.fullmatch(path.parent.name)
    if (type(now) is not int or type(maximum_age_seconds) is not int
            or not 1 <= maximum_age_seconds <= 86_400
            or path.name != "google-finance-denial.json" or match is None
            or int(match.group(1)) < 2 or path.is_symlink()
            or path.parent.is_symlink() or not path.is_file()
            or not path.parent.is_dir() or path.stat().st_size > 4096
            or path.stat().st_uid != os.getuid()
            or path.parent.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or stat.S_IMODE(path.parent.stat().st_mode) & 0o077):
        raise ContractRejected("finance denial observation is unavailable")
    schema = files("employee_read_demo").joinpath("schemas", SCHEMA).read_bytes()
    if hashlib.sha256(schema).hexdigest() != SCHEMA_SHA256:
        raise ContractRejected("finance denial schema changed")
    observation, raw = _load(path, SCHEMA)
    if hashlib.sha256(raw).hexdigest() != pins.evidence_sha256:
        raise ContractRejected("finance denial digest disagrees with pin")
    if (set(observation) != _FIELDS
            or observation["schema_version"] != "demo-co/google-finance-denial/v1"
            or observation["status"] != "passed"
            or observation["attribution"] != "provider_state_only"
            or (observation["company"], observation["instance"],
                observation["definition_hash"], observation["customer_id"],
                observation["jules_subject"], observation["document_id"]) != (
                    pins.company, pins.instance, pins.definition_hash,
                    pins.customer_id, pins.jules_subject, pins.document_id)
            or observation["resource_id"] != "doc-finance-budget"
            or observation["admin_file_observed"] is not True
            or observation["admin_content_matches_fixture"] is not True
            or observation["jules_metadata_http_status"] not in (403, 404)
            or observation["jules_export_http_status"] not in (403, 404)
            or observation["metadata_response_leaked_fixture"] is not False
            or observation["export_response_leaked_fixture"] is not False):
        raise ContractRejected("finance denial probe differs from pinned fixture")
    try:
        observed = parse_aware_timestamp(
            observation["observed_at"])
    except (TypeError, ValueError) as error:
        raise ContractRejected("finance denial observation time is malformed") from error
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ContractRejected("finance denial observation time is malformed")
    age = now - int(observed.astimezone(timezone.utc).timestamp())
    if not 0 <= age <= maximum_age_seconds:
        raise ContractRejected("finance denial observation is stale or in the future")
    return observation
