"""Pin demo_co's direct finance denial under the same Jules grant as Auths."""

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
from .finance_denial_handoff import FinanceDenialPins
from .write_handoff import WRITE_SCOPES


SCHEMA = "google-finance-write-grant-denial-v1.schema.json"
SCHEMA_SHA256 = "945d45f7f2a4ff7165d6ac168391a19bafb21f0b56136424ab6779ca0b447cb1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
_FIELDS = {
    "schema_version", "status", "attribution", "company", "instance",
    "definition_hash", "observed_at", "jules_subject", "resource_id",
    "document_id", "grant_kind", "granted_scopes",
    "source_admin_finance_denial_generation",
    "source_admin_finance_denial_sha256", "metadata_http_status",
    "export_http_status", "metadata_response_leaked_fixture",
    "export_response_leaked_fixture",
}


@dataclass(frozen=True)
class FinanceWriteGrantPins:
    source: FinanceDenialPins
    source_generation: int
    evidence_sha256: str

    def validate(self) -> None:
        self.source.validate()
        if (type(self.source_generation) is not int
                or self.source_generation < 2
                or type(self.evidence_sha256) is not str
                or _HEX64.fullmatch(self.evidence_sha256) is None):
            raise ContractRejected("finance write-grant pins are invalid")


def validate_finance_write_grant(path: Path, pins: FinanceWriteGrantPins, *,
                                 now: int, maximum_age_seconds: int = 3600) -> dict:
    """Require a fresh, private same-grant denial tied to the admin probe."""
    pins.validate()
    generation = _GENERATION.fullmatch(path.parent.name)
    if (type(now) is not int or type(maximum_age_seconds) is not int
            or not 1 <= maximum_age_seconds <= 86_400
            or path.name != "google-finance-write-grant-denial.json"
            or generation is None
            or int(generation.group(1)) <= pins.source_generation
            or path.is_symlink() or path.parent.is_symlink()
            or not path.is_file() or not path.parent.is_dir()
            or path.stat().st_size > 4096
            or path.stat().st_uid != os.getuid()
            or path.parent.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or stat.S_IMODE(path.parent.stat().st_mode) & 0o077):
        raise ContractRejected("finance write-grant observation is unavailable")
    schema = files("employee_read_demo").joinpath("schemas", SCHEMA).read_bytes()
    if hashlib.sha256(schema).hexdigest() != SCHEMA_SHA256:
        raise ContractRejected("finance write-grant schema changed")
    observation, raw = _load(path, SCHEMA)
    if hashlib.sha256(raw).hexdigest() != pins.evidence_sha256:
        raise ContractRejected("finance write-grant digest disagrees with pin")
    if (set(observation) != _FIELDS
            or observation["schema_version"] !=
                "demo-co/google-finance-write-grant-denial/v1"
            or observation["status"] != "passed"
            or observation["attribution"] != "provider_state_only"
            or (observation["company"], observation["instance"],
                observation["definition_hash"], observation["jules_subject"],
                observation["document_id"]) != (
                    pins.source.company, pins.source.instance,
                    pins.source.definition_hash, pins.source.jules_subject,
                    pins.source.document_id)
            or observation["resource_id"] != "doc-finance-budget"
            or observation["grant_kind"] !=
                "existing_google_write_person_jules_drive_file"
            or type(observation["granted_scopes"]) is not list
            or len(observation["granted_scopes"]) != len(WRITE_SCOPES)
            or set(observation["granted_scopes"]) != WRITE_SCOPES
            or observation["source_admin_finance_denial_generation"] !=
                pins.source_generation
            or observation["source_admin_finance_denial_sha256"] !=
                pins.source.evidence_sha256
            or observation["metadata_http_status"] not in (403, 404)
            or observation["export_http_status"] not in (403, 404)
            or observation["metadata_response_leaked_fixture"] is not False
            or observation["export_response_leaked_fixture"] is not False):
        raise ContractRejected("finance write-grant probe differs from pinned fixture")
    try:
        observed = parse_aware_timestamp(
            observation["observed_at"])
    except (TypeError, ValueError) as error:
        raise ContractRejected("finance write-grant time is malformed") from error
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ContractRejected("finance write-grant time is malformed")
    age = now - int(observed.astimezone(timezone.utc).timestamp())
    if not 0 <= age <= maximum_age_seconds:
        raise ContractRejected("finance write-grant observation is stale or in the future")
    return observation
