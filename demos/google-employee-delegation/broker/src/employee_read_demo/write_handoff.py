"""Pinned consumer of demo_co's write fixture evidence.

Producer readiness is distinct from an installed Auths write path. This
module never loads OAuth material or authorizes a provider mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .demo_co_contract import ContractRejected, _load, _unique_pairs


HEX64 = re.compile(r"^[0-9a-f]{64}$")
WRITE_SCOPES = frozenset({
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/drive.file",
})
_GENERATION = re.compile(r"generation-([0-9]{4,})\Z")
_WRITE_OBSERVATION_FIELDS = {
    "schema_version", "company", "instance", "definition_hash", "observed_at",
    "document_id", "tab_id", "revision_id", "content_sha256",
    "content_byte_count", "original_marker_count",
}


class WriteHandoffPending(RuntimeError):
    """No reviewed producer export can authorize the Google write vertical."""


@dataclass(frozen=True)
class WriteHandoffStatus:
    contract: str
    status: str
    reason: str
    producer_ready: bool = False
    evidence_sha256: str | None = None

    @property
    def ready(self) -> bool:
        return False

    def require_ready(self) -> None:
        raise WriteHandoffPending(self.reason)


@dataclass(frozen=True)
class WriteHandoffPins:
    company: str
    instance: str
    definition_hash: str
    customer_id: str
    jules_subject: str
    jules_email: str
    evidence_sha256: str

    def validate(self) -> None:
        if (not all((self.company, self.instance, self.customer_id,
                     self.jules_subject, self.jules_email))
                or not HEX64.fullmatch(self.definition_hash)
                or not HEX64.fullmatch(self.evidence_sha256)):
            raise ContractRejected("write handoff operator pins are invalid")


def validate_write_handoff(export: Path, pins: WriteHandoffPins) -> dict:
    """Validate one exact producer generation without granting write authority."""
    pins.validate()
    evidence, raw = _load(export, "google-write-verification-v1.schema.json")
    if hashlib.sha256(raw).hexdigest() != pins.evidence_sha256:
        raise ContractRejected("write handoff digest disagrees with operator pin")
    if (evidence.get("schema_version") != "demo-co/google-write-verification/v1"
            or evidence.get("status") != "ready"):
        raise ContractRejected("write handoff version or status is unavailable")
    if (evidence["company"], evidence["instance"], evidence["definition_hash"],
            evidence["customer_id"], evidence["jules_subject"], evidence["jules_email"]) != (
            pins.company, pins.instance, pins.definition_hash, pins.customer_id,
            pins.jules_subject, pins.jules_email):
        raise ContractRejected("write handoff identity disagrees with operator pin")
    scopes = evidence["granted_scopes"]
    if (len(scopes) != 3 or set(scopes) != WRITE_SCOPES
            or not evidence["folder_can_add_children"]
            or not evidence["document_can_edit"]
            or not evidence["probe_created_as_jules"]
            or not evidence["probe_edited_as_jules"]
            or not evidence["project_b_write_capability_denied"]
            or evidence.get("canonical_documents_mutated") is not False):
        raise ContractRejected("write handoff lacks required independent probes")
    for name, maximum in (("drive_id", 128), ("document_id", 64),
                          ("folder_id", 128), ("probe_document_id", 64),
                          ("tab_id", 16), ("revision_id", 128), ("marker", 48)):
        value = evidence[name]
        if not value or len(value.encode("utf-8")) > maximum or any(c.isspace() for c in value):
            raise ContractRejected("write handoff has an unsupported resource bound")
    if (evidence["document_mime_type"] != "application/vnd.google-apps.document"
            or type(evidence["baseline_byte_count"]) is not int
            or not 0 < evidence["baseline_byte_count"] <= 16_384
            or not HEX64.fullmatch(evidence["baseline_sha256"])
            or not HEX64.fullmatch(evidence["probe_sha256"])):
        raise ContractRejected("write handoff baseline is invalid")
    return evidence


def validate_current_write_observation(
    path: Path, expected_sha256: str, *, evidence: dict, now: int,
    maximum_age: timedelta | None = None,
) -> tuple[int, dict]:
    """Bind a later read-only producer snapshot to the original write fixture.

    The original verification remains the capability proof. This snapshot
    supplies only the current working Doc content and tab for a later edit.
    """
    match = _GENERATION.fullmatch(path.parent.name)
    if (path.name != "google-write-observation.json" or match is None
            or int(match.group(1)) < 2
            or type(expected_sha256) is not str
            or not HEX64.fullmatch(expected_sha256)
            or path.is_symlink() or path.parent.is_symlink()
            or not path.is_file() or not path.parent.is_dir()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
            or type(now) is not int):
        raise ContractRejected("current write observation is unavailable")
    raw = path.read_bytes()
    if len(raw) > 4096 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ContractRejected("current write observation digest disagrees with pin")
    try:
        observation = json.loads(raw, object_pairs_hook=_unique_pairs)
        observed = datetime.fromisoformat(observation["observed_at"])
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as error:
        raise ContractRejected("current write observation is malformed") from error
    if (type(observation) is not dict
            or set(observation) != _WRITE_OBSERVATION_FIELDS
            or observation["schema_version"] != "demo-co/google-write-observation/v1"
            or any(observation[field] != evidence[field] for field in (
                "company", "instance", "definition_hash", "document_id", "tab_id"))
            or type(observation["revision_id"]) is not str
            or not 1 <= len(observation["revision_id"].encode()) <= 128
            or type(observation["content_sha256"]) is not str
            or HEX64.fullmatch(observation["content_sha256"]) is None
            or type(observation["content_byte_count"]) is not int
            or not 1 <= observation["content_byte_count"] <= 16_384
            or type(observation["original_marker_count"]) is not int
            or not 0 <= observation["original_marker_count"] <= 10
            or observed.tzinfo is None or observed.utcoffset() is None):
        raise ContractRejected("current write observation differs from verified fixture")
    age = datetime.fromtimestamp(now, timezone.utc) - observed
    if age < timedelta(0) or (maximum_age is not None and age > maximum_age):
        raise ContractRejected("current write observation is stale or in the future")
    return int(match.group(1)), observation


def inspect_write_handoff(export: Path | None = None,
                          pins: WriteHandoffPins | None = None) -> WriteHandoffStatus:
    """Report producer readiness separately from installed write readiness.

    An unpinned file never activates the write path. Even a pinned, passing
    producer generation still requires Auths authority, custody and execution.
    """
    if export is None or pins is None:
        reason = "producer export and operator pins have not both been supplied"
        return WriteHandoffStatus(
            contract="auths.demo-co-google-write-handoff-status/v1",
            status="write_not_configured", reason=reason,
        )
    try:
        validate_write_handoff(export, pins)
    except (ContractRejected, OSError, ValueError) as error:
        return WriteHandoffStatus(
            contract="auths.demo-co-google-write-handoff-status/v1",
            status="producer_rejected", reason=str(error),
        )
    return WriteHandoffStatus(
        contract="auths.demo-co-google-write-handoff-status/v1",
        status="write_not_configured",
        reason="producer generation is pinned; installed Auths task write is not configured",
        producer_ready=True,
        evidence_sha256=pins.evidence_sha256,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect AP-SPEC-071 producer write readiness")
    parser.add_argument("--export", type=Path)
    args = parser.parse_args()
    print(json.dumps(asdict(inspect_write_handoff(args.export)), sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
