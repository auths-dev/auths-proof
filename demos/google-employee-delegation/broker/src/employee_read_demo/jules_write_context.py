"""Jules-only AP-071 enrollment context from pinned producer write evidence.

This context permits Google login, Jules key enrollment and the installed
task-write ceremony. It does not claim the six-person company import is ready
or enable AP-070's general resource/task transport.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .write_handoff import WriteHandoffPins, validate_write_handoff


@dataclass(frozen=True)
class JulesWriteContext:
    bundle: dict
    bundle_sha256: str
    jules_subject: str
    google_ready: bool = False
    adoptable: bool = False

    @classmethod
    def from_pinned_evidence(cls, path: Path, pins: WriteHandoffPins) -> "JulesWriteContext":
        evidence = validate_write_handoff(path, pins)
        return cls(
            bundle={
                "company_id": pins.company,
                "instance_id": pins.instance,
                "people": [{
                    "logical_person_id": "jules", "provider": "google",
                    "status": "ready", "provider_subject": pins.jules_subject,
                }],
            },
            bundle_sha256=pins.evidence_sha256,
            jules_subject=evidence["jules_subject"],
        )
