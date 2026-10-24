"""Application read ordering; a provider adapter has no authorization role."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Protocol

from .admission import AdmissionDenied, AdmissionStore
from .authority import verify_read
from .contracts import ReadCommand, TaskDescriptor


class GoogleReadPort(Protocol):
    def read_exact(self, command: ReadCommand) -> bytes:
        """Use only the bound employee connection, fixed Google GETs and byte cap."""


@dataclass(frozen=True)
class ReadOutcome:
    content: bytes
    native_code: str
    released: bool


def execute_read(
    *, task: TaskDescriptor, challenge: bytes, proof: bytes, action: bytes,
    trusted_template: bytes, store: AdmissionStore,
    provider: GoogleReadPort,
) -> ReadOutcome:
    evaluation_time = int(time.time())
    verified = verify_read(
        proof=proof, action=action, trusted_template=trusted_template,
        challenge=challenge, evaluation_time=evaluation_time, task=task,
    )
    reservation = store.claim(task, verified, challenge, now=evaluation_time)
    try:
        if not store.current(reservation):
            raise AdmissionDenied("task changed before provider dispatch")
        # Provider content remains in this process. A failed or ambiguous fetch
        # retains its conservative call, attempt and byte charges.
        content = provider.read_exact(verified.command)
        if not isinstance(content, bytes):
            raise TypeError("provider returned non-byte content")
        released = store.release(reservation, content)
        return ReadOutcome(released, verified.native_code, True)
    except BaseException:
        store.fail(reservation)
        raise
