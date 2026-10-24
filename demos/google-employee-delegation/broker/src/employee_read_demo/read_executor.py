"""Application read ordering; a provider adapter has no authorization role."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Protocol

from .admission import AdmissionDenied, AdmissionStore
from .authority import verify_read
from .contracts import ReadCommand, TaskDescriptor
from .google_drive import GoogleDenied, GoogleDriveReader, ProviderTrace
from .receipts import ReceiptStore


class GoogleReadPort(Protocol):
    def read_exact(self, command: ReadCommand) -> bytes:
        """Use only the bound employee connection, fixed Google GETs and byte cap."""


@dataclass(frozen=True)
class ReadOutcome:
    content: bytes
    native_code: str
    released: bool
    receipt_id: str | None = None


def execute_read(
    *, task: TaskDescriptor, challenge: bytes, proof: bytes, action: bytes,
    trusted_template: bytes, store: AdmissionStore,
    provider: GoogleReadPort,
    receipts: ReceiptStore | None = None,
) -> ReadOutcome:
    evaluation_time = int(time.time())
    verified = verify_read(
        proof=proof, action=action, trusted_template=trusted_template,
        challenge=challenge, evaluation_time=evaluation_time, task=task,
    )
    reservation = store.claim(task, verified, challenge, now=evaluation_time)
    provider_stage = "not_contacted"
    try:
        if not store.current(reservation):
            raise AdmissionDenied("task changed before provider dispatch")
        if isinstance(provider, GoogleDriveReader):
            provider.set_attempt_observer(store.attempt_observer(reservation))
        # Provider content remains in this process. A failed or ambiguous fetch
        # retains its conservative call, attempt and byte charges.
        provider_stage = "requested"
        content = provider.read_exact(verified.command)
        if not isinstance(content, bytes):
            raise TypeError("provider returned non-byte content")
        provider_stage = "content_fetched"
        released = store.release(reservation, content)
    except BaseException as error:
        if isinstance(error, GoogleDenied):
            provider_stage = "provider_denied"
        store.fail(reservation)
        if receipts is not None:
            trace = getattr(provider, "trace", None)
            receipts.record(task=task, verified=verified, challenge=challenge,
                            provider_stage=provider_stage, release_stage="not_committed",
                            content=None, trace=trace if isinstance(trace, ProviderTrace) else None)
        raise
    trace = getattr(provider, "trace", None)
    receipt = None if receipts is None else receipts.record(
        task=task, verified=verified, challenge=challenge,
        provider_stage="content_fetched", release_stage="committed", content=released,
        trace=trace if isinstance(trace, ProviderTrace) else None,
    )
    return ReadOutcome(released, verified.native_code, True,
                       None if receipt is None else receipt.payload["receipt_id"])
