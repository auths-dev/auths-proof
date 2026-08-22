"""Explicit outcome handling and durable recovery with the Auths local agent."""

from __future__ import annotations

from typing import Optional, Protocol

import auths
from auths.profile_runtime import (
    Completed,
    Conflict,
    Denied,
    NotApplied,
    Partial,
    ReceiptIntegrityFailed,
    RecoveryRequired,
    Unavailable,
)
from auths_profiles.stripe import Stripe


class RecoveryStore(Protocol):
    """Store that durably copies and atomically replaces bytes before returning."""

    async def save(self, operation_id: str, encoded: bytearray) -> None: ...

    async def delete(self, operation_id: str) -> None: ...


async def save_recovery(
    store: RecoveryStore,
    operation_id: str,
    recovery: auths.RecoveryHandle,
) -> None:
    encoded = bytearray(recovery.to_bytes())
    try:
        await store.save(operation_id, encoded)
    finally:
        encoded[:] = b"\0" * len(encoded)


async def create_refund(
    recovery_store: RecoveryStore,
    *,
    refund_request_id: str,
) -> None:
    """Create one refund; keep ``refund_request_id`` stable only for its retries."""

    async with auths.connect() as session:
        refunds = Stripe(session, connection="billing").refunds
        outcome = await refunds.create_outcome(
            payment_intent="pi_123",
            amount=2_000,
            currency="usd",
            options=auths.OperationOptions(idempotency_key=refund_request_id),
        )

        pending_recovery: Optional[str] = None
        if isinstance(outcome, RecoveryRequired):
            await save_recovery(
                recovery_store, outcome.operation_id, outcome.recovery
            )
            pending_recovery = outcome.operation_id
            outcome = await refunds.recover_outcome(outcome.recovery)

        if isinstance(outcome, Completed):
            refund = outcome.value
            if pending_recovery is not None:
                await recovery_store.delete(pending_recovery)
            print("refund", refund.id)
            print("operation", refund.auths.operation_id, refund.auths.completion)
            print("receipts", *refund.auths.receipt_ids)
            return

        if isinstance(outcome, RecoveryRequired):
            await save_recovery(
                recovery_store, outcome.operation_id, outcome.recovery
            )
            print("recovery queued", outcome.operation_id, *outcome.receipt_ids)
            return

        if isinstance(outcome, ReceiptIntegrityFailed):
            print(
                "receipt integrity failure; contact the Auths operator/support",
                outcome.operation_id,
                outcome.state,
                outcome.effect,
                outcome.terminal,
                outcome.issue.code,
            )
            return

        if isinstance(outcome, Conflict):
            await save_recovery(
                recovery_store, outcome.operation_id, outcome.recovery
            )
            raise RuntimeError(
                f"refund conflict for original operation {outcome.operation_id}: "
                f"{outcome.issue.code}"
            )

        if isinstance(outcome, Denied):
            if pending_recovery is not None:
                await recovery_store.delete(pending_recovery)
            raise RuntimeError(
                f"refund denied for operation {outcome.operation_id}: {outcome.issue.code}"
            )

        if isinstance(outcome, Unavailable):
            raise RuntimeError(
                f"refund unavailable before effect (operation={outcome.operation_id}): "
                f"{outcome.issue.code}"
            )

        if isinstance(outcome, NotApplied):
            if pending_recovery is not None:
                await recovery_store.delete(pending_recovery)
            raise RuntimeError(
                f"refund proven not applied for operation {outcome.operation_id} "
                f"({outcome.completion}): {outcome.issue.code}"
            )

        if isinstance(outcome, Partial):
            if pending_recovery is not None:
                await recovery_store.delete(pending_recovery)
            raise RuntimeError(
                f"refund partially applied for operation {outcome.operation_id} "
                f"({outcome.completion}): {outcome.issue.code}"
            )

        raise AssertionError("unrecognized Auths outcome")


# The application bootstrap calls create_refund with its deployment secret store.
