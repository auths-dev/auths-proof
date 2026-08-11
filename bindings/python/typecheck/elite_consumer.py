from __future__ import annotations

from auths.authority import ProofPlan, ProofPlanBuilder, ProofReference
from auths.identity import (
    AuthenticatedIdentity,
    IdentityRegistry,
    decode_identity,
)
from auths.runtime import BudgetReservation, InMemoryRuntimeStore
from auths.verify import VerificationInput, VerificationResult, verify_many


async def authenticate(
    packet: bytes,
    message: bytes,
    signature: bytes,
    registry: IdentityRegistry,
) -> AuthenticatedIdentity:
    decoded = decode_identity(packet)
    resolved = await decoded.resolve(registry)
    validated = await resolved.validate(registry)
    return await validated.authenticate(message, signature, registry)


def compose_plan(first: bytes, second: bytes) -> ProofPlan:
    builder = ProofPlanBuilder()
    return builder.threshold(
        1,
        (
            builder.proof(ProofReference(first)),
            builder.proof(ProofReference(second)),
        ),
    )


def batch(values: tuple[VerificationInput, ...]) -> tuple[VerificationResult, ...]:
    return verify_many(values)


async def reserve(store: InMemoryRuntimeStore, commitment: bytes) -> BudgetReservation:
    return await store.reserve(commitment, "numeric-ceiling-v1", 1)
