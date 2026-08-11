"""Canonical native Auths decision and execution receipts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from . import _native as native


@dataclass(frozen=True)
class ReceiptSigner:
    principal: str
    verification_method: str
    suite: str
    evidence: bytes

    def __post_init__(self) -> None:
        evidence = bytes(self.evidence)
        if (
            not self.principal
            or not self.verification_method
            or not self.suite
            or not evidence
        ):
            raise ValueError("invalid receipt signer")
        object.__setattr__(self, "evidence", evidence)


class ReceiptAttestor(Protocol):
    signer: ReceiptSigner

    async def sign(self, preimage: bytes) -> bytes: ...


@dataclass(frozen=True)
class AttestedReceipt:
    kind: str
    receipt_id: bytes
    bytes: bytes
    signer: ReceiptSigner

    def __post_init__(self) -> None:
        if self.kind not in ("decision", "execution"):
            raise ValueError("unsupported receipt kind")
        if len(self.receipt_id) != 32 or not self.bytes:
            raise ValueError("invalid attested receipt")
        object.__setattr__(self, "receipt_id", bytes(self.receipt_id))
        object.__setattr__(self, "bytes", bytes(self.bytes))


def verify_receipt(receipt: AttestedReceipt) -> None:
    if type(receipt) is not AttestedReceipt:
        raise TypeError("attested receipt is required")
    native.verify_raw_key_receipt_v1(
        receipt.kind,
        receipt.bytes,
        receipt.receipt_id,
        receipt.signer.principal,
        receipt.signer.verification_method,
        receipt.signer.suite,
        receipt.signer.evidence,
    )


async def _attest_decision(
    preparation: native.ReceiptPreparation, attestor: ReceiptAttestor
) -> AttestedReceipt:
    signature = await attestor.sign(bytes(preparation.signing_preimage))
    signer = attestor.signer
    encoded = native.attest_decision_receipt_v1(
        preparation.canonical,
        signer.principal,
        signer.verification_method,
        signer.suite,
        signature,
    )
    return AttestedReceipt(
        "decision", bytes(preparation.receipt_id), bytes(encoded), signer
    )


async def _attest_execution(
    preparation: native.ReceiptPreparation, attestor: ReceiptAttestor
) -> AttestedReceipt:
    signature = await attestor.sign(bytes(preparation.signing_preimage))
    signer = attestor.signer
    encoded = native.attest_execution_receipt_v1(
        preparation.canonical,
        signer.principal,
        signer.verification_method,
        signer.suite,
        signature,
    )
    return AttestedReceipt(
        "execution", bytes(preparation.receipt_id), bytes(encoded), signer
    )


__all__ = ["AttestedReceipt", "ReceiptAttestor", "ReceiptSigner", "verify_receipt"]
