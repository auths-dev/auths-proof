"""Canonical native Auths decision and execution receipts."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Mapping, Protocol, cast

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


@dataclass(frozen=True)
class Receipt:
    decision: AttestedReceipt
    execution: AttestedReceipt

    def __post_init__(self) -> None:
        if self.decision.kind != "decision" or self.execution.kind != "execution":
            raise ValueError("Auths receipt pair has invalid kinds")


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


def verify_linked_receipt(receipt: Receipt) -> None:
    if type(receipt) is not Receipt:
        raise TypeError("Auths receipt is required")
    verify_receipt(receipt.decision)
    verify_receipt(receipt.execution)
    native.verify_receipt_link_v1(
        receipt.decision.bytes,
        receipt.decision.receipt_id,
        receipt.execution.bytes,
        receipt.execution.receipt_id,
    )


def encode_linked_receipt(receipt: Receipt) -> bytes:
    if type(receipt) is not Receipt:
        raise TypeError("Auths receipt is required")
    return json.dumps(
        {
            "schema": "auths.portable-receipt/1",
            "decision": _receipt_projection(receipt.decision),
            "execution": _receipt_projection(receipt.execution),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def decode_linked_receipt(value: bytes) -> Receipt:
    encoded = bytes(value)
    if not encoded or len(encoded) > 1024 * 1024:
        raise ValueError("portable Auths receipt is outside bounds")
    try:
        parsed: object = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("portable Auths receipt is malformed") from None
    if type(parsed) is not dict:
        raise ValueError("unsupported portable Auths receipt")
    item = cast(Mapping[str, object], parsed)
    if item.get("schema") != "auths.portable-receipt/1":
        raise ValueError("unsupported portable Auths receipt")
    return Receipt(
        _parse_receipt_projection(item.get("decision"), "decision"),
        _parse_receipt_projection(item.get("execution"), "execution"),
    )


def _receipt_projection(receipt: AttestedReceipt) -> dict[str, object]:
    return {
        "receiptId": _base64url(receipt.receipt_id),
        "bytes": _base64url(receipt.bytes),
        "signer": {
            "principal": receipt.signer.principal,
            "verificationMethod": receipt.signer.verification_method,
            "suite": receipt.signer.suite,
            "evidence": _base64url(receipt.signer.evidence),
        },
    }


def _parse_receipt_projection(value: object, kind: str) -> AttestedReceipt:
    if type(value) is not dict:
        raise ValueError("portable Auths receipt member is malformed")
    item = cast(Mapping[str, object], value)
    signer_value = item.get("signer")
    if type(signer_value) is not dict:
        raise ValueError("portable Auths receipt member is malformed")
    signer = cast(Mapping[str, object], signer_value)
    return AttestedReceipt(
        kind,
        _decode_base64url(item.get("receiptId"), 32, 32),
        _decode_base64url(item.get("bytes"), 1, 768 * 1024),
        ReceiptSigner(
            _bounded_text(signer.get("principal")),
            _bounded_text(signer.get("verificationMethod")),
            _bounded_text(signer.get("suite")),
            _decode_base64url(signer.get("evidence"), 1, 128 * 1024),
        ),
    )


def _bounded_text(value: object) -> str:
    if type(value) is not str or not value or len(value) > 1024:
        raise ValueError("portable Auths receipt text is outside bounds")
    return value


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: object, minimum: int, maximum: int) -> bytes:
    if type(value) is not str or not value or len(value) > maximum * 2:
        raise ValueError("portable Auths receipt bytes are outside bounds")
    try:
        decoded = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise ValueError("portable Auths receipt bytes are malformed") from None
    if not minimum <= len(decoded) <= maximum or _base64url(decoded) != value:
        raise ValueError("portable Auths receipt bytes are not canonical")
    return decoded


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


__all__ = [
    "AttestedReceipt",
    "ReceiptAttestor",
    "ReceiptSigner",
    "Receipt",
    "decode_linked_receipt",
    "encode_linked_receipt",
    "verify_receipt",
    "verify_linked_receipt",
]
