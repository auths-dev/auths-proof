"""Deterministic, effect-free Auths verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal, Optional, Tuple, Union

from ._boundary import boundary
from ._native import NativeVerificationResult, verify_many_v1, verify_v1
from ._inspection import (
    ApprovalInspection,
    DecisionCommitments,
    DecisionInspection,
    DecisionSummary,
    KernelSummary,
    VerificationMetrics,
    inspect_decision as _inspect_decision,
)
from ._receipts import (
    InvalidReceiptInspection,
    ReceiptDisclosureMaterial,
    ReceiptDisclosureProtector,
    ReceiptDisclosureStore,
    ReceiptInspectionCommitments,
    ReceiptInspectionMetadata,
    ReceiptInspectionProfile,
    ReceiptInspectionResult,
    ReceiptInspectionSigner,
    ReceiptSummary,
    ReceiptSummaryField,
    ReceiptViewMode,
    VerifiedDisclosedReceipt,
    VerifiedOpaqueReceipt,
    create_receipt_disclosure as _create_receipt_disclosure,
    decode_linked_receipt,
    encode_linked_receipt,
    inspect_receipt as _inspect_receipt,
    verify_linked_receipt,
)

# Every published receipt entry point crosses the pyo3 boundary or parses
# attacker-controlled bytes. Each one reports failure as `AuthsError`, so a
# caller can read the effect axis from any of them.
create_receipt_disclosure = boundary("Auths receipt disclosure is not preparable")(
    _create_receipt_disclosure
)
decode_receipt = boundary("portable Auths receipt is not decodable")(
    decode_linked_receipt
)
encode_receipt = boundary("portable Auths receipt is not encodable")(
    encode_linked_receipt
)
inspect_receipt = boundary("Auths receipt is not inspectable")(_inspect_receipt)
verify_receipt = boundary("Auths receipt does not verify")(verify_linked_receipt)

inspect_decision = boundary("Auths decision is not inspectable")(_inspect_decision)

VerdictKind = Literal["authorized", "denied", "indeterminate"]
# The verdict types are `*Result`, matching `@auths-dev/sdk/verify`. A bare
# `Denied` here would be a second, unrelated type under a name the product
# root already owns (contract 4.3 bans homonyms).
VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]


@dataclass(frozen=True)
class Explanation:
    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class AuthorizedResult:
    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


@dataclass(frozen=True)
class DeniedResult:
    kind: Literal["denied"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


@dataclass(frozen=True)
class IndeterminateResult:
    kind: Literal["indeterminate"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


VerificationResult = Union[AuthorizedResult, DeniedResult, IndeterminateResult]
VerificationInput = Tuple[bytes, bytes, bytes]


@boundary("Auths verification input is not decodable")
def verify(
    proof_cbor: bytes,
    canonical_action_cbor: bytes,
    trusted_context_cbor: bytes,
) -> VerificationResult:
    native = verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor)
    return _project(native)


@boundary("Auths verification input is not decodable")
def verify_many(inputs: Iterable[VerificationInput]) -> Tuple[VerificationResult, ...]:
    values = tuple(inputs)
    for value in values:
        if type(value) is not tuple or len(value) != 3:
            raise TypeError("verification inputs must be three-byte tuples")
        if any(type(part) is not bytes for part in value):
            raise TypeError("verification inputs must be bytes")
    return tuple(_project(value) for value in verify_many_v1(list(values)))


def _project(native: NativeVerificationResult) -> VerificationResult:
    kind = native.kind
    metrics = VerificationMetrics(*native.metrics)
    explanation = _explain(kind, native.code)
    required = native.required_configuration
    local = native.local_configuration
    encoded = native.result_cbor
    if kind == "authorized":
        if native.action is None:
            raise RuntimeError("native verifier omitted authorized capability")
        return AuthorizedResult(
            "authorized",
            native.code,
            native.stage,
            explanation,
            metrics,
            required,
            local,
            encoded,
        )
    if kind == "denied":
        return DeniedResult(
            "denied",
            native.code,
            native.stage,
            explanation,
            metrics,
            required,
            local,
            encoded,
        )
    return IndeterminateResult(
        "indeterminate",
        native.code,
        native.stage,
        explanation,
        metrics,
        required,
        local,
        encoded,
    )


def _explain(kind: VerdictKind, code: str) -> Explanation:
    if kind == "authorized":
        message = "the proof establishes exact authority for this action"
    elif kind == "denied":
        message = "the supplied proof does not authorize this exact action"
    else:
        message = "a required trustworthy fact or implementation is unavailable"
    return Explanation(code=code, message=message, retryable=kind == "indeterminate")


__all__ = [
    "ApprovalInspection",
    "AuthorizedResult",
    "DecisionCommitments",
    "DecisionInspection",
    "DecisionSummary",
    "DeniedResult",
    "InvalidReceiptInspection",
    "ReceiptDisclosureMaterial",
    "ReceiptDisclosureProtector",
    "ReceiptDisclosureStore",
    "ReceiptInspectionCommitments",
    "ReceiptInspectionMetadata",
    "ReceiptInspectionProfile",
    "ReceiptInspectionResult",
    "ReceiptInspectionSigner",
    "ReceiptSummary",
    "ReceiptSummaryField",
    "ReceiptViewMode",
    "VerifiedDisclosedReceipt",
    "VerifiedOpaqueReceipt",
    "create_receipt_disclosure",
    "decode_receipt",
    "encode_receipt",
    "Explanation",
    "IndeterminateResult",
    "KernelSummary",
    "VerificationInput",
    "VerificationMetrics",
    "VerificationResult",
    "inspect_decision",
    "inspect_receipt",
    "verify",
    "verify_many",
    "verify_receipt",
]
