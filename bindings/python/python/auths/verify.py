"""Deterministic, effect-free Auths verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal, Optional, Tuple, Union

from ._native import NativeVerificationResult, verify_many_v1, verify_v1
from ._inspection import (
    ApprovalInspection,
    DecisionCommitments,
    DecisionInspection,
    DecisionSummary,
    InspectionMetrics,
    KernelSummary,
    inspect_decision,
)
from ._receipts import (
    Receipt,
    decode_linked_receipt as decode_receipt,
    encode_linked_receipt as encode_receipt,
    verify_linked_receipt as verify_receipt,
)

VerdictKind = Literal["authorized", "denied", "indeterminate"]
VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]


@dataclass(frozen=True)
class Explanation:
    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class VerificationMetrics:
    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int


@dataclass(frozen=True)
class Authorized:
    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


@dataclass(frozen=True)
class Denied:
    kind: Literal["denied"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


@dataclass(frozen=True)
class Indeterminate:
    kind: Literal["indeterminate"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


VerificationResult = Union[Authorized, Denied, Indeterminate]
VerificationInput = Tuple[bytes, bytes, bytes]


def verify(
    proof_cbor: bytes,
    canonical_action_cbor: bytes,
    trusted_context_cbor: bytes,
) -> VerificationResult:
    native = verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor)
    return _project(native)


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
        return Authorized(
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
        return Denied(
            "denied",
            native.code,
            native.stage,
            explanation,
            metrics,
            required,
            local,
            encoded,
        )
    return Indeterminate(
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
    "Authorized",
    "DecisionCommitments",
    "DecisionInspection",
    "DecisionSummary",
    "Denied",
    "Receipt",
    "decode_receipt",
    "encode_receipt",
    "Explanation",
    "Indeterminate",
    "InspectionMetrics",
    "KernelSummary",
    "VerificationInput",
    "VerificationMetrics",
    "VerificationResult",
    "inspect_decision",
    "verify",
    "verify_many",
    "verify_receipt",
]
