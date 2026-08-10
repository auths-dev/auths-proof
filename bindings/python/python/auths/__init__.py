"""Embedded Auths SDK with native protocol semantics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Union

from . import workflow as _workflow
from . import mcp as _mcp
from .mcp import *  # noqa: F403
from .workflow import *  # noqa: F403

from ._native import VerifiedAction, verify_v1

VerdictKind = Literal["authorized", "denied", "indeterminate"]
VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]


@dataclass(frozen=True)
class Explanation:
    """Stable, non-sensitive result explanation."""

    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class VerificationMetrics:
    """Deterministic input and verifier-work counters."""

    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int


@dataclass(frozen=True)
class Authorized:
    """Exact authority was established."""

    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes
    action: VerifiedAction


@dataclass(frozen=True)
class Denied:
    """Available trustworthy facts established rejection."""

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
    """A required trustworthy fact or implementation was unavailable."""

    kind: Literal["indeterminate"]
    code: str
    stage: VerificationStage
    explanation: Explanation
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


VerificationResult = Union[Authorized, Denied, Indeterminate]


def verify(
    proof_cbor: bytes,
    canonical_action_cbor: bytes,
    trusted_context_cbor: bytes,
) -> VerificationResult:
    """Runs the complete embedded three-input V1 verification operation."""

    native = verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor)
    metrics = VerificationMetrics(*native.metrics)
    explanation = _explain(native.kind, native.code)
    if native.kind == "authorized":
        if native.action is None:
            raise RuntimeError("native verifier omitted authorized capability")
        return Authorized(
            kind="authorized",
            code=native.code,
            stage=native.stage,
            explanation=explanation,
            metrics=metrics,
            required_configuration=native.required_configuration,
            local_configuration=native.local_configuration,
            result_cbor=native.result_cbor,
            action=native.action,
        )
    if native.kind == "denied":
        return Denied(
            kind="denied",
            code=native.code,
            stage=native.stage,
            explanation=explanation,
            metrics=metrics,
            required_configuration=native.required_configuration,
            local_configuration=native.local_configuration,
            result_cbor=native.result_cbor,
        )
    return Indeterminate(
        kind="indeterminate",
        code=native.code,
        stage=native.stage,
        explanation=explanation,
        metrics=metrics,
        required_configuration=native.required_configuration,
        local_configuration=native.local_configuration,
        result_cbor=native.result_cbor,
    )


def _explain(kind: VerdictKind, code: str) -> Explanation:
    if kind == "authorized":
        message = "the proof establishes exact authority for this action"
    elif kind == "denied":
        message = "the supplied proof does not authorize this exact action"
    else:
        message = "a required trustworthy fact or implementation is unavailable"
    return Explanation(code=code, message=message, retryable=kind == "indeterminate")


__all__ = (
    [
        "Authorized",
        "Denied",
        "Explanation",
        "Indeterminate",
        "VerificationMetrics",
        "VerificationResult",
        "VerifiedAction",
        "verify",
    ]
    + _workflow.__all__
    + _mcp.__all__
)
