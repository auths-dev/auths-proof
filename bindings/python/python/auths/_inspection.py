"""Bounded, non-effect-capable Auths decision inspection."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import (
    Literal,
    Mapping,
    Optional,
    Protocol,
    Tuple,
    Union,
    cast,
)

from ._native import (
    AuthorizationPlan,
    McpAction,
    SignedObject,
    TrustedContext,
    UnsignedObject,
    VerifiedAction,
    commit_canonical_v1,
    inspect_mcp_action,
    inspect_plan,
    inspect_signed,
    inspect_trusted_context,
    inspect_unsigned,
    inspect_verified_action,
    parse_signed,
    parse_trusted_context,
    parse_unsigned,
    unsigned_from_signed,
)

VerdictKind = Literal["authorized", "denied", "indeterminate"]
VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]
SafeLogValue = Union[str, bool]


@dataclass(frozen=True)
class VerificationMetrics:
    """The one metrics type. `InspectionMetrics` was a second name for it."""

    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int


@dataclass(frozen=True)
class DecisionSummary:
    kind: VerdictKind


@dataclass(frozen=True)
class KernelSummary:
    stage: VerificationStage
    code: str


@dataclass(frozen=True)
class DecisionCommitments:
    result: bytes
    local_configuration: bytes
    required_configuration: Optional[bytes]
    action: Optional[bytes]


@dataclass(frozen=True)
class ApprovalInspection:
    policy_id: str
    evaluator_version: str
    required_configuration: bytes
    executed_configuration: bytes
    executed_mode: str
    executed_max_uses: int
    executed_expires_in_seconds: int
    executed_requirements: Tuple[str, ...]


@dataclass(frozen=True)
class DecisionInspection:
    decision: DecisionSummary
    kernel: KernelSummary
    commitments: DecisionCommitments
    metrics: VerificationMetrics
    approval: Optional[ApprovalInspection]
    safe_to_log: Mapping[str, SafeLogValue]


class _Metrics(Protocol):
    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int


class _Explanation(Protocol):
    retryable: bool


class InspectableDecision(Protocol):
    kind: VerdictKind
    code: str
    stage: VerificationStage
    explanation: _Explanation
    metrics: _Metrics
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


class _ApprovalSummary(Protocol):
    policy_id: str
    evaluator_version: str
    required_configuration: bytes
    executed_configuration: bytes
    executed_mode: str
    executed_max_uses: int
    executed_expires_in_seconds: int
    executed_requirements: Tuple[str, ...]


def inspect_decision(result: InspectableDecision) -> DecisionInspection:
    if result.kind not in ("authorized", "denied", "indeterminate"):
        raise TypeError("decision is not an Auths verification result")
    metrics = result.metrics
    inspection_metrics = VerificationMetrics(
        metrics.proof_bytes,
        metrics.action_bytes,
        metrics.context_bytes,
        metrics.object_count,
        metrics.plan_leaves,
        metrics.plan_depth,
        metrics.work_units,
    )
    action_commitment: Optional[bytes] = None
    action = getattr(result, "action", None)
    if type(action) is VerifiedAction:
        action_commitment = bytes(
            commit_canonical_v1(
                "auths.canonical-action.v1", inspect_verified_action(action)
            )
        )
    supplied_action_commitment = getattr(result, "action_commitment", None)
    if supplied_action_commitment is not None:
        supplied_action = bytes(supplied_action_commitment)
        if len(supplied_action) != 32:
            raise TypeError("decision contains an invalid action commitment")
        action_commitment = supplied_action
    required = result.required_configuration
    approval = _approval_inspection(getattr(result, "approval", None))
    return DecisionInspection(
        decision=DecisionSummary(result.kind),
        kernel=KernelSummary(result.stage, result.code),
        commitments=DecisionCommitments(
            result=bytes(
                commit_canonical_v1("auths.verification-result.v1", result.result_cbor)
            ),
            local_configuration=bytes(
                commit_canonical_v1(
                    "auths.verifier-configuration.v1",
                    result.local_configuration,
                )
            ),
            required_configuration=(
                None
                if required is None
                else bytes(
                    commit_canonical_v1("auths.required-configuration.v1", required)
                )
            ),
            action=action_commitment,
        ),
        metrics=inspection_metrics,
        approval=approval,
        safe_to_log=MappingProxyType(
            {
                "kind": result.kind,
                "stage": result.stage,
                "code": result.code,
                "retryable": result.explanation.retryable,
            }
        ),
    )


def canonical_action_bytes(action: VerifiedAction) -> bytes:
    return inspect_verified_action(action)


def unsigned_object_bytes(value: UnsignedObject) -> bytes:
    return inspect_unsigned(value)


def signed_object_bytes(value: SignedObject) -> bytes:
    return inspect_signed(value)


def authorization_plan_bytes(value: AuthorizationPlan) -> bytes:
    return inspect_plan(value)


def mcp_action_bytes(value: McpAction) -> Tuple[bytes, bytes]:
    return inspect_mcp_action(value)


def trusted_context_bytes(value: TrustedContext) -> bytes:
    return inspect_trusted_context(value)


def parse_signed_object(kind: str, value: bytes) -> SignedObject:
    return parse_signed(kind, value)


def parse_unsigned_object(kind: str, value: bytes) -> UnsignedObject:
    return parse_unsigned(kind, value)


def parse_trusted_context_bytes(value: bytes) -> TrustedContext:
    return parse_trusted_context(value)


def signed_object_statement(value: SignedObject) -> UnsignedObject:
    return unsigned_from_signed(value)


def _approval_inspection(value: object) -> Optional[ApprovalInspection]:
    if value is None:
        return None
    summary = cast(_ApprovalSummary, value)
    try:
        return ApprovalInspection(
            policy_id=summary.policy_id,
            evaluator_version=summary.evaluator_version,
            required_configuration=bytes(summary.required_configuration),
            executed_configuration=bytes(summary.executed_configuration),
            executed_mode=summary.executed_mode,
            executed_max_uses=summary.executed_max_uses,
            executed_expires_in_seconds=summary.executed_expires_in_seconds,
            executed_requirements=tuple(summary.executed_requirements),
        )
    except (AttributeError, TypeError, ValueError):
        raise TypeError("decision contains an invalid approval summary") from None


__all__ = [
    "ApprovalInspection",
    "DecisionCommitments",
    "DecisionInspection",
    "DecisionSummary",
    "InspectableDecision",
    "VerificationMetrics",
    "KernelSummary",
    "authorization_plan_bytes",
    "canonical_action_bytes",
    "inspect_decision",
    "mcp_action_bytes",
    "parse_signed_object",
    "parse_trusted_context_bytes",
    "parse_unsigned_object",
    "signed_object_bytes",
    "signed_object_statement",
    "trusted_context_bytes",
    "unsigned_object_bytes",
]
