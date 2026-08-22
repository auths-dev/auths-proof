from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Literal, Optional, Tuple, Union

from . import ErrorInfo, Receipt
from ._native import (
    NativeVerificationResult, validate_receipt_anchor_v1,
    verify_many_v1, verify_pinned_receipt_v1, verify_receipt_link_v1, verify_v1,
)
from ._public import error_info, mint_receipt, parse_portable_receipt

VerificationStage = Literal["decode", "resolve", "principal-control", "authority", "complete"]
VerificationKind = Literal["authorized", "denied", "indeterminate"]


@dataclass(frozen=True, init=False)
class VerificationInput:
    proof: bytes
    action: bytes
    trusted_context: bytes

    def __init__(self, *, proof: bytes, action: bytes, trusted_context: bytes) -> None:
        object.__setattr__(self, "proof", bytes(proof))
        object.__setattr__(self, "action", bytes(action))
        object.__setattr__(self, "trusted_context", bytes(trusted_context))


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
class AuthorizedVerification:
    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    correlation_id: str
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    executed_configuration: bytes
    decision_bytes: bytes


@dataclass(frozen=True)
class UnsuccessfulVerification:
    kind: Literal["denied", "indeterminate"]
    code: str
    stage: VerificationStage
    correlation_id: str
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    executed_configuration: bytes
    decision_bytes: bytes
    issue: ErrorInfo


VerificationResult = Union[AuthorizedVerification, UnsuccessfulVerification]


@dataclass(frozen=True)
class ApprovalInspection:
    policy_id: str
    evaluator_version: str
    decision: Literal["approved", "rejected"]
    commitment: bytes


@dataclass(frozen=True)
class VerificationInspection:
    kind: VerificationKind
    code: str
    stage: VerificationStage
    result_commitment: bytes
    action_commitment: Optional[bytes]
    required_configuration_commitment: Optional[bytes]
    executed_configuration_commitment: bytes
    metrics: VerificationMetrics
    approval: Optional[ApprovalInspection]


@dataclass(frozen=True)
class ReceiptSignerInfo:
    principal: str
    verification_method: str
    suite: str


ReceiptSignerRole = Literal["decision", "execution"]


@dataclass(frozen=True)
class ReceiptProfile:
    id: str
    version: int


@dataclass(frozen=True)
class ReceiptTrustAnchor:
    role: ReceiptSignerRole
    principal: str
    verification_method: str
    suite: Literal["ed25519-v1", "p256-sha256-v1"]
    public_key: bytes


_TRUST_TOKEN = object()


class ReceiptTrustPolicy:
    def __init__(self, token: object, anchors: Tuple[ReceiptTrustAnchor, ...], profiles: Tuple[ReceiptProfile, ...], verification_time: Optional[int], maximum_age: int) -> None:
        if token is not _TRUST_TOKEN:
            raise TypeError("ReceiptTrustPolicy is sealed")
        self._anchors = anchors
        self._profiles = profiles
        self._verification_time = verification_time
        self._maximum_age = maximum_age

    @property
    def allowed_profiles(self) -> Tuple[ReceiptProfile, ...]:
        return self._profiles

    @property
    def anchor_count(self) -> int:
        return len(self._anchors)


def pinned_receipt_trust(*, anchors: Iterable[ReceiptTrustAnchor], allowed_profiles: Iterable[ReceiptProfile], verification_time_unix_seconds: Optional[int] = None, maximum_receipt_age_seconds: Optional[int] = None) -> ReceiptTrustPolicy:
    anchor_values = tuple(ReceiptTrustAnchor(value.role, value.principal, value.verification_method, value.suite, bytes(value.public_key)) for value in anchors)
    profiles = tuple(ReceiptProfile(value.id, value.version) for value in allowed_profiles)
    if not 1 <= len(anchor_values) <= 32 or not any(value.role == "decision" for value in anchor_values):
        raise ValueError("receipt trust requires 1..32 anchors including a decision anchor")
    if not 1 <= len(profiles) <= 16:
        raise ValueError("receipt trust requires 1..16 profiles")
    if len({(value.id, value.version) for value in profiles}) != len(profiles):
        raise ValueError("duplicate receipt profile")
    if verification_time_unix_seconds is not None and verification_time_unix_seconds < 0:
        raise ValueError("verification time is invalid")
    seen = set()
    for anchor in anchor_values:
        identity = (anchor.role, anchor.principal, anchor.verification_method, anchor.suite)
        if identity in seen:
            raise ValueError("duplicate receipt trust anchor")
        seen.add(identity)
        validate_receipt_anchor_v1(anchor.suite, anchor.public_key)
    maximum_age = 86_400 if maximum_receipt_age_seconds is None else maximum_receipt_age_seconds
    if not 1 <= maximum_age <= 31_536_000:
        raise ValueError("maximum receipt age is outside bounds")
    return ReceiptTrustPolicy(_TRUST_TOKEN, anchor_values, profiles, verification_time_unix_seconds, maximum_age)


@dataclass(frozen=True)
class DecisionReceiptDetails:
    kind: Literal["decision"]
    receipt_id: str
    profile_id: str
    profile_version: int
    decision: Literal["authorized", "denied", "indeterminate"]
    reasons: Tuple[str, ...]
    decided_at_unix_seconds: int
    decision_signer: ReceiptSignerInfo
    proof_commitment: str
    action_commitment: str
    context_commitment: str
    principal_status_commitment: str
    grant_status_commitment: str


@dataclass(frozen=True)
class ExecutionReceiptDetails:
    kind: Literal["execution"]
    decision_receipt_id: str
    execution_receipt_id: str
    profile_id: str
    profile_version: int
    decision: Literal["authorized", "denied", "indeterminate"]
    outcome: Literal["succeeded", "failed", "indeterminate"]
    reasons: Tuple[str, ...]
    decided_at_unix_seconds: int
    completed_at_unix_seconds: int
    decision_signer: ReceiptSignerInfo
    execution_signer: ReceiptSignerInfo
    proof_commitment: str
    action_commitment: str
    context_commitment: str
    principal_status_commitment: str
    grant_status_commitment: str
    execution_lease_commitment: str
    command_commitment: str
    result_commitment: Optional[str]


ReceiptEnvelopeDetails = Union[DecisionReceiptDetails, ExecutionReceiptDetails]


@dataclass(frozen=True, init=False)
class VerifiedReceipt:
    kind: Literal["verified"]
    receipt: Receipt
    details: ReceiptEnvelopeDetails

    def __init__(self, token: object, receipt: Receipt, details: ReceiptEnvelopeDetails) -> None:
        if token is not _VERIFIED_TOKEN:
            raise TypeError("VerifiedReceipt is sealed")
        object.__setattr__(self, "kind", "verified")
        object.__setattr__(self, "receipt", receipt)
        object.__setattr__(self, "details", details)


@dataclass(frozen=True)
class RejectedReceipt:
    kind: Literal["rejected"]
    issue: ErrorInfo


@dataclass(frozen=True)
class IndeterminateReceipt:
    kind: Literal["indeterminate"]
    issue: ErrorInfo


ReceiptVerification = Union[VerifiedReceipt, RejectedReceipt, IndeterminateReceipt]
_VERIFIED_TOKEN = object()


class _Verifier:
    def __init__(self, token: object) -> None:
        if token is not _VERIFIER_TOKEN:
            raise TypeError("Verifier is sealed")

    def verify(self, input: VerificationInput, *, correlation_id: Optional[str] = None) -> VerificationResult:
        native = verify_v1(input.proof, input.action, input.trusted_context)
        return _project(native, correlation_id or f"auths-{time.time_ns():x}")

    def verify_many(self, inputs: Iterable[VerificationInput], *, chunk_size: int = 32) -> Tuple[VerificationResult, ...]:
        values = tuple(inputs)
        if not 1 <= len(values) <= 256 or not 1 <= chunk_size <= 256:
            raise ValueError("verification batch is outside bounds")
        native = verify_many_v1([(value.proof, value.action, value.trusted_context) for value in values])
        return tuple(_project(value, f"auths-{time.time_ns():x}-{index}") for index, value in enumerate(native))

    def inspect(self, result: VerificationResult) -> VerificationInspection:
        def digest(domain: bytes, value: bytes) -> bytes:
            return hashlib.sha256(domain + value).digest()
        return VerificationInspection(result.kind, result.code, result.stage, digest(b"result", result.decision_bytes), digest(b"action", result.decision_bytes) if result.kind == "authorized" else None, None if result.required_configuration is None else digest(b"required", result.required_configuration), digest(b"executed", result.executed_configuration), result.metrics, None)

    def verify_receipt(self, *, receipt: Union[Receipt, bytes], trust: ReceiptTrustPolicy) -> ReceiptVerification:
        if not isinstance(trust, ReceiptTrustPolicy):
            raise TypeError("unsealed receipt trust policy")
        try:
            if not isinstance(receipt, (Receipt, bytes)):
                raise TypeError("receipt must be sealed or bytes")
            source_bytes = receipt.to_bytes() if isinstance(receipt, Receipt) else receipt
            kind, portable_id, decision_id, execution_id, attested_decision, attested_execution = parse_portable_receipt(source_bytes)
            source = receipt if isinstance(receipt, Receipt) else mint_receipt(portable_id, source_bytes)
            if source.id != portable_id:
                raise ValueError
            decision_metadata = _verify_with_anchors(
                "decision", attested_decision, decision_id, "decision", trust,
            )
            metadata = decision_metadata
            if kind == "execution":
                if execution_id is None or attested_execution is None:
                    raise ValueError
                metadata = _verify_with_anchors(
                    "execution", attested_execution, execution_id, "execution", trust,
                )
                verify_receipt_link_v1(
                    attested_decision, decision_id, attested_execution, execution_id,
                )
                if metadata["decisionReceiptId"] != decision_id.hex():
                    raise ValueError

            profile = decision_metadata["profile"]
            if not any(value.id == profile["id"] and value.version == profile["version"] for value in trust.allowed_profiles):
                return RejectedReceipt("rejected", error_info("core.receipt-profile-denied"))
            now = trust._verification_time
            if now is None:
                try: now = int(time.time())
                except (OSError, OverflowError):
                    return IndeterminateReceipt("indeterminate", error_info("core.receipt-trust-indeterminate"))
            decided_at = int(decision_metadata["decidedAtUnixSeconds"])
            completed_at = decided_at if kind == "decision" else int(metadata["completedAtUnixSeconds"])
            if decided_at > now + 300 or completed_at > now + 300 or now - decided_at > trust._maximum_age:
                return RejectedReceipt("rejected", error_info("core.receipt-expired"))
            decision_signer = _signer(decision_metadata["decisionSigner"])
            common = decision_metadata["commitments"]
            if kind == "decision":
                details: ReceiptEnvelopeDetails = DecisionReceiptDetails(
                    "decision", decision_id.hex(), profile["id"], int(profile["version"]),
                    decision_metadata["decision"], tuple(decision_metadata["reasons"]), decided_at,
                    decision_signer, common["proof"], common["action"], common["context"],
                    common["principalStatus"], common["grantStatus"],
                )
            else:
                assert execution_id is not None
                execution_commitments = metadata["commitments"]
                details = ExecutionReceiptDetails(
                    "execution", metadata["decisionReceiptId"], execution_id.hex(), profile["id"], int(profile["version"]),
                    decision_metadata["decision"], metadata["outcome"], tuple(decision_metadata["reasons"]), decided_at,
                    completed_at, decision_signer, _signer(metadata["executionSigner"]), common["proof"], common["action"],
                    common["context"], common["principalStatus"], common["grantStatus"], execution_commitments["executionLease"],
                    execution_commitments["command"], execution_commitments.get("result"),
                )
            return VerifiedReceipt(_VERIFIED_TOKEN, source, details)
        except (AssertionError, KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return RejectedReceipt("rejected", error_info("core.receipt-malformed"))


def _verify_with_anchors(kind: str, attested: bytes, receipt_id: bytes, role: ReceiptSignerRole, trust: ReceiptTrustPolicy) -> Dict[str, Any]:
    attempted = False
    for anchor in trust._anchors:
        if anchor.role != role:
            continue
        attempted = True
        try:
            encoded = verify_pinned_receipt_v1(kind, attested, receipt_id, anchor.principal, anchor.verification_method, anchor.suite, anchor.public_key)
            value = json.loads(bytes(encoded).decode("utf-8"))
            if type(value) is dict:
                return value
        except Exception:
            continue
    if not attempted:
        raise ValueError("receipt signer is untrusted")
    raise ValueError("receipt signature is invalid")


_VERIFIER_TOKEN = object()


_VERIFIER = _Verifier(_VERIFIER_TOKEN)


def verify(value: VerificationInput, /) -> VerificationResult:
    return _VERIFIER.verify(value)


def verify_many(values: Iterable[VerificationInput], /) -> Tuple[VerificationResult, ...]:
    return _VERIFIER.verify_many(values)


def inspect(value: VerificationResult, /) -> VerificationInspection:
    return _VERIFIER.inspect(value)


def verify_receipt(
    receipt: Union[Receipt, bytes], /, *, trust: ReceiptTrustPolicy,
) -> ReceiptVerification:
    return _VERIFIER.verify_receipt(
        receipt=receipt,
        trust=trust,
    )


def _project(native: NativeVerificationResult, correlation_id: str) -> VerificationResult:
    metrics = VerificationMetrics(*native.metrics)
    common = (native.code, native.stage, correlation_id, metrics, native.required_configuration, bytes(native.local_configuration), bytes(native.result_cbor))
    if native.kind == "authorized":
        return AuthorizedVerification("authorized", *common)
    code = "core.authorization-denied" if native.kind == "denied" else "core.authorization-indeterminate"
    return UnsuccessfulVerification(native.kind, *common, error_info(code, correlation_id=correlation_id))


def _signer(value: Dict[str, Any]) -> ReceiptSignerInfo:
    return ReceiptSignerInfo(value["principal"], value["verificationMethod"], value["suite"])


__all__ = [
    "ApprovalInspection", "AuthorizedVerification", "DecisionReceiptDetails", "ExecutionReceiptDetails", "IndeterminateReceipt", "ReceiptEnvelopeDetails", "ReceiptProfile", "ReceiptSignerInfo", "ReceiptTrustAnchor", "ReceiptTrustPolicy", "ReceiptVerification", "RejectedReceipt", "UnsuccessfulVerification", "VerificationInput", "VerificationInspection", "VerificationMetrics", "VerificationResult", "VerifiedReceipt", "inspect", "pinned_receipt_trust", "verify", "verify_many", "verify_receipt",
]
