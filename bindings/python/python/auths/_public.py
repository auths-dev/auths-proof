from __future__ import annotations

import hashlib
import importlib.metadata
import platform as host_platform
import re
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Optional, Tuple, Type, TypeVar, cast

from ._error_registry import ERROR_REGISTRY
from ._native import native_abi_version


class EffectState(str, Enum):
    NOT_APPLIED = "not-applied"
    POSSIBLE = "possible"
    APPLIED = "applied"

    def __str__(self) -> str:
        return self.value


class RetryClass(str, Enum):
    NEVER = "never"
    SAFE = "safe"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


class RecommendedAction(str, Enum):
    CORRECT_INPUT = "correct-input"
    CORRECT_CONFIGURATION = "correct-configuration"
    INSTALL_COMPATIBLE_RUNTIME = "install-compatible-runtime"
    RETRY_EXECUTION = "retry-execution"
    SATISFY_CONDITION = "satisfy-condition"
    RESUME_AND_RECONCILE = "resume-and-reconcile"
    INSPECT_RECEIPT = "inspect-receipt"
    CONTACT_SUPPORT = "contact-support"

    def __str__(self) -> str:
        return self.value


class _ValueString(str):
    def __str__(self) -> str:
        return str.__str__(self)


def _member_name(code: str) -> str:
    return code.upper().replace(".", "_").replace("-", "_")


KnownAuthsErrorCode = cast(
    Type[Enum],
    Enum(
        "KnownAuthsErrorCode",
        {_member_name(item["code"]): item["code"] for item in ERROR_REGISTRY["definitions"]},
        type=_ValueString,
        module="auths",
    ),
)


@dataclass(frozen=True)
class EnteredBoundaries:
    approval: bool
    signer: bool
    state: bool
    credential: bool
    provider: bool


@dataclass(frozen=True)
class ErrorInfo:
    schema: str
    code: Any
    family: str
    operation: str
    stage: str
    summary: str
    correlation_id: str
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction
    entered_boundaries: EnteredBoundaries
    execution_reference: Optional[str]
    decision_reference: Optional[str]
    receipt_reference: Optional[str]
    causes: Tuple[str, ...]


_ERROR_TOKEN = object()
_AuthsErrorT = TypeVar("_AuthsErrorT", bound="AuthsError")


class AuthsError(Exception):
    def __new__(
        cls: Type[_AuthsErrorT], *args: Any, **kwargs: Any
    ) -> _AuthsErrorT:
        if cls is AuthsError and (
            kwargs
            or len(args) != 2
            or args[0] is not _ERROR_TOKEN
            or not isinstance(args[1], ErrorInfo)
        ):
            raise TypeError("AuthsError is sealed")
        return cast(_AuthsErrorT, cast(object, Exception.__new__(cls)))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if type(self) is not AuthsError:
            Exception.__init__(self, *args)
            return
        if (
            kwargs
            or len(args) != 2
            or args[0] is not _ERROR_TOKEN
            or not isinstance(args[1], ErrorInfo)
        ):
            raise TypeError("AuthsError is sealed")
        info = args[1]
        super().__init__(info.summary)
        self.info = info

    @property
    def code(self) -> Any:
        return self.info.code

    @property
    def effect(self) -> EffectState:
        return self.info.effect

    @property
    def retry(self) -> RetryClass:
        return self.info.retry


_DEFINITIONS: Mapping[str, Mapping[str, Any]] = {
    cast(str, item["code"]): item
    for item in cast(Iterable[Mapping[str, Any]], ERROR_REGISTRY["definitions"])
}
_ERROR_KEYS = {
    "schema", "family", "code", "operation", "stage", "summary",
    "correlationId", "retry", "effect", "entered", "recommendedAction",
    "executionReference", "decisionReference", "receiptReference", "causes",
}
_ENTERED_KEYS = {"approval", "signer", "state", "credential", "provider"}
_CAUSES = {
    "cancelled", "conflict", "corrupt-state", "invalid-response",
    "limit-exceeded", "timeout", "unavailable", "unknown",
}
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


def parse_error_info(value: object) -> ErrorInfo:
    """Parse one exact registry-bound ``auths.error/1`` host projection."""
    if not isinstance(value, Mapping):
        raise ValueError("Auths error envelope has unknown or missing fields")
    untyped_envelope = cast(Mapping[Any, Any], cast(object, value))
    if set(untyped_envelope) != _ERROR_KEYS:
        raise ValueError("Auths error envelope has unknown or missing fields")
    envelope = cast(Mapping[str, Any], value)
    if envelope["schema"] != "auths.error/1":
        raise ValueError("unsupported Auths error schema")
    code = envelope["code"]
    if not isinstance(code, str) or not _TOKEN.fullmatch(code):
        raise ValueError("invalid Auths error code")
    definition = _DEFINITIONS.get(code)
    if definition is None or envelope["family"] != definition["family"]:
        raise ValueError("unknown or contradictory Auths error code")
    operation, stage = envelope["operation"], envelope["stage"]
    if operation != definition["operation"] or stage not in definition["stages"]:
        raise ValueError("Auths error operation or stage is not registered")
    for token in (operation, stage, envelope["correlationId"]):
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise ValueError("invalid Auths error token")
    operation = cast(str, operation)
    stage = cast(str, stage)
    correlation_id = cast(str, envelope["correlationId"])
    summary = envelope["summary"]
    if not isinstance(summary, str) or not 1 <= len(summary.encode("utf-8")) <= 256:
        raise ValueError("invalid Auths error summary")
    try:
        retry = RetryClass(envelope["retry"])
        effect = EffectState(envelope["effect"])
        action = RecommendedAction(envelope["recommendedAction"])
    except (TypeError, ValueError) as error:
        raise ValueError("invalid Auths recovery classification") from error
    if not any(
        item["retry"] == retry.value and item["effect"] == effect.value
        for item in definition["outcomes"]
    ) or action.value != definition["recommendedAction"]:
        raise ValueError("Auths recovery classification is not registered")
    entered_value = envelope["entered"]
    if not isinstance(entered_value, Mapping):
        raise ValueError("invalid Auths entered-boundary projection")
    untyped_entered = cast(Mapping[Any, Any], cast(object, entered_value))
    if set(untyped_entered) != _ENTERED_KEYS or any(
        type(untyped_entered[key]) is not bool for key in _ENTERED_KEYS
    ):
        raise ValueError("invalid Auths entered-boundary projection")
    entered = cast(Mapping[str, bool], untyped_entered)
    references: list[Optional[str]] = []
    for name in ("executionReference", "decisionReference", "receiptReference"):
        reference = envelope[name]
        if reference is not None and (
            not isinstance(reference, str) or not _TOKEN.fullmatch(reference)
        ):
            raise ValueError("invalid Auths error reference")
        references.append(reference)
    execution, decision, receipt = references
    if (execution is not None) != bool(definition["allowsExecutionReference"]):
        raise ValueError("invalid Auths execution reference")
    if decision is not None and not definition["allowsDecisionReference"]:
        raise ValueError("invalid Auths decision reference")
    if receipt is not None and not definition["allowsReceiptReference"]:
        raise ValueError("invalid Auths receipt reference")
    if retry is RetryClass.SAFE and effect is not EffectState.NOT_APPLIED:
        raise ValueError("unsafe Auths retry classification")
    terminal_integrity_failure = (
        code == "core.terminal-receipt-integrity-failed"
        and retry is RetryClass.NEVER
        and action is RecommendedAction.CONTACT_SUPPORT
        and execution is not None
        and entered["provider"] is True
    )
    if effect is EffectState.POSSIBLE and not terminal_integrity_failure and (
        retry is not RetryClass.UNKNOWN
        or action is not RecommendedAction.RESUME_AND_RECONCILE
        or execution is None
        or entered["provider"] is not True
        or receipt is not None
    ):
        raise ValueError("possible Auths effect lacks recovery invariants")
    if effect is EffectState.NOT_APPLIED and receipt is not None:
        raise ValueError("not-applied Auths error cannot name an execution receipt")
    causes_value = envelope["causes"]
    if not isinstance(causes_value, list):
        raise ValueError("invalid Auths cause categories")
    untyped_causes = cast(list[Any], cast(object, causes_value))
    if len(untyped_causes) > 8 or any(
        not isinstance(item, str) or item not in _CAUSES for item in untyped_causes
    ):
        raise ValueError("invalid Auths cause categories")
    causes = tuple(cast(str, item) for item in untyped_causes)
    return ErrorInfo(
        "auths.error/1", KnownAuthsErrorCode(code), definition["family"], operation,
        stage, summary, correlation_id, effect, retry, action,
        EnteredBoundaries(
            entered["approval"], entered["signer"], entered["state"],
            entered["credential"], entered["provider"],
        ),
        execution, decision, receipt, causes,
    )


def error_info(
    code: str,
    *,
    summary: Optional[str] = None,
    correlation_id: str = "auths-python",
    execution_reference: Optional[str] = None,
    decision_reference: Optional[str] = None,
    receipt_reference: Optional[str] = None,
    causes: Iterable[str] = (),
    provider_entered: Optional[bool] = None,
) -> ErrorInfo:
    definition = _DEFINITIONS.get(code)
    if definition is None:
        raise ValueError("unknown Auths error code")
    outcome = definition["outcomes"][0]
    effect = EffectState(outcome["effect"])
    return ErrorInfo(
        schema="auths.error/1",
        code=KnownAuthsErrorCode(code),
        family=definition["family"],
        operation=definition["operation"],
        stage=definition["stages"][0],
        summary=summary or definition["title"],
        correlation_id=correlation_id,
        effect=effect,
        retry=RetryClass(outcome["retry"]),
        recommended_action=RecommendedAction(definition["recommendedAction"]),
        entered_boundaries=EnteredBoundaries(
            False,
            False,
            execution_reference is not None,
            False,
            effect is not EffectState.NOT_APPLIED if provider_entered is None else provider_entered,
        ),
        execution_reference=execution_reference,
        decision_reference=decision_reference,
        receipt_reference=receipt_reference,
        causes=tuple(causes),
    )


def auths_error(code: str, **kwargs: Any) -> AuthsError:
    return AuthsError(_ERROR_TOKEN, error_info(code, **kwargs))


_RECEIPT_TOKEN = object()


class Receipt:
    __slots__ = ("_id", "_bytes")

    def __new__(cls, token: object, receipt_id: str, value: bytes) -> "Receipt":
        if token is not _RECEIPT_TOKEN:
            raise TypeError("Receipt is sealed")
        return super().__new__(cls)

    def __init__(self, token: object, receipt_id: str, value: bytes) -> None:
        if token is not _RECEIPT_TOKEN or len(value) < 1 or len(value) > 1024 * 1024:
            raise TypeError("invalid Auths receipt")
        self._id = receipt_id
        self._bytes = bytes(value)

    @property
    def id(self) -> str:
        return self._id

    def to_bytes(self) -> bytes:
        return self._bytes

    def __repr__(self) -> str:
        return f"Receipt(id={self._id!r}, bytes=<redacted>)"


def mint_receipt(receipt_id: str, value: bytes) -> Receipt:
    if not re.fullmatch(r"rcpt_[A-Za-z0-9_-]{43}", receipt_id):
        raise ValueError("invalid portable receipt identifier")
    return Receipt(_RECEIPT_TOKEN, receipt_id, value)


def parse_portable_receipt(
    value: bytes,
) -> Tuple[str, str, bytes, Optional[bytes], bytes, Optional[bytes]]:
    if not isinstance(value, bytes):
        raise TypeError("portable receipt must be bytes")
    if not 1 <= len(value) <= 1_048_576:
        raise ValueError("portable receipt is outside bounds")
    from ._native import decode_portable_receipt_v1

    projected = decode_portable_receipt_v1(value)
    kind = projected.kind
    portable_id = projected.portable_receipt_id
    decision_id = bytes(projected.decision_receipt_id)
    projected_execution_id = projected.execution_receipt_id
    execution_id = (
        None
        if projected_execution_id is None
        else bytes(projected_execution_id)
    )
    decision = bytes(projected.attested_decision)
    projected_execution = projected.attested_execution
    execution = (
        None
        if projected_execution is None
        else bytes(projected_execution)
    )
    if (
        kind not in ("decision", "execution")
        or re.fullmatch(r"rcpt_[A-Za-z0-9_-]{43}", portable_id) is None
        or len(decision_id) != 32
        or not 1 <= len(decision) <= 1024 * 1024
        or (kind == "decision") != (execution_id is None and execution is None)
        or (execution_id is not None and len(execution_id) != 32)
        or (execution is not None and not 1 <= len(execution) <= 1024 * 1024)
    ):
        raise ValueError("malformed portable receipt projection")
    return kind, portable_id, decision_id, execution_id, decision, execution


@dataclass(frozen=True)
class RuntimeInfo:
    sdk_version: str
    python_version: str
    platform: str
    native_abi: int
    identity_abi: int
    error_registry_digest: str
    compatible: bool
    semantic_subjects: Tuple[str, ...]
    profiles: Tuple[str, ...]
    capabilities: Tuple[str, ...]
    warnings: Tuple[str, ...]


def runtime_info() -> RuntimeInfo:
    try:
        version = importlib.metadata.version("auths")
    except importlib.metadata.PackageNotFoundError:
        version = "source-tree"
    digest = hashlib.sha256(
        __import__("json").dumps(
            ERROR_REGISTRY, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    native = native_abi_version()
    return RuntimeInfo(
        version,
        sys.version.split()[0],
        host_platform.platform(),
        native,
        1,
        digest,
        native == 2,
        (
            "auths.profile-operation/1",
        ),
        (),
        (
            "verification", "identity", "local-agent.session-v1",
            "profile-operation.v1", "profile-runtime.v1",
        ),
        () if native == 2 else ("native ABI mismatch",),
    )
