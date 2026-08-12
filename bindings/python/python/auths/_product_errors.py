"""Bounded error and recovery projections owned by the Rust registry."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from asyncio import CancelledError
from types import MappingProxyType
from typing import Any, Final, Mapping, Optional, Sequence, Tuple

from ._error_registry import ERROR_REGISTRY

AuthsErrorCode = str

MAX_TOKEN_BYTES: Final = 128
MAX_TEXT_BYTES: Final = 256
TOKEN_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._:/-")


class RetryClass(str, Enum):
    NEVER = "never"
    SAFE = "safe"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"


class EffectState(str, Enum):
    NOT_APPLIED = "not-applied"
    POSSIBLE = "possible"
    APPLIED = "applied"


class RecommendedAction(str, Enum):
    CORRECT_INPUT = "correct-input"
    CORRECT_CONFIGURATION = "correct-configuration"
    INSTALL_COMPATIBLE_RUNTIME = "install-compatible-runtime"
    RETRY_EXECUTION = "retry-execution"
    SATISFY_CONDITION = "satisfy-condition"
    RESUME_AND_RECONCILE = "resume-and-reconcile"
    INSPECT_RECEIPT = "inspect-receipt"
    CONTACT_SUPPORT = "contact-support"


class CauseCategory(str, Enum):
    CANCELLED = "cancelled"
    CONFLICT = "conflict"
    CORRUPT_STATE = "corrupt-state"
    INVALID_RESPONSE = "invalid-response"
    LIMIT_EXCEEDED = "limit-exceeded"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EnteredBoundaries:
    approval: bool
    signer: bool
    state: bool
    credential: bool
    provider: bool


@dataclass(frozen=True)
class AuthsErrorDetails:
    family: str
    code: str
    operation: str
    stage: str
    summary: str
    correlation_id: str
    retry: RetryClass
    effect: EffectState
    entered: EnteredBoundaries
    recommended_action: RecommendedAction
    execution_reference: Optional[str]
    decision_reference: Optional[str]
    receipt_reference: Optional[str]
    causes: Tuple[CauseCategory, ...]

    def to_dict(self) -> Mapping[str, Any]:
        return MappingProxyType(
            {
                "schema": "auths.error/1",
                "family": self.family,
                "code": self.code,
                "operation": self.operation,
                "stage": self.stage,
                "summary": self.summary,
                "correlationId": self.correlation_id,
                "retry": self.retry.value,
                "effect": self.effect.value,
                "entered": {
                    "approval": self.entered.approval,
                    "signer": self.entered.signer,
                    "state": self.entered.state,
                    "credential": self.entered.credential,
                    "provider": self.entered.provider,
                },
                "recommendedAction": self.recommended_action.value,
                "executionReference": self.execution_reference,
                "decisionReference": self.decision_reference,
                "receiptReference": self.receipt_reference,
                "causes": tuple(cause.value for cause in self.causes),
            }
        )


class AuthsError(Exception):
    def __init__(self, details: AuthsErrorDetails) -> None:
        super().__init__(details.summary)
        self.details = details

    @classmethod
    def parse(cls, value: object) -> "AuthsError":
        return cls(_parse_details(value))

    @property
    def code(self) -> str:
        return self.details.code

    @property
    def retry(self) -> RetryClass:
        return self.details.retry

    @property
    def effect(self) -> EffectState:
        return self.details.effect

    @property
    def recommended_action(self) -> RecommendedAction:
        return self.details.recommended_action

    @property
    def execution_reference(self) -> Optional[str]:
        return self.details.execution_reference

    def to_dict(self) -> Mapping[str, Any]:
        return self.details.to_dict()


def format_auths_error(error: AuthsError) -> str:
    return (
        f"{error.code}: {error} [effect={error.effect.value}, "
        f"retry={error.retry.value}, action={error.recommended_action.value}]"
    )


def error_reference_url(code: str) -> str:
    return f"https://auths.dev/errors/{_token(code)}"


def cause_category_from(value: object) -> CauseCategory:
    if isinstance(value, CancelledError):
        return CauseCategory.CANCELLED
    if isinstance(value, TimeoutError):
        return CauseCategory.TIMEOUT
    if isinstance(value, ConnectionError):
        return CauseCategory.UNAVAILABLE
    if isinstance(value, ValueError):
        return CauseCategory.INVALID_RESPONSE
    return CauseCategory.UNKNOWN


def create_support_bundle(
    *,
    sdk_version: str,
    runtime_family: str,
    runtime_version: str,
    platform: str,
    abi_version: str,
    semantic_subject: str,
    profiles: Sequence[str],
    capabilities: Sequence[str],
    errors: Sequence[AuthsError] = (),
) -> Mapping[str, Any]:
    parsed_errors = []
    for error in errors:
        if type(error) is not AuthsError:
            raise TypeError("support bundle errors must be AuthsError values")
        parsed_errors.append(dict(error.to_dict()))
    parsed_errors.sort(key=lambda value: (value["code"], value["correlationId"]))
    return MappingProxyType(
        {
            "schema": "auths.support/2",
            "sdkVersion": _token(sdk_version),
            "runtime": {
                "family": _token(runtime_family),
                "version": _token(runtime_version),
                "platform": _token(platform),
            },
            "abiVersion": _token(abi_version),
            "semanticSubject": _token(semantic_subject),
            "profiles": _sorted_tokens(profiles),
            "capabilities": _sorted_tokens(capabilities),
            "errors": tuple(parsed_errors),
        }
    )


_DEFINITIONS = {
    definition["code"]: definition for definition in ERROR_REGISTRY["definitions"]
}


def _parse_details(value: object) -> AuthsErrorDetails:
    item = _mapping(value)
    if item.get("schema") != "auths.error/1":
        raise ValueError("unsupported Auths error schema")
    code = _token(item.get("code"))
    definition = _DEFINITIONS.get(code)
    if definition is None:
        raise ValueError("unknown Auths error code")
    operation = _token(item.get("operation"))
    stage = _token(item.get("stage"))
    if operation != definition["operation"] or stage not in definition["stages"]:
        raise ValueError(
            "Auths error operation or stage does not match its registry entry"
        )
    summary = _text(item.get("summary"))
    correlation_id = _token(item.get("correlationId"))
    retry = RetryClass(_token(item.get("retry")))
    effect = EffectState(_token(item.get("effect")))
    if not any(
        outcome["retry"] == retry.value and outcome["effect"] == effect.value
        for outcome in definition["outcomes"]
    ):
        raise ValueError("Auths error recovery classification is not registered")
    recommended_action = RecommendedAction(_token(item.get("recommendedAction")))
    if recommended_action.value != definition["recommendedAction"]:
        raise ValueError("Auths error remediation does not match its registry entry")
    entered = _entered(item.get("entered"))
    execution_reference = _reference(item.get("executionReference"))
    decision_reference = _reference(item.get("decisionReference"))
    receipt_reference = _reference(item.get("receiptReference"))
    if (
        (execution_reference is not None) != definition["allowsExecutionReference"]
        or (
            decision_reference is not None and not definition["allowsDecisionReference"]
        )
        or (receipt_reference is not None and not definition["allowsReceiptReference"])
    ):
        raise ValueError("Auths error contains an unregistered reference")
    if retry is RetryClass.SAFE and effect is not EffectState.NOT_APPLIED:
        raise ValueError("retry-safe Auths errors must be not-applied")
    if effect is EffectState.POSSIBLE and (
        retry is not RetryClass.UNKNOWN
        or recommended_action is not RecommendedAction.RESUME_AND_RECONCILE
        or execution_reference is None
        or not entered.provider
        or receipt_reference is not None
    ):
        raise ValueError("possible Auths effects require explicit reconciliation")
    raw_causes = item.get("causes")
    if not isinstance(raw_causes, list) or len(raw_causes) > 8:
        raise ValueError("Auths error causes are invalid")
    causes = tuple(CauseCategory(_token(cause)) for cause in raw_causes)
    return AuthsErrorDetails(
        family=definition["family"],
        code=code,
        operation=operation,
        stage=stage,
        summary=summary,
        correlation_id=correlation_id,
        retry=retry,
        effect=effect,
        entered=entered,
        recommended_action=recommended_action,
        execution_reference=execution_reference,
        decision_reference=decision_reference,
        receipt_reference=receipt_reference,
        causes=causes,
    )


def _entered(value: object) -> EnteredBoundaries:
    item = _mapping(value)
    names = ("approval", "signer", "state", "credential", "provider")
    if any(type(item.get(name)) is not bool for name in names):
        raise TypeError("Auths error boundary states must be boolean")
    return EnteredBoundaries(
        approval=item["approval"],
        signer=item["signer"],
        state=item["state"],
        credential=item["credential"],
        provider=item["provider"],
    )


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("Auths error value must be a mapping")
    return value


def _reference(value: object) -> Optional[str]:
    return None if value is None else _token(value)


def _token(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode()) > MAX_TOKEN_BYTES
        or any(character not in TOKEN_CHARS for character in value)
    ):
        raise ValueError("Auths error token is invalid")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > MAX_TEXT_BYTES:
        raise ValueError("Auths error text is invalid")
    return value


def _sorted_tokens(values: Sequence[str]) -> Tuple[str, ...]:
    if len(values) > 64:
        raise ValueError("support bundle list is too large")
    return tuple(sorted({_token(value) for value in values}))


__all__ = [
    "AuthsErrorCode",
    "AuthsError",
    "AuthsErrorDetails",
    "CauseCategory",
    "EffectState",
    "EnteredBoundaries",
    "RecommendedAction",
    "RetryClass",
    "cause_category_from",
    "create_support_bundle",
    "error_reference_url",
    "format_auths_error",
]
