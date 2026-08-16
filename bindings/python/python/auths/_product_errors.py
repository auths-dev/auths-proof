"""The single Auths error vocabulary, projected from the Rust registry.

Every value in this module is owned by `auths_errors` and reaches Python
through `bindings/python/python/auths/_error_registry.py`, which
`cargo xtask error-registry` generates and byte-compares. Nothing here
defines what a code, an effect, a retry class, or a recommended action
*means*; the only decision Python makes is which registry code names a
failure it observed.

There is exactly one exception hierarchy. `AuthsError` is its root and is
what every failing Auths path raises.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from asyncio import CancelledError
from types import MappingProxyType
from typing import Any, Final, Literal, Mapping, Optional, Sequence, Tuple, cast

from ._error_registry import ERROR_REGISTRY, UNRECOGNIZED_CODE

AuthsErrorCode = str

ProductVerb = Literal["create", "delegate", "execute", "resume", "verify"]
"""`auths_errors::ProductVerb` -- the five product operations.

The wire field is `verb`. The `step` spelling and any sixth verb are deleted:
`sign` is a stage of `create`/`delegate`, and `recover` has no Rust owner.
"""

MAX_TOKEN_BYTES: Final = 128
MAX_TEXT_BYTES: Final = 256
TOKEN_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._:/-")


class RetryClass(str, Enum):
    """`auths_errors::RetryClass` — *may I retry?*"""

    NEVER = "never"
    SAFE = "safe"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"


class EffectState(str, Enum):
    """`auths_errors::EffectState` — *did the real-world effect happen?*

    Exactly three members. An unrecognized code fails closed to ``POSSIBLE``;
    there is no fourth value and never a downgrade to ``NOT_APPLIED``.
    """

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
class AuthsErrorClassification:
    """What the Rust registry says a code means. Never computed locally."""

    code: str
    known: bool
    family: str
    operation: str
    stage: str
    retry: RetryClass
    effect: EffectState
    recommended_action: RecommendedAction


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
    reason: Optional[str] = None
    """Unstable diagnostic label for the exact site that failed.

    Never a code: it is not registered, not versioned, and no caller may
    branch on it in production. `code` is the stable identity.
    """

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
    """The one Auths exception. Raised by every path that fails."""

    def __init__(self, details: AuthsErrorDetails) -> None:
        super().__init__(details.summary)
        self.details = details

    @classmethod
    def parse(cls, value: object) -> "AuthsError":
        return cls(_parse_details(value))

    @classmethod
    def from_native_code(
        cls,
        code: str,
        summary: str,
        *,
        reason: Optional[str] = None,
        correlation_id: str = "unset",
    ) -> "AuthsError":
        """Rebuilds an error Rust already classified, at the pyo3 boundary.

        Unlike `from_code`, a code this build's registry does not contain is
        accepted and fails closed to `possible` -- a newer Rust must not be
        able to crash an older binding, nor be silently downgraded.
        """
        return cls(
            _details_for_code(
                code,
                summary,
                reason=reason,
                correlation_id=correlation_id,
                entered=None,
                execution_reference=None,
                decision_reference=None,
                receipt_reference=None,
                causes=(),
                known_only=False,
            )
        )

    @classmethod
    def from_code(
        cls,
        code: str,
        summary: str,
        *,
        reason: Optional[str] = None,
        correlation_id: str = "unset",
        entered: Optional[EnteredBoundaries] = None,
        execution_reference: Optional[str] = None,
        decision_reference: Optional[str] = None,
        receipt_reference: Optional[str] = None,
        causes: Sequence[CauseCategory] = (),
    ) -> "AuthsError":
        """Mints an error whose whole recovery contract comes from Rust.

        `code` must be a registry code. Everything the caller branches on --
        family, operation, stage, retry, effect, recommended action -- is read
        from the registry, never supplied here.
        """
        return cls(
            _details_for_code(
                code,
                summary,
                reason=reason,
                correlation_id=correlation_id,
                entered=entered,
                execution_reference=execution_reference,
                decision_reference=decision_reference,
                receipt_reference=receipt_reference,
                causes=causes,
            )
        )

    @property
    def code(self) -> str:
        return self.details.code

    @property
    def reason(self) -> Optional[str]:
        return self.details.reason

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

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code!r}, reason={self.reason!r}, "
            f"effect={self.effect.value!r}, retry={self.retry.value!r}, "
            f"recommended_action={self.recommended_action.value!r})"
        )


WORKFLOW_REASON_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {
        # Custody boundary -- an approval or signing provider said no, went
        # away, or answered something other than what was asked.
        "approval-cancelled": "custody.cancelled",
        "approval-failed": "custody.unavailable",
        "approval-rejected": "custody.denied",
        "approval-response-mismatch": "custody.request-mismatch",
        "approval-timeout": "custody.unavailable",
        "approval-unsupported": "custody.provider-unknown",
        "signer-cancelled": "custody.cancelled",
        "signer-failed": "custody.unavailable",
        "signer-rejected": "custody.denied",
        "signer-response-mismatch": "custody.request-mismatch",
        "signer-timeout": "custody.unavailable",
        "signer-unsupported": "custody.provider-unknown",
        "cleanup-failed": "custody.unavailable",
        "authority-mismatch": "custody.evidence-mismatch",
        # Authority source -- a caller-supplied signed-grant provider.
        "authority-source-cancelled": "core.runtime-cancelled",
        "authority-source-failed": "core.runtime-unavailable",
        "authority-source-rejected": "core.authorization-denied",
        "authority-source-timeout": "core.runtime-unavailable",
        "authority-source-unavailable": "core.runtime-unavailable",
        "authority-source-unsupported": "core.invalid-configuration",
        # Authority algebra -- delegation may narrow, never widen.
        "delegation-expanded": "core.authorization-denied",
        "invalid-delegation": "core.authorization-denied",
        # Input and configuration.
        "invalid-action": "core.malformed-input",
        "invalid-authority": "core.malformed-input",
        "invalid-principal": "core.unauthenticated-principal",
        "invalid-profile": "core.invalid-configuration",
        "invalid-provider": "core.invalid-configuration",
        "invalid-trusted-authority": "core.invalid-configuration",
        "approval-policy-mismatch": "core.invalid-configuration",
        "profile-mismatch": "core.invalid-configuration",
        # State.
        "disposed": "core.workflow-terminal",
        "gateway-conflict": "core.runtime-conflict",
        "transaction-consumed": "core.runtime-conflict",
        "transaction-expired": "core.runtime-conflict",
        # The gateway entered the provider and cannot prove the outcome. Both
        # are `mcp.handler-failed`: effect `possible`, reconcile before retry.
        "gateway-cancelled": "mcp.handler-failed",
        "gateway-failed": "mcp.handler-failed",
        # The binding believed something Rust guarantees.
        "native-authorization-failed": "core.internal-invariant",
    }
)
"""Which Rust-owned code names each workflow failure site.

This is the only place the Python package selects a code, and every value is
a `product/errors/v1/registry.json` entry. The keys are diagnostic labels,
not a second code space: `tests/test_registry_code_inventory.py` fails when a
call site uses a key that is not here, or a value that is not in the registry.
"""


class AuthsWorkflowError(AuthsError):
    """An authorization workflow failure, named by a registry code.

    `reason` is the failure site; `code` is the Rust-owned identity a caller
    branches on. Only reasons listed in `WORKFLOW_REASON_CODES` exist.
    """

    def __init__(
        self,
        reason: str,
        summary: str,
        *,
        correlation_id: str = "unset",
        entered: Optional[EnteredBoundaries] = None,
        causes: Sequence[CauseCategory] = (),
    ) -> None:
        code = WORKFLOW_REASON_CODES.get(reason)
        if code is None:
            raise LookupError(
                f"workflow failure reason {reason!r} names no registry code; "
                f"add it to WORKFLOW_REASON_CODES"
            )
        super().__init__(
            _details_for_code(
                code,
                summary,
                reason=reason,
                correlation_id=correlation_id,
                entered=entered,
                execution_reference=None,
                decision_reference=None,
                receipt_reference=None,
                causes=causes,
            )
        )


ProviderFailureKind = Literal[
    "unavailable", "rejected", "cancelled", "timeout", "unsupported"
]

_PROVIDER_FAILURE_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "unavailable": "custody.unavailable",
        "rejected": "custody.denied",
        "cancelled": "custody.cancelled",
        "timeout": "custody.unavailable",
        "unsupported": "custody.provider-unknown",
    }
)


class ProviderOperationError(AuthsError):
    """Raised by a caller-supplied signer or approval provider.

    The `kind` is the provider's own vocabulary; the registry code it maps to
    is what a caller branches on.
    """

    _CODES: Final[Mapping[str, str]] = _PROVIDER_FAILURE_CODES

    def __init__(self, kind: ProviderFailureKind) -> None:
        code = self._CODES.get(kind)
        if code is None:
            raise ValueError("unsupported provider failure kind")
        super().__init__(
            _details_for_code(
                code,
                "external provider operation failed",
                reason=kind,
                correlation_id="unset",
                entered=EnteredBoundaries(False, True, False, True, True),
                execution_reference=None,
                decision_reference=None,
                receipt_reference=None,
                causes=(),
            )
        )
        self.kind: ProviderFailureKind = kind


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
    parsed_errors: list[dict[str, Any]] = []
    for error in errors:
        if not isinstance(error, AuthsError):
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


_DEFINITIONS: Final[Mapping[str, Any]] = MappingProxyType(
    {definition["code"]: definition for definition in ERROR_REGISTRY["definitions"]}
)


def classify(code: str) -> AuthsErrorClassification:
    """Reads Rust's classification of `code`, failing closed for unknown codes.

    This is the only way anything in this package learns what a code means.
    """
    definition = _DEFINITIONS.get(code)
    if definition is None:
        return AuthsErrorClassification(
            code=code,
            known=False,
            family=UNRECOGNIZED_CODE["family"],
            operation=UNRECOGNIZED_CODE["operation"],
            stage=UNRECOGNIZED_CODE["stages"][0],
            retry=RetryClass(UNRECOGNIZED_CODE["retry"]),
            effect=EffectState(UNRECOGNIZED_CODE["effect"]),
            recommended_action=RecommendedAction(
                UNRECOGNIZED_CODE["recommendedAction"]
            ),
        )
    outcome = definition["outcomes"][0]
    return AuthsErrorClassification(
        code=code,
        known=True,
        family=definition["family"],
        operation=definition["operation"],
        stage=definition["stages"][0],
        retry=RetryClass(outcome["retry"]),
        effect=EffectState(outcome["effect"]),
        recommended_action=RecommendedAction(definition["recommendedAction"]),
    )


def registry_codes() -> Tuple[str, ...]:
    return tuple(_DEFINITIONS)


def _details_for_code(
    code: str,
    summary: str,
    *,
    reason: Optional[str],
    correlation_id: str,
    entered: Optional[EnteredBoundaries],
    execution_reference: Optional[str],
    decision_reference: Optional[str],
    receipt_reference: Optional[str],
    causes: Sequence[CauseCategory],
    known_only: bool = True,
) -> AuthsErrorDetails:
    if known_only and code not in _DEFINITIONS:
        raise ValueError(
            "Auths errors carry registry codes only; "
            f"{code!r} is in no build of product/errors/v1/registry.json"
        )
    classification = classify(code)
    boundaries = (
        EnteredBoundaries(False, False, False, False, False)
        if entered is None
        else entered
    )
    if classification.effect is EffectState.POSSIBLE and not boundaries.provider:
        boundaries = EnteredBoundaries(
            boundaries.approval,
            boundaries.signer,
            boundaries.state,
            boundaries.credential,
            True,
        )
    return AuthsErrorDetails(
        family=classification.family,
        code=code,
        operation=classification.operation,
        stage=classification.stage,
        summary=_text(summary),
        correlation_id=_token(correlation_id),
        retry=classification.retry,
        effect=classification.effect,
        entered=boundaries,
        recommended_action=classification.recommended_action,
        execution_reference=execution_reference,
        decision_reference=decision_reference,
        receipt_reference=receipt_reference,
        causes=tuple(causes),
        reason=reason,
    )


def _parse_details(value: object) -> AuthsErrorDetails:
    item = _mapping(value)
    if item.get("schema") != "auths.error/1":
        raise ValueError("unsupported Auths error schema")
    code = _token(item.get("code"))
    definition = _DEFINITIONS.get(code)
    if definition is None:
        return _unknown_details(item, code)
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
    if type(raw_causes) is not list:
        raise ValueError("Auths error causes are invalid")
    cause_values = cast(list[object], raw_causes)
    if len(cause_values) > 8:
        raise ValueError("Auths error causes are invalid")
    causes = tuple(CauseCategory(_token(cause)) for cause in cause_values)
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


def _unknown_details(item: Mapping[str, Any], code: str) -> AuthsErrorDetails:
    """A code this build's registry does not contain.

    The answer is `auths_errors::classify`'s, projected through
    `UNRECOGNIZED_CODE`. It is `possible`: a newer Rust code must never be
    downgraded to `not-applied` by an older binding.
    """
    _token(item.get("operation"))
    _token(item.get("stage"))
    _text(item.get("summary"))
    correlation_id = _token(item.get("correlationId"))
    raw_causes = item.get("causes")
    if type(raw_causes) is not list:
        raise ValueError("Auths error causes are invalid")
    cause_values = cast(list[object], raw_causes)
    if len(cause_values) > 8:
        raise ValueError("Auths error causes are invalid")
    classification = classify(code)
    return AuthsErrorDetails(
        family=classification.family,
        code=code,
        operation=classification.operation,
        stage=classification.stage,
        summary="Unknown Auths error code",
        correlation_id=correlation_id,
        retry=classification.retry,
        effect=classification.effect,
        entered=EnteredBoundaries(False, False, False, False, True),
        recommended_action=classification.recommended_action,
        execution_reference=None,
        decision_reference=None,
        receipt_reference=None,
        causes=() if not cause_values else (CauseCategory.UNKNOWN,),
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
    return cast(Mapping[str, Any], value)


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
    "AuthsError",
    "AuthsErrorClassification",
    "AuthsErrorCode",
    "AuthsErrorDetails",
    "AuthsWorkflowError",
    "CauseCategory",
    "EffectState",
    "EnteredBoundaries",
    "ProductVerb",
    "ProviderFailureKind",
    "ProviderOperationError",
    "RecommendedAction",
    "RetryClass",
    "WORKFLOW_REASON_CODES",
    "cause_category_from",
    "classify",
    "create_support_bundle",
    "error_reference_url",
    "format_auths_error",
    "registry_codes",
]
