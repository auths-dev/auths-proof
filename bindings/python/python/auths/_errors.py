"""Stable, redacted Auths SDK failures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Tuple

RetryClass = Literal["never", "safe", "conditional", "unknown"]
EffectState = Literal[
    "not-started", "in-progress", "completed", "failed", "outcome-unknown"
]
ProviderFailureKind = Literal[
    "unavailable", "rejected", "cancelled", "timeout", "unsupported"
]


@dataclass(frozen=True)
class ErrorDetails:
    family: str
    code: str
    operation: str
    stage: str
    correlation_id: Optional[str]
    retry: RetryClass
    effect_state: EffectState
    remediation: str
    cause_codes: Tuple[str, ...]


class AuthsError(Exception):
    def __init__(self, message: str, details: ErrorDetails) -> None:
        super().__init__(message)
        self.details = details
        self.family = details.family
        self.code = details.code
        self.operation = details.operation
        self.stage = details.stage
        self.correlation_id = details.correlation_id
        self.retry = details.retry
        self.effect_state = details.effect_state
        self.remediation = details.remediation
        self.cause_codes = details.cause_codes

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(family={self.family!r}, code={self.code!r}, "
            f"operation={self.operation!r}, stage={self.stage!r}, "
            f"retry={self.retry!r}, effect_state={self.effect_state!r})"
        )


class AuthsWorkflowError(AuthsError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        operation: str = "workflow",
        stage: str = "coordinate",
        retry: RetryClass = "never",
        effect_state: EffectState = "not-started",
        remediation: str = "inspect the typed workflow input and retry only if corrected",
        correlation_id: Optional[str] = None,
        cause_codes: Tuple[str, ...] = (),
    ) -> None:
        super().__init__(
            message,
            ErrorDetails(
                "workflow",
                code,
                operation,
                stage,
                correlation_id,
                retry,
                effect_state,
                remediation,
                tuple(cause_codes),
            ),
        )


class ProviderOperationError(AuthsError):
    def __init__(self, kind: ProviderFailureKind) -> None:
        if kind not in (
            "unavailable",
            "rejected",
            "cancelled",
            "timeout",
            "unsupported",
        ):
            raise ValueError("unsupported provider failure kind")
        retry: RetryClass = "safe" if kind in ("unavailable", "timeout") else "never"
        super().__init__(
            "external provider operation failed",
            ErrorDetails(
                "provider",
                kind,
                "provider-callback",
                "provider",
                None,
                retry,
                "not-started",
                "inspect the provider health and its conformance result",
                (),
            ),
        )
        self.kind: ProviderFailureKind = kind


class RuntimeStateError(AuthsError):
    def __init__(
        self, code: str, *, retry: RetryClass, effect_state: EffectState
    ) -> None:
        super().__init__(
            "runtime state transition failed",
            ErrorDetails(
                "runtime",
                code,
                "execute",
                "state",
                None,
                retry,
                effect_state,
                "reconcile the command state before attempting another effect",
                (),
            ),
        )


__all__ = [
    "AuthsError",
    "AuthsWorkflowError",
    "EffectState",
    "ErrorDetails",
    "ProviderFailureKind",
    "ProviderOperationError",
    "RetryClass",
    "RuntimeStateError",
]
