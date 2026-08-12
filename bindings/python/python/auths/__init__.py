"""Create, delegate, execute, resume, and verify protected actions."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._doctor import DoctorReport as DoctorReport, doctor as doctor
    from ._product import (
        Actor as Actor,
        Auths as Auths,
        Authority as Authority,
        Completed as Completed,
        Denied as Denied,
        ExecutionReference as ExecutionReference,
        ExecutionResult as ExecutionResult,
        Indeterminate as Indeterminate,
        Receipt as Receipt,
        RecoveryResult as RecoveryResult,
    )
    from ._product_errors import (
        AuthsError as AuthsError,
        AuthsErrorCode as AuthsErrorCode,
        RecommendedAction as RecommendedAction,
    )
    from ._workflow import Approval as Approval

__all__ = [
    "Actor",
    "Approval",
    "Auths",
    "AuthsError",
    "AuthsErrorCode",
    "Authority",
    "Completed",
    "Denied",
    "DoctorReport",
    "ExecutionReference",
    "ExecutionResult",
    "Indeterminate",
    "Receipt",
    "RecommendedAction",
    "RecoveryResult",
    "doctor",
]

_OWNERS = {
    "Actor": "._product",
    "Approval": "._workflow",
    "Auths": "._product",
    "AuthsError": "._product_errors",
    "AuthsErrorCode": "._product_errors",
    "Authority": "._product",
    "Completed": "._product",
    "Denied": "._product",
    "DoctorReport": "._doctor",
    "ExecutionReference": "._product",
    "ExecutionResult": "._product",
    "Indeterminate": "._product",
    "Receipt": "._product",
    "RecommendedAction": "._product_errors",
    "RecoveryResult": "._product",
    "doctor": "._doctor",
}


def __getattr__(name: str) -> Any:
    owner = _OWNERS.get(name)
    if owner is None:
        raise AttributeError(f"module 'auths' has no attribute {name!r}")
    value = getattr(import_module(owner, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *__all__))
