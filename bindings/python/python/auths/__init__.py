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
        create_auths as create_auths,
        ExecutionResult as ExecutionResult,
        Indeterminate as Indeterminate,
        PlanCompleted as PlanCompleted,
        PlanRecoveryResult as PlanRecoveryResult,
        Receipt as Receipt,
        RecoveryResult as RecoveryResult,
    )
    from ._product_errors import (
        AuthsError as AuthsError,
        AuthsErrorCode as AuthsErrorCode,
        EffectState as EffectState,
        ProductVerb as ProductVerb,
        RecommendedAction as RecommendedAction,
        RetryClass as RetryClass,
    )
    from ._workflow import Approval as Approval

# One owner per name. `_OWNERS` is the single table the lazy import, the
# `__init__.pyi` stub, and `tools/check_type_stub.py` all read, so the runtime
# surface and the typed surface cannot drift apart.
_OWNERS = {
    "Actor": "._product",
    "Approval": "._workflow",
    "Authority": "._product",
    "Auths": "._product",
    "AuthsError": "._product_errors",
    "AuthsErrorCode": "._product_errors",
    "Completed": "._product",
    "Denied": "._product",
    "DoctorReport": "._doctor",
    "EffectState": "._product_errors",
    "ExecutionReference": "._product",
    "ExecutionResult": "._product",
    "Indeterminate": "._product",
    "PlanCompleted": "._product",
    "PlanRecoveryResult": "._product",
    "ProductVerb": "._product_errors",
    "Receipt": "._product",
    "RecommendedAction": "._product_errors",
    "RecoveryResult": "._product",
    "RetryClass": "._product_errors",
    "create_auths": "._product",
    "doctor": "._doctor",
}


__all__ = sorted(_OWNERS)


def __getattr__(name: str) -> Any:
    owner = _OWNERS.get(name)
    if owner is None:
        raise AttributeError(f"module 'auths' has no attribute {name!r}")
    value = getattr(import_module(owner, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *__all__))
