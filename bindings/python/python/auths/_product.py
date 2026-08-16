from __future__ import annotations

import time
from dataclasses import dataclass
from types import TracebackType
from typing import Awaitable, Callable, Final, Literal, NoReturn, Optional, Type, Union

from ._product_errors import (
    AuthsError,
    AuthsErrorCode,
    EffectState,
    RecommendedAction,
    RetryClass,
    classify,
)
from .profiles._mcp import (
    McpAction,
    McpClosedProvider,
    McpCompleted,
    McpDenied,
    McpExecutionResources,
    McpExecutionObserver,
    McpExecutionStore,
    McpIndeterminate,
    McpNotApplied,
    McpPlan,
    McpPlanCompleted,
    McpPlanDenied,
    McpPlanIndeterminate,
    McpPlanRecoveryResult,
    McpReceiptSink,
    McpRecoverable,
    McpToolAuthority,
    execute_mcp_closed,
    execute_mcp_plan_closed,
    resources_for_mcp_authority,
    resume_mcp_closed,
)
from ._receipts import (
    Receipt,
    ReceiptAttestor,
    decode_linked_receipt,
    encode_linked_receipt,
    verify_linked_receipt,
)
from ._workflow import (
    AttachedAgent,
    DelegatedAuthority,
    ExpiryOnly,
    InheritAction,
    InheritBudget,
    Signer,
    Validity,
)

_CONFIGURATION_TOKEN = object()
_REFERENCE_TOKEN = object()


@dataclass(frozen=True)
class Actor:
    principal: str


Authority = McpToolAuthority


@dataclass(frozen=True)
class Completed:
    kind: Literal["completed"]
    execution_id: str
    result: object
    receipt: Receipt


@dataclass(frozen=True)
class Denied:
    """Nothing happened, and the caller can prove it from `effect`."""

    kind: Literal["denied"]
    code: AuthsErrorCode
    reason: str
    """The kernel's own denial reason, e.g. `permission-not-granted`.

    Diagnostic. `code` is the stable identity a caller branches on.
    """
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction


@dataclass(frozen=True)
class Indeterminate:
    """The decision could not be reached; read `effect` before retrying."""

    kind: Literal["indeterminate"]
    code: AuthsErrorCode
    reason: str
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction


class ExecutionReference:
    __slots__ = ("_value",)

    def __init__(self, token: object, value: str) -> None:
        if token is not _REFERENCE_TOKEN:
            raise TypeError("sealed Auths execution reference")
        self._value = value

    def __copy__(self) -> None:
        raise TypeError("Auths execution reference is not copyable")

    def __deepcopy__(self, _: object) -> None:
        raise TypeError("Auths execution reference is not copyable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Auths execution reference is not serializable")

    @classmethod
    def from_bytes(cls, value: bytes) -> ExecutionReference:
        return decode_execution_reference(value)

    def to_bytes(self) -> bytes:
        return encode_execution_reference(self)


def encode_execution_reference(reference: ExecutionReference) -> bytes:
    if type(reference) is not ExecutionReference:
        raise TypeError("forged Auths execution reference")
    return reference._value.encode()


def decode_execution_reference(value: bytes) -> ExecutionReference:
    try:
        parsed = bytes(value).decode("ascii")
    except (TypeError, UnicodeDecodeError):
        raise ValueError("invalid Auths execution reference") from None
    if (
        len(parsed) != 134
        or not parsed.startswith("mcp1.")
        or parsed[69] != "."
        or any(character not in "0123456789abcdef" for character in parsed[5:69])
        or any(character not in "0123456789abcdef" for character in parsed[70:])
    ):
        raise ValueError("invalid Auths execution reference")
    return ExecutionReference(_REFERENCE_TOKEN, parsed)


@dataclass(frozen=True)
class RecoveryResult:
    """An execution that did not complete.

    `effect` is the safety-critical field: `possible` means the real-world
    effect may already have been applied and a blind retry may repeat it.
    """

    kind: Literal["recoverable", "not-applied", "exact-replay", "conflict"]
    execution_id: str
    code: AuthsErrorCode
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction
    reference: Optional[ExecutionReference] = None


@dataclass(frozen=True)
class PlanCompleted:
    kind: Literal["completed"]
    results: tuple[object, ...]
    receipts: tuple[Receipt, ...]


@dataclass(frozen=True)
class PlanRecoveryResult:
    kind: Literal["recoverable", "not-applied", "exact-replay", "conflict"]
    execution_id: str
    code: AuthsErrorCode
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction
    completed_results: tuple[object, ...]
    completed_receipts: tuple[Receipt, ...]
    reference: Optional[ExecutionReference] = None


ExecutionResult = Union[
    Completed,
    PlanCompleted,
    Denied,
    Indeterminate,
    RecoveryResult,
    PlanRecoveryResult,
]


@dataclass(frozen=True)
class _AuthsResources:
    agent: AttachedAgent
    authority: McpToolAuthority
    state: McpExecutionStore
    receipts: McpReceiptSink
    receipt_attestor: ReceiptAttestor
    session_key: bytes
    child_signer: Callable[[], Awaitable[Signer]]
    dispose: Callable[[], Awaitable[None]]
    observer: Optional[McpExecutionObserver] = None


class AuthsConfiguration:
    __slots__ = ("mode", "diagnostics", "_open")

    def __init__(
        self,
        token: object,
        mode: Literal["development", "production"],
        diagnostics: tuple[str, ...],
        open_resources: Callable[[], Awaitable[_AuthsResources]],
    ) -> None:
        if token is not _CONFIGURATION_TOKEN:
            raise TypeError("sealed Auths configuration")
        self.mode = mode
        self.diagnostics = diagnostics
        self._open = open_resources


class Auths:
    def __init__(
        self,
        resources: _AuthsResources,
        diagnostics: tuple[str, ...],
    ) -> None:
        self._resources = resources
        self.actor = Actor(resources.agent.identity.principal.principal.value)
        self.authority: Authority = resources.authority
        self.diagnostics = diagnostics
        self._children: set[Auths] = set()
        self._closed = False

    async def execute(
        self,
        *,
        action: Optional[McpAction] = None,
        plan: Optional[McpPlan] = None,
        provider: McpClosedProvider,
        request_id: Optional[str] = None,
    ) -> ExecutionResult:
        self._assert_active()
        self._assert_provider(provider)
        execution = McpExecutionResources(
            provider,
            self._resources.state,
            self._resources.receipts,
            self._resources.receipt_attestor,
            self._resources.session_key,
            request_id,
            self._resources.observer,
        )
        if action is not None and plan is None:
            return _project_execution(
                await execute_mcp_closed(self._resources.agent, action, execution)
            )
        if plan is not None and action is None:
            return _project_plan_execution(
                await execute_mcp_plan_closed(self._resources.agent, plan, execution)
            )
        raise TypeError("Auths execute requires exactly one action or plan")

    async def resume(
        self,
        *,
        reference: ExecutionReference,
        provider: McpClosedProvider,
    ) -> ExecutionResult:
        self._assert_active()
        self._assert_provider(provider)
        if type(reference) is not ExecutionReference:
            raise TypeError("forged Auths execution reference")
        result = await resume_mcp_closed(
            reference._value,
            McpExecutionResources(
                provider,
                self._resources.state,
                self._resources.receipts,
                self._resources.receipt_attestor,
                self._resources.session_key,
                None,
                self._resources.observer,
            ),
        )
        return _project_execution(result)

    async def delegate(
        self,
        *,
        authority: McpToolAuthority,
        name: str = "delegated-agent",
        expires_in_seconds: int = 300,
    ) -> Auths:
        self._assert_active()
        profile, permissions, _, audiences = resources_for_mcp_authority(authority)
        parent_profile, _, _, _ = resources_for_mcp_authority(self.authority)
        if profile.service != parent_profile.service:
            raise TypeError("delegated authority belongs to another MCP service")
        if (
            type(expires_in_seconds) is not int
            or expires_in_seconds < 1
            or expires_in_seconds > 86_400
        ):
            raise ValueError("delegated authority expiry is outside bounds")
        now = int(time.time())
        signer = await self._resources.child_signer()
        agent = await self._resources.agent.delegate(
            name=name,
            authority=DelegatedAuthority(
                permissions,
                Validity(now, now + expires_in_seconds),
                audiences,
                0,
                InheritAction(),
                InheritBudget(),
                ExpiryOnly(),
            ),
            signer=signer,
        )

        async def dispose() -> None:
            await agent.aclose()

        child = Auths(
            _AuthsResources(
                agent,
                authority,
                self._resources.state,
                self._resources.receipts,
                self._resources.receipt_attestor,
                self._resources.session_key,
                self._resources.child_signer,
                dispose,
                self._resources.observer,
            ),
            self.diagnostics,
        )
        self._children.add(child)
        return child

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        for child in tuple(self._children):
            await child.aclose()
        self._children.clear()
        await self._resources.dispose()

    async def __aenter__(self) -> Auths:
        self._assert_active()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        await self.aclose()

    def _assert_active(self) -> None:
        if self._closed:
            raise RuntimeError("Auths is closed")

    def _assert_provider(self, provider: McpClosedProvider) -> None:
        profile, _, _, _ = resources_for_mcp_authority(self.authority)
        if (
            getattr(provider, "profile", None) != "auths.mcp"
            or getattr(provider, "service", None) != profile.service
        ):
            raise TypeError("MCP provider does not match this Auths authority")


def _create_auths_configuration(
    mode: Literal["development", "production"],
    diagnostics: tuple[str, ...],
    open_resources: Callable[[], Awaitable[_AuthsResources]],
) -> AuthsConfiguration:
    if (
        not diagnostics
        or any(
            type(value) is not str or not value or len(value) > 256
            for value in diagnostics
        )
        or not callable(open_resources)
    ):
        raise TypeError("invalid Auths composition")
    return AuthsConfiguration(
        _CONFIGURATION_TOKEN,
        mode,
        tuple(diagnostics),
        open_resources,
    )


async def _create_auths(configuration: AuthsConfiguration) -> Auths:
    if type(configuration) is not AuthsConfiguration:
        raise TypeError("Auths configuration was not created by an integration")
    return Auths(await configuration._open(), configuration.diagnostics)


def verify_receipt(receipt: Receipt) -> None:
    verify_linked_receipt(receipt)


def encode_receipt(receipt: Receipt) -> bytes:
    return encode_linked_receipt(receipt)


def decode_receipt(value: bytes) -> Receipt:
    return decode_linked_receipt(value)


# The two registry codes that name a kernel verdict. The kernel's own reason
# string (`permission-not-granted`, ...) is carried as `reason`; these are the
# stable identities whose effect, retry class, and recommended action Rust owns.
_DENIED_CODE: Final = "core.authorization-denied"
_INDETERMINATE_CODE: Final = "core.authorization-indeterminate"


def _axis(code: str) -> tuple[EffectState, RetryClass, RecommendedAction]:
    """Reads Rust's classification of `code`. Nothing here is computed."""
    classification = classify(code)
    return (
        classification.effect,
        classification.retry,
        classification.recommended_action,
    )


def _project_execution(value: object) -> ExecutionResult:
    if isinstance(value, McpCompleted):
        return Completed(
            "completed",
            value.execution_id,
            value.result,
            Receipt(value.receipt.decision, value.receipt.execution),
        )
    if isinstance(value, McpDenied):
        return Denied("denied", _DENIED_CODE, value.code, *_axis(_DENIED_CODE))
    if isinstance(value, McpIndeterminate):
        return Indeterminate(
            "indeterminate",
            _INDETERMINATE_CODE,
            value.code,
            *_axis(_INDETERMINATE_CODE),
        )
    if isinstance(value, McpRecoverable):
        return RecoveryResult(
            "recoverable",
            value.execution_id,
            value.code,
            *_axis(value.code),
            ExecutionReference(_REFERENCE_TOKEN, value.execution_reference),
        )
    if isinstance(value, McpNotApplied):
        return RecoveryResult(
            value.kind, value.execution_id, value.code, *_axis(value.code)
        )
    raise RuntimeError("MCP execution returned an unsupported result")


def _project_plan_execution(value: object) -> ExecutionResult:
    if isinstance(value, McpPlanCompleted):
        return PlanCompleted(
            "completed",
            value.results,
            tuple(Receipt(item.decision, item.execution) for item in value.receipts),
        )
    if isinstance(value, McpPlanDenied):
        return Denied("denied", _DENIED_CODE, value.result.code, *_axis(_DENIED_CODE))
    if isinstance(value, McpPlanIndeterminate):
        return Indeterminate(
            "indeterminate",
            _INDETERMINATE_CODE,
            value.result.code,
            *_axis(_INDETERMINATE_CODE),
        )
    if isinstance(value, McpPlanRecoveryResult):
        return PlanRecoveryResult(
            value.kind,
            value.execution_id,
            value.code,
            *_axis(value.code),
            value.completed_results,
            tuple(
                Receipt(item.decision, item.execution)
                for item in value.completed_receipts
            ),
            ExecutionReference(_REFERENCE_TOKEN, value.execution_reference)
            if value.execution_reference is not None
            else None,
        )
    raise RuntimeError("MCP plan execution returned an unsupported result")


__all__ = [
    "Actor",
    "Auths",
    "AuthsConfiguration",
    "AuthsError",
    "AuthsErrorCode",
    "Authority",
    "Completed",
    "Denied",
    "decode_execution_reference",
    "decode_receipt",
    "encode_execution_reference",
    "encode_receipt",
    "EffectState",
    "ExecutionReference",
    "ExecutionResult",
    "Indeterminate",
    "PlanCompleted",
    "PlanRecoveryResult",
    "Receipt",
    "RecommendedAction",
    "RecoveryResult",
    "RetryClass",
    "verify_receipt",
]
