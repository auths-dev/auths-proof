from __future__ import annotations

import time
from dataclasses import dataclass
from types import TracebackType
from typing import Awaitable, Callable, Literal, Optional, Type, Union

from .profiles.mcp import (
    McpAction,
    McpClosedProvider,
    McpCompleted,
    McpDenied,
    McpExecutionResources,
    McpExecutionStore,
    McpIndeterminate,
    McpNotApplied,
    McpReceiptSink,
    McpRecoverable,
    McpToolAuthority,
    execute_mcp_closed,
    resources_for_mcp_authority,
    resume_mcp_closed,
)
from .workflow import (
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
class Receipt:
    bytes: bytes


@dataclass(frozen=True)
class Completed:
    kind: Literal["completed"]
    execution_id: str
    result: object
    receipt: Receipt


@dataclass(frozen=True)
class Denied:
    kind: Literal["denied"]
    code: str


@dataclass(frozen=True)
class Indeterminate:
    kind: Literal["indeterminate"]
    code: str


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

    def __reduce__(self) -> None:
        raise TypeError("Auths execution reference is not serializable")


@dataclass(frozen=True)
class RecoveryResult:
    kind: Literal["recoverable", "not-applied", "exact-replay", "conflict"]
    execution_id: str
    reference: Optional[ExecutionReference] = None


ExecutionResult = Union[Completed, Denied, Indeterminate, RecoveryResult]


@dataclass(frozen=True)
class _AuthsResources:
    agent: AttachedAgent
    authority: McpToolAuthority
    state: McpExecutionStore
    receipts: McpReceiptSink
    session_key: bytes
    child_signer: Callable[[], Awaitable[Signer]]
    dispose: Callable[[], Awaitable[None]]


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
        action: McpAction,
        provider: McpClosedProvider,
        request_id: Optional[str] = None,
    ) -> ExecutionResult:
        self._assert_active()
        result = await execute_mcp_closed(
            self._resources.agent,
            action,
            McpExecutionResources(
                provider,
                self._resources.state,
                self._resources.receipts,
                self._resources.session_key,
                request_id,
            ),
        )
        return _project_execution(result)

    async def resume(
        self,
        *,
        reference: ExecutionReference,
        provider: McpClosedProvider,
    ) -> ExecutionResult:
        self._assert_active()
        if type(reference) is not ExecutionReference:
            raise TypeError("forged Auths execution reference")
        result = await resume_mcp_closed(
            reference._value,
            McpExecutionResources(
                provider,
                self._resources.state,
                self._resources.receipts,
                self._resources.session_key,
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
        if profile is not parent_profile:
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
                self._resources.session_key,
                self._resources.child_signer,
                dispose,
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


def _project_execution(value: object) -> ExecutionResult:
    if isinstance(value, McpCompleted):
        return Completed(
            "completed",
            value.execution_id,
            value.result,
            Receipt(bytes(value.receipt)),
        )
    if isinstance(value, McpDenied):
        return Denied("denied", value.code)
    if isinstance(value, McpIndeterminate):
        return Indeterminate("indeterminate", value.code)
    if isinstance(value, McpRecoverable):
        return RecoveryResult(
            "recoverable",
            value.execution_id,
            ExecutionReference(_REFERENCE_TOKEN, value.execution_reference),
        )
    if isinstance(value, McpNotApplied):
        return RecoveryResult(value.kind, value.execution_id)
    raise RuntimeError("MCP execution returned an unsupported result")


__all__ = [
    "Actor",
    "Auths",
    "AuthsConfiguration",
    "Authority",
    "Completed",
    "Denied",
    "ExecutionReference",
    "ExecutionResult",
    "Indeterminate",
    "Receipt",
    "RecoveryResult",
]
