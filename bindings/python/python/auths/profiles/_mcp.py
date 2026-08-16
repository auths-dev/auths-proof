"""Profile-bound MCP authorization and execution."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import (
    Awaitable,
    Callable,
    Generic,
    Literal,
    Mapping,
    NoReturn,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

from .. import _native as native
from .._mcp_profile import MCP_PROFILE
from .._plan import PlanApprovalSession
from .._product_errors import (
    CauseCategory,
    EnteredBoundaries,
    cause_category_from,
)
from .._receipts import (
    AttestedReceipt,
    ReceiptAttestor,
    _attest_decision,
    _attest_execution,
    verify_receipt,
)
from .._workflow import (
    ApprovalConfiguration,
    ApprovalProvider,
    AttachedAgent,
    AuthsWorkflowError,
    ControlEvidence,
    Permission,
    Profile,
    ReviewField,
    _SigningCoordinator,
    _transaction_expiry,
)

VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]
McpOutcome = Literal["succeeded", "failed", "cancelled", "outcome-unknown"]
McpExecutionState = Literal["committed", "outcome-unknown"]
McpHandlerEffect = Literal["not-applied", "applied", "possible"]
McpHandlerCause = Literal[
    "cancelled",
    "invalid-output",
    "limit-exceeded",
    "timeout",
    "unavailable",
    "unknown",
]

_PLAN_TOKEN = object()
_AUTHORITY_TOKEN = object()
GatewayResult = TypeVar("GatewayResult")
_development_profile: Optional[McpProfile] = None


@dataclass(frozen=True)
class AuthorizationRequest:
    challenge: bytes = field(default_factory=native.generate_challenge_v1)
    evaluation_time: int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self) -> None:
        challenge = bytes(self.challenge)
        if len(challenge) != 32:
            raise ValueError("authorization challenge must contain 32 bytes")
        if (
            type(self.evaluation_time) is not int
            or self.evaluation_time < 0
            or self.evaluation_time > (1 << 64) - 1
        ):
            raise ValueError("invalid authorization evaluation time")
        object.__setattr__(self, "challenge", challenge)


@dataclass(frozen=True)
class McpReview:
    title: str
    fields: Tuple[ReviewField, ...]
    action_commitment: bytes


class McpProfile(Profile):
    service: str

    def __init__(self, service: str) -> None:
        super().__init__("auths.mcp", 1)
        try:
            native.validate_mcp_service(service)
        except (TypeError, ValueError):
            raise ValueError("invalid MCP service")
        object.__setattr__(self, "service", service)

    def call(self, name: str, arguments: Mapping[str, object]) -> McpAction:
        try:
            encoded = json.dumps(
                dict(arguments),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode()
            native_call = native.mcp_call(self.service, name, encoded)
        except (TypeError, ValueError):
            raise ValueError("invalid MCP tool call") from None
        return McpAction(self, native_call)

    def review(self, action: McpAction) -> McpReview:
        if type(action) is not McpAction or action.profile is not self:
            raise AuthsWorkflowError(
                "profile-mismatch", "MCP action belongs to another profile"
            )
        title, fields, commitment = native.review_mcp_call(action._call)
        return McpReview(
            title,
            tuple(ReviewField(label, value) for label, value in fields),
            bytes(commitment),
        )

    def plan(self, actions: Sequence[McpAction]) -> McpPlan:
        values = tuple(actions)
        if not values or len(values) > 256:
            raise AuthsWorkflowError(
                "invalid-profile", "MCP plan action count is outside bounds"
            )
        if any(
            type(action) is not McpAction or action.profile is not self
            for action in values
        ):
            raise AuthsWorkflowError(
                "invalid-profile", "MCP plan contains an action from another profile"
            )
        try:
            projection = native.commit_mcp_plan([action._call for action in values])
        except (TypeError, ValueError):
            raise AuthsWorkflowError(
                "invalid-profile", "native MCP profile rejected the plan"
            ) from None
        authority = McpPlanAuthority(
            permissions=tuple(
                Permission(capability, resource)
                for capability, resource in projection.permissions
            ),
            resource_namespaces=tuple(projection.resource_namespaces),
            audiences=tuple(projection.audiences),
        )
        return McpPlan(
            _PLAN_TOKEN,
            self,
            values,
            bytes(projection.commitment),
            tuple(bytes(member) for member in projection.members),
            authority,
        )

    def gateway(
        self, executor: Callable[[McpGatewayCall], Awaitable[GatewayResult]]
    ) -> McpGateway[GatewayResult]:
        if not callable(executor):
            raise TypeError("MCP gateway executor must be callable")
        return McpGateway(self.service, executor)


class McpToolAuthority:
    __slots__ = ("_profile", "_tools")

    def __init__(
        self,
        token: object,
        profile: McpProfile,
        tools: Tuple[str, ...],
    ) -> None:
        if token is not _AUTHORITY_TOKEN:
            raise TypeError("sealed Auths MCP authority")
        self._profile = profile
        self._tools = tools

    @property
    def profile(self) -> Literal["auths.mcp"]:
        return "auths.mcp"

    @property
    def service(self) -> str:
        return self._profile.service

    @property
    def tools(self) -> Tuple[str, ...]:
        return self._tools

    def __copy__(self) -> None:
        raise TypeError("MCP authority is not copyable")

    def __deepcopy__(self, _: object) -> None:
        raise TypeError("MCP authority is not copyable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("MCP authority is not serializable")


class McpAction:
    def __init__(self, profile: McpProfile, call: native.McpCall) -> None:
        self._profile = profile
        self._call = call

    @property
    def profile(self) -> McpProfile:
        return self._profile

    @property
    def service(self) -> str:
        return self._call.service

    @property
    def name(self) -> str:
        return self._call.name


@dataclass(frozen=True)
class McpPlanAuthority:
    permissions: Tuple[Permission, ...]
    resource_namespaces: Tuple[str, ...]
    audiences: Tuple[str, ...]


class McpPlan:
    def __init__(
        self,
        token: object,
        profile: McpProfile,
        actions: Tuple[McpAction, ...],
        commitment: bytes,
        member_commitments: Tuple[bytes, ...],
        authority: McpPlanAuthority,
    ) -> None:
        if token is not _PLAN_TOKEN:
            raise TypeError("sealed Auths MCP plan")
        self._profile = profile
        self._actions = actions
        self._commitment = commitment
        self._member_commitments = member_commitments
        self._authority = authority

    @property
    def length(self) -> int:
        return len(self._actions)

    @property
    def commitment(self) -> bytes:
        return self._commitment

    @property
    def authority(self) -> McpPlanAuthority:
        return self._authority


@dataclass(frozen=True)
class AuthorizationMetrics:
    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int


@dataclass(frozen=True)
class AuthorizationExplanation:
    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class ApprovalSummary:
    policy_id: str
    evaluator_version: str
    required_configuration: bytes
    executed_configuration: bytes
    executed_mode: str
    executed_max_uses: int
    executed_expires_in_seconds: int
    executed_requirements: Tuple[str, ...]
    transaction_digest: bytes
    decision: Literal["approved"]


@dataclass(frozen=True)
class McpAuthorized:
    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    explanation: AuthorizationExplanation
    metrics: AuthorizationMetrics
    approval: ApprovalSummary
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes
    action_commitment: bytes
    command: native.McpCommand


@dataclass(frozen=True)
class McpDenied:
    kind: Literal["denied"]
    code: str
    stage: VerificationStage
    explanation: AuthorizationExplanation
    metrics: AuthorizationMetrics
    approval: ApprovalSummary
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


@dataclass(frozen=True)
class McpIndeterminate:
    kind: Literal["indeterminate"]
    code: str
    stage: VerificationStage
    explanation: AuthorizationExplanation
    metrics: AuthorizationMetrics
    approval: ApprovalSummary
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


McpAuthorizationResult = Union[McpAuthorized, McpDenied, McpIndeterminate]


@dataclass(frozen=True)
class McpPlanMemberAuthorized:
    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    explanation: AuthorizationExplanation
    metrics: AuthorizationMetrics
    approval: ApprovalSummary
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes
    action_commitment: bytes


McpPlanMemberResult = Union[McpPlanMemberAuthorized, McpDenied, McpIndeterminate]


@dataclass(frozen=True)
class McpPlanAuthorized:
    kind: Literal["authorized"]
    command: native.McpPlanCommand
    results: Tuple[McpPlanMemberAuthorized, ...]


@dataclass(frozen=True)
class McpPlanDenied:
    kind: Literal["denied"]
    failed_index: int
    result: McpDenied
    results: Tuple[McpPlanMemberResult, ...]


@dataclass(frozen=True)
class McpPlanIndeterminate:
    kind: Literal["indeterminate"]
    failed_index: int
    result: McpIndeterminate
    results: Tuple[McpPlanMemberResult, ...]


McpPlanAuthorizationResult = Union[
    McpPlanAuthorized, McpPlanDenied, McpPlanIndeterminate
]


@dataclass(frozen=True)
class McpGatewayCall:
    service: str
    name: str
    arguments_json: bytes


@dataclass(frozen=True)
class McpReceipt:
    idempotency_key: str
    command_commitment: bytes
    authority_commitment: bytes
    context_commitment: bytes
    plan_commitment: Optional[bytes]
    state_claim: McpExecutionState
    outcome: McpOutcome
    observed_at: int


class McpGatewayError(AuthsWorkflowError):
    def __init__(
        self,
        receipt: McpReceipt,
        completed_receipts: Tuple[McpReceipt, ...] = (),
    ) -> None:
        super().__init__(
            "gateway-failed",
            "MCP gateway execution outcome is unknown",
            entered=EnteredBoundaries(False, False, True, False, True),
        )
        self.receipt = receipt
        self.completed_receipts = completed_receipts


@dataclass(frozen=True)
class McpHandlerOutcome(Generic[GatewayResult]):
    effect: McpHandlerEffect
    result: Optional[GatewayResult] = None
    cause: Optional[McpHandlerCause] = None

    def __post_init__(self) -> None:
        if self.effect == "applied" and self.cause is not None:
            raise ValueError("applied MCP outcome cannot carry a failure cause")
        if self.effect != "applied" and self.result is not None:
            raise ValueError("non-applied MCP outcome cannot carry a result")


@dataclass(frozen=True)
class McpToolContext:
    execution_id: str
    service: str
    tool: str


class McpClosedProvider(Protocol):
    profile: Literal["auths.mcp"]
    service: str

    async def invoke(
        self,
        service: str,
        tool: str,
        arguments: Mapping[str, object],
        context: McpToolContext,
    ) -> object: ...

    async def reconcile(
        self, execution_id: str, service: str
    ) -> McpHandlerOutcome[object]: ...


McpToolHandler = Callable[[Mapping[str, object], McpToolContext], Awaitable[object]]
McpReconciler = Callable[[str, str], Awaitable[McpHandlerOutcome[object]]]


class McpProviderContractError(TypeError):
    """The caller's handler does not implement the port it was registered as.

    This is a programmer error, not an authorization outcome. The handler body
    never ran, so no effect was attempted, and reporting it through the effect
    axis would tell the caller a write may have happened when nothing did
    (contract 5.7).
    """


class DevelopmentMcpProvider:
    profile: Literal["auths.mcp"] = "auths.mcp"

    def __init__(
        self,
        *,
        tools: Mapping[str, McpToolHandler],
        service: str = "development",
        timeout_ms: Optional[int] = None,
        reconcile: Optional[McpReconciler] = None,
    ) -> None:
        entries = tuple(tools.items())
        limits = MCP_PROFILE["limits"]
        if not entries or len(entries) > limits["toolCount"]:
            raise ValueError("MCP tool declarations are outside profile limits")
        parsed: dict[str, McpToolHandler] = {}
        for name, handler in entries:
            if (
                not isinstance(name, str)
                or not name
                or len(name.encode()) > limits["toolNameBytes"]
                or not all(
                    character.isascii() and (character.isalnum() or character in "._-")
                    for character in name
                )
                or not callable(handler)
                or name in parsed
            ):
                raise ValueError("invalid MCP tool declaration")
            parsed[name] = handler
        duration = limits["defaultDurationMs"] if timeout_ms is None else timeout_ms
        if (
            type(duration) is not int
            or duration < 1
            or duration > limits["maximumDurationMs"]
        ):
            raise ValueError("MCP handler timeout is outside profile limits")
        if reconcile is not None and not callable(reconcile):
            raise TypeError("MCP reconciler is not callable")
        self._tools = MappingProxyType(parsed)
        self.service = McpProfile(service).service
        self._timeout_seconds = duration / 1000
        self._reconcile = reconcile
        self._closed = False

    async def invoke(
        self,
        service: str,
        tool: str,
        arguments: Mapping[str, object],
        context: McpToolContext,
    ) -> object:
        self._assert_open()
        if service != self.service:
            return McpHandlerOutcome[object]("not-applied", cause="invalid-output")
        handler = self._tools.get(tool)
        if handler is None:
            return McpHandlerOutcome[object]("not-applied", cause="invalid-output")
        # Bind the call before awaiting it. A handler declared with the wrong
        # signature raises here, before its body runs, so it is a contract
        # violation and not an authorization outcome (contract 5.7). Reporting
        # it as `mcp.handler-failed`/`possible` would tell the caller a
        # real-world effect may have been applied by a coroutine that never
        # started.
        try:
            pending = handler(arguments, context)
        except TypeError as error:
            raise McpProviderContractError(
                f"MCP tool handler {tool!r} does not accept (arguments, context)"
            ) from error
        return await asyncio.wait_for(pending, timeout=self._timeout_seconds)

    async def reconcile(
        self, execution_id: str, service: str
    ) -> McpHandlerOutcome[object]:
        self._assert_open()
        if self._reconcile is None:
            return McpHandlerOutcome("possible", cause="unavailable")
        return await asyncio.wait_for(
            self._reconcile(execution_id, service),
            timeout=self._timeout_seconds,
        )

    async def aclose(self) -> None:
        self._closed = True

    async def __aenter__(self) -> DevelopmentMcpProvider:
        self._assert_open()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    def _assert_open(self) -> None:
        if self._closed:
            raise asyncio.CancelledError


@dataclass(frozen=True)
class McpRecoveryCheckpoint:
    execution_id: str
    reference: str
    record_json: bytes


class McpExecutionStore(Protocol):
    async def reserve(
        self, execution_id: str, recovery: McpRecoveryCheckpoint
    ) -> Literal["acquired", "exact-replay", "conflict"]: ...

    async def mark_provider_entry(
        self, execution_id: str, recovery: McpRecoveryCheckpoint
    ) -> None: ...

    async def save_recovery(self, recovery: McpRecoveryCheckpoint) -> None: ...

    async def load_recovery(self, reference: str) -> Optional[bytes]: ...

    async def clear_pending(self, execution_id: str) -> None: ...


class McpReceiptSink(Protocol):
    async def persist(self, execution_id: str, receipt_json: bytes) -> None: ...


McpExecutionCheckpointStage = Literal[
    "before-verification",
    "after-verification",
    "after-reservation",
    "before-provider-transmission",
    "after-provider-transmission",
    "before-receipt-persistence",
]


@dataclass(frozen=True)
class McpExecutionCheckpointEvent:
    stage: McpExecutionCheckpointStage
    execution_id: Optional[str] = None


class McpExecutionObserver(Protocol):
    async def checkpoint(self, event: McpExecutionCheckpointEvent) -> None: ...


@dataclass(frozen=True)
class McpExecutionResources:
    provider: McpClosedProvider
    state: McpExecutionStore
    receipts: McpReceiptSink
    attestor: ReceiptAttestor
    session_key: bytes
    request_id: Optional[str] = None
    observer: Optional[McpExecutionObserver] = None

    def __post_init__(self) -> None:
        key = bytes(self.session_key)
        if len(key) != 32:
            raise ValueError("MCP session key must contain 32 bytes")
        object.__setattr__(self, "session_key", key)


@dataclass(frozen=True)
class McpCompleted:
    kind: Literal["completed"]
    execution_id: str
    result: object
    receipt: McpAttestedReceipt


@dataclass(frozen=True)
class McpAttestedReceipt:
    decision: AttestedReceipt
    execution: AttestedReceipt


@dataclass(frozen=True)
class McpNotApplied:
    kind: Literal["not-applied", "exact-replay", "conflict"]
    execution_id: str
    code: str
    """`McpTerminal::registry_code`. Never derived from `kind` here."""


@dataclass(frozen=True)
class McpRecoverable:
    kind: Literal["recoverable"]
    execution_id: str
    execution_reference: str
    code: str
    """`McpTerminal::registry_code`. Never derived from `kind` here."""


McpClosedResult = Union[McpCompleted, McpNotApplied, McpRecoverable]


@dataclass(frozen=True)
class McpPlanCompleted:
    kind: Literal["completed"]
    results: Tuple[object, ...]
    receipts: Tuple[McpAttestedReceipt, ...]


@dataclass(frozen=True)
class McpPlanRecoveryResult:
    kind: Literal["recoverable", "not-applied", "exact-replay", "conflict"]
    execution_id: str
    code: str
    completed_results: Tuple[object, ...]
    completed_receipts: Tuple[McpAttestedReceipt, ...]
    execution_reference: Optional[str] = None


McpPlanClosedResult = Union[McpPlanCompleted, McpPlanRecoveryResult]


class McpGatewayCancelled(AuthsWorkflowError):
    def __init__(
        self,
        receipt: McpReceipt,
        completed_receipts: Tuple[McpReceipt, ...] = (),
    ) -> None:
        super().__init__(
            "gateway-cancelled",
            "MCP gateway task was cancelled after provider entry",
            entered=EnteredBoundaries(False, False, True, False, True),
        )
        self.receipt = receipt
        self.completed_receipts = completed_receipts


class McpGateway(Generic[GatewayResult]):
    def __init__(
        self,
        service: str,
        executor: Callable[[McpGatewayCall], Awaitable[GatewayResult]],
    ) -> None:
        self._service = service
        self._executor = executor

    async def execute(
        self, command: native.McpCommand, *, idempotency_key: str
    ) -> Tuple[GatewayResult, McpReceipt]:
        if type(command) is not native.McpCommand or not idempotency_key:
            raise TypeError("gateway requires a native MCP command and idempotency key")
        binding = (
            bytes(command.action_commitment),
            bytes(command.authority_commitment),
            bytes(command.context_commitment),
        )
        try:
            call = native.consume_mcp_command(command, self._service)
        except (TypeError, RuntimeError):
            raise
        try:
            result = await self._executor(
                McpGatewayCall(
                    service=call.service,
                    name=call.name,
                    arguments_json=bytes(call.arguments_json),
                )
            )
        except asyncio.CancelledError:
            raise McpGatewayCancelled(
                _receipt(idempotency_key, binding, None, "cancelled")
            ) from None
        except Exception:
            raise McpGatewayError(
                _receipt(
                    idempotency_key,
                    binding,
                    None,
                    "outcome-unknown",
                )
            ) from None
        return result, _receipt(idempotency_key, binding, None, "succeeded")

    async def execute_plan(
        self, command: native.McpPlanCommand, *, idempotency_key: str
    ) -> Tuple[Tuple[GatewayResult, ...], Tuple[McpReceipt, ...]]:
        if type(command) is not native.McpPlanCommand or not idempotency_key:
            raise TypeError(
                "gateway requires a native MCP plan command and idempotency key"
            )
        plan_commitment = bytes(command.plan_commitment)
        bindings = tuple(
            (bytes(action), bytes(authority), bytes(context))
            for action, authority, context in command.receipt_bindings
        )
        if len(bindings) != command.count:
            raise RuntimeError("native MCP plan command omitted receipt bindings")
        calls = native.consume_mcp_plan_command(command, self._service)
        results: list[GatewayResult] = []
        receipts: list[McpReceipt] = []
        for index, (call, binding) in enumerate(zip(calls, bindings)):
            member_key = f"{idempotency_key}:{index}"
            try:
                results.append(
                    await self._executor(
                        McpGatewayCall(
                            service=call.service,
                            name=call.name,
                            arguments_json=bytes(call.arguments_json),
                        )
                    )
                )
                receipts.append(
                    _receipt(
                        member_key,
                        binding,
                        plan_commitment,
                        "succeeded",
                    )
                )
            except asyncio.CancelledError:
                raise McpGatewayCancelled(
                    _receipt(
                        member_key,
                        binding,
                        plan_commitment,
                        "cancelled",
                    ),
                    tuple(receipts),
                ) from None
            except Exception:
                raise McpGatewayError(
                    _receipt(
                        member_key,
                        binding,
                        plan_commitment,
                        "outcome-unknown",
                    ),
                    tuple(receipts),
                ) from None
        return tuple(results), tuple(receipts)


class McpFacade:
    def profile(self, *, service: str, version: Literal[1] = 1) -> McpProfile:
        if version != 1:
            raise AuthsWorkflowError(
                "invalid-profile", "unsupported MCP profile version"
            )
        return McpProfile(service)

    def development_provider(
        self,
        *,
        tools: Mapping[str, McpToolHandler],
        service: str = "development",
        timeout_ms: Optional[int] = None,
        reconcile: Optional[McpReconciler] = None,
    ) -> DevelopmentMcpProvider:
        return DevelopmentMcpProvider(
            tools=tools,
            service=service,
            timeout_ms=timeout_ms,
            reconcile=reconcile,
        )

    def allow_tools(
        self,
        tools: Sequence[str],
        *,
        service: str = "development",
    ) -> McpToolAuthority:
        values = tuple(sorted(_bounded_tool_name(value) for value in tools))
        if (
            not values
            or len(values) > MCP_PROFILE["limits"]["toolCount"]
            or len(set(values)) != len(values)
        ):
            raise ValueError("MCP authority tools are outside profile limits")
        profile = (
            _development_mcp_profile()
            if service == "development"
            else McpProfile(service)
        )
        return McpToolAuthority(_AUTHORITY_TOKEN, profile, values)

    def call_tool(
        self,
        *,
        name: str,
        arguments: Mapping[str, object],
        service: str = "development",
    ) -> McpAction:
        profile = (
            _development_mcp_profile()
            if service == "development"
            else McpProfile(service)
        )
        return profile.call(name, arguments)

    def plan(self, actions: Sequence[McpAction]) -> McpPlan:
        values = tuple(actions)
        if not values or type(values[0]) is not McpAction:
            raise TypeError("MCP plan requires MCP actions")
        return values[0].profile.plan(values)


mcp = McpFacade()


def resources_for_mcp_authority(
    authority: McpToolAuthority,
) -> Tuple[McpProfile, Tuple[Permission, ...], Tuple[str, ...], Tuple[str, ...]]:
    if type(authority) is not McpToolAuthority:
        raise TypeError("forged Auths MCP authority")
    base = f"mcp://{authority.service}"
    return (
        authority._profile,
        tuple(
            Permission("tools/call", f"{base}/tools/{tool}") for tool in authority.tools
        ),
        (base,),
        (base,),
    )


def _development_mcp_profile() -> McpProfile:
    global _development_profile
    if _development_profile is None:
        _development_profile = McpProfile("development")
    return _development_profile


def _bounded_tool_name(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode()) > MCP_PROFILE["limits"]["toolNameBytes"]
        or not all(
            character.isascii() and (character.isalnum() or character in "._-")
            for character in value
        )
    ):
        raise ValueError("invalid MCP tool name")
    return value


async def _authorize_mcp(
    agent: AttachedAgent,
    action: McpAction,
    request: Optional[AuthorizationRequest],
    approval_override: Optional[ApprovalConfiguration] = None,
) -> McpAuthorizationResult:
    agent._assert_active()
    if type(action) is not McpAction:
        raise TypeError("action must be an MCP action")
    if not isinstance(agent._profile, McpProfile):
        raise AuthsWorkflowError(
            "profile-mismatch", "attached agent does not use the MCP profile"
        )
    if action.profile is not agent._profile:
        raise AuthsWorkflowError(
            "profile-mismatch", "MCP action belongs to a different profile instance"
        )
    request = AuthorizationRequest() if request is None else request
    if type(request) is not AuthorizationRequest:
        raise TypeError("request must be an AuthorizationRequest")
    if not agent._grant_chain:
        raise AuthsWorkflowError("disposed", "attached authority is unavailable")
    try:
        prepared = native.prepare_mcp_call_action(
            action._call,
            agent.identity.principal.principal,
            agent._grant_chain[-1].signed_grant,
            request.challenge,
            request.evaluation_time,
        )
    except (TypeError, ValueError):
        raise AuthsWorkflowError(
            "invalid-action", "native MCP profile rejected the action"
        ) from None
    approval_configuration = (
        agent._approval if approval_override is None else approval_override
    )
    signed = await _SigningCoordinator().execute(
        unsigned=prepared.unsigned,
        principal=agent.identity.principal,
        signer=agent._signer,
        approval=approval_configuration,
        required_approval=agent._client._configured_authority.required_approval,
        expires_at=_transaction_expiry(
            approval_configuration.policy.expires_in_seconds
        ),
        display=tuple(
            ReviewField(label, value) for label, value in prepared.review_fields
        ),
    )
    grant_evidence = [
        [_native_evidence(value) for value in material.evidence]
        for material in agent._grant_chain
    ]
    try:
        native_result, command = native.authorize_mcp(
            prepared,
            signed.signed_object,
            [material.signed_grant for material in agent._grant_chain],
            grant_evidence,
            [_native_evidence(value) for value in signed.evidence],
            agent._client._configured_authority.context,
        )
    except (TypeError, ValueError, RuntimeError):
        raise AuthsWorkflowError(
            "native-authorization-failed", "native MCP authorization failed"
        ) from None
    metrics = AuthorizationMetrics(*native_result.metrics)
    kind = native_result.kind
    approval = ApprovalSummary(
        policy_id=approval_configuration.policy.reference.policy_id,
        evaluator_version=approval_configuration.policy.reference.evaluator_version,
        required_configuration=bytes(
            agent._client._configured_authority.required_approval.configuration_digest
        ),
        executed_configuration=bytes(
            approval_configuration.policy.reference.configuration_digest
        ),
        executed_mode=approval_configuration.policy.mode,
        executed_max_uses=approval_configuration.policy.max_uses,
        executed_expires_in_seconds=approval_configuration.policy.expires_in_seconds,
        executed_requirements=approval_configuration.policy.requirements,
        transaction_digest=signed.transaction_digest,
        decision="approved",
    )
    explanation = _explanation(kind, native_result.code)
    stage = native_result.stage
    if kind == "authorized":
        if command is None:
            raise AuthsWorkflowError(
                "native-authorization-failed",
                "native MCP authorization omitted its sealed command",
            )
        canonical_action, _ = native.inspect_mcp_action(prepared)
        action_commitment = native.commit_canonical_v1(
            "auths.canonical-action.v1", canonical_action
        )
        return McpAuthorized(
            kind="authorized",
            code=native_result.code,
            stage=stage,
            explanation=explanation,
            metrics=metrics,
            approval=approval,
            required_configuration=native_result.required_configuration,
            local_configuration=bytes(native_result.local_configuration),
            result_cbor=bytes(native_result.result_cbor),
            action_commitment=bytes(action_commitment),
            command=command,
        )
    if command is not None:
        raise AuthsWorkflowError(
            "native-authorization-failed",
            "native MCP authorization returned a command for a failed verdict",
        )
    if kind == "denied":
        return McpDenied(
            kind="denied",
            code=native_result.code,
            stage=stage,
            explanation=explanation,
            metrics=metrics,
            approval=approval,
            required_configuration=native_result.required_configuration,
            local_configuration=bytes(native_result.local_configuration),
            result_cbor=bytes(native_result.result_cbor),
        )
    return McpIndeterminate(
        kind="indeterminate",
        code=native_result.code,
        stage=stage,
        explanation=explanation,
        metrics=metrics,
        approval=approval,
        required_configuration=native_result.required_configuration,
        local_configuration=bytes(native_result.local_configuration),
        result_cbor=bytes(native_result.result_cbor),
    )


async def execute_mcp_closed(
    agent: AttachedAgent,
    action: McpAction,
    resources: McpExecutionResources,
    request: Optional[AuthorizationRequest] = None,
) -> Union[McpDenied, McpIndeterminate, McpClosedResult]:
    await _observe_checkpoint(resources, "before-verification")
    authorization = await _authorize_mcp(agent, action, request)
    if not isinstance(authorization, McpAuthorized):
        return authorization
    await _observe_checkpoint(resources, "after-verification")
    signer = resources.attestor.signer
    decision_preparation = native.prepare_mcp_command_decision_receipt_v1(
        authorization.command,
        int(time.time()),
        signer.principal,
        signer.verification_method,
        signer.suite,
    )
    decision_receipt = await _attest_decision(decision_preparation, resources.attestor)
    session = native.begin_mcp_execution(
        authorization.command,
        decision_receipt.receipt_id,
        decision_receipt.bytes,
        resources.session_key,
        resources.request_id,
    )
    return await _drive_mcp_session(session, resources, decision_receipt)


async def execute_mcp_plan_closed(
    agent: AttachedAgent,
    plan: McpPlan,
    resources: McpExecutionResources,
) -> Union[McpPlanDenied, McpPlanIndeterminate, McpPlanClosedResult]:
    authorization = await _authorize_mcp_plan(agent, plan, None)
    if not isinstance(authorization, McpPlanAuthorized):
        return authorization
    signer = resources.attestor.signer
    preparations = native.prepare_mcp_plan_decision_receipts_v1(
        authorization.command,
        int(time.time()),
        signer.principal,
        signer.verification_method,
        signer.suite,
    )
    decisions = tuple(
        [
            await _attest_decision(preparation, resources.attestor)
            for preparation in preparations
        ]
    )
    results: list[object] = []
    receipts: list[McpAttestedReceipt] = []
    for index, decision in enumerate(decisions):
        session = native.begin_mcp_plan_member_execution(
            authorization.command,
            index,
            decision.receipt_id,
            decision.bytes,
            resources.session_key,
            resources.request_id,
        )
        member = await _drive_mcp_session(
            session,
            resources,
            decision,
        )
        if isinstance(member, McpCompleted):
            results.append(member.result)
            receipts.append(member.receipt)
            continue
        return McpPlanRecoveryResult(
            member.kind,
            member.execution_id,
            member.code,
            tuple(results),
            tuple(receipts),
            member.execution_reference if isinstance(member, McpRecoverable) else None,
        )
    return McpPlanCompleted("completed", tuple(results), tuple(receipts))


async def resume_mcp_closed(
    reference: str,
    resources: McpExecutionResources,
) -> McpClosedResult:
    record = await resources.state.load_recovery(_bounded_reference(reference))
    if record is None:
        raise AuthsWorkflowError(
            "gateway-conflict", "MCP execution reference has no matching state"
        )
    session = native.resume_mcp_execution(
        resources.session_key,
        reference,
        bytes(record),
    )
    decision_receipt = AttestedReceipt(
        "decision",
        bytes(session.decision_receipt_id),
        bytes(session.decision_receipt),
        resources.attestor.signer,
    )
    verify_receipt(decision_receipt)
    return await _drive_mcp_session(session, resources, decision_receipt)


async def _drive_mcp_session(
    session: native.McpExecutionSession,
    resources: McpExecutionResources,
    decision_receipt: AttestedReceipt,
) -> McpClosedResult:
    receipt: Optional[McpAttestedReceipt] = None
    while True:
        terminal = session.terminal()
        if terminal is not None:
            return await _project_terminal(terminal, resources.state, receipt)
        step = session.next_step()
        if step.kind == "reserve":
            reservation = await resources.state.reserve(
                step.execution_id, _recovery_checkpoint(session)
            )
            if reservation == "acquired":
                await _observe_checkpoint(
                    resources, "after-reservation", step.execution_id
                )
            session.accept_reservation(reservation)
        elif step.kind == "mark-provider-entry":
            try:
                await resources.state.mark_provider_entry(
                    step.execution_id, _recovery_checkpoint(session)
                )
            except asyncio.CancelledError:
                session.cancel_before_provider()
            else:
                session.accept_provider_entry()
        elif step.kind == "invoke":
            await _invoke_mcp_handler(session, step, resources)
        elif step.kind == "persist-receipt":
            try:
                signer = resources.attestor.signer
                preparation = native.prepare_application_execution_receipt_v1(
                    decision_receipt.receipt_id,
                    step.execution_id,
                    session.plan_commitment,
                    session.member_index,
                    session.member_count,
                    bytes(session.canonical_action),
                    "succeeded",
                    _required_bytes(step.bytes),
                    int(time.time()),
                    signer.principal,
                    signer.verification_method,
                    signer.suite,
                )
                execution_receipt = await _attest_execution(
                    preparation, resources.attestor
                )
                receipt = McpAttestedReceipt(decision_receipt, execution_receipt)
                await _observe_checkpoint(
                    resources, "before-receipt-persistence", step.execution_id
                )
                await resources.receipts.persist(
                    step.execution_id, execution_receipt.bytes
                )
            except Exception:
                try:
                    session.accept_receipt(False)
                except RuntimeError:
                    pass
            else:
                session.accept_receipt(True)
        elif step.kind == "reconcile":
            await _reconcile_mcp_handler(
                session,
                step.execution_id,
                _required_string(step.service),
                resources.provider,
            )
        else:
            raise RuntimeError("native MCP session released an unknown step")


async def _invoke_mcp_handler(
    session: native.McpExecutionSession,
    step: native.McpSessionStep,
    resources: McpExecutionResources,
) -> None:
    service = _required_string(step.service)
    tool = _required_string(step.tool)
    try:
        parsed: object = json.loads(_required_bytes(step.bytes))
        if type(parsed) is not dict:
            raise ValueError("MCP arguments must be an object")
        arguments = cast(dict[str, object], parsed)
    except (TypeError, ValueError, json.JSONDecodeError):
        session.accept_handler("possible", None, "invalid-output")
        return
    await _observe_checkpoint(
        resources, "before-provider-transmission", step.execution_id
    )
    try:
        observed = await resources.provider.invoke(
            service,
            tool,
            arguments,
            McpToolContext(step.execution_id, service, tool),
        )
    except asyncio.CancelledError:
        session.accept_handler("possible", None, "cancelled")
        return
    except McpProviderContractError:
        raise
    except Exception as error:
        session.accept_handler("possible", None, _profile_cause(error))
        return
    await _observe_checkpoint(
        resources, "after-provider-transmission", step.execution_id
    )
    _accept_mcp_observation(session, observed)


async def _observe_checkpoint(
    resources: McpExecutionResources,
    stage: McpExecutionCheckpointStage,
    execution_id: Optional[str] = None,
) -> None:
    if resources.observer is not None:
        await resources.observer.checkpoint(
            McpExecutionCheckpointEvent(stage, execution_id)
        )


async def _reconcile_mcp_handler(
    session: native.McpExecutionSession,
    execution_id: str,
    service: str,
    provider: McpClosedProvider,
) -> None:
    try:
        observed = await provider.reconcile(execution_id, service)
        _accept_mcp_observation(session, observed)
    except asyncio.CancelledError:
        session.accept_handler("possible", None, "cancelled")
    except McpProviderContractError:
        raise
    except Exception as error:
        session.accept_handler("possible", None, _profile_cause(error))


def _accept_mcp_observation(
    session: native.McpExecutionSession,
    observed: object,
) -> None:
    if isinstance(observed, McpHandlerOutcome):
        outcome = cast(McpHandlerOutcome[object], observed)
        if outcome.effect == "applied":
            _accept_applied(session, outcome.result)
        else:
            session.accept_handler(outcome.effect, None, outcome.cause)
        return
    _accept_applied(session, observed)


def _accept_applied(session: native.McpExecutionSession, value: object) -> None:
    try:
        output = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        session.accept_handler("applied", output)
    except (TypeError, ValueError, RuntimeError):
        session.accept_handler("possible", None, "invalid-output")


async def _project_terminal(
    terminal: native.McpSessionTerminal,
    state: McpExecutionStore,
    receipt: Optional[McpAttestedReceipt],
) -> McpClosedResult:
    if terminal.kind == "completed":
        if receipt is None:
            raise RuntimeError("native MCP completion omitted its signed receipt")
        await state.clear_pending(terminal.execution_id)
        return McpCompleted(
            "completed",
            terminal.execution_id,
            json.loads(_required_bytes(terminal.output_json)),
            receipt,
        )
    if terminal.kind == "recoverable":
        recovery = _terminal_recovery(terminal)
        await state.save_recovery(recovery)
        return McpRecoverable(
            "recoverable",
            terminal.execution_id,
            recovery.reference,
            _terminal_code(terminal),
        )
    if terminal.kind not in ("not-applied", "exact-replay", "conflict"):
        raise RuntimeError("native MCP session returned an unknown terminal result")
    if terminal.kind == "not-applied":
        await state.clear_pending(terminal.execution_id)
    return McpNotApplied(
        cast(Literal["not-applied", "exact-replay", "conflict"], terminal.kind),
        terminal.execution_id,
        _terminal_code(terminal),
    )


def _terminal_code(terminal: native.McpSessionTerminal) -> str:
    """Reads the code the MCP profile assigned. Never invents one."""
    code = terminal.code
    if code is None:
        raise RuntimeError("native MCP failure terminal carries no registry code")
    return code


def _recovery_checkpoint(
    session: native.McpExecutionSession,
) -> McpRecoveryCheckpoint:
    return _terminal_recovery(session.checkpoint())


def _terminal_recovery(
    terminal: native.McpSessionTerminal,
) -> McpRecoveryCheckpoint:
    if terminal.kind != "recoverable":
        raise RuntimeError("native MCP checkpoint was not recoverable")
    return McpRecoveryCheckpoint(
        terminal.execution_id,
        _bounded_reference(terminal.reference),
        _required_bytes(terminal.record_json),
    )


def _profile_cause(value: object) -> McpHandlerCause:
    cause = cause_category_from(value)
    if cause is CauseCategory.INVALID_RESPONSE:
        return "invalid-output"
    if cause in (CauseCategory.CONFLICT, CauseCategory.CORRUPT_STATE):
        return "unknown"
    return cast(McpHandlerCause, cause.value)


def _bounded_reference(value: Optional[str]) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 134
        or not value.startswith("mcp1.")
        or any(character not in "0123456789abcdef." for character in value[5:])
    ):
        raise ValueError("invalid MCP execution reference")
    return value


def _required_string(value: Optional[str]) -> str:
    if value is None:
        raise RuntimeError("native MCP step omitted a required field")
    return value


def _required_bytes(value: Optional[bytes]) -> bytes:
    if value is None:
        raise RuntimeError("native MCP step omitted bounded bytes")
    return bytes(value)


async def _authorize_mcp_plan(
    agent: AttachedAgent,
    plan: McpPlan,
    approval_provider: Optional[ApprovalProvider],
    requests: Optional[Sequence[AuthorizationRequest]] = None,
) -> McpPlanAuthorizationResult:
    agent._assert_active()
    if type(plan) is not McpPlan or plan._profile is not agent._profile:
        raise AuthsWorkflowError(
            "profile-mismatch", "MCP plan belongs to a different profile instance"
        )
    approval = agent._approval
    if approval.policy.mode != "plan-once" or approval.policy.max_uses != plan.length:
        raise AuthsWorkflowError(
            "approval-policy-mismatch",
            "plan-once approval must match the exact MCP plan length",
        )
    provider = approval.provider if approval_provider is None else approval_provider
    if not callable(getattr(provider, "approve", None)):
        raise TypeError("approval provider is invalid")
    request_values = (
        tuple(AuthorizationRequest() for _ in plan._actions)
        if requests is None
        else tuple(requests)
    )
    if len(request_values) != plan.length or any(
        type(request) is not AuthorizationRequest for request in request_values
    ):
        raise ValueError("authorization requests must match the MCP plan length")
    _validate_plan_members(plan)
    started_at = int(time.time())
    expires_at = started_at + approval.policy.expires_in_seconds
    try:
        plan_approval = native.commit_plan_approval(
            plan._commitment,
            approval.policy.reference.configuration_digest,
            approval.policy.max_uses,
            expires_at,
        )
    except (TypeError, ValueError):
        raise AuthsWorkflowError(
            "invalid-profile", "native authoring rejected the MCP plan approval"
        ) from None
    session = PlanApprovalSession(
        plan_approval=bytes(plan_approval),
        member_commitments=plan._member_commitments,
        approval=approval,
        provider=provider,
        expires_at=expires_at,
        display=(
            ReviewField("Profile", plan._profile.id + "/" + str(plan._profile.version)),
            ReviewField("Actions", str(plan.length)),
        ),
    )
    results: list[McpAuthorizationResult] = []
    try:
        for index, (action, request) in enumerate(zip(plan._actions, request_values)):
            _validate_plan_members(plan)
            member_approval = ApprovalConfiguration(
                approval.policy,
                session.provider_for(index, plan._member_commitments[index]),
            )
            result = await _authorize_mcp(agent, action, request, member_approval)
            results.append(result)
            if isinstance(result, McpDenied):
                return McpPlanDenied(
                    "denied",
                    index,
                    result,
                    tuple(_plan_member_result(value) for value in results),
                )
            if isinstance(result, McpIndeterminate):
                return McpPlanIndeterminate(
                    "indeterminate",
                    index,
                    result,
                    tuple(_plan_member_result(value) for value in results),
                )
        authorized = tuple(
            result for result in results if isinstance(result, McpAuthorized)
        )
        if len(authorized) != plan.length:
            raise AuthsWorkflowError(
                "native-authorization-failed",
                "MCP plan omitted an authorized member",
            )
        try:
            command = native.seal_mcp_plan_command(
                [result.command for result in authorized],
                plan._profile.service,
                plan._commitment,
            )
        except (TypeError, ValueError, RuntimeError):
            raise AuthsWorkflowError(
                "native-authorization-failed",
                "native MCP profile rejected the verified plan",
            ) from None
        return McpPlanAuthorized(
            "authorized",
            command,
            tuple(_authorized_member(result) for result in authorized),
        )
    finally:
        session.dispose()


def _validate_plan_members(plan: McpPlan) -> None:
    try:
        projection = native.commit_mcp_plan([action._call for action in plan._actions])
    except (TypeError, ValueError):
        raise AuthsWorkflowError(
            "invalid-profile", "native MCP profile rejected the plan"
        ) from None
    if not native.commitments_equal_v1(
        bytes(projection.commitment), plan._commitment
    ) or len(projection.members) != len(plan._member_commitments):
        raise AuthsWorkflowError(
            "invalid-profile", "MCP plan membership changed after construction"
        )
    for actual, expected in zip(projection.members, plan._member_commitments):
        if not native.commitments_equal_v1(bytes(actual), expected):
            raise AuthsWorkflowError(
                "invalid-profile", "MCP plan membership changed after construction"
            )


def _authorized_member(result: McpAuthorized) -> McpPlanMemberAuthorized:
    return McpPlanMemberAuthorized(
        kind="authorized",
        code=result.code,
        stage=result.stage,
        explanation=result.explanation,
        metrics=result.metrics,
        approval=result.approval,
        required_configuration=result.required_configuration,
        local_configuration=result.local_configuration,
        result_cbor=result.result_cbor,
        action_commitment=result.action_commitment,
    )


def _plan_member_result(result: McpAuthorizationResult) -> McpPlanMemberResult:
    if isinstance(result, McpAuthorized):
        return _authorized_member(result)
    return result


def _native_evidence(value: ControlEvidence) -> Tuple[str, str, bytes]:
    return value.evidence_type, value.media_type, value.bytes


def _receipt(
    idempotency_key: str,
    binding: Tuple[bytes, bytes, bytes],
    plan_commitment: Optional[bytes],
    outcome: McpOutcome,
) -> McpReceipt:
    return McpReceipt(
        idempotency_key,
        binding[0],
        binding[1],
        binding[2],
        plan_commitment,
        cast(McpExecutionState, native.runtime_execution_state_v1(outcome)),
        outcome,
        int(time.time()),
    )


def _explanation(
    kind: Literal["authorized", "denied", "indeterminate"], code: str
) -> AuthorizationExplanation:
    if kind == "authorized":
        message = "the proof establishes exact authority for this MCP tool call"
    elif kind == "denied":
        message = "the supplied proof does not authorize this exact MCP tool call"
    else:
        message = "a required trustworthy fact or implementation is unavailable"
    return AuthorizationExplanation(code, message, kind == "indeterminate")


__all__ = [
    "ApprovalSummary",
    "AuthorizationExplanation",
    "AuthorizationMetrics",
    "AuthorizationRequest",
    "DevelopmentMcpProvider",
    "McpAction",
    "McpAuthorizationResult",
    "McpAuthorized",
    "McpDenied",
    "McpFacade",
    "McpGateway",
    "McpGatewayCancelled",
    "McpGatewayCall",
    "McpGatewayError",
    "McpClosedProvider",
    "McpClosedResult",
    "McpCompleted",
    "McpExecutionResources",
    "McpExecutionCheckpointEvent",
    "McpExecutionCheckpointStage",
    "McpExecutionObserver",
    "McpExecutionStore",
    "McpHandlerOutcome",
    "McpIndeterminate",
    "McpNotApplied",
    "McpPlan",
    "McpPlanAuthority",
    "McpPlanAuthorizationResult",
    "McpPlanAuthorized",
    "McpPlanClosedResult",
    "McpPlanCompleted",
    "McpPlanDenied",
    "McpPlanIndeterminate",
    "McpPlanMemberAuthorized",
    "McpPlanMemberResult",
    "McpPlanRecoveryResult",
    "McpProviderContractError",
    "McpProfile",
    "McpReceipt",
    "McpReceiptSink",
    "McpRecoverable",
    "McpRecoveryCheckpoint",
    "McpReview",
    "McpToolContext",
    "McpToolHandler",
    "McpToolAuthority",
    "execute_mcp_closed",
    "execute_mcp_plan_closed",
    "mcp",
    "resume_mcp_closed",
]
