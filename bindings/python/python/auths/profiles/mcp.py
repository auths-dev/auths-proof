"""Profile-bound MCP authorization and execution."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import (
    Awaitable,
    Callable,
    Generic,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

from .. import _native as native
from .._plan import PlanApprovalSession
from ..workflow import (
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

_PLAN_TOKEN = object()


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
            operation="execute",
            stage="provider",
            retry="unknown",
            effect_state="outcome-unknown",
            remediation="reconcile the idempotency key before another execution attempt",
        )
        self.receipt = receipt
        self.completed_receipts = completed_receipts


class McpGatewayCancelled(asyncio.CancelledError):
    def __init__(
        self,
        receipt: McpReceipt,
        completed_receipts: Tuple[McpReceipt, ...] = (),
    ) -> None:
        super().__init__("MCP gateway task was cancelled after provider entry")
        self.receipt = receipt
        self.completed_receipts = completed_receipts


GatewayResult = TypeVar("GatewayResult")


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
        return result, _receipt(
            idempotency_key, binding, None, "succeeded"
        )

    async def execute_plan(
        self, command: native.McpPlanCommand, *, idempotency_key: str
    ) -> Tuple[Tuple[GatewayResult, ...], Tuple[McpReceipt, ...]]:
        if type(command) is not native.McpPlanCommand or not idempotency_key:
            raise TypeError("gateway requires a native MCP plan command and idempotency key")
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
    def profile(self, *, service: str) -> McpProfile:
        return McpProfile(service)


mcp = McpFacade()


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
    "McpAction",
    "McpAuthorizationResult",
    "McpAuthorized",
    "McpDenied",
    "McpFacade",
    "McpGateway",
    "McpGatewayCancelled",
    "McpGatewayCall",
    "McpGatewayError",
    "McpIndeterminate",
    "McpPlan",
    "McpPlanAuthority",
    "McpPlanAuthorizationResult",
    "McpPlanAuthorized",
    "McpPlanDenied",
    "McpPlanIndeterminate",
    "McpPlanMemberAuthorized",
    "McpPlanMemberResult",
    "McpProfile",
    "McpReceipt",
    "McpReview",
    "mcp",
]
