"""Closed HTTP authorization and execution profile."""

from __future__ import annotations

import asyncio
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
HttpOutcome = Literal["succeeded", "failed", "cancelled", "outcome-unknown"]
HttpExecutionState = Literal["committed", "outcome-unknown"]
_PLAN_TOKEN = object()


class HttpProfileError(AuthsWorkflowError):
    pass


@dataclass(frozen=True)
class HttpAuthorizationRequest:
    challenge: bytes = field(default_factory=native.generate_challenge_v1)
    evaluation_time: int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self) -> None:
        challenge = bytes(self.challenge)
        if len(challenge) != 32:
            raise ValueError("authorization challenge must contain 32 bytes")
        if type(self.evaluation_time) is not int or not 0 <= self.evaluation_time <= (1 << 64) - 1:
            raise ValueError("invalid authorization evaluation time")
        object.__setattr__(self, "challenge", challenge)


@dataclass(frozen=True)
class HttpReview:
    title: str
    fields: Tuple[ReviewField, ...]
    action_commitment: bytes


class HttpProfile(Profile):
    def __init__(self, *, scheme: str, authority: str) -> None:
        super().__init__("auths.http", 1)
        probe = native.http_call("GET", scheme, authority, "/", [], [], None, None)
        self._origin = f"{probe.scheme}://{probe.authority}"
        self.scheme = probe.scheme
        self.authority = probe.authority

    @property
    def origin(self) -> str:
        return self._origin

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Mapping[str, Sequence[str]]] = None,
        headers: Optional[Mapping[str, str]] = None,
        content_type: Optional[str] = None,
        body_digest: Optional[str] = None,
    ) -> HttpAction:
        try:
            call = native.http_call(
                method,
                self.scheme,
                self.authority,
                path,
                []
                if query is None
                else [(key, list(values)) for key, values in query.items()],
                [] if headers is None else list(headers.items()),
                content_type,
                body_digest,
            )
        except (TypeError, ValueError):
            raise ValueError("invalid HTTP action") from None
        return HttpAction(self, call)

    def review(self, action: HttpAction) -> HttpReview:
        if type(action) is not HttpAction or action.profile is not self:
            raise HttpProfileError(
                "profile-mismatch", "HTTP action belongs to another profile"
            )
        title, fields, commitment = native.review_http_call(action._call)
        return HttpReview(
            title,
            tuple(ReviewField(label, value) for label, value in fields),
            bytes(commitment),
        )

    def plan(self, actions: Sequence[HttpAction]) -> HttpPlan:
        values = tuple(actions)
        if not values or len(values) > 256:
            raise HttpProfileError("invalid-profile", "HTTP plan action count is outside bounds")
        if any(type(action) is not HttpAction or action.profile is not self for action in values):
            raise HttpProfileError("invalid-profile", "HTTP plan contains an action from another profile")
        projection = native.commit_http_plan([action._call for action in values])
        authority = HttpPlanAuthority(
            tuple(Permission(capability, resource) for capability, resource in projection.permissions),
            tuple(projection.resource_namespaces),
            tuple(projection.audiences),
        )
        return HttpPlan(
            _PLAN_TOKEN,
            self,
            values,
            bytes(projection.commitment),
            tuple(bytes(value) for value in projection.members),
            authority,
        )

    def gateway(
        self, executor: Callable[[HttpGatewayRequest], Awaitable[GatewayResult]]
    ) -> HttpGateway[GatewayResult]:
        if not callable(executor):
            raise TypeError("HTTP gateway executor must be callable")
        return HttpGateway(self.origin, executor)


class HttpAction:
    def __init__(self, profile: HttpProfile, call: native.HttpCall) -> None:
        self._profile = profile
        self._call = call

    @property
    def profile(self) -> HttpProfile:
        return self._profile

    @property
    def method(self) -> str:
        return self._call.method

    @property
    def path(self) -> str:
        return self._call.path


@dataclass(frozen=True)
class HttpPlanAuthority:
    permissions: Tuple[Permission, ...]
    resource_namespaces: Tuple[str, ...]
    audiences: Tuple[str, ...]


class HttpPlan:
    def __init__(
        self,
        token: object,
        profile: HttpProfile,
        actions: Tuple[HttpAction, ...],
        commitment: bytes,
        member_commitments: Tuple[bytes, ...],
        authority: HttpPlanAuthority,
    ) -> None:
        if token is not _PLAN_TOKEN:
            raise TypeError("sealed Auths HTTP plan")
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
    def authority(self) -> HttpPlanAuthority:
        return self._authority


@dataclass(frozen=True)
class HttpAuthorizationMetrics:
    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int


@dataclass(frozen=True)
class HttpExplanation:
    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class HttpApproval:
    policy_id: str
    evaluator_version: str
    required_configuration: bytes
    executed_configuration: bytes
    executed_mode: str
    executed_max_uses: int
    transaction_digest: bytes


@dataclass(frozen=True)
class HttpAuthorized:
    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    explanation: HttpExplanation
    metrics: HttpAuthorizationMetrics
    approval: HttpApproval
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes
    action_commitment: bytes
    command: native.HttpCommand


@dataclass(frozen=True)
class HttpDenied:
    kind: Literal["denied"]
    code: str
    stage: VerificationStage
    explanation: HttpExplanation
    metrics: HttpAuthorizationMetrics
    approval: HttpApproval
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


@dataclass(frozen=True)
class HttpIndeterminate:
    kind: Literal["indeterminate"]
    code: str
    stage: VerificationStage
    explanation: HttpExplanation
    metrics: HttpAuthorizationMetrics
    approval: HttpApproval
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


HttpAuthorizationResult = Union[HttpAuthorized, HttpDenied, HttpIndeterminate]


@dataclass(frozen=True)
class HttpPlanAuthorized:
    kind: Literal["authorized"]
    command: native.HttpPlanCommand
    results: Tuple[HttpAuthorized, ...]


@dataclass(frozen=True)
class HttpPlanDenied:
    kind: Literal["denied"]
    failed_index: int
    result: HttpDenied
    results: Tuple[HttpAuthorizationResult, ...]


@dataclass(frozen=True)
class HttpPlanIndeterminate:
    kind: Literal["indeterminate"]
    failed_index: int
    result: HttpIndeterminate
    results: Tuple[HttpAuthorizationResult, ...]


HttpPlanAuthorizationResult = Union[HttpPlanAuthorized, HttpPlanDenied, HttpPlanIndeterminate]


@dataclass(frozen=True)
class HttpGatewayRequest:
    method: str
    scheme: str
    authority: str
    path: str
    query: Tuple[Tuple[str, Tuple[str, ...]], ...]
    headers: Tuple[Tuple[str, str], ...]
    content_type: Optional[str]
    body_digest: Optional[str]


@dataclass(frozen=True)
class HttpReceipt:
    idempotency_key: str
    command_commitment: bytes
    authority_commitment: bytes
    context_commitment: bytes
    plan_commitment: Optional[bytes]
    state_claim: HttpExecutionState
    outcome: HttpOutcome
    observed_at: int


class HttpGatewayError(HttpProfileError):
    def __init__(
        self,
        receipt: HttpReceipt,
        completed_receipts: Tuple[HttpReceipt, ...] = (),
    ) -> None:
        super().__init__(
            "gateway-failed",
            "HTTP gateway execution outcome is unknown",
            operation="execute",
            stage="provider",
            retry="unknown",
            effect_state="outcome-unknown",
            remediation="reconcile the idempotency key before another execution attempt",
        )
        self.receipt = receipt
        self.completed_receipts = completed_receipts


class HttpGatewayCancelled(HttpProfileError):
    def __init__(
        self,
        receipt: HttpReceipt,
        completed_receipts: Tuple[HttpReceipt, ...] = (),
    ) -> None:
        super().__init__(
            "gateway-cancelled",
            "HTTP gateway task was cancelled after provider entry",
            operation="execute",
            stage="provider",
            retry="unknown",
            effect_state="outcome-unknown",
            remediation="reconcile the idempotency key before another execution attempt",
        )
        self.receipt = receipt
        self.completed_receipts = completed_receipts


GatewayResult = TypeVar("GatewayResult")


class HttpGateway(Generic[GatewayResult]):
    def __init__(
        self,
        origin: str,
        executor: Callable[[HttpGatewayRequest], Awaitable[GatewayResult]],
    ) -> None:
        self._origin = origin
        self._executor = executor

    async def execute(
        self, command: native.HttpCommand, *, idempotency_key: str
    ) -> Tuple[GatewayResult, HttpReceipt]:
        if type(command) is not native.HttpCommand or not idempotency_key:
            raise TypeError("gateway requires a native HTTP command and idempotency key")
        binding = (
            bytes(command.action_commitment),
            bytes(command.authority_commitment),
            bytes(command.context_commitment),
        )
        request = _gateway_request(native.consume_http_command(command, self._origin))
        try:
            result = await self._executor(request)
        except asyncio.CancelledError:
            raise HttpGatewayCancelled(
                _receipt(idempotency_key, binding, None, "cancelled")
            ) from None
        except Exception:
            raise HttpGatewayError(
                _receipt(
                    idempotency_key,
                    binding,
                    None,
                    "outcome-unknown",
                )
            ) from None
        return result, _receipt(idempotency_key, binding, None, "succeeded")

    async def execute_plan(
        self, command: native.HttpPlanCommand, *, idempotency_key: str
    ) -> Tuple[Tuple[GatewayResult, ...], Tuple[HttpReceipt, ...]]:
        if type(command) is not native.HttpPlanCommand or not idempotency_key:
            raise TypeError("gateway requires a native HTTP plan command and idempotency key")
        plan_commitment = bytes(command.plan_commitment)
        bindings = tuple(
            (bytes(action), bytes(authority), bytes(context))
            for action, authority, context in command.receipt_bindings
        )
        if len(bindings) != command.count:
            raise RuntimeError("native HTTP plan command omitted receipt bindings")
        calls = native.consume_http_plan_command(command, self._origin)
        results: list[GatewayResult] = []
        receipts: list[HttpReceipt] = []
        for index, (call, binding) in enumerate(zip(calls, bindings)):
            member_key = f"{idempotency_key}:{index}"
            try:
                results.append(await self._executor(_gateway_request(call)))
            except asyncio.CancelledError:
                raise HttpGatewayCancelled(
                    _receipt(
                        member_key,
                        binding,
                        plan_commitment,
                        "cancelled",
                    ),
                    tuple(receipts),
                ) from None
            except Exception:
                raise HttpGatewayError(
                    _receipt(
                        member_key,
                        binding,
                        plan_commitment,
                        "outcome-unknown",
                    ),
                    tuple(receipts),
                ) from None
            receipts.append(
                _receipt(
                    member_key,
                    binding,
                    plan_commitment,
                    "succeeded",
                )
            )
        return tuple(results), tuple(receipts)


class HttpFacade:
    def profile(self, *, scheme: str, authority: str) -> HttpProfile:
        return HttpProfile(scheme=scheme, authority=authority)


http = HttpFacade()


async def _authorize_http(
    agent: AttachedAgent,
    action: HttpAction,
    request: Optional[HttpAuthorizationRequest],
    approval_override: Optional[ApprovalConfiguration] = None,
) -> HttpAuthorizationResult:
    agent._assert_active()
    if type(action) is not HttpAction or type(agent._profile) is not HttpProfile:
        raise HttpProfileError("profile-mismatch", "attached agent does not use the HTTP profile")
    if action.profile is not agent._profile:
        raise HttpProfileError("profile-mismatch", "HTTP action belongs to another profile")
    request = HttpAuthorizationRequest() if request is None else request
    if type(request) is not HttpAuthorizationRequest:
        raise TypeError("request must be an HttpAuthorizationRequest")
    if not agent._grant_chain:
        raise HttpProfileError("disposed", "attached authority is unavailable")
    prepared = native.prepare_http_action(
        action._call,
        agent.identity.principal.principal,
        agent._grant_chain[-1].signed_grant,
        request.challenge,
        request.evaluation_time,
    )
    approval_configuration = agent._approval if approval_override is None else approval_override
    signed = await _SigningCoordinator().execute(
        unsigned=prepared.unsigned,
        principal=agent.identity.principal,
        signer=agent._signer,
        approval=approval_configuration,
        required_approval=agent._client._configured_authority.required_approval,
        expires_at=_transaction_expiry(approval_configuration.policy.expires_in_seconds),
        display=tuple(ReviewField(label, value) for label, value in prepared.review_fields),
    )
    native_result, command = native.authorize_http(
        prepared,
        signed.signed_object,
        [value.signed_grant for value in agent._grant_chain],
        [[_native_evidence(evidence) for evidence in value.evidence] for value in agent._grant_chain],
        [_native_evidence(value) for value in signed.evidence],
        agent._client._configured_authority.context,
    )
    metrics = HttpAuthorizationMetrics(*native_result.metrics)
    approval = HttpApproval(
        approval_configuration.policy.reference.policy_id,
        approval_configuration.policy.reference.evaluator_version,
        bytes(agent._client._configured_authority.required_approval.configuration_digest),
        bytes(approval_configuration.policy.reference.configuration_digest),
        approval_configuration.policy.mode,
        approval_configuration.policy.max_uses,
        signed.transaction_digest,
    )
    explanation = _explanation(native_result.kind, native_result.code)
    required = native_result.required_configuration
    local = bytes(native_result.local_configuration)
    encoded = bytes(native_result.result_cbor)
    if native_result.kind == "authorized":
        if command is None:
            raise HttpProfileError("native-authorization-failed", "native HTTP authorization omitted its command")
        canonical = bytes(native.inspect_http_action(prepared))
        commitment = bytes(native.commit_canonical_v1("auths.canonical-action.v1", canonical))
        return HttpAuthorized(
            "authorized",
            native_result.code,
            native_result.stage,
            explanation,
            metrics,
            approval,
            required,
            local,
            encoded,
            commitment,
            command,
        )
    if command is not None:
        raise HttpProfileError("native-authorization-failed", "failed HTTP decision returned a command")
    if native_result.kind == "denied":
        return HttpDenied(
            "denied",
            native_result.code,
            native_result.stage,
            explanation,
            metrics,
            approval,
            required,
            local,
            encoded,
        )
    return HttpIndeterminate(
        "indeterminate",
        native_result.code,
        native_result.stage,
        explanation,
        metrics,
        approval,
        required,
        local,
        encoded,
    )


async def _authorize_http_plan(
    agent: AttachedAgent,
    plan: HttpPlan,
    approval_provider: Optional[ApprovalProvider],
    requests: Optional[Sequence[HttpAuthorizationRequest]] = None,
) -> HttpPlanAuthorizationResult:
    agent._assert_active()
    if type(plan) is not HttpPlan or plan._profile is not agent._profile:
        raise HttpProfileError("profile-mismatch", "HTTP plan belongs to another profile")
    approval = agent._approval
    if approval.policy.mode != "plan-once" or approval.policy.max_uses != plan.length:
        raise HttpProfileError("approval-policy-mismatch", "plan-once approval must match the HTTP plan length")
    provider = approval.provider if approval_provider is None else approval_provider
    request_values = tuple(HttpAuthorizationRequest() for _ in plan._actions) if requests is None else tuple(requests)
    if len(request_values) != plan.length or any(type(value) is not HttpAuthorizationRequest for value in request_values):
        raise ValueError("authorization requests must match the HTTP plan length")
    _validate_plan(plan)
    expires_at = int(time.time()) + approval.policy.expires_in_seconds
    plan_approval = native.commit_plan_approval(
        plan._commitment,
        approval.policy.reference.configuration_digest,
        approval.policy.max_uses,
        expires_at,
    )
    session = PlanApprovalSession(
        plan_approval=bytes(plan_approval),
        member_commitments=plan._member_commitments,
        approval=approval,
        provider=provider,
        expires_at=expires_at,
        display=(ReviewField("Profile", "auths.http/1"), ReviewField("Actions", str(plan.length))),
    )
    results: list[HttpAuthorizationResult] = []
    try:
        for index, (action, request) in enumerate(zip(plan._actions, request_values)):
            _validate_plan(plan)
            member_approval = ApprovalConfiguration(
                approval.policy,
                session.provider_for(index, plan._member_commitments[index]),
            )
            result = await _authorize_http(agent, action, request, member_approval)
            results.append(result)
            if isinstance(result, HttpDenied):
                return HttpPlanDenied("denied", index, result, tuple(results))
            if isinstance(result, HttpIndeterminate):
                return HttpPlanIndeterminate("indeterminate", index, result, tuple(results))
        authorized = tuple(value for value in results if isinstance(value, HttpAuthorized))
        command = native.seal_http_plan_command(
            [value.command for value in authorized], plan._profile.origin, plan._commitment
        )
        return HttpPlanAuthorized("authorized", command, authorized)
    finally:
        session.dispose()


def _validate_plan(plan: HttpPlan) -> None:
    projection = native.commit_http_plan([action._call for action in plan._actions])
    if not native.commitments_equal_v1(bytes(projection.commitment), plan._commitment):
        raise HttpProfileError("invalid-profile", "HTTP plan membership changed")
    if len(projection.members) != len(plan._member_commitments):
        raise HttpProfileError("invalid-profile", "HTTP plan membership changed")
    for actual, expected in zip(projection.members, plan._member_commitments):
        if not native.commitments_equal_v1(bytes(actual), expected):
            raise HttpProfileError("invalid-profile", "HTTP plan membership changed")


def _gateway_request(value: native.HttpGatewayRequest) -> HttpGatewayRequest:
    return HttpGatewayRequest(
        value.method,
        value.scheme,
        value.authority,
        value.path,
        tuple((key, tuple(items)) for key, items in value.query),
        tuple(value.headers),
        value.content_type,
        value.body_digest,
    )


def _native_evidence(value: ControlEvidence) -> Tuple[str, str, bytes]:
    return value.evidence_type, value.media_type, value.bytes


def _receipt(
    idempotency_key: str,
    binding: Tuple[bytes, bytes, bytes],
    plan_commitment: Optional[bytes],
    outcome: HttpOutcome,
) -> HttpReceipt:
    return HttpReceipt(
        idempotency_key,
        binding[0],
        binding[1],
        binding[2],
        plan_commitment,
        cast(HttpExecutionState, native.runtime_execution_state_v1(outcome)),
        outcome,
        int(time.time()),
    )


def _explanation(kind: str, code: str) -> HttpExplanation:
    if kind == "authorized":
        message = "the proof establishes exact authority for this HTTP request"
    elif kind == "denied":
        message = "the supplied proof does not authorize this exact HTTP request"
    else:
        message = "a required trustworthy fact or implementation is unavailable"
    return HttpExplanation(code, message, kind == "indeterminate")


__all__ = [
    "HttpAction",
    "HttpAuthorizationRequest",
    "HttpAuthorizationResult",
    "HttpAuthorized",
    "HttpDenied",
    "HttpExplanation",
    "HttpGateway",
    "HttpGatewayCancelled",
    "HttpGatewayError",
    "HttpGatewayRequest",
    "HttpIndeterminate",
    "HttpPlan",
    "HttpPlanAuthority",
    "HttpPlanAuthorizationResult",
    "HttpPlanAuthorized",
    "HttpPlanDenied",
    "HttpPlanIndeterminate",
    "HttpProfile",
    "HttpProfileError",
    "HttpReceipt",
    "HttpReview",
    "http",
]
