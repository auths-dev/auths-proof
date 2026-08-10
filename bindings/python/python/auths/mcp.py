"""Profile-bound MCP authorization and execution."""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import (
    Awaitable,
    Callable,
    Generic,
    Literal,
    Mapping,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

from . import _native as native
from .workflow import (
    AttachedAgent,
    AuthsWorkflowError,
    ControlEvidence,
    Profile,
    ReviewField,
    _SigningCoordinator,
    _transaction_expiry,
)

VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]


@dataclass(frozen=True)
class AuthorizationRequest:
    challenge: bytes = field(default_factory=lambda: secrets.token_bytes(32))
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
    command: native.McpCommand


@dataclass(frozen=True)
class McpDenied:
    kind: Literal["denied"]
    code: str
    stage: VerificationStage
    explanation: AuthorizationExplanation
    metrics: AuthorizationMetrics
    approval: ApprovalSummary


@dataclass(frozen=True)
class McpIndeterminate:
    kind: Literal["indeterminate"]
    code: str
    stage: VerificationStage
    explanation: AuthorizationExplanation
    metrics: AuthorizationMetrics
    approval: ApprovalSummary


McpAuthorizationResult = Union[McpAuthorized, McpDenied, McpIndeterminate]


@dataclass(frozen=True)
class McpGatewayCall:
    service: str
    name: str
    arguments_json: bytes


GatewayResult = TypeVar("GatewayResult")


class McpGateway(Generic[GatewayResult]):
    def __init__(
        self,
        service: str,
        executor: Callable[[McpGatewayCall], Awaitable[GatewayResult]],
    ) -> None:
        self._service = service
        self._executor = executor

    async def execute(self, command: native.McpCommand) -> GatewayResult:
        if type(command) is not native.McpCommand:
            raise TypeError("gateway requires a native MCP command")
        try:
            call = native.consume_mcp_command(command, self._service)
        except (TypeError, RuntimeError):
            raise
        try:
            return await self._executor(
                McpGatewayCall(
                    service=call.service,
                    name=call.name,
                    arguments_json=bytes(call.arguments_json),
                )
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AuthsWorkflowError(
                "gateway-failed", "MCP gateway execution failed"
            ) from None


class McpFacade:
    def profile(self, *, service: str) -> McpProfile:
        return McpProfile(service)


mcp = McpFacade()


async def _authorize_mcp(
    agent: AttachedAgent,
    action: McpAction,
    request: Optional[AuthorizationRequest],
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
    signed = await _SigningCoordinator().execute(
        unsigned=prepared.unsigned,
        principal=agent.identity.principal,
        signer=agent._signer,
        approval=agent._approval,
        required_approval=agent._client._configured_authority.required_approval,
        expires_at=_transaction_expiry(agent._approval.policy.expires_in_seconds),
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
        policy_id=agent._approval.policy.reference.policy_id,
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
        return McpAuthorized(
            "authorized",
            native_result.code,
            stage,
            explanation,
            metrics,
            approval,
            command,
        )
    if command is not None:
        raise AuthsWorkflowError(
            "native-authorization-failed",
            "native MCP authorization returned a command for a failed verdict",
        )
    if kind == "denied":
        return McpDenied(
            "denied", native_result.code, stage, explanation, metrics, approval
        )
    return McpIndeterminate(
        "indeterminate", native_result.code, stage, explanation, metrics, approval
    )


def _native_evidence(value: ControlEvidence) -> Tuple[str, str, bytes]:
    return value.evidence_type, value.media_type, value.bytes


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
    "McpGatewayCall",
    "McpIndeterminate",
    "McpProfile",
    "mcp",
]
