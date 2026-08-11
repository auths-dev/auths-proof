"""Application-owned profiles over the native Auths workflow waist."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Generic,
    Literal,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

from . import _native as native
from ._plan import PlanApprovalSession
from .workflow import (
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

InputT = TypeVar("InputT")
CommandT = TypeVar("CommandT")
ResultT = TypeVar("ResultT")
ApplicationOutcome = Literal["succeeded", "failed", "cancelled", "outcome-unknown"]
ApplicationExecutionState = Literal["committed", "outcome-unknown"]
VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]
_ACTION_TOKEN = object()
_PLAN_TOKEN = object()


@dataclass(frozen=True)
class ProfilePermission:
    capability: str
    resource: str


@dataclass(frozen=True)
class ProfileBudget:
    algebra: str
    value: int


@dataclass(frozen=True)
class CanonicalProfileAction:
    media_type: str
    body: bytes
    permission: ProfilePermission
    resource_namespace: str
    audience: str
    display: Tuple[ReviewField, ...]
    budget: Optional[ProfileBudget] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "body", bytes(self.body))
        object.__setattr__(self, "display", tuple(self.display))


@dataclass(frozen=True)
class ProfileDefinition(Generic[InputT, CommandT]):
    id: str
    version: int
    canonicalize: Callable[[InputT], CanonicalProfileAction]
    decode_verified: Callable[[CanonicalProfileAction], CommandT]


@dataclass(frozen=True)
class ApplicationAuthority:
    permissions: Tuple[Permission, ...]
    resource_namespaces: Tuple[str, ...]
    audiences: Tuple[str, ...]
    budget: Optional[ProfileBudget]


@dataclass(frozen=True)
class ApplicationReview:
    title: str
    fields: Tuple[ReviewField, ...]
    action_commitment: bytes


class ApplicationAction(Generic[InputT]):
    def __init__(
        self,
        token: object,
        profile: ApplicationProfile[InputT, Any],
        canonical: CanonicalProfileAction,
        native_action: native.ApplicationAction,
    ) -> None:
        if token is not _ACTION_TOKEN:
            raise TypeError("sealed Auths application action")
        self._profile = profile
        self._canonical = canonical
        self._native = native_action

    @property
    def profile(self) -> ApplicationProfile[InputT, Any]:
        return self._profile


class ApplicationPlan(Generic[InputT]):
    def __init__(
        self,
        token: object,
        profile: ApplicationProfile[InputT, Any],
        actions: Tuple[ApplicationAction[InputT], ...],
        commitment: bytes,
        member_commitments: Tuple[bytes, ...],
        authority: ApplicationAuthority,
    ) -> None:
        if token is not _PLAN_TOKEN:
            raise TypeError("sealed Auths application plan")
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
    def authority(self) -> ApplicationAuthority:
        return self._authority


@dataclass(frozen=True)
class ApplicationRequest:
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
class ApplicationMetrics:
    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int


@dataclass(frozen=True)
class ApplicationExplanation:
    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class ApplicationApproval:
    policy_id: str
    evaluator_version: str
    required_configuration: bytes
    executed_configuration: bytes
    executed_mode: str
    executed_max_uses: int
    transaction_digest: bytes


@dataclass(frozen=True)
class ApplicationAuthorized(Generic[CommandT]):
    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    explanation: ApplicationExplanation
    metrics: ApplicationMetrics
    approval: ApplicationApproval
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes
    command: native.ApplicationCommand


@dataclass(frozen=True)
class ApplicationDenied:
    kind: Literal["denied"]
    code: str
    stage: VerificationStage
    explanation: ApplicationExplanation
    metrics: ApplicationMetrics
    approval: ApplicationApproval
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


@dataclass(frozen=True)
class ApplicationIndeterminate:
    kind: Literal["indeterminate"]
    code: str
    stage: VerificationStage
    explanation: ApplicationExplanation
    metrics: ApplicationMetrics
    approval: ApplicationApproval
    required_configuration: Optional[bytes]
    local_configuration: bytes
    result_cbor: bytes


ApplicationResult = Union[ApplicationAuthorized[CommandT], ApplicationDenied, ApplicationIndeterminate]


@dataclass(frozen=True)
class ApplicationPlanAuthorized(Generic[CommandT]):
    kind: Literal["authorized"]
    command: native.ApplicationPlanCommand
    results: Tuple[ApplicationAuthorized[CommandT], ...]


@dataclass(frozen=True)
class ApplicationPlanDenied:
    kind: Literal["denied"]
    failed_index: int
    result: ApplicationDenied


@dataclass(frozen=True)
class ApplicationPlanIndeterminate:
    kind: Literal["indeterminate"]
    failed_index: int
    result: ApplicationIndeterminate


ApplicationPlanResult = Union[
    ApplicationPlanAuthorized[CommandT], ApplicationPlanDenied, ApplicationPlanIndeterminate
]


@dataclass(frozen=True)
class ApplicationReceipt:
    idempotency_key: str
    command_commitment: bytes
    authority_commitment: bytes
    context_commitment: bytes
    plan_commitment: Optional[bytes]
    state_claim: ApplicationExecutionState
    outcome: ApplicationOutcome
    observed_at: int


class ApplicationGatewayError(AuthsWorkflowError):
    def __init__(
        self,
        receipt: ApplicationReceipt,
        completed_receipts: Tuple[ApplicationReceipt, ...] = (),
    ) -> None:
        super().__init__(
            "gateway-failed",
            "application gateway execution outcome is unknown",
            operation="execute",
            stage="provider",
            retry="unknown",
            effect_state="outcome-unknown",
            remediation="reconcile the idempotency key before another execution attempt",
        )
        self.receipt = receipt
        self.completed_receipts = completed_receipts


class ApplicationGatewayCancelled(asyncio.CancelledError):
    def __init__(
        self,
        receipt: ApplicationReceipt,
        completed_receipts: Tuple[ApplicationReceipt, ...] = (),
    ) -> None:
        super().__init__("application gateway task was cancelled after provider entry")
        self.receipt = receipt
        self.completed_receipts = completed_receipts


class ApplicationGateway(Generic[CommandT, ResultT]):
    def __init__(
        self,
        profile: ApplicationProfile[Any, CommandT],
        executor: Callable[[CommandT], Awaitable[ResultT]],
    ) -> None:
        self._profile = profile
        self._executor = executor

    async def execute(
        self, command: native.ApplicationCommand, *, idempotency_key: str
    ) -> Tuple[ResultT, ApplicationReceipt]:
        if type(command) is not native.ApplicationCommand or not idempotency_key:
            raise TypeError(
                "gateway requires a native application command and idempotency key"
            )
        binding = (
            bytes(command.action_commitment),
            bytes(command.authority_commitment),
            bytes(command.context_commitment),
        )
        call = native.consume_application_command(
            command, self._profile.id, self._profile.version
        )
        decoded = self._profile._decode(_canonical_from_call(call))
        try:
            result = await self._executor(decoded)
        except asyncio.CancelledError:
            raise ApplicationGatewayCancelled(
                _receipt(idempotency_key, binding, None, "cancelled")
            ) from None
        except Exception:
            raise ApplicationGatewayError(
                _receipt(
                    idempotency_key,
                    binding,
                    None,
                    "outcome-unknown",
                )
            ) from None
        return result, _receipt(idempotency_key, binding, None, "succeeded")

    async def execute_plan(
        self, command: native.ApplicationPlanCommand, *, idempotency_key: str
    ) -> Tuple[Tuple[ResultT, ...], Tuple[ApplicationReceipt, ...]]:
        if type(command) is not native.ApplicationPlanCommand or not idempotency_key:
            raise TypeError(
                "gateway requires a native application plan command and idempotency key"
            )
        plan_commitment = bytes(command.plan_commitment)
        bindings = tuple(
            (bytes(action), bytes(authority), bytes(context))
            for action, authority, context in command.receipt_bindings
        )
        if len(bindings) != command.count:
            raise RuntimeError("native application plan command omitted receipt bindings")
        calls = native.consume_application_plan_command(
            command, self._profile.id, self._profile.version
        )
        results: list[ResultT] = []
        receipts: list[ApplicationReceipt] = []
        for index, (call, binding) in enumerate(zip(calls, bindings)):
            decoded = self._profile._decode(_canonical_from_call(call))
            member_key = f"{idempotency_key}:{index}"
            try:
                results.append(await self._executor(decoded))
            except asyncio.CancelledError:
                raise ApplicationGatewayCancelled(
                    _receipt(
                        member_key,
                        binding,
                        plan_commitment,
                        "cancelled",
                    ),
                    tuple(receipts),
                ) from None
            except Exception:
                raise ApplicationGatewayError(
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


class ApplicationProfile(Profile, Generic[InputT, CommandT]):
    def __init__(self, definition: ProfileDefinition[InputT, CommandT]) -> None:
        if not callable(definition.canonicalize) or not callable(definition.decode_verified):
            raise TypeError("profile requires canonicalize and decode_verified callables")
        super().__init__(definition.id, definition.version)
        self._canonicalize = definition.canonicalize
        self._decode = definition.decode_verified

    def action(self, value: InputT) -> ApplicationAction[InputT]:
        try:
            canonical = self._canonicalize(value)
        except Exception:
            raise AuthsWorkflowError("invalid-profile", "profile rejected the action") from None
        if type(canonical) is not CanonicalProfileAction:
            raise TypeError("profile canonicalizer must return CanonicalProfileAction")
        native_action = native.application_action(
            self.id,
            self.version,
            canonical.media_type,
            canonical.body,
            canonical.permission.capability,
            canonical.permission.resource,
            None if canonical.budget is None else (canonical.budget.algebra, canonical.budget.value),
            canonical.resource_namespace,
            canonical.audience,
        )
        return ApplicationAction(_ACTION_TOKEN, self, canonical, native_action)

    def authority_for(self, action: ApplicationAction[InputT]) -> ApplicationAuthority:
        self._assert_action(action)
        canonical = action._canonical
        return ApplicationAuthority(
            (Permission(canonical.permission.capability, canonical.permission.resource),),
            (canonical.resource_namespace,),
            (canonical.audience,),
            canonical.budget,
        )

    def inspect_action(self, action: ApplicationAction[InputT]) -> CanonicalProfileAction:
        self._assert_action(action)
        return action._canonical

    def review(self, action: ApplicationAction[InputT]) -> ApplicationReview:
        self._assert_action(action)
        return ApplicationReview(
            f"{self.id}/{self.version}",
            action._canonical.display,
            bytes(native.application_action_commitment_v1(action._native)),
        )

    def plan(self, actions: Sequence[ApplicationAction[InputT]]) -> ApplicationPlan[InputT]:
        values = tuple(actions)
        if not values or any(value._profile is not self for value in values):
            raise AuthsWorkflowError("invalid-profile", "application plan contains an incompatible action")
        projection = native.commit_application_plan([value._native for value in values])
        first = values[0]._canonical
        aggregate = sum(value._canonical.budget.value for value in values if value._canonical.budget is not None)
        budget = None if first.budget is None else ProfileBudget(first.budget.algebra, aggregate)
        authority = ApplicationAuthority(
            tuple(
                dict.fromkeys(
                    Permission(value._canonical.permission.capability, value._canonical.permission.resource)
                    for value in values
                )
            ),
            (first.resource_namespace,),
            (first.audience,),
            budget,
        )
        return ApplicationPlan(
            _PLAN_TOKEN,
            self,
            values,
            bytes(projection.commitment),
            tuple(bytes(value) for value in projection.members),
            authority,
        )

    def gateway(
        self, executor: Callable[[CommandT], Awaitable[ResultT]]
    ) -> ApplicationGateway[CommandT, ResultT]:
        if not callable(executor):
            raise TypeError("application gateway executor must be callable")
        return ApplicationGateway(self, executor)

    def _assert_action(self, action: ApplicationAction[InputT]) -> None:
        if type(action) is not ApplicationAction or action._profile is not self:
            raise AuthsWorkflowError("invalid-profile", "action belongs to another profile")


def define_profile(
    definition: ProfileDefinition[InputT, CommandT],
) -> ApplicationProfile[InputT, CommandT]:
    if type(definition) is not ProfileDefinition:
        raise TypeError("profile definition is required")
    return ApplicationProfile(definition)


def _receipt(
    idempotency_key: str,
    binding: Tuple[bytes, bytes, bytes],
    plan_commitment: Optional[bytes],
    outcome: ApplicationOutcome,
) -> ApplicationReceipt:
    return ApplicationReceipt(
        idempotency_key,
        binding[0],
        binding[1],
        binding[2],
        plan_commitment,
        cast(ApplicationExecutionState, native.runtime_execution_state_v1(outcome)),
        outcome,
        int(time.time()),
    )


async def _authorize_application(
    agent: AttachedAgent,
    action: ApplicationAction[object],
    request: Optional[ApplicationRequest],
    approval_override: Optional[ApprovalConfiguration] = None,
) -> ApplicationResult[object]:
    agent._assert_active()
    if type(action) is not ApplicationAction or action._profile is not agent._profile:
        raise AuthsWorkflowError("profile-mismatch", "application action belongs to another profile")
    request = ApplicationRequest() if request is None else request
    if type(request) is not ApplicationRequest:
        raise TypeError("request must be an ApplicationRequest")
    prepared = native.prepare_application_action(
        action._native,
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
        display=action._canonical.display,
    )
    native_result, command = native.authorize_application(
        prepared,
        signed.signed_object,
        [value.signed_grant for value in agent._grant_chain],
        [[_native_evidence(evidence) for evidence in value.evidence] for value in agent._grant_chain],
        [_native_evidence(value) for value in signed.evidence],
        agent._client._configured_authority.context,
    )
    metrics = ApplicationMetrics(*native_result.metrics)
    approval = ApplicationApproval(
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
            raise AuthsWorkflowError("native-authorization-failed", "application authorization omitted its command")
        return ApplicationAuthorized(
            "authorized",
            native_result.code,
            native_result.stage,
            explanation,
            metrics,
            approval,
            required,
            local,
            encoded,
            command,
        )
    if command is not None:
        raise AuthsWorkflowError("native-authorization-failed", "failed application decision returned a command")
    if native_result.kind == "denied":
        return ApplicationDenied(
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
    return ApplicationIndeterminate(
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


async def _authorize_application_plan(
    agent: AttachedAgent,
    plan: ApplicationPlan[object],
    approval_provider: Optional[ApprovalProvider],
    requests: Optional[Sequence[ApplicationRequest]],
) -> ApplicationPlanResult[object]:
    if type(plan) is not ApplicationPlan or plan._profile is not agent._profile:
        raise AuthsWorkflowError("profile-mismatch", "application plan belongs to another profile")
    agent._assert_active()
    _validate_application_plan(plan)
    approval = agent._approval
    if approval.policy.mode != "plan-once" or approval.policy.max_uses != plan.length:
        raise AuthsWorkflowError("approval-policy-mismatch", "plan-once approval must match the application plan")
    provider = approval.provider if approval_provider is None else approval_provider
    request_values = tuple(ApplicationRequest() for _ in plan._actions) if requests is None else tuple(requests)
    if len(request_values) != plan.length:
        raise ValueError("authorization requests must match the application plan")
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
        display=(ReviewField("Profile", f"{plan._profile.id}/{plan._profile.version}"), ReviewField("Actions", str(plan.length))),
    )
    results: list[ApplicationResult[object]] = []
    try:
        for index, (action, request) in enumerate(zip(plan._actions, request_values)):
            _validate_application_plan(plan)
            member_approval = ApprovalConfiguration(
                approval.policy,
                session.provider_for(index, plan._member_commitments[index]),
            )
            result = await _authorize_application(agent, action, request, member_approval)
            results.append(result)
            if isinstance(result, ApplicationDenied):
                return ApplicationPlanDenied("denied", index, result)
            if isinstance(result, ApplicationIndeterminate):
                return ApplicationPlanIndeterminate("indeterminate", index, result)
        authorized = cast(
            Tuple[ApplicationAuthorized[object], ...],
            tuple(
                value for value in results if isinstance(value, ApplicationAuthorized)
            ),
        )
        command = native.seal_application_plan_command(
            [value.command for value in authorized],
            plan._profile.id,
            plan._profile.version,
            plan._commitment,
        )
        return ApplicationPlanAuthorized("authorized", command, authorized)
    finally:
        session.dispose()


def _validate_application_plan(plan: ApplicationPlan[object]) -> None:
    projection = native.commit_application_plan(
        [action._native for action in plan._actions]
    )
    if not native.commitments_equal_v1(bytes(projection.commitment), plan._commitment):
        raise AuthsWorkflowError("invalid-profile", "application plan membership changed")
    if len(projection.members) != len(plan._member_commitments):
        raise AuthsWorkflowError("invalid-profile", "application plan membership changed")
    for actual, expected in zip(projection.members, plan._member_commitments):
        if not native.commitments_equal_v1(bytes(actual), expected):
            raise AuthsWorkflowError(
                "invalid-profile", "application plan membership changed"
            )


def _canonical_from_call(call: native.ApplicationGatewayCall) -> CanonicalProfileAction:
    permission = ProfilePermission(*call.permission)
    budget = None if call.budget is None else ProfileBudget(*call.budget)
    return CanonicalProfileAction(
        call.media_type,
        bytes(call.body),
        permission,
        call.resource_namespace,
        call.audience,
        (),
        budget,
    )


def _native_evidence(value: ControlEvidence) -> Tuple[str, str, bytes]:
    return value.evidence_type, value.media_type, value.bytes


def _explanation(kind: str, code: str) -> ApplicationExplanation:
    if kind == "authorized":
        message = "the proof establishes exact authority for this application action"
    elif kind == "denied":
        message = "the supplied proof does not authorize this application action"
    else:
        message = "a required trustworthy fact or implementation is unavailable"
    return ApplicationExplanation(code, message, kind == "indeterminate")


__all__ = [
    "ApplicationAction",
    "ApplicationAuthority",
    "ApplicationGateway",
    "ApplicationGatewayCancelled",
    "ApplicationGatewayError",
    "ApplicationPlan",
    "ApplicationPlanAuthorized",
    "ApplicationPlanDenied",
    "ApplicationPlanIndeterminate",
    "ApplicationPlanResult",
    "ApplicationProfile",
    "ApplicationRequest",
    "ApplicationReceipt",
    "ApplicationReview",
    "ApplicationResult",
    "ApplicationAuthorized",
    "ApplicationDenied",
    "ApplicationIndeterminate",
    "CanonicalProfileAction",
    "ProfileBudget",
    "ProfileDefinition",
    "ProfilePermission",
    "define_profile",
]
