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
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

from . import _native as native
from ._plan import PlanApprovalSession
from ._workflow import (
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
from ._errors import ProviderOperationError
from ._receipts import (
    AttestedReceipt,
    ReceiptAttestor,
    _attest_decision,
    _attest_execution,
)

InputT = TypeVar("InputT")
CommandT = TypeVar("CommandT")
CredentialCommandT = TypeVar("CredentialCommandT", contravariant=True)
ResultT = TypeVar("ResultT")
ApplicationOutcome = Literal["succeeded", "failed", "cancelled", "outcome-unknown"]
ApplicationExecutionState = Literal["committed", "released", "outcome-unknown"]
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
        if (
            type(self.evaluation_time) is not int
            or not 0 <= self.evaluation_time <= (1 << 64) - 1
        ):
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


ApplicationResult = Union[
    ApplicationAuthorized[CommandT], ApplicationDenied, ApplicationIndeterminate
]


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
    ApplicationPlanAuthorized[CommandT],
    ApplicationPlanDenied,
    ApplicationPlanIndeterminate,
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
    decision_receipt: AttestedReceipt
    execution_receipt: Optional[AttestedReceipt]


@dataclass(frozen=True)
class ApplicationExecutionContext:
    idempotency_key: str
    canonical_command: bytes
    plan_commitment: Optional[bytes] = None
    member_index: Optional[int] = None
    member_count: Optional[int] = None

    def __post_init__(self) -> None:
        command = bytes(self.canonical_command)
        if not command or len(command) > 1024 * 1024:
            raise ValueError("canonical command is outside bounds")
        object.__setattr__(self, "canonical_command", command)
        if self.plan_commitment is not None:
            commitment = bytes(self.plan_commitment)
            if len(commitment) != 32:
                raise ValueError("plan commitment must contain 32 bytes")
            object.__setattr__(self, "plan_commitment", commitment)


@dataclass(frozen=True)
class ApplicationReservation:
    idempotency_key: str
    command_commitment: bytes
    authority_commitment: bytes
    context_commitment: bytes
    plan_commitment: Optional[bytes]
    member_index: Optional[int]
    member_count: Optional[int]
    observed_at: int


class ApplicationExecutionStore(Protocol):
    async def reserve(
        self, reservation: ApplicationReservation
    ) -> Literal[
        "reserved",
        "exact-replay",
        "conflict",
        "expired",
        "out-of-order",
        "unavailable",
    ]: ...

    async def authorize_credential(
        self, idempotency_key: str
    ) -> Literal["authorized", "conflict", "unavailable"]: ...

    async def enter_provider(
        self, idempotency_key: str
    ) -> Literal["entered", "conflict", "unavailable"]: ...

    async def finish(
        self,
        idempotency_key: str,
        outcome: ApplicationOutcome,
        decision_receipt: AttestedReceipt,
        execution_receipt: Optional[AttestedReceipt],
    ) -> Literal["stored", "conflict", "unavailable"]: ...


class ApplicationCredentialProvider(Protocol, Generic[CredentialCommandT]):
    async def acquire(
        self, command: CredentialCommandT, context: ApplicationExecutionContext
    ) -> object: ...


@dataclass(frozen=True)
class ApplicationGatewayOptions(Generic[CommandT, ResultT]):
    state: ApplicationExecutionStore
    credentials: ApplicationCredentialProvider[CommandT]
    receipts: ReceiptAttestor
    execute: Callable[
        [CommandT, object, ApplicationExecutionContext], Awaitable[ResultT]
    ]
    canonicalize_result: Callable[[ResultT], bytes]


class ApplicationGatewayError(AuthsWorkflowError):
    def __init__(
        self,
        receipt: ApplicationReceipt,
        completed_receipts: Tuple[ApplicationReceipt, ...] = (),
    ) -> None:
        unknown = receipt.outcome == "outcome-unknown"
        super().__init__(
            "gateway-failed",
            "application gateway execution outcome is unknown"
            if unknown
            else "application gateway execution failed without an effect",
            operation="execute",
            stage="provider",
            retry="unknown" if unknown else "safe",
            effect_state="outcome-unknown" if unknown else "failed",
            remediation=(
                "reconcile the idempotency key before another execution attempt"
                if unknown
                else "inspect the provider failure before retrying"
            ),
        )
        self.receipt = receipt
        self.completed_receipts = completed_receipts


class ApplicationGatewayCancelled(AuthsWorkflowError):
    def __init__(
        self,
        receipt: ApplicationReceipt,
        completed_receipts: Tuple[ApplicationReceipt, ...] = (),
    ) -> None:
        entered_provider = receipt.outcome == "outcome-unknown"
        super().__init__(
            "gateway-cancelled",
            "application gateway task was cancelled after provider entry"
            if entered_provider
            else "application gateway task was cancelled before provider entry",
            operation="execute",
            stage="provider" if entered_provider else "credential",
            retry="unknown" if entered_provider else "safe",
            effect_state="outcome-unknown" if entered_provider else "failed",
            remediation=(
                "reconcile the idempotency key before another execution attempt"
                if entered_provider
                else "retry with a new authorized command"
            ),
        )
        self.receipt = receipt
        self.completed_receipts = completed_receipts


class ApplicationGateway(Generic[CommandT, ResultT]):
    def __init__(
        self,
        profile: ApplicationProfile[Any, CommandT],
        options: ApplicationGatewayOptions[CommandT, ResultT],
    ) -> None:
        self._profile = profile
        self._options = options

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
        signer = self._options.receipts.signer
        decision_preparation = native.prepare_application_command_decision_receipt_v1(
            command,
            int(time.time()),
            signer.principal,
            signer.verification_method,
            signer.suite,
        )
        decision_receipt = await _attest_decision(
            decision_preparation, self._options.receipts
        )
        call = native.consume_application_command(
            command, self._profile.id, self._profile.version
        )
        decoded = self._profile._decode(_canonical_from_call(call))
        context = ApplicationExecutionContext(idempotency_key, bytes(call.body))
        return await self._execute_one(decoded, binding, context, decision_receipt)

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
            raise RuntimeError(
                "native application plan command omitted receipt bindings"
            )
        signer = self._options.receipts.signer
        decision_preparations = native.prepare_application_plan_decision_receipts_v1(
            command,
            int(time.time()),
            signer.principal,
            signer.verification_method,
            signer.suite,
        )
        decision_receipts = tuple(
            [
                await _attest_decision(value, self._options.receipts)
                for value in decision_preparations
            ]
        )
        if len(decision_receipts) != len(bindings):
            raise RuntimeError("native application plan omitted decision receipts")
        calls = native.consume_application_plan_command(
            command, self._profile.id, self._profile.version
        )
        results: list[ResultT] = []
        receipts: list[ApplicationReceipt] = []
        for index, (call, binding, decision_receipt) in enumerate(
            zip(calls, bindings, decision_receipts)
        ):
            decoded = self._profile._decode(_canonical_from_call(call))
            member_key = f"{idempotency_key}:{index}"
            context = ApplicationExecutionContext(
                member_key,
                bytes(call.body),
                plan_commitment,
                index,
                len(bindings),
            )
            try:
                result, receipt = await self._execute_one(
                    decoded,
                    binding,
                    context,
                    decision_receipt,
                )
                results.append(result)
                receipts.append(receipt)
            except ApplicationGatewayCancelled as error:
                raise ApplicationGatewayCancelled(
                    error.receipt, tuple(receipts)
                ) from None
            except ApplicationGatewayError as error:
                raise ApplicationGatewayError(error.receipt, tuple(receipts)) from None
        return tuple(results), tuple(receipts)

    async def _execute_one(
        self,
        command: CommandT,
        binding: Tuple[bytes, bytes, bytes],
        context: ApplicationExecutionContext,
        decision_receipt: AttestedReceipt,
    ) -> Tuple[ResultT, ApplicationReceipt]:
        reservation = ApplicationReservation(
            context.idempotency_key,
            binding[0],
            binding[1],
            binding[2],
            context.plan_commitment,
            context.member_index,
            context.member_count,
            int(time.time()),
        )
        reserved = await _state_call(self._options.state.reserve(reservation))
        if reserved != "reserved":
            raise _gateway_state_error(reserved)
        credential_authorized = await _state_call(
            self._options.state.authorize_credential(context.idempotency_key)
        )
        if credential_authorized != "authorized":
            await self._finish(context, "failed", decision_receipt, None)
            raise _gateway_state_error(credential_authorized)
        try:
            credential = await self._options.credentials.acquire(command, context)
        except asyncio.CancelledError:
            await self._finish(context, "cancelled", decision_receipt, None)
            raise ApplicationGatewayCancelled(
                _receipt(
                    context.idempotency_key,
                    binding,
                    context.plan_commitment,
                    "cancelled",
                    decision_receipt,
                    None,
                )
            ) from None
        except Exception:
            await self._finish(context, "failed", decision_receipt, None)
            raise ApplicationGatewayError(
                _receipt(
                    context.idempotency_key,
                    binding,
                    context.plan_commitment,
                    "failed",
                    decision_receipt,
                    None,
                )
            ) from None
        entered = await _state_call(
            self._options.state.enter_provider(context.idempotency_key)
        )
        if entered != "entered":
            await self._finish(context, "failed", decision_receipt, None)
            raise _gateway_state_error(entered)
        try:
            result = await self._options.execute(command, credential, context)
        except asyncio.CancelledError:
            await self._finish(context, "outcome-unknown", decision_receipt, None)
            raise ApplicationGatewayCancelled(
                _receipt(
                    context.idempotency_key,
                    binding,
                    context.plan_commitment,
                    "outcome-unknown",
                    decision_receipt,
                    None,
                )
            ) from None
        except Exception as error:
            outcome: ApplicationOutcome = (
                "failed"
                if isinstance(error, ProviderOperationError)
                and error.effect_state == "not-started"
                else "outcome-unknown"
            )
            execution_receipt = None
            if outcome == "failed":
                try:
                    execution_receipt = await self._execution_receipt(
                        decision_receipt,
                        context,
                        context.canonical_command,
                        "failed",
                        None,
                    )
                except Exception:
                    execution_receipt = None
            await self._finish(context, outcome, decision_receipt, execution_receipt)
            raise ApplicationGatewayError(
                _receipt(
                    context.idempotency_key,
                    binding,
                    context.plan_commitment,
                    outcome,
                    decision_receipt,
                    execution_receipt,
                )
            ) from None
        try:
            result_bytes = bytes(self._options.canonicalize_result(result))
            if not result_bytes:
                raise ValueError("empty canonical result")
        except Exception:
            await self._finish(context, "outcome-unknown", decision_receipt, None)
            raise ApplicationGatewayError(
                _receipt(
                    context.idempotency_key,
                    binding,
                    context.plan_commitment,
                    "outcome-unknown",
                    decision_receipt,
                    None,
                )
            ) from None
        try:
            execution_receipt = await self._execution_receipt(
                decision_receipt,
                context,
                context.canonical_command,
                "succeeded",
                result_bytes,
            )
        except Exception:
            await self._finish(context, "outcome-unknown", decision_receipt, None)
            raise ApplicationGatewayError(
                _receipt(
                    context.idempotency_key,
                    binding,
                    context.plan_commitment,
                    "outcome-unknown",
                    decision_receipt,
                    None,
                )
            ) from None
        completed = _receipt(
            context.idempotency_key,
            binding,
            context.plan_commitment,
            "succeeded",
            decision_receipt,
            execution_receipt,
        )
        if (
            await self._finish(
                context, "succeeded", decision_receipt, execution_receipt
            )
            != "stored"
        ):
            raise ApplicationGatewayError(
                _receipt(
                    context.idempotency_key,
                    binding,
                    context.plan_commitment,
                    "outcome-unknown",
                    decision_receipt,
                    execution_receipt,
                )
            )
        return result, completed

    async def _execution_receipt(
        self,
        decision_receipt: AttestedReceipt,
        context: ApplicationExecutionContext,
        command_bytes: bytes,
        outcome: Literal["succeeded", "failed"],
        result: Optional[bytes],
    ) -> AttestedReceipt:
        signer = self._options.receipts.signer
        preparation = native.prepare_application_execution_receipt_v1(
            decision_receipt.receipt_id,
            context.idempotency_key,
            context.plan_commitment,
            context.member_index,
            context.member_count,
            command_bytes,
            outcome,
            result,
            int(time.time()),
            signer.principal,
            signer.verification_method,
            signer.suite,
        )
        return await _attest_execution(preparation, self._options.receipts)

    async def _finish(
        self,
        context: ApplicationExecutionContext,
        outcome: ApplicationOutcome,
        decision_receipt: AttestedReceipt,
        execution_receipt: Optional[AttestedReceipt],
    ) -> str:
        return await _state_call(
            self._options.state.finish(
                context.idempotency_key,
                outcome,
                decision_receipt,
                execution_receipt,
            )
        )


class ApplicationProfile(Profile, Generic[InputT, CommandT]):
    def __init__(self, definition: ProfileDefinition[InputT, CommandT]) -> None:
        if not callable(definition.canonicalize) or not callable(
            definition.decode_verified
        ):
            raise TypeError(
                "profile requires canonicalize and decode_verified callables"
            )
        super().__init__(definition.id, definition.version)
        self._canonicalize = definition.canonicalize
        self._decode = definition.decode_verified

    def action(self, value: InputT) -> ApplicationAction[InputT]:
        try:
            canonical = self._canonicalize(value)
        except Exception:
            raise AuthsWorkflowError(
                "invalid-profile", "profile rejected the action"
            ) from None
        if type(canonical) is not CanonicalProfileAction:
            raise TypeError("profile canonicalizer must return CanonicalProfileAction")
        native_action = native.application_action(
            self.id,
            self.version,
            canonical.media_type,
            canonical.body,
            canonical.permission.capability,
            canonical.permission.resource,
            None
            if canonical.budget is None
            else (canonical.budget.algebra, canonical.budget.value),
            canonical.resource_namespace,
            canonical.audience,
        )
        return ApplicationAction(_ACTION_TOKEN, self, canonical, native_action)

    def authority_for(self, action: ApplicationAction[InputT]) -> ApplicationAuthority:
        self._assert_action(action)
        canonical = action._canonical
        return ApplicationAuthority(
            (
                Permission(
                    canonical.permission.capability, canonical.permission.resource
                ),
            ),
            (canonical.resource_namespace,),
            (canonical.audience,),
            canonical.budget,
        )

    def inspect_action(
        self, action: ApplicationAction[InputT]
    ) -> CanonicalProfileAction:
        self._assert_action(action)
        return action._canonical

    def review(self, action: ApplicationAction[InputT]) -> ApplicationReview:
        self._assert_action(action)
        return ApplicationReview(
            f"{self.id}/{self.version}",
            action._canonical.display,
            bytes(native.application_action_commitment_v1(action._native)),
        )

    def plan(
        self, actions: Sequence[ApplicationAction[InputT]]
    ) -> ApplicationPlan[InputT]:
        values = tuple(actions)
        if not values or any(value._profile is not self for value in values):
            raise AuthsWorkflowError(
                "invalid-profile", "application plan contains an incompatible action"
            )
        projection = native.commit_application_plan([value._native for value in values])
        first = values[0]._canonical
        aggregate = sum(
            value._canonical.budget.value
            for value in values
            if value._canonical.budget is not None
        )
        budget = (
            None
            if first.budget is None
            else ProfileBudget(first.budget.algebra, aggregate)
        )
        authority = ApplicationAuthority(
            tuple(
                dict.fromkeys(
                    Permission(
                        value._canonical.permission.capability,
                        value._canonical.permission.resource,
                    )
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
        self,
        options: ApplicationGatewayOptions[CommandT, ResultT],
    ) -> ApplicationGateway[CommandT, ResultT]:
        if type(options) is not ApplicationGatewayOptions:
            raise TypeError("application gateway ports are required")
        if (
            not callable(options.execute)
            or not callable(options.canonicalize_result)
            or not callable(getattr(options.receipts, "sign", None))
            or not callable(getattr(options.credentials, "acquire", None))
            or not callable(getattr(options.state, "reserve", None))
            or not callable(getattr(options.state, "authorize_credential", None))
            or not callable(getattr(options.state, "enter_provider", None))
            or not callable(getattr(options.state, "finish", None))
        ):
            raise TypeError("application gateway ports are incomplete")
        return ApplicationGateway(self, options)

    def _assert_action(self, action: ApplicationAction[InputT]) -> None:
        if type(action) is not ApplicationAction or action._profile is not self:
            raise AuthsWorkflowError(
                "invalid-profile", "action belongs to another profile"
            )


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
    decision_receipt: AttestedReceipt,
    execution_receipt: Optional[AttestedReceipt],
) -> ApplicationReceipt:
    return ApplicationReceipt(
        idempotency_key,
        binding[0],
        binding[1],
        binding[2],
        plan_commitment,
        cast(
            ApplicationExecutionState,
            native.runtime_application_execution_state_v1(outcome),
        ),
        outcome,
        int(time.time()),
        decision_receipt,
        execution_receipt,
    )


async def _state_call(operation: Awaitable[str]) -> str:
    try:
        return await operation
    except Exception:
        return "unavailable"


def _gateway_state_error(code: str) -> AuthsWorkflowError:
    value = (
        code
        if code
        in ("exact-replay", "conflict", "expired", "out-of-order", "unavailable")
        else "unavailable"
    )
    return AuthsWorkflowError(
        "gateway-" + value,
        "application gateway state rejected execution",
        operation="execute",
        stage="reservation",
        retry="safe" if value == "unavailable" else "never",
        effect_state="not-started",
    )


async def _authorize_application(
    agent: AttachedAgent,
    action: ApplicationAction[object],
    request: Optional[ApplicationRequest],
    approval_override: Optional[ApprovalConfiguration] = None,
) -> ApplicationResult[object]:
    agent._assert_active()
    if type(action) is not ApplicationAction or action._profile is not agent._profile:
        raise AuthsWorkflowError(
            "profile-mismatch", "application action belongs to another profile"
        )
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
        display=action._canonical.display,
    )
    native_result, command = native.authorize_application(
        prepared,
        signed.signed_object,
        [value.signed_grant for value in agent._grant_chain],
        [
            [_native_evidence(evidence) for evidence in value.evidence]
            for value in agent._grant_chain
        ],
        [_native_evidence(value) for value in signed.evidence],
        agent._client._configured_authority.context,
    )
    metrics = ApplicationMetrics(*native_result.metrics)
    approval = ApplicationApproval(
        approval_configuration.policy.reference.policy_id,
        approval_configuration.policy.reference.evaluator_version,
        bytes(
            agent._client._configured_authority.required_approval.configuration_digest
        ),
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
            raise AuthsWorkflowError(
                "native-authorization-failed",
                "application authorization omitted its command",
            )
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
        raise AuthsWorkflowError(
            "native-authorization-failed",
            "failed application decision returned a command",
        )
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
        raise AuthsWorkflowError(
            "profile-mismatch", "application plan belongs to another profile"
        )
    agent._assert_active()
    _validate_application_plan(plan)
    approval = agent._approval
    if approval.policy.mode != "plan-once" or approval.policy.max_uses != plan.length:
        raise AuthsWorkflowError(
            "approval-policy-mismatch",
            "plan-once approval must match the application plan",
        )
    provider = approval.provider if approval_provider is None else approval_provider
    request_values = (
        tuple(ApplicationRequest() for _ in plan._actions)
        if requests is None
        else tuple(requests)
    )
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
        display=(
            ReviewField("Profile", f"{plan._profile.id}/{plan._profile.version}"),
            ReviewField("Actions", str(plan.length)),
        ),
    )
    results: list[ApplicationResult[object]] = []
    try:
        for index, (action, request) in enumerate(zip(plan._actions, request_values)):
            _validate_application_plan(plan)
            member_approval = ApprovalConfiguration(
                approval.policy,
                session.provider_for(index, plan._member_commitments[index]),
            )
            result = await _authorize_application(
                agent, action, request, member_approval
            )
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
        raise AuthsWorkflowError(
            "invalid-profile", "application plan membership changed"
        )
    if len(projection.members) != len(plan._member_commitments):
        raise AuthsWorkflowError(
            "invalid-profile", "application plan membership changed"
        )
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
    "ApplicationGatewayOptions",
    "ApplicationCredentialProvider",
    "ApplicationExecutionStore",
    "ApplicationExecutionContext",
    "ApplicationReservation",
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
