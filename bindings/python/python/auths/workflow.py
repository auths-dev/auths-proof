"""Async agent attachment and authority delegation."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from types import TracebackType
from typing import (
    Any,
    Callable,
    Literal,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
    Union,
    cast,
    runtime_checkable,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from .mcp import (
        AuthorizationRequest,
        McpAction,
        McpAuthorizationResult,
        McpPlan,
        McpPlanAuthorizationResult,
    )

from ._native import (
    ApprovalPolicyReference,
    AuthorityDiff,
    GrantAuthority,
    NativeDelegationExpandedError,
    Principal,
    PrincipalDescriptor,
    SignedObject,
    TrustedContext,
    approval_policy_reference,
    bind_delegated_authority,
    plan_child_fields,
    prepare_signing_transaction,
    validate_root_authority,
    validate_trusted_authority,
)

SignerLifecycle = Literal["durable", "ephemeral"]
SigningObjectKind = Literal["grant", "action", "principal-status", "grant-status"]
ApprovalMode = Literal[
    "grant-only", "risk-based", "every-action", "plan-once", "custom"
]
ApprovalDecision = Literal["approved", "rejected"]
ProviderFailureKind = Literal[
    "unavailable", "rejected", "cancelled", "timeout", "unsupported"
]

MAX_IDENTIFIER_BYTES = 128
MAX_DISPLAY_FIELDS = 32
MAX_DISPLAY_FIELD_BYTES = 4 * 1024
MAX_DISPLAY_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 512
MAX_EVIDENCE = 32
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_COLLECTION = 256
MAX_U64 = (1 << 64) - 1


class AuthsError(Exception):
    """Base class for safe public SDK failures."""


class AuthsWorkflowError(AuthsError):
    """Closed workflow failure with a stable local code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ProviderOperationError(AuthsError):
    """Sanitized failure raised by an application provider adapter."""

    def __init__(self, kind: ProviderFailureKind) -> None:
        if kind not in (
            "unavailable",
            "rejected",
            "cancelled",
            "timeout",
            "unsupported",
        ):
            raise ValueError("unsupported provider failure kind")
        super().__init__("external provider operation failed")
        self.kind: ProviderFailureKind = kind


@dataclass(frozen=True)
class ReviewField:
    label: str
    value: str

    def __post_init__(self) -> None:
        _bounded_display_text(self.label, "review label")
        _bounded_display_text(self.value, "review value")


@dataclass(frozen=True)
class ControlEvidence:
    evidence_type: str
    media_type: str
    bytes: bytes

    def __post_init__(self) -> None:
        _bounded_identifier(self.evidence_type, "evidence type")
        _bounded_identifier(self.media_type, "evidence media type")
        object.__setattr__(self, "bytes", bytes(self.bytes))
        if not self.bytes or len(self.bytes) > MAX_EVIDENCE_BYTES:
            raise ValueError("invalid control evidence bytes")


@dataclass(frozen=True)
class SigningRequest:
    request_id: str
    object_kind: SigningObjectKind
    object_id: bytes
    principal: PrincipalDescriptor
    transaction_digest: bytes
    signing_preimage: bytes
    expires_at: int
    display: Tuple[ReviewField, ...]


@dataclass(frozen=True)
class SigningResponse:
    request_id: str
    principal: PrincipalDescriptor
    transaction_digest: bytes
    signature: bytes
    evidence: Tuple[ControlEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "transaction_digest", bytes(self.transaction_digest))
        object.__setattr__(self, "signature", bytes(self.signature))
        object.__setattr__(self, "evidence", tuple(self.evidence))


@runtime_checkable
class Signer(Protocol):
    kind: str
    lifecycle: SignerLifecycle

    async def public_identity(self) -> PrincipalDescriptor: ...

    async def sign(self, request: SigningRequest) -> SigningResponse: ...

    async def aclose(self) -> None: ...


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    object_kind: SigningObjectKind
    transaction_digest: bytes
    policy: ApprovalPolicyReference
    expires_at: int
    display: Tuple[ReviewField, ...]


@dataclass(frozen=True)
class ApprovalResponse:
    request_id: str
    transaction_digest: bytes
    policy: ApprovalPolicyReference
    decision: ApprovalDecision

    def __post_init__(self) -> None:
        object.__setattr__(self, "transaction_digest", bytes(self.transaction_digest))


@runtime_checkable
class ApprovalProvider(Protocol):
    async def approve(self, request: ApprovalRequest) -> ApprovalResponse: ...


@dataclass(frozen=True)
class ApprovalPolicy:
    reference: ApprovalPolicyReference
    mode: ApprovalMode
    max_uses: int
    expires_in_seconds: int
    requirements: Tuple[str, ...]


@dataclass(frozen=True)
class ApprovalConfiguration:
    policy: ApprovalPolicy
    provider: ApprovalProvider


class Approval:
    """Typed builders for the four supported approval modes."""

    @staticmethod
    def grant_only(
        policy_id: str,
        provider: ApprovalProvider,
        *,
        evaluator_version: str = "1",
        max_uses: int = 1,
        expires_in_seconds: int = 300,
        requirements: Sequence[str] = (),
    ) -> ApprovalConfiguration:
        return _approval(
            policy_id,
            provider,
            "grant-only",
            evaluator_version,
            max_uses,
            expires_in_seconds,
            requirements,
        )

    @staticmethod
    def risk_based(
        policy_id: str,
        provider: ApprovalProvider,
        *,
        evaluator_version: str = "1",
        max_uses: int = 1,
        expires_in_seconds: int = 300,
        requirements: Sequence[str] = (),
    ) -> ApprovalConfiguration:
        return _approval(
            policy_id,
            provider,
            "risk-based",
            evaluator_version,
            max_uses,
            expires_in_seconds,
            requirements,
        )

    @staticmethod
    def every_action(
        policy_id: str,
        provider: ApprovalProvider,
        *,
        evaluator_version: str = "1",
        max_uses: int = 1,
        expires_in_seconds: int = 300,
        requirements: Sequence[str] = (),
    ) -> ApprovalConfiguration:
        return _approval(
            policy_id,
            provider,
            "every-action",
            evaluator_version,
            max_uses,
            expires_in_seconds,
            requirements,
        )

    @staticmethod
    def plan_once(
        policy_id: str,
        provider: ApprovalProvider,
        *,
        evaluator_version: str = "1",
        max_uses: int,
        expires_in_seconds: int = 300,
        requirements: Sequence[str] = (),
    ) -> ApprovalConfiguration:
        return _approval(
            policy_id,
            provider,
            "plan-once",
            evaluator_version,
            max_uses,
            expires_in_seconds,
            requirements,
        )

    @staticmethod
    def custom(
        policy_id: str,
        provider: ApprovalProvider,
        *,
        evaluator_version: str,
        max_uses: int,
        expires_in_seconds: int,
        requirements: Sequence[str],
    ) -> ApprovalConfiguration:
        return _approval(
            policy_id,
            provider,
            "custom",
            evaluator_version,
            max_uses,
            expires_in_seconds,
            requirements,
        )


@dataclass(frozen=True)
class Profile:
    id: str
    version: int

    def __post_init__(self) -> None:
        _bounded_identifier(self.id, "profile")
        _bounded_u16(self.version, "profile version")


@dataclass(frozen=True)
class Permission:
    capability: str
    resource: str

    def __post_init__(self) -> None:
        _bounded_identifier(self.capability, "capability")
        _bounded_identifier(self.resource, "resource")


@dataclass(frozen=True)
class Validity:
    not_before: int
    expires_at: int

    def __post_init__(self) -> None:
        _bounded_u64(self.not_before, "not before")
        _bounded_u64(self.expires_at, "expiry")
        if self.not_before > self.expires_at:
            raise ValueError("validity starts after it expires")


@dataclass(frozen=True)
class InheritAction:
    pass


@dataclass(frozen=True)
class AnyBody:
    pass


@dataclass(frozen=True)
class ExactBody:
    digest: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "digest", _digest(self.digest, "body digest"))


@dataclass(frozen=True)
class AllowedBodies:
    digests: Tuple[bytes, ...]

    def __post_init__(self) -> None:
        values = tuple(_digest(value, "body digest") for value in self.digests)
        if (
            not values
            or len(values) > MAX_COLLECTION
            or len(set(values)) != len(values)
        ):
            raise ValueError("invalid allowed body digests")
        object.__setattr__(self, "digests", values)


DelegatedActionConstraint = Union[InheritAction, AnyBody, ExactBody, AllowedBodies]


@dataclass(frozen=True)
class InheritBudget:
    pass


@dataclass(frozen=True)
class NoBudget:
    pass


@dataclass(frozen=True)
class BudgetCeiling:
    algebra: str
    value: int

    def __post_init__(self) -> None:
        _bounded_identifier(self.algebra, "budget algebra")
        _bounded_u64(self.value, "budget value")


DelegatedBudget = Union[InheritBudget, NoBudget, BudgetCeiling]


@dataclass(frozen=True)
class InheritStatus:
    pass


@dataclass(frozen=True)
class ExpiryOnly:
    pass


@dataclass(frozen=True)
class SnapshotRequired:
    method: str
    max_age: int

    def __post_init__(self) -> None:
        _bounded_identifier(self.method, "status method")
        _bounded_u64(self.max_age, "status maximum age")


DelegatedStatus = Union[InheritStatus, ExpiryOnly, SnapshotRequired]


@dataclass(frozen=True)
class DelegatedAuthority:
    permissions: Tuple[Permission, ...]
    validity: Validity
    audiences: Tuple[str, ...]
    remaining_depth: int
    action_constraint: DelegatedActionConstraint = InheritAction()
    budget: DelegatedBudget = InheritBudget()
    status: DelegatedStatus = InheritStatus()
    assurance_floor: Optional[str] = None

    def __post_init__(self) -> None:
        permissions = tuple(self.permissions)
        audiences = tuple(self.audiences)
        if (
            not permissions
            or len(permissions) > MAX_COLLECTION
            or not audiences
            or len(audiences) > MAX_COLLECTION
        ):
            raise ValueError("delegated authority collections are invalid")
        if not all(type(value) is Permission for value in permissions):
            raise TypeError("permissions must contain Permission values")
        for audience in audiences:
            _bounded_identifier(audience, "audience")
        _bounded_u16(self.remaining_depth, "remaining delegation depth")
        if self.assurance_floor is not None:
            _bounded_identifier(self.assurance_floor, "assurance floor")
        if type(self.action_constraint) not in (
            InheritAction,
            AnyBody,
            ExactBody,
            AllowedBodies,
        ):
            raise TypeError("unsupported action constraint")
        if type(self.budget) not in (InheritBudget, NoBudget, BudgetCeiling):
            raise TypeError("unsupported delegated budget")
        if type(self.status) not in (InheritStatus, ExpiryOnly, SnapshotRequired):
            raise TypeError("unsupported delegated status")
        object.__setattr__(self, "permissions", permissions)
        object.__setattr__(self, "audiences", audiences)


@dataclass(frozen=True)
class SignedGrantLoadRequest:
    source_id: str
    authority_id: str
    subject: Principal
    profile: Profile


@dataclass(frozen=True)
class SignedGrantMaterial:
    signed_grant: SignedObject
    evidence: Tuple[ControlEvidence, ...] = ()

    def __post_init__(self) -> None:
        if type(self.signed_grant) is not SignedObject:
            raise TypeError("signed grant material requires a native signed object")
        object.__setattr__(self, "evidence", _evidence(self.evidence))


@runtime_checkable
class SignedGrantProvider(Protocol):
    async def load_signed_grant(
        self, request: SignedGrantLoadRequest
    ) -> SignedGrantMaterial: ...


@dataclass(frozen=True)
class SignedGrantSource:
    source_id: str
    provider: SignedGrantProvider

    def __post_init__(self) -> None:
        _bounded_identifier(self.source_id, "signed grant source")
        if not callable(getattr(self.provider, "load_signed_grant", None)):
            raise TypeError("signed grant provider is invalid")


SignedGrantInput = Union[SignedObject, SignedGrantMaterial, SignedGrantSource]


@dataclass(frozen=True)
class TrustedAuthority:
    authority_id: str
    root_principal: Principal
    context: TrustedContext
    required_approval: ApprovalPolicyReference

    def __post_init__(self) -> None:
        _bounded_identifier(self.authority_id, "trusted authority")
        if type(self.root_principal) is not Principal:
            raise TypeError("trusted authority requires a native principal")
        if type(self.context) is not TrustedContext:
            raise TypeError("trusted authority requires a native trusted context")
        if type(self.required_approval) is not ApprovalPolicyReference:
            raise TypeError("trusted authority requires a native approval policy")


@dataclass(frozen=True)
class TrustedAuthoritySnapshot:
    authority_id: str
    root_principal: Principal
    verifier_configuration: bytes
    required_approval: ApprovalPolicyReference


@dataclass(frozen=True)
class AgentIdentity:
    principal: PrincipalDescriptor
    signer_kind: str
    signer_lifecycle: SignerLifecycle


@dataclass(frozen=True)
class ActionConstraintSummary:
    kind: Literal["any-body", "exact-body", "allowed-bodies"]
    digest_count: int


@dataclass(frozen=True)
class BudgetSummary:
    algebra: str
    value: int


@dataclass(frozen=True)
class StatusSummary:
    policy: Literal["expiry-only", "snapshot-required"]
    method: Optional[str]
    max_age: Optional[int]


@dataclass(frozen=True)
class SignatureSummary:
    principal_method: str
    verification_method: str
    suite: str


@dataclass(frozen=True)
class AuthorityExplanation:
    stage: Literal["attach"]
    code: Literal[
        "root-authority-structurally-bound",
        "delegated-authority-structurally-bound",
    ]
    verification: Literal["pending-authorization"]
    message: str


@dataclass(frozen=True)
class EffectiveAuthoritySummary:
    grant_id: bytes
    issuer: Principal
    subject: Principal
    profile: Profile
    permissions: Tuple[Permission, ...]
    validity: Validity
    audiences: Tuple[str, ...]
    action_constraint: ActionConstraintSummary
    budget: Optional[BudgetSummary]
    remaining_depth: int
    status: StatusSummary
    assurance_floor: str
    critical_extensions: Tuple[str, ...]
    signature: SignatureSummary
    explanation: AuthorityExplanation


@dataclass(frozen=True)
class DelegationReview:
    diff: AuthorityDiff
    warnings: Tuple[str, ...]


@dataclass(frozen=True)
class _SignedTransaction:
    signed_object: SignedObject
    transaction_digest: bytes
    evidence: Tuple[ControlEvidence, ...]


class _SigningCoordinator:
    def __init__(self, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        self._clock = clock
        self._consumed = False

    async def execute(
        self,
        *,
        unsigned: Any,
        principal: PrincipalDescriptor,
        signer: Signer,
        approval: ApprovalConfiguration,
        required_approval: ApprovalPolicyReference,
        expires_at: int,
        display: Sequence[ReviewField],
    ) -> _SignedTransaction:
        if self._consumed:
            raise AuthsWorkflowError(
                "transaction-consumed",
                "signing transaction has already reached a terminal state",
            )
        self._consumed = True
        _validate_signer(signer)
        _validate_approval(approval)
        _bounded_u64(expires_at, "transaction expiry")
        fields = _display(display)
        if not required_approval.matches(approval.policy.reference):
            raise AuthsWorkflowError(
                "approval-policy-mismatch",
                "executed approval policy does not match the trusted authority",
            )
        if self._clock() > expires_at:
            raise AuthsWorkflowError(
                "transaction-expired", "signing transaction expired before provider use"
            )
        try:
            transaction = prepare_signing_transaction(
                unsigned,
                principal,
                approval.policy.reference,
                expires_at,
            )
        except (TypeError, ValueError):
            raise AuthsWorkflowError(
                "invalid-provider", "native authoring rejected the signing transaction"
            ) from None
        try:
            approval_response = await _call_approval(
                approval.provider,
                ApprovalRequest(
                    request_id=transaction.request_id,
                    object_kind=cast(SigningObjectKind, transaction.object_kind),
                    transaction_digest=transaction.transaction_digest,
                    policy=transaction.policy,
                    expires_at=transaction.expires_at,
                    display=fields,
                ),
            )
            if type(approval_response) is not ApprovalResponse:
                raise AuthsWorkflowError(
                    "approval-response-mismatch",
                    "approval response is not bound to the exact transaction",
                )
            try:
                approved = transaction.accept_approval(
                    approval_response.request_id,
                    approval_response.transaction_digest,
                    approval_response.policy,
                    approval_response.decision,
                    self._clock(),
                )
            except RuntimeError as error:
                raise _transaction_runtime_error(error) from None
            except (TypeError, ValueError):
                raise AuthsWorkflowError(
                    "approval-response-mismatch",
                    "approval response is not bound to the exact transaction",
                ) from None
            if not approved:
                raise AuthsWorkflowError(
                    "approval-rejected",
                    "approval provider rejected the signing transaction",
                )
            signing_response = await _call_signer(
                signer,
                SigningRequest(
                    request_id=transaction.request_id,
                    object_kind=cast(SigningObjectKind, transaction.object_kind),
                    object_id=transaction.object_id,
                    principal=transaction.principal,
                    transaction_digest=transaction.transaction_digest,
                    signing_preimage=transaction.signing_preimage,
                    expires_at=transaction.expires_at,
                    display=fields,
                ),
            )
            if type(signing_response) is not SigningResponse:
                raise AuthsWorkflowError(
                    "signer-response-mismatch",
                    "signer response is not bound to the exact transaction",
                )
            signature = bytes(signing_response.signature)
            if not signature or len(signature) > MAX_SIGNATURE_BYTES:
                raise AuthsWorkflowError(
                    "signer-response-mismatch",
                    "signer returned an invalid signature length",
                )
            evidence = _evidence(signing_response.evidence)
            transaction_digest = transaction.transaction_digest
            try:
                signed = transaction.complete_response(
                    signing_response.request_id,
                    signing_response.principal,
                    signing_response.transaction_digest,
                    signature,
                    self._clock(),
                )
            except RuntimeError as error:
                raise _transaction_runtime_error(error) from None
            except (TypeError, ValueError):
                raise AuthsWorkflowError(
                    "signer-response-mismatch",
                    "signer response is not bound to the exact transaction",
                ) from None
            return _SignedTransaction(signed, transaction_digest, evidence)
        finally:
            transaction.discard()


class AuthsClient:
    """Owns one root signer and its attached agent graph."""

    def __init__(self, *, signer: Signer, trusted_authority: TrustedAuthority) -> None:
        _validate_signer(signer)
        if type(trusted_authority) is not TrustedAuthority:
            raise TypeError("trusted_authority must be a TrustedAuthority")
        self._signer = signer
        self._configured_authority = trusted_authority
        self._identity: Optional[AgentIdentity] = None
        self._agents: Set[AttachedAgent] = set()
        self._open = False
        self._closed = False

    @property
    def identity(self) -> AgentIdentity:
        self._assert_open()
        if self._identity is None:
            raise AuthsWorkflowError("disposed", "Auths client is not open")
        return self._identity

    @property
    def trusted_authority(self) -> TrustedAuthoritySnapshot:
        self._assert_open()
        authority = self._configured_authority
        return TrustedAuthoritySnapshot(
            authority_id=authority.authority_id,
            root_principal=authority.root_principal,
            verifier_configuration=bytes(authority.context.configuration),
            required_approval=authority.required_approval,
        )

    @property
    def closed(self) -> bool:
        return self._closed

    async def open(self) -> AuthsClient:
        if self._closed:
            raise AuthsWorkflowError("disposed", "Auths client is disposed")
        if self._open:
            return self
        try:
            try:
                validate_trusted_authority(
                    self._configured_authority.context,
                    self._configured_authority.root_principal,
                )
            except (TypeError, ValueError):
                raise AuthsWorkflowError(
                    "invalid-trusted-authority",
                    "trusted authority does not bind the configured root and verifier",
                ) from None
            descriptor = await _call_public_identity(self._signer, "signer")
            self._identity = AgentIdentity(
                principal=descriptor,
                signer_kind=_bounded_identifier(self._signer.kind, "signer kind"),
                signer_lifecycle=_signer_lifecycle(self._signer.lifecycle),
            )
            self._open = True
            return self
        except asyncio.CancelledError:
            await self._close_after_failed_open()
            raise
        except Exception:
            await self._close_after_failed_open()
            raise

    async def attach_agent(
        self,
        *,
        name: str,
        profile: Profile,
        authority: SignedGrantInput,
        approval: ApprovalConfiguration,
    ) -> AttachedAgent:
        self._assert_open()
        name = _agent_name(name)
        if not isinstance(profile, Profile):
            raise TypeError("profile must be a Profile")
        _validate_approval(approval)
        if not self._configured_authority.required_approval.matches(
            approval.policy.reference
        ):
            raise AuthsWorkflowError(
                "approval-policy-mismatch",
                "attach approval policy does not match the trusted authority",
            )
        material = await _load_signed_grant(
            authority,
            SignedGrantLoadRequest(
                source_id=(
                    authority.source_id
                    if type(authority) is SignedGrantSource
                    else "direct"
                ),
                authority_id=self._configured_authority.authority_id,
                subject=self.identity.principal.principal,
                profile=profile,
            ),
        )
        if material.signed_grant.kind != "grant":
            raise AuthsWorkflowError(
                "invalid-authority", "authority input is not a signed grant"
            )
        try:
            bound = validate_root_authority(
                material.signed_grant,
                self._configured_authority.root_principal,
                self.identity.principal,
                profile.id,
                profile.version,
            )
        except (TypeError, ValueError):
            raise AuthsWorkflowError(
                "authority-mismatch",
                "signed grant does not bind the trusted root, agent, and profile",
            ) from None
        agent = AttachedAgent._create(
            client=self,
            name=name,
            identity=self.identity,
            profile=profile,
            authority=bound,
            approval=approval,
            signer=self._signer,
            owns_signer=False,
            grant_chain=(material,),
            delegation=None,
        )
        self._agents.add(agent)
        return agent

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._open = False
        failed = False
        for agent in tuple(self._agents):
            if not await agent._close(suppress_errors=True):
                failed = True
        self._agents.clear()
        if not await _close_signer(self._signer):
            failed = True
        self._identity = None
        if failed:
            raise AuthsWorkflowError(
                "cleanup-failed", "one or more signer providers failed during cleanup"
            )

    async def _close_after_failed_open(self) -> None:
        self._closed = True
        self._open = False
        self._identity = None
        await _close_signer(self._signer)

    def _assert_open(self) -> None:
        if self._closed or not self._open:
            raise AuthsWorkflowError("disposed", "Auths client is not open")

    async def __aenter__(self) -> AuthsClient:
        return await self.open()

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        try:
            await self.aclose()
        except AuthsWorkflowError:
            if exc is None:
                raise


class AttachedAgent:
    """One structurally bound authority and its configured signer."""

    _TOKEN = object()

    def __init__(
        self,
        token: object,
        *,
        client: AuthsClient,
        name: str,
        identity: AgentIdentity,
        profile: Profile,
        authority: GrantAuthority,
        approval: ApprovalConfiguration,
        signer: Signer,
        owns_signer: bool,
        grant_chain: Tuple[SignedGrantMaterial, ...],
        delegation: Optional[DelegationReview],
    ) -> None:
        if token is not self._TOKEN:
            raise TypeError("sealed Auths attached agent")
        self._client = client
        self._name = name
        self._identity = identity
        self._profile = profile
        self._native_authority = authority
        self._authority = _authority_summary(authority)
        self._approval = approval
        self._signer = signer
        self._owns_signer = owns_signer
        self._grant_chain = grant_chain
        self._delegation = delegation
        self._closed = False

    @classmethod
    def _create(
        cls,
        *,
        client: AuthsClient,
        name: str,
        identity: AgentIdentity,
        profile: Profile,
        authority: GrantAuthority,
        approval: ApprovalConfiguration,
        signer: Signer,
        owns_signer: bool,
        grant_chain: Tuple[SignedGrantMaterial, ...],
        delegation: Optional[DelegationReview],
    ) -> AttachedAgent:
        return cls(
            cls._TOKEN,
            client=client,
            name=name,
            identity=identity,
            profile=profile,
            authority=authority,
            approval=approval,
            signer=signer,
            owns_signer=owns_signer,
            grant_chain=grant_chain,
            delegation=delegation,
        )

    @property
    def name(self) -> str:
        self._assert_active()
        return self._name

    @property
    def identity(self) -> AgentIdentity:
        self._assert_active()
        return self._identity

    @property
    def profile(self) -> Profile:
        self._assert_active()
        return self._profile

    @property
    def authority(self) -> EffectiveAuthoritySummary:
        self._assert_active()
        return self._authority

    @property
    def delegation(self) -> Optional[DelegationReview]:
        self._assert_active()
        return self._delegation

    @property
    def closed(self) -> bool:
        return self._closed

    async def delegate(
        self,
        *,
        name: str,
        authority: DelegatedAuthority,
        signer: Signer,
    ) -> AttachedAgent:
        self._assert_active()
        name = _agent_name(name)
        if type(authority) is not DelegatedAuthority:
            raise TypeError("authority must be a DelegatedAuthority")
        _validate_signer(signer)
        child_identity: Optional[AgentIdentity] = None
        transferred = False
        try:
            descriptor = await _call_public_identity(signer, "child signer")
            child_identity = AgentIdentity(
                principal=descriptor,
                signer_kind=_bounded_identifier(signer.kind, "signer kind"),
                signer_lifecycle=_signer_lifecycle(signer.lifecycle),
            )
            action_mode, action_digests = _action_fields(authority.action_constraint)
            budget_mode, budget = _budget_fields(authority.budget)
            status_mode, status = _status_fields(authority.status)
            try:
                plan = plan_child_fields(
                    self._native_authority,
                    descriptor,
                    [
                        (permission.capability, permission.resource)
                        for permission in authority.permissions
                    ],
                    authority.validity.not_before,
                    authority.validity.expires_at,
                    list(authority.audiences),
                    action_mode,
                    list(action_digests),
                    budget_mode,
                    budget,
                    authority.remaining_depth,
                    status_mode,
                    status,
                    authority.assurance_floor,
                )
            except NativeDelegationExpandedError as error:
                dimension = str(error)
                raise AuthsWorkflowError(
                    "delegation-expanded",
                    "native authoring rejected widened child authority: " + dimension,
                ) from None
            except (TypeError, ValueError):
                raise AuthsWorkflowError(
                    "invalid-delegation",
                    "native authoring rejected invalid child authority",
                ) from None
            review = DelegationReview(plan.diff, tuple(plan.warnings))
            expires_at = _transaction_expiry(self._approval.policy.expires_in_seconds)
            signed = await _SigningCoordinator().execute(
                unsigned=plan.unsigned,
                principal=self.identity.principal,
                signer=self._signer,
                approval=self._approval,
                required_approval=self._client._configured_authority.required_approval,
                expires_at=expires_at,
                display=_delegation_display(name, self, child_identity, review),
            )
            try:
                bound = bind_delegated_authority(
                    signed.signed_object,
                    self._native_authority,
                    child_identity.principal,
                    self.identity.principal,
                    self.profile.id,
                    self.profile.version,
                )
            except (TypeError, ValueError):
                raise AuthsWorkflowError(
                    "authority-mismatch",
                    "signed child authority does not match the native plan",
                ) from None
            material = SignedGrantMaterial(signed.signed_object, signed.evidence)
            child = AttachedAgent._create(
                client=self._client,
                name=name,
                identity=child_identity,
                profile=self._profile,
                authority=bound,
                approval=self._approval,
                signer=signer,
                owns_signer=True,
                grant_chain=self._grant_chain + (material,),
                delegation=review,
            )
            self._client._agents.add(child)
            transferred = True
            return child
        except asyncio.CancelledError:
            raise
        finally:
            if not transferred:
                await _close_signer(signer)

    async def authorize(
        self,
        action: McpAction,
        *,
        request: Optional[AuthorizationRequest] = None,
    ) -> McpAuthorizationResult:
        from .mcp import _authorize_mcp

        return await _authorize_mcp(self, action, request)

    async def authorize_plan(
        self,
        plan: McpPlan,
        *,
        approval_provider: Optional[ApprovalProvider] = None,
        requests: Optional[Sequence[AuthorizationRequest]] = None,
    ) -> McpPlanAuthorizationResult:
        from .mcp import _authorize_mcp_plan

        return await _authorize_mcp_plan(self, plan, approval_provider, requests)

    async def aclose(self) -> None:
        if not await self._close(suppress_errors=False):
            raise AuthsWorkflowError(
                "cleanup-failed", "child signer provider cleanup failed"
            )

    async def _close(self, *, suppress_errors: bool) -> bool:
        if self._closed:
            return True
        self._closed = True
        self._client._agents.discard(self)
        successful = True
        if self._owns_signer:
            successful = await _close_signer(self._signer)
        self._grant_chain = ()
        if not successful and not suppress_errors:
            return False
        return successful

    def _assert_active(self) -> None:
        if self._closed:
            raise AuthsWorkflowError("disposed", "attached agent is disposed")
        self._client._assert_open()

    async def __aenter__(self) -> AttachedAgent:
        self._assert_active()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        try:
            await self.aclose()
        except AuthsWorkflowError:
            if exc is None:
                raise


def _approval(
    policy_id: str,
    provider: ApprovalProvider,
    mode: ApprovalMode,
    evaluator_version: str,
    max_uses: int,
    expires_in_seconds: int,
    requirements: Sequence[str],
) -> ApprovalConfiguration:
    if not callable(getattr(provider, "approve", None)):
        raise TypeError("approval provider is invalid")
    reference, values = _approval_commitment(
        policy_id,
        evaluator_version,
        mode,
        max_uses,
        expires_in_seconds,
        requirements,
    )
    return ApprovalConfiguration(
        ApprovalPolicy(reference, mode, max_uses, expires_in_seconds, values),
        provider,
    )


def _approval_commitment(
    policy_id: str,
    evaluator_version: str,
    mode: ApprovalMode,
    max_uses: int,
    expires_in_seconds: int,
    requirements: Sequence[str],
) -> Tuple[ApprovalPolicyReference, Tuple[str, ...]]:
    _bounded_u32(max_uses, "approval maximum uses")
    _bounded_u32(expires_in_seconds, "approval expiry")
    if max_uses == 0 or expires_in_seconds == 0:
        raise ValueError("approval bounds must be positive")
    values = tuple(requirements)
    if len(values) > MAX_COLLECTION or len(set(values)) != len(values):
        raise ValueError("approval requirements are invalid")
    for requirement in values:
        _bounded_identifier(requirement, "approval requirement")
    reference = approval_policy_reference(
        policy_id,
        evaluator_version,
        mode,
        max_uses,
        expires_in_seconds,
        list(values),
    )
    return reference, values


async def _call_public_identity(signer: Signer, label: str) -> PrincipalDescriptor:
    try:
        descriptor = await signer.public_identity()
    except asyncio.CancelledError:
        raise
    except ProviderOperationError as error:
        raise _provider_failure("signer", error.kind) from None
    except TimeoutError:
        raise _provider_failure("signer", "timeout") from None
    except Exception:
        raise AuthsWorkflowError(
            "invalid-principal", label + " returned an invalid principal descriptor"
        ) from None
    if type(descriptor) is not PrincipalDescriptor:
        raise AuthsWorkflowError(
            "invalid-principal", label + " returned an invalid principal descriptor"
        )
    return descriptor


async def _call_approval(
    provider: ApprovalProvider, request: ApprovalRequest
) -> ApprovalResponse:
    try:
        return await provider.approve(request)
    except asyncio.CancelledError:
        raise
    except ProviderOperationError as error:
        raise _provider_failure("approval", error.kind) from None
    except TimeoutError:
        raise _provider_failure("approval", "timeout") from None
    except Exception:
        raise AuthsWorkflowError(
            "approval-failed", "approval provider failed"
        ) from None


async def _call_signer(signer: Signer, request: SigningRequest) -> SigningResponse:
    try:
        return await signer.sign(request)
    except asyncio.CancelledError:
        raise
    except ProviderOperationError as error:
        raise _provider_failure("signer", error.kind) from None
    except TimeoutError:
        raise _provider_failure("signer", "timeout") from None
    except Exception:
        raise AuthsWorkflowError("signer-failed", "signer provider failed") from None


def _provider_failure(
    operation: Literal["approval", "signer"], kind: ProviderFailureKind
) -> AuthsWorkflowError:
    suffix = {
        "unavailable": "failed",
        "rejected": "rejected",
        "cancelled": "cancelled",
        "timeout": "timeout",
        "unsupported": "unsupported",
    }[kind]
    return AuthsWorkflowError(
        operation + "-" + suffix,
        operation + " provider failed",
    )


def _transaction_runtime_error(error: RuntimeError) -> AuthsWorkflowError:
    if "expired" in str(error):
        return AuthsWorkflowError(
            "transaction-expired", "signing transaction expired during provider use"
        )
    return AuthsWorkflowError(
        "transaction-consumed",
        "signing transaction has already reached a terminal state",
    )


async def _load_signed_grant(
    value: SignedGrantInput, request: SignedGrantLoadRequest
) -> SignedGrantMaterial:
    if type(value) is SignedObject:
        return SignedGrantMaterial(value)
    if type(value) is SignedGrantMaterial:
        return value
    if type(value) is not SignedGrantSource:
        raise TypeError(
            "authority must be native signed grant material or a typed source"
        )
    try:
        material = await value.provider.load_signed_grant(request)
    except asyncio.CancelledError:
        raise
    except ProviderOperationError as error:
        raise AuthsWorkflowError(
            "authority-source-" + error.kind,
            "signed grant provider failed",
        ) from None
    except TimeoutError:
        raise AuthsWorkflowError(
            "authority-source-timeout", "signed grant provider timed out"
        ) from None
    except Exception:
        raise AuthsWorkflowError(
            "authority-source-failed", "signed grant provider failed"
        ) from None
    if type(material) is not SignedGrantMaterial:
        raise AuthsWorkflowError(
            "invalid-authority", "signed grant provider returned an invalid value"
        )
    return material


async def _close_signer(signer: Signer) -> bool:
    try:
        operation = signer.aclose()
        await asyncio.shield(operation)
        return True
    except asyncio.CancelledError:
        raise
    except Exception:
        return False


def _validate_signer(signer: Signer) -> None:
    if (
        not callable(getattr(signer, "public_identity", None))
        or not callable(getattr(signer, "sign", None))
        or not callable(getattr(signer, "aclose", None))
    ):
        raise TypeError("signer does not implement the required protocol")
    _bounded_identifier(getattr(signer, "kind", None), "signer kind")
    _signer_lifecycle(getattr(signer, "lifecycle", None))


def _validate_approval(approval: ApprovalConfiguration) -> None:
    if type(approval) is not ApprovalConfiguration:
        raise TypeError("approval must be an ApprovalConfiguration")
    if type(approval.policy) is not ApprovalPolicy:
        raise TypeError("approval policy is invalid")
    if type(approval.policy.reference) is not ApprovalPolicyReference:
        raise TypeError("approval policy reference is invalid")
    if approval.policy.mode not in (
        "grant-only",
        "risk-based",
        "every-action",
        "plan-once",
        "custom",
    ):
        raise TypeError("approval mode is invalid")
    committed, _ = _approval_commitment(
        approval.policy.reference.policy_id,
        approval.policy.reference.evaluator_version,
        approval.policy.mode,
        approval.policy.max_uses,
        approval.policy.expires_in_seconds,
        approval.policy.requirements,
    )
    if not approval.policy.reference.matches(committed):
        raise ValueError("approval policy fields do not match their native commitment")
    if not callable(getattr(approval.provider, "approve", None)):
        raise TypeError("approval provider is invalid")


def _signer_lifecycle(value: object) -> SignerLifecycle:
    if value == "durable":
        return "durable"
    if value == "ephemeral":
        return "ephemeral"
    raise ValueError("invalid signer lifecycle")


def _action_fields(
    value: DelegatedActionConstraint,
) -> Tuple[str, Tuple[bytes, ...]]:
    if type(value) is InheritAction:
        return "inherit", ()
    if type(value) is AnyBody:
        return "any-body", ()
    if type(value) is ExactBody:
        return "exact-body", (value.digest,)
    if type(value) is AllowedBodies:
        return "allowed-bodies", value.digests
    raise TypeError("unsupported action constraint")


def _budget_fields(value: DelegatedBudget) -> Tuple[str, Optional[Tuple[str, int]]]:
    if type(value) is InheritBudget:
        return "inherit", None
    if type(value) is NoBudget:
        return "none", None
    if type(value) is BudgetCeiling:
        return "ceiling", (value.algebra, value.value)
    raise TypeError("unsupported delegated budget")


def _status_fields(value: DelegatedStatus) -> Tuple[str, Optional[Tuple[str, int]]]:
    if type(value) is InheritStatus:
        return "inherit", None
    if type(value) is ExpiryOnly:
        return "expiry-only", None
    if type(value) is SnapshotRequired:
        return "snapshot-required", (value.method, value.max_age)
    raise TypeError("unsupported delegated status")


def _authority_summary(value: GrantAuthority) -> EffectiveAuthoritySummary:
    profile_id, profile_version = value.profile
    action_kind, digest_count = value.action_constraint
    status_policy, status_method, status_max_age = value.status
    signature_method, verification_method, suite = value.signature
    if action_kind not in ("any-body", "exact-body", "allowed-bodies"):
        raise AuthsWorkflowError(
            "invalid-authority", "native authority returned an invalid action summary"
        )
    if status_policy not in ("expiry-only", "snapshot-required"):
        raise AuthsWorkflowError(
            "invalid-authority", "native authority returned an invalid status summary"
        )
    budget = value.budget
    binding = value.binding
    root = binding == "root"
    return EffectiveAuthoritySummary(
        grant_id=bytes(value.grant_id),
        issuer=value.issuer,
        subject=value.subject,
        profile=Profile(profile_id, profile_version),
        permissions=tuple(Permission(*permission) for permission in value.permissions),
        validity=Validity(*value.validity),
        audiences=tuple(value.audiences),
        action_constraint=ActionConstraintSummary(
            cast(
                Literal["any-body", "exact-body", "allowed-bodies"],
                action_kind,
            ),
            digest_count,
        ),
        budget=None if budget is None else BudgetSummary(*budget),
        remaining_depth=value.remaining_depth,
        status=StatusSummary(
            cast(Literal["expiry-only", "snapshot-required"], status_policy),
            status_method,
            status_max_age,
        ),
        assurance_floor=value.assurance_floor,
        critical_extensions=tuple(value.critical_extensions),
        signature=SignatureSummary(
            signature_method,
            verification_method,
            suite,
        ),
        explanation=AuthorityExplanation(
            stage="attach",
            code=(
                "root-authority-structurally-bound"
                if root
                else "delegated-authority-structurally-bound"
            ),
            verification="pending-authorization",
            message=(
                "Canonical root authority is bound; cryptographic and live checks remain pending authorization."
                if root
                else "Canonical delegated authority is bound; cryptographic and live checks remain pending authorization."
            ),
        ),
    )


def _delegation_display(
    name: str,
    parent: AttachedAgent,
    child: AgentIdentity,
    review: DelegationReview,
) -> Tuple[ReviewField, ...]:
    return _display(
        (
            ReviewField("Agent", name),
            ReviewField("Issuer", parent.identity.principal.principal.value),
            ReviewField("Subject", child.principal.principal.value),
            ReviewField(
                "Profile", parent.profile.id + "/" + str(parent.profile.version)
            ),
            ReviewField(
                "Authority",
                str(review.diff.removed_permissions)
                + " permissions removed; "
                + str(len(review.warnings))
                + " warnings",
            ),
        )
    )


def _display(values: Sequence[ReviewField]) -> Tuple[ReviewField, ...]:
    fields = tuple(values)
    if len(fields) > MAX_DISPLAY_FIELDS or not all(
        type(value) is ReviewField for value in fields
    ):
        raise ValueError("invalid review display")
    if (
        sum(len(value.label.encode()) + len(value.value.encode()) for value in fields)
        > MAX_DISPLAY_BYTES
    ):
        raise ValueError("review display exceeds its byte limit")
    return fields


def _evidence(values: Sequence[ControlEvidence]) -> Tuple[ControlEvidence, ...]:
    evidence = tuple(values)
    if len(evidence) > MAX_EVIDENCE or not all(
        type(value) is ControlEvidence for value in evidence
    ):
        raise ValueError("invalid control evidence")
    if sum(len(value.bytes) for value in evidence) > MAX_EVIDENCE_BYTES:
        raise ValueError("control evidence exceeds its aggregate byte limit")
    return evidence


def _transaction_expiry(expires_in_seconds: int) -> int:
    now = int(time.time())
    expiry = now + expires_in_seconds
    _bounded_u64(expiry, "transaction expiry")
    return expiry


def _agent_name(value: str) -> str:
    return _bounded_identifier(value, "agent name")


def _bounded_identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode()) > MAX_IDENTIFIER_BYTES
        or any(character.isspace() and character not in (" ",) for character in value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("invalid " + label)
    return value


def _bounded_display_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode()) > MAX_DISPLAY_FIELD_BYTES
        or any(
            ord(character) < 32 and character not in ("\n", "\t") for character in value
        )
    ):
        raise ValueError("invalid " + label)
    return value


def _digest(value: bytes, label: str) -> bytes:
    result = bytes(value)
    if len(result) != 32:
        raise ValueError(label + " must contain 32 bytes")
    return result


def _bounded_u16(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 0xFFFF
    ):
        raise ValueError("invalid " + label)
    return value


def _bounded_u32(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 0xFFFFFFFF
    ):
        raise ValueError("invalid " + label)
    return value


def _bounded_u64(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_U64
    ):
        raise ValueError("invalid " + label)
    return value


__all__ = [
    "ActionConstraintSummary",
    "AgentIdentity",
    "AllowedBodies",
    "AnyBody",
    "Approval",
    "ApprovalConfiguration",
    "ApprovalDecision",
    "ApprovalMode",
    "ApprovalPolicy",
    "ApprovalPolicyReference",
    "ApprovalProvider",
    "ApprovalRequest",
    "ApprovalResponse",
    "AttachedAgent",
    "AuthorityExplanation",
    "AuthsClient",
    "AuthsError",
    "AuthsWorkflowError",
    "BudgetCeiling",
    "BudgetSummary",
    "ControlEvidence",
    "DelegatedActionConstraint",
    "DelegatedAuthority",
    "DelegatedBudget",
    "DelegatedStatus",
    "DelegationReview",
    "EffectiveAuthoritySummary",
    "ExactBody",
    "ExpiryOnly",
    "InheritAction",
    "InheritBudget",
    "InheritStatus",
    "NoBudget",
    "Permission",
    "Principal",
    "PrincipalDescriptor",
    "Profile",
    "ProviderFailureKind",
    "ProviderOperationError",
    "ReviewField",
    "SignatureSummary",
    "SignedGrantInput",
    "SignedGrantLoadRequest",
    "SignedGrantMaterial",
    "SignedGrantProvider",
    "SignedGrantSource",
    "Signer",
    "SignerLifecycle",
    "SigningObjectKind",
    "SigningRequest",
    "SigningResponse",
    "SnapshotRequired",
    "StatusSummary",
    "TrustedAuthority",
    "TrustedAuthoritySnapshot",
    "Validity",
]
