from typing import List, Literal, Optional, Tuple

Permission = Tuple[str, str]
Budget = Tuple[str, int]
StatusPolicy = Tuple[str, int]
CriticalExtension = Tuple[str, bytes]

class Principal:
    def __init__(self, value: str) -> None: ...
    @property
    def value(self) -> str: ...

class PrincipalDescriptor:
    def __init__(
        self,
        principal: Principal,
        principal_method: str,
        verification_method: str,
        suite: str,
    ) -> None: ...
    @property
    def principal(self) -> Principal: ...
    @property
    def principal_method(self) -> str: ...
    @property
    def verification_method(self) -> str: ...
    @property
    def suite(self) -> str: ...
    def matches(self, other: PrincipalDescriptor) -> bool: ...

class ApprovalPolicyReference:
    def __init__(
        self,
        policy_id: str,
        evaluator_version: str,
        configuration_digest: bytes,
    ) -> None: ...
    @property
    def policy_id(self) -> str: ...
    @property
    def evaluator_version(self) -> str: ...
    @property
    def configuration_digest(self) -> bytes: ...
    def matches(self, other: ApprovalPolicyReference) -> bool: ...

class UnsignedObject:
    @property
    def kind(self) -> str: ...

class SignedObject:
    @property
    def kind(self) -> str: ...

class GrantRequest:
    def __init__(
        self,
        subject: Principal,
        profile_id: str,
        profile_version: int,
        permissions: List[Permission],
        not_before: int,
        expires_at: int,
        audiences: List[str],
        body_digests: Optional[List[bytes]],
        budget: Optional[Budget],
        remaining_depth: int,
        status: Optional[StatusPolicy],
        assurance_floor: str,
        extensions: List[CriticalExtension],
    ) -> None: ...

class AuthorityDiff:
    @property
    def removed_permissions(self) -> int: ...
    @property
    def removed_audiences(self) -> int: ...
    @property
    def validity_shortened(self) -> bool: ...
    @property
    def action_narrowed(self) -> bool: ...
    @property
    def budget_narrowed(self) -> bool: ...
    @property
    def status_narrowed(self) -> bool: ...
    @property
    def delegation_depth(self) -> Tuple[int, int]: ...

class GrantPlan:
    @property
    def diff(self) -> AuthorityDiff: ...
    @property
    def warnings(self) -> List[str]: ...
    @property
    def unsigned(self) -> UnsignedObject: ...

class GrantAuthority:
    @property
    def binding(self) -> Literal["root", "delegated"]: ...
    @property
    def grant_id(self) -> bytes: ...
    @property
    def issuer(self) -> Principal: ...
    @property
    def subject(self) -> Principal: ...
    @property
    def profile(self) -> Tuple[str, int]: ...
    @property
    def permissions(self) -> List[Permission]: ...
    @property
    def validity(self) -> Tuple[int, int]: ...
    @property
    def audiences(self) -> List[str]: ...
    @property
    def action_constraint(self) -> Tuple[str, int]: ...
    @property
    def budget(self) -> Optional[Budget]: ...
    @property
    def remaining_depth(self) -> int: ...
    @property
    def parent_id(self) -> Optional[bytes]: ...
    @property
    def status(self) -> Tuple[str, Optional[str], Optional[int]]: ...
    @property
    def assurance_floor(self) -> str: ...
    @property
    def critical_extensions(self) -> List[str]: ...
    @property
    def signature(self) -> Tuple[str, str, str]: ...

class SigningRequest:
    @property
    def object_kind(self) -> str: ...
    @property
    def request_id(self) -> str: ...
    @property
    def object_id(self) -> bytes: ...
    @property
    def signing_preimage(self) -> bytes: ...
    @property
    def transaction_digest(self) -> bytes: ...
    def complete(self, signature: bytes) -> SignedObject: ...

class SigningTransaction:
    @property
    def object_kind(self) -> str: ...
    @property
    def request_id(self) -> str: ...
    @property
    def object_id(self) -> bytes: ...
    @property
    def signing_preimage(self) -> bytes: ...
    @property
    def transaction_digest(self) -> bytes: ...
    @property
    def principal(self) -> PrincipalDescriptor: ...
    @property
    def policy(self) -> ApprovalPolicyReference: ...
    @property
    def expires_at(self) -> int: ...
    @property
    def phase(
        self,
    ) -> Literal["awaiting-approval", "awaiting-signature", "terminal"]: ...
    def accept_approval(
        self,
        request_id: str,
        transaction_digest: bytes,
        policy: ApprovalPolicyReference,
        decision: str,
        now: int,
    ) -> bool: ...
    def complete_response(
        self,
        request_id: str,
        principal: PrincipalDescriptor,
        transaction_digest: bytes,
        signature: bytes,
        now: int,
    ) -> SignedObject: ...
    def discard(self) -> None: ...

class NativeDelegationExpandedError(ValueError): ...

class AuthorizationPlan:
    @property
    def plan_id(self) -> bytes: ...
    @property
    def shape(self) -> Tuple[int, int]: ...

class AuthorizationPlanBuilder:
    def __init__(self) -> None: ...
    def proof(self, reference: bytes) -> AuthorizationPlan: ...
    def all_of(self, members: List[AuthorizationPlan]) -> AuthorizationPlan: ...
    def any_of(self, members: List[AuthorizationPlan]) -> AuthorizationPlan: ...
    def threshold(
        self, required: int, members: List[AuthorizationPlan]
    ) -> AuthorizationPlan: ...

class McpAction:
    @property
    def unsigned(self) -> UnsignedObject: ...
    @property
    def audience(self) -> str: ...
    @property
    def resource(self) -> str: ...
    @property
    def display_digest_hex(self) -> str: ...
    @property
    def review_title(self) -> str: ...
    @property
    def review_fields(self) -> List[Tuple[str, str]]: ...

class McpCall:
    @property
    def service(self) -> str: ...
    @property
    def name(self) -> str: ...

class McpCommand:
    @property
    def service(self) -> str: ...
    @property
    def name(self) -> str: ...

class McpGatewayCall:
    @property
    def service(self) -> str: ...
    @property
    def name(self) -> str: ...
    @property
    def arguments_json(self) -> bytes: ...

class AssurancePolicy:
    def __init__(
        self,
        identifier: str,
        requirements: List[Tuple[str, str, str, Optional[int]]],
    ) -> None: ...

class TrustAnchor:
    def __init__(
        self,
        identifier: str,
        principal: Principal,
        accepted_methods: List[str],
        profiles: List[Tuple[str, int]],
        permissions: List[Permission],
        resource_namespaces: List[str],
        audiences: List[str],
        not_before: int,
        expires_at: int,
        budget: Optional[Budget],
        max_delegation_depth: int,
        assurance_policy: str,
        status: Optional[StatusPolicy],
    ) -> None: ...

class StatusSnapshot:
    @property
    def kind(self) -> str: ...

class TrustedContext:
    @property
    def configuration(self) -> bytes: ...
    def bind_request(
        self, audience: str, challenge: bytes, evaluation_time: int
    ) -> TrustedContext: ...

class VerifiedAction:
    pass

class NativeVerificationResult:
    @property
    def kind(self) -> Literal["authorized", "denied", "indeterminate"]: ...
    @property
    def code(self) -> str: ...
    @property
    def stage(
        self,
    ) -> Literal["decode", "resolve", "principal-control", "authority", "complete"]: ...
    @property
    def metrics(self) -> Tuple[int, int, int, int, int, int, int]: ...
    @property
    def required_configuration(self) -> Optional[bytes]: ...
    @property
    def local_configuration(self) -> bytes: ...
    @property
    def result_cbor(self) -> bytes: ...
    @property
    def action(self) -> Optional[VerifiedAction]: ...

def native_abi_version_v1() -> int: ...
def approval_policy_reference(
    policy_id: str,
    evaluator_version: str,
    mode: str,
    max_uses: int,
    expires_in_seconds: int,
    requirements: List[str],
) -> ApprovalPolicyReference: ...
def validate_trusted_authority(context: TrustedContext, root: Principal) -> None: ...
def validate_root_authority(
    signed: SignedObject,
    root: Principal,
    subject: PrincipalDescriptor,
    profile_id: str,
    profile_version: int,
) -> GrantAuthority: ...
def bind_delegated_authority(
    signed: SignedObject,
    parent: GrantAuthority,
    subject: PrincipalDescriptor,
    issuer: PrincipalDescriptor,
    profile_id: str,
    profile_version: int,
) -> GrantAuthority: ...
def plan_child_fields(
    parent: GrantAuthority,
    subject: PrincipalDescriptor,
    permissions: List[Permission],
    not_before: int,
    expires_at: int,
    audiences: List[str],
    action_mode: str,
    action_digests: List[bytes],
    budget_mode: str,
    budget: Optional[Budget],
    remaining_depth: int,
    status_mode: str,
    status: Optional[StatusPolicy],
    assurance_floor: Optional[str],
) -> GrantPlan: ...
def prepare_signing_transaction(
    unsigned: UnsignedObject,
    principal: PrincipalDescriptor,
    policy: ApprovalPolicyReference,
    expires_at: int,
) -> SigningTransaction: ...
def root_grant(issuer: Principal, request: GrantRequest) -> UnsignedObject: ...
def plan_child(parent: SignedObject, request: GrantRequest) -> GrantPlan: ...
def plan_child_statement(
    parent: UnsignedObject, request: GrantRequest
) -> GrantPlan: ...
def grant_request_from_statement(statement: UnsignedObject) -> GrantRequest: ...
def principal_status_statement(
    method: str,
    principal: Principal,
    purpose: str,
    state: str,
    sequence: int,
    observed_at: int,
    valid_until: int,
    issuer: Principal,
    extensions: List[CriticalExtension],
) -> UnsignedObject: ...
def grant_status_statement(
    method: str,
    grant_id: bytes,
    state: str,
    sequence: int,
    observed_at: int,
    valid_until: int,
    issuer: Principal,
    extensions: List[CriticalExtension],
) -> UnsignedObject: ...
def prepare_signing(
    unsigned: UnsignedObject,
    principal_method: str,
    verification_method: str,
    suite: str,
) -> SigningRequest: ...
def prepare_mcp_action(
    service: str,
    name: str,
    arguments_json: bytes,
    actor: Principal,
    terminal_grant: SignedObject,
    challenge: bytes,
    evaluation_time: int,
) -> McpAction: ...
def validate_mcp_service(service: str) -> None: ...
def mcp_call(service: str, name: str, arguments_json: bytes) -> McpCall: ...
def prepare_mcp_call_action(
    call: McpCall,
    actor: Principal,
    terminal_grant: SignedObject,
    challenge: bytes,
    evaluation_time: int,
) -> McpAction: ...
def authorize_mcp(
    prepared: McpAction,
    signed_action: SignedObject,
    grants: List[SignedObject],
    grant_evidence: List[List[Tuple[str, str, bytes]]],
    action_evidence: List[Tuple[str, str, bytes]],
    context: TrustedContext,
) -> Tuple[NativeVerificationResult, Optional[McpCommand]]: ...
def consume_mcp_command(
    command: McpCommand, expected_service: str
) -> McpGatewayCall: ...
def status_snapshot(
    kind: str,
    identifier: bytes,
    observed_at: int,
    valid_until: int,
    statements: List[SignedObject],
    checkpoints: List[bytes],
    trust: List[Tuple[str, str, int]],
) -> StatusSnapshot: ...
def compile_trusted_context(
    configuration: bytes,
    expected_plan: Optional[AuthorizationPlan],
    minimum_authorized_branches: int,
    minimum_distinct_actors: int,
    minimum_distinct_roots: int,
    anchors: List[TrustAnchor],
    assurance_policy: AssurancePolicy,
    principal_status: Optional[StatusSnapshot],
    grant_status: Optional[StatusSnapshot],
    channel_policy: str,
    evidence_types: List[str],
    critical_extensions: List[str],
) -> TrustedContext: ...
def self_contained_configuration() -> bytes: ...
def verify_v1(
    proof_cbor: bytes,
    canonical_action_cbor: bytes,
    trusted_context_cbor: bytes,
) -> NativeVerificationResult: ...
def inspect_verified_action(action: VerifiedAction) -> bytes: ...
def inspect_unsigned(value: UnsignedObject) -> bytes: ...
def inspect_signed(value: SignedObject) -> bytes: ...
def inspect_plan(value: AuthorizationPlan) -> bytes: ...
def inspect_mcp_action(value: McpAction) -> Tuple[bytes, bytes]: ...
def inspect_trusted_context(value: TrustedContext) -> bytes: ...
def parse_signed(kind: str, value: bytes) -> SignedObject: ...
def parse_unsigned(kind: str, value: bytes) -> UnsignedObject: ...
def parse_trusted_context(value: bytes) -> TrustedContext: ...
def unsigned_from_signed(value: SignedObject) -> UnsignedObject: ...
