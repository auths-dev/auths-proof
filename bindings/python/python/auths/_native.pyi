from typing import List, Literal, Optional, Tuple

Permission = Tuple[str, str]
Budget = Tuple[str, int]
StatusPolicy = Tuple[str, int]
CriticalExtension = Tuple[str, bytes]


class Principal:
    def __init__(self, value: str) -> None: ...
    @property
    def value(self) -> str: ...


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
def root_grant(issuer: Principal, request: GrantRequest) -> UnsignedObject: ...
def plan_child(parent: SignedObject, request: GrantRequest) -> GrantPlan: ...
def plan_child_statement(parent: UnsignedObject, request: GrantRequest) -> GrantPlan: ...
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
def unsigned_from_signed(value: SignedObject) -> UnsignedObject: ...
