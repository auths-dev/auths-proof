from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from auths import (
    Approval,
    ApprovalRequest,
    ApprovalResponse,
    Permission,
    Principal,
    Profile,
    ReviewField,
)
from auths.approvals import threshold_approval
from auths.authority import ProofPlanBuilder, ProofReference
from auths.diagnostics import runtime_diagnostic
from auths.identity import (
    IdentityRegistry,
    ResolutionEvidence,
    ResolvedIdentityRecord,
    ResolverIdentityMethod,
    VerificationMaterial,
    VerificationRelationship,
    decode_identity,
    encode_identity,
)
from auths.integrations import exchange_identity
from auths.lifecycle import rotate_identity
from auths.observability import AuthsEvent, DecisionTimeline, support_bundle
from auths.profile_kit import (
    CanonicalProfileAction,
    ProfileBudget,
    ProfileDefinition,
    ProfilePermission,
    define_profile,
)
from auths.profiles.http import HttpProfile, HttpProfileError
from auths.runtime import InMemoryRuntimeStore, RuntimeKernel, TransitionGates
from auths.trust import (
    AssurancePolicy,
    CompiledTrust,
    TrustAnchor,
    compile_trust,
    replace_policy,
)
from auths.verify import verify, verify_many

ROOT = Path(__file__).parents[3]
CORPUS = ROOT / "core" / "fixtures" / "v1" / "valid"
VECTORS = ROOT / "target" / "binding-vectors"


def test_identity_import_does_not_load_authority_workflow_or_profiles() -> None:
    source = """
import sys
import auths.identity
blocked = sorted(name for name in sys.modules if name in {
    'auths.workflow', 'auths.authority', 'auths.approvals', 'auths.trust',
    'auths.lifecycle', 'auths.runtime', 'auths.profile_kit',
    'auths.profiles.mcp', 'auths.profiles.http'
})
print(','.join(blocked))
"""
    completed = subprocess.run(
        [sys.executable, "-c", source],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == ""


@pytest.mark.asyncio
async def test_resolver_and_hybrid_suite_own_verification_material_shape() -> None:
    relationship = VerificationRelationship(
        "hybrid-auth",
        "authentication",
        "hybrid-v1",
        (
            VerificationMaterial("classical", b"classical-key"),
            VerificationMaterial("post-quantum", b"post-quantum-key"),
        ),
    )

    class Resolver:
        async def resolve(
            self, method_id: str, identity_id: str, *, maximum_bytes: int
        ) -> ResolvedIdentityRecord:
            assert maximum_bytes == 4096
            return ResolvedIdentityRecord(
                method_id,
                identity_id,
                b"resolver-version-7",
                (relationship,),
                ResolutionEvidence("resolver", 10, 20, ("https",), ("rotated-1",)),
            )

    class HybridSuite:
        suite_id = "hybrid-v1"
        version = 1

        async def verify(
            self,
            material: tuple[VerificationMaterial, ...],
            preimage: bytes,
            signature: bytes,
        ) -> None:
            assert tuple(value.material_id for value in material) == (
                "classical",
                "post-quantum",
            )
            assert preimage
            if signature != b"valid-hybrid-signature":
                raise ValueError("invalid hybrid signature")

    packet = encode_identity(
        "did-web-v1",
        "did:web:example.com:alice",
        method_material=b"alice",
        relationships=(relationship,),
    )
    registry = IdentityRegistry(
        methods=[
            ResolverIdentityMethod(
                "did-web-v1", Resolver(), maximum_bytes=4096
            )
        ],
        suites=[HybridSuite()],
    )
    validated = await decode_identity(packet).validate(registry)
    authenticated = await validated.authenticate(
        b"application message",
        b"valid-hybrid-signature",
        registry,
        relationship_id="hybrid-auth",
    )
    principal = authenticated.validated.authority_input(
        relationship_id="hybrid-auth", assurance="hybrid-reviewed"
    )
    assert principal.method_id == "did-web-v1"
    assert principal.suite_id == "hybrid-v1"
    assert principal.provenance == ("https",)


def test_native_proof_plans_bind_composition_and_builder_ownership() -> None:
    builder = ProofPlanBuilder()
    first = builder.proof(ProofReference(bytes([1]) * 32))
    second = builder.proof(ProofReference(bytes([2]) * 32))
    all_plan = builder.all_of((first, second))
    any_plan = builder.any_of((first, second))
    threshold = builder.threshold(1, (first, second))
    assert all_plan.plan_id != any_plan.plan_id != threshold.plan_id
    assert all_plan.leaf_count == 2
    assert threshold.maximum_depth == 2
    assert threshold.canonical_bytes()
    foreign = ProofPlanBuilder().proof(ProofReference(bytes([3]) * 32))
    with pytest.raises(ValueError, match="another builder"):
        builder.all_of((first, foreign))


@pytest.mark.asyncio
async def test_identity_transport_carries_only_bounded_bytes() -> None:
    class Loopback:
        contract_version = 1

        async def exchange(self, packet: bytes, *, maximum_bytes: int) -> bytes:
            assert len(packet) <= maximum_bytes
            return packet

    packet = b"canonical-public-identity"
    assert await exchange_identity(Loopback(), packet) == packet


@pytest.mark.asyncio
async def test_none_and_threshold_approval_preserve_exact_request() -> None:
    none = Approval.none()
    request = ApprovalRequest(
        "request-1",
        "action",
        bytes([4]) * 32,
        none.policy.reference,
        100,
        (),
    )
    response = await none.provider.approve(request)
    assert response.decision == "approved"
    assert none.policy.mode == "none"

    class Provider:
        def __init__(self, decision: str) -> None:
            self._decision = decision

        async def approve(self, value: ApprovalRequest) -> ApprovalResponse:
            return ApprovalResponse(
                value.request_id,
                value.transaction_digest,
                value.policy,
                "approved" if self._decision == "approved" else "rejected",
            )

    provider = threshold_approval(
        (Provider("approved"), Provider("approved"), Provider("rejected")),
        threshold=2,
    )
    assert (await provider.approve(request)).decision == "approved"


def test_http_and_application_plans_are_native_bound_and_profile_specific() -> None:
    http = HttpProfile(scheme="https", authority="api.example.com")
    first = http.request("GET", "/reports", query={"month": ("august",)})
    second = http.request("POST", "/reports/publish", headers={"x-mode": "safe"})
    plan = http.plan((first, second))
    review = http.review(first)
    assert review.fields
    assert len(review.action_commitment) == 32
    assert plan.length == 2
    assert len(plan.commitment) == 32
    with pytest.raises(HttpProfileError):
        http.plan((HttpProfile(scheme="https", authority="other.example").request("GET", "/"),))

    def canonicalize(value: str) -> CanonicalProfileAction:
        return CanonicalProfileAction(
            "application/json",
            value.encode(),
            ProfilePermission("records/update", "records://demo"),
            "records://demo",
            "records://service",
            (ReviewField("Record", value),),
            ProfileBudget("numeric-ceiling-v1", 1),
        )

    application = define_profile(
        ProfileDefinition("com.example.records", 1, canonicalize, lambda value: value.body)
    )
    application_plan = application.plan((application.action("one"), application.action("two")))
    assert application_plan.authority.budget == ProfileBudget("numeric-ceiling-v1", 2)
    assert len(application.review(application.action("three")).action_commitment) == 32


def test_typed_trust_compilation_has_no_protocol_byte_construction() -> None:
    root = Principal("key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs")
    anchor = TrustAnchor(
        "local.root",
        root,
        ("raw-key-v1",),
        (Profile("auths.mcp", 1),),
        (Permission("tools/call", "mcp://reports/tools/update_demo_record"),),
        ("mcp://reports",),
        ("mcp://reports",),
        0,
        100,
        2,
        "raw-key-baseline",
    )
    compiled = compile_trust(
        anchors=(anchor,), assurance=AssurancePolicy("raw-key-baseline", ())
    )
    assert compiled.roots == (root,)
    assert len(compiled.context.configuration) == 32


def test_rotation_and_clean_policy_replacement_are_typed_recipes() -> None:
    previous = Principal("key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs")
    current = Principal("key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E")
    rotation = rotate_identity(
        method="auths.status",
        previous=previous,
        current=current,
        purpose="authentication",
        issuer=previous,
        previous_sequence=2,
        current_sequence=1,
        valid_for=60,
        observed_at=10,
    )
    assert rotation.previous.state == "superseded"
    assert rotation.current.state == "active"

    def trusted(root: Principal, permission: str) -> CompiledTrust:
        return compile_trust(
            anchors=(
                TrustAnchor(
                    "local.root",
                    root,
                    ("raw-key-v1",),
                    (Profile("auths.mcp", 1),),
                    (Permission(permission, "mcp://reports/tools/update_demo_record"),),
                    ("mcp://reports",),
                    ("mcp://reports",),
                    0,
                    100,
                    2,
                    "raw-key-baseline",
                ),
            ),
            assurance=AssurancePolicy("raw-key-baseline", ()),
        )

    replacement = replace_policy(
        trusted(previous, "tools/call"),
        trusted(current, "tools/admin"),
        activated_at=20,
    )
    assert replacement.activated_at == 20


@pytest.mark.asyncio
async def test_in_memory_runtime_store_is_atomic_for_replay_and_budget() -> None:
    store = InMemoryRuntimeStore(budget_ceilings={"numeric-ceiling-v1": 3})
    challenge = bytes([5]) * 32
    assert await store.issue(challenge, expires_at=100)
    assert not await store.issue(challenge, expires_at=100)
    assert await store.claim(challenge, now=50) == "claimed"
    assert await store.claim(challenge, now=50) == "duplicate"
    first = bytes([6]) * 32
    second = bytes([7]) * 32
    assert await store.reserve(first, "numeric-ceiling-v1", 2) == "reserved"
    assert await store.reserve(first, "numeric-ceiling-v1", 2) == "duplicate"
    assert await store.reserve(second, "numeric-ceiling-v1", 2) == "exhausted"
    assert RuntimeKernel().transition(
        None,
        "record-decision",
        TransitionGates(
            core_authorized=True,
            policy_eligible=True,
            configuration_matches=True,
            not_revoked=True,
            not_expired=True,
        ),
    ).kind == "applied"


def test_observability_is_bounded_redacted_and_deterministic() -> None:
    event = AuthsEvent(
        "auths.verify",
        "verify",
        "complete",
        "authorized",
        10,
        (("profile", "auths.mcp"),),
    )
    timeline = DecisionTimeline()
    timeline.append(event)
    first = support_bundle(timeline.snapshot(), runtime={"python": "3.13"})
    second = support_bundle(timeline.snapshot(), runtime={"python": "3.13"})
    assert first == second
    with pytest.raises(ValueError, match="attribute name"):
        AuthsEvent("auths.verify", "verify", "complete", "denied", 10, (("proof", "secret"),))


def test_runtime_diagnostic_binds_trust_and_adapter_contracts() -> None:
    diagnostic = runtime_diagnostic(
        trust_configuration=bytes([8]) * 32,
        adapters={"custody.kms": 1, "runtime.sqlite": 1},
    )
    assert diagnostic.coherent
    assert diagnostic.trust_configuration == bytes([8]) * 32
    assert diagnostic.adapters == (("custody.kms", 1), ("runtime.sqlite", 1))


def test_batch_verification_preserves_single_item_meaning_and_order() -> None:
    values = (
        (
            (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
            (CORPUS / "raw-key-chain.action.cbor").read_bytes(),
            (VECTORS / "authorized.context.cbor").read_bytes(),
        ),
        (
            (CORPUS / "raw-key-chain.proof.cbor").read_bytes(),
            b"not-canonical-cbor",
            (VECTORS / "authorized.context.cbor").read_bytes(),
        ),
    )
    independent = tuple(verify(*value) for value in values)
    batched = verify_many(values)
    assert [(value.kind, value.code) for value in batched] == [
        (value.kind, value.code) for value in independent
    ]
