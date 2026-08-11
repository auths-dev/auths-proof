from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from typing import Callable, Optional

import pytest

from auths import (
    AnyBody,
    Approval,
    ApprovalRequest,
    ApprovalResponse,
    AuthsClient,
    AuthsWorkflowError,
    BudgetCeiling,
    DelegatedAuthority,
    ExpiryOnly,
    Permission,
    Principal,
    PrincipalDescriptor,
    Profile,
    ProviderOperationError,
    SignedGrantLoadRequest,
    SignedGrantMaterial,
    SignedGrantSource,
    SigningRequest,
    SigningResponse,
    SnapshotRequired,
    TrustedAuthority,
    Validity,
    _native as native,
)
from auths.inspection import parse_signed_object, parse_unsigned_object


VECTORS = Path(__file__).parents[3] / "target" / "binding-vectors"
ROOT = Principal("key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs")
PARENT = Principal("key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E")
CHILD = Principal("key:sha256:8C7PrA0wN6L7dI7ZmbYVYnR1Q21dzCq6FjDEHNt58fA")
PROFILE = Profile("auths.mcp", 1)


class ApprovalDouble:
    def __init__(self) -> None:
        self.calls = 0
        self.mutate: Optional[Callable[[ApprovalRequest], ApprovalResponse]] = None
        self.started: Optional[asyncio.Event] = None
        self.release: Optional[asyncio.Event] = None

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        self.calls += 1
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            await self.release.wait()
        if self.mutate is not None:
            return self.mutate(request)
        return ApprovalResponse(
            request.request_id,
            request.transaction_digest,
            request.policy,
            "approved",
        )


class SignerDouble:
    def __init__(
        self,
        principal: Principal,
        *,
        kind: str,
        lifecycle: str,
    ) -> None:
        self.kind = kind
        self.lifecycle = lifecycle
        self.descriptor = PrincipalDescriptor(
            principal,
            "raw-key-v1",
            principal.value,
            "ed25519-v1",
        )
        self.identity_calls = 0
        self.sign_calls = 0
        self.close_calls = 0
        self.mutate: Optional[Callable[[SigningRequest], SigningResponse]] = None
        self.identity_started: Optional[asyncio.Event] = None
        self.identity_release: Optional[asyncio.Event] = None
        self.sign_started: Optional[asyncio.Event] = None
        self.sign_release: Optional[asyncio.Event] = None

    async def public_identity(self) -> PrincipalDescriptor:
        self.identity_calls += 1
        if self.identity_started is not None:
            self.identity_started.set()
        if self.identity_release is not None:
            await self.identity_release.wait()
        return self.descriptor

    async def sign(self, request: SigningRequest) -> SigningResponse:
        self.sign_calls += 1
        if self.sign_started is not None:
            self.sign_started.set()
        if self.sign_release is not None:
            await self.sign_release.wait()
        if self.mutate is not None:
            return self.mutate(request)
        return SigningResponse(
            request.request_id,
            request.principal,
            request.transaction_digest,
            bytes([9]) * 64,
        )

    async def aclose(self) -> None:
        self.close_calls += 1


def trusted_context() -> native.TrustedContext:
    assurance = native.AssurancePolicy(
        "raw-key-baseline",
        [
            ("root", "every", "self-certifying-identifier", None),
            ("actor", "every", "self-certifying-identifier", None),
        ],
    )
    anchor = native.TrustAnchor(
        ROOT.value,
        ROOT,
        ["raw-key-v1"],
        [(PROFILE.id, PROFILE.version)],
        [("tools/call", "mcp://reports/read")],
        ["mcp://reports"],
        ["mcp://reports"],
        0,
        100,
        ("numeric-ceiling-v1", 20),
        2,
        "raw-key-baseline",
        None,
    )
    return native.compile_trusted_context(
        native.self_contained_configuration(),
        None,
        1,
        1,
        1,
        [anchor],
        assurance,
        None,
        None,
        "none-v1",
        ["raw-key-v1"],
        ["extension.test-v1"],
    )


def signed_root(
    name: str = "authoring.delegation-root-grant.cbor",
) -> native.SignedObject:
    return parse_signed_object("grant", (VECTORS / name).read_bytes())


def base_authority() -> DelegatedAuthority:
    return DelegatedAuthority(
        permissions=(Permission("tools/call", "mcp://reports/read"),),
        validity=Validity(20, 80),
        audiences=("mcp://reports",),
        remaining_depth=1,
        budget=BudgetCeiling("numeric-ceiling-v1", 10),
        status=SnapshotRequired("status.test-v1", 30),
    )


def workflow_fixture(
    *, approval_provider: Optional[ApprovalDouble] = None
) -> tuple[
    AuthsClient,
    SignerDouble,
    SignerDouble,
    ApprovalDouble,
    object,
]:
    provider = approval_provider or ApprovalDouble()
    approval = Approval.grant_only("approval.default", provider)
    parent_signer = SignerDouble(
        PARENT,
        kind="test-parent",
        lifecycle="durable",
    )
    child_signer = SignerDouble(
        CHILD,
        kind="test-child",
        lifecycle="ephemeral",
    )
    client = AuthsClient(
        signer=parent_signer,
        trusted_authority=TrustedAuthority(
            "local.test-root",
            ROOT,
            trusted_context(),
            approval.policy.reference,
        ),
    )
    return client, parent_signer, child_signer, provider, approval


def test_attach_and_delegate_use_native_authority_without_protocol_bytes() -> None:
    async def scenario() -> None:
        client, parent_signer, child_signer, provider, approval = workflow_fixture()
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            assert parent.authority.issuer.value == ROOT.value
            assert parent.authority.subject.value == PARENT.value
            assert (
                parent.authority.explanation.code == "root-authority-structurally-bound"
            )
            async with await parent.delegate(
                name="records-child",
                authority=base_authority(),
                signer=child_signer,  # type: ignore[arg-type]
            ) as child:
                assert child.identity.principal.principal.value == CHILD.value
                assert child.authority.issuer.value == PARENT.value
                assert child.authority.subject.value == CHILD.value
                assert child.authority.critical_extensions == ("extension.test-v1",)
                assert child.delegation is not None
                assert child.delegation.diff.delegation_depth == (2, 1)
                assert child.delegation.warnings == ("any-body", "delegation-allowed")
            assert child_signer.close_calls == 1
        assert parent_signer.close_calls == 1
        assert provider.calls == 1
        assert parent_signer.sign_calls == 1
        assert child_signer.sign_calls == 0

    asyncio.run(scenario())


def test_attach_loads_only_typed_signed_grant_material() -> None:
    class Source:
        def __init__(self) -> None:
            self.calls = 0

        async def load_signed_grant(
            self, request: SignedGrantLoadRequest
        ) -> SignedGrantMaterial:
            self.calls += 1
            assert request.subject.value == PARENT.value
            assert request.profile == PROFILE
            return SignedGrantMaterial(signed_root())

    async def scenario() -> None:
        client, _, _, _, approval = workflow_fixture()
        source = Source()
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=SignedGrantSource("fixture.root", source),
                approval=approval,  # type: ignore[arg-type]
            )
            assert source.calls == 1
            await parent.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "authority",
    [
        lambda: DelegatedAuthority(
            permissions=(
                Permission("tools/call", "mcp://reports/read"),
                Permission("tools/admin", "mcp://reports/admin"),
            ),
            validity=Validity(20, 80),
            audiences=("mcp://reports",),
            remaining_depth=1,
        ),
        lambda: DelegatedAuthority(
            permissions=base_authority().permissions,
            validity=Validity(0, 101),
            audiences=base_authority().audiences,
            remaining_depth=1,
        ),
        lambda: DelegatedAuthority(
            permissions=base_authority().permissions,
            validity=base_authority().validity,
            audiences=("mcp://other",),
            remaining_depth=1,
        ),
        lambda: DelegatedAuthority(
            permissions=base_authority().permissions,
            validity=base_authority().validity,
            audiences=base_authority().audiences,
            remaining_depth=1,
            budget=BudgetCeiling("numeric-ceiling-v1", 21),
        ),
        lambda: DelegatedAuthority(
            permissions=base_authority().permissions,
            validity=base_authority().validity,
            audiences=base_authority().audiences,
            remaining_depth=2,
        ),
        lambda: DelegatedAuthority(
            permissions=base_authority().permissions,
            validity=base_authority().validity,
            audiences=base_authority().audiences,
            remaining_depth=1,
            status=ExpiryOnly(),
        ),
        lambda: DelegatedAuthority(
            permissions=base_authority().permissions,
            validity=base_authority().validity,
            audiences=base_authority().audiences,
            remaining_depth=1,
            assurance_floor="weaker-policy",
        ),
    ],
)
def test_every_exposed_authority_dimension_fails_before_approval_when_widened(
    authority: Callable[[], DelegatedAuthority],
) -> None:
    async def scenario() -> None:
        client, parent_signer, child_signer, provider, approval = workflow_fixture()
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            with pytest.raises(AuthsWorkflowError) as raised:
                await parent.delegate(
                    name="records-child",
                    authority=authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            assert raised.value.code == "delegation-expanded"
            assert provider.calls == 0
            assert parent_signer.sign_calls == 0
            assert child_signer.close_calls == 1

    asyncio.run(scenario())


def test_action_widening_fails_before_approval() -> None:
    async def scenario() -> None:
        client, parent_signer, child_signer, provider, approval = workflow_fixture()
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root("authoring.signed-root-grant.cbor"),
                approval=approval,  # type: ignore[arg-type]
            )
            request = base_authority()
            with pytest.raises(AuthsWorkflowError) as raised:
                await parent.delegate(
                    name="records-child",
                    authority=DelegatedAuthority(
                        permissions=request.permissions,
                        validity=request.validity,
                        audiences=request.audiences,
                        remaining_depth=0,
                        action_constraint=AnyBody(),
                        budget=request.budget,
                        status=request.status,
                    ),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            assert raised.value.code == "delegation-expanded"
            assert provider.calls == 0
            assert parent_signer.sign_calls == 0

    asyncio.run(scenario())


def test_approval_substitution_never_calls_the_parent_signer() -> None:
    provider = ApprovalDouble()
    provider.mutate = lambda request: ApprovalResponse(
        request.request_id,
        bytes(32),
        request.policy,
        "approved",
    )

    async def scenario() -> None:
        client, parent_signer, child_signer, _, approval = workflow_fixture(
            approval_provider=provider
        )
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            with pytest.raises(AuthsWorkflowError) as raised:
                await parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            assert raised.value.code == "approval-response-mismatch"
            assert provider.calls == 1
            assert parent_signer.sign_calls == 0
            assert child_signer.close_calls == 1

    asyncio.run(scenario())


def test_approval_fields_cannot_outlive_their_native_commitment() -> None:
    async def scenario() -> None:
        client, _, child_signer, provider, approval = workflow_fixture()
        tampered = replace(
            approval,
            policy=replace(approval.policy, expires_in_seconds=86_400),
        )
        async with client:
            with pytest.raises(ValueError, match="native commitment"):
                await client.attach_agent(
                    name="research-agent",
                    profile=PROFILE,
                    authority=signed_root(),
                    approval=tampered,
                )
            assert provider.calls == 0
            assert child_signer.close_calls == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("substitution", ["request", "policy", "decision"])
def test_every_approval_binding_field_fails_closed(substitution: str) -> None:
    provider = ApprovalDouble()

    def mutate(request: ApprovalRequest) -> ApprovalResponse:
        if substitution == "request":
            return ApprovalResponse(
                "grant:substituted",
                request.transaction_digest,
                request.policy,
                "approved",
            )
        if substitution == "policy":
            other = Approval.grant_only("approval.other", ApprovalDouble())
            return ApprovalResponse(
                request.request_id,
                request.transaction_digest,
                other.policy.reference,
                "approved",
            )
        return ApprovalResponse(
            request.request_id,
            request.transaction_digest,
            request.policy,
            "rejected",
        )

    provider.mutate = mutate

    async def scenario() -> None:
        client, parent_signer, child_signer, _, approval = workflow_fixture(
            approval_provider=provider
        )
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            with pytest.raises(AuthsWorkflowError) as raised:
                await parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            expected = (
                "approval-rejected"
                if substitution == "decision"
                else "approval-response-mismatch"
            )
            assert raised.value.code == expected
            assert parent_signer.sign_calls == 0
            assert child_signer.close_calls == 1

    asyncio.run(scenario())


def test_signer_substitution_cannot_complete_the_child_grant() -> None:
    async def scenario() -> None:
        client, parent_signer, child_signer, provider, approval = workflow_fixture()
        parent_signer.mutate = lambda request: SigningResponse(
            request.request_id,
            request.principal,
            bytes(32),
            bytes([9]) * 64,
        )
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            with pytest.raises(AuthsWorkflowError) as raised:
                await parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            assert raised.value.code == "signer-response-mismatch"
            assert provider.calls == 1
            assert parent_signer.sign_calls == 1
            assert child_signer.close_calls == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "substitution", ["request", "principal", "descriptor", "signature"]
)
def test_every_signer_binding_field_fails_closed(substitution: str) -> None:
    async def scenario() -> None:
        client, parent_signer, child_signer, provider, approval = workflow_fixture()

        def mutate(request: SigningRequest) -> SigningResponse:
            principal = request.principal
            request_id = request.request_id
            signature = bytes([9]) * 64
            if substitution == "request":
                request_id = "grant:substituted"
            elif substitution == "principal":
                principal = PrincipalDescriptor(
                    CHILD, "raw-key-v1", CHILD.value, "ed25519-v1"
                )
            elif substitution == "descriptor":
                principal = PrincipalDescriptor(
                    PARENT, "raw-key-v1", PARENT.value, "p256-sha256-v1"
                )
            elif substitution == "signature":
                signature = b""
            return SigningResponse(
                request_id,
                principal,
                request.transaction_digest,
                signature,
            )

        parent_signer.mutate = mutate
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            with pytest.raises(AuthsWorkflowError) as raised:
                await parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            assert raised.value.code == "signer-response-mismatch"
            assert provider.calls == 1
            assert parent_signer.sign_calls == 1
            assert child_signer.close_calls == 1

    asyncio.run(scenario())


def test_provider_errors_are_typed_and_sanitized() -> None:
    provider = ApprovalDouble()

    async def fail(_request: ApprovalRequest) -> ApprovalResponse:
        raise RuntimeError("secret provider credential")

    provider.approve = fail  # type: ignore[assignment]

    async def scenario() -> None:
        client, _, child_signer, _, approval = workflow_fixture(
            approval_provider=provider
        )
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            with pytest.raises(AuthsWorkflowError) as raised:
                await parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            assert raised.value.code == "approval-failed"
            assert "credential" not in str(raised.value)

    asyncio.run(scenario())


def test_cancellation_closes_the_partial_child_and_produces_no_signature() -> None:
    provider = ApprovalDouble()

    async def scenario() -> None:
        provider.started = asyncio.Event()
        provider.release = asyncio.Event()
        client, parent_signer, child_signer, _, approval = workflow_fixture(
            approval_provider=provider
        )
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            operation = asyncio.create_task(
                parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            )
            await provider.started.wait()
            operation.cancel()
            with pytest.raises(asyncio.CancelledError):
                await operation
            assert parent_signer.sign_calls == 0
            assert child_signer.close_calls == 1

    asyncio.run(scenario())


def test_cancellation_during_child_identity_disposes_the_child_signer() -> None:
    async def scenario() -> None:
        client, parent_signer, child_signer, provider, approval = workflow_fixture()
        child_signer.identity_started = asyncio.Event()
        child_signer.identity_release = asyncio.Event()
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            operation = asyncio.create_task(
                parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            )
            await child_signer.identity_started.wait()
            operation.cancel()
            with pytest.raises(asyncio.CancelledError):
                await operation
            assert child_signer.close_calls == 1
            assert provider.calls == 0
            assert parent_signer.sign_calls == 0

    asyncio.run(scenario())


def test_cancellation_during_parent_signing_disposes_the_child_signer() -> None:
    async def scenario() -> None:
        client, parent_signer, child_signer, provider, approval = workflow_fixture()
        parent_signer.sign_started = asyncio.Event()
        parent_signer.sign_release = asyncio.Event()
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            operation = asyncio.create_task(
                parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            )
            await parent_signer.sign_started.wait()
            operation.cancel()
            with pytest.raises(asyncio.CancelledError):
                await operation
            assert provider.calls == 1
            assert parent_signer.sign_calls == 1
            assert child_signer.close_calls == 1

    asyncio.run(scenario())


def test_client_cleanup_is_idempotent_for_root_and_child_signers() -> None:
    async def scenario() -> None:
        client, parent_signer, child_signer, _, approval = workflow_fixture()
        await client.open()
        parent = await client.attach_agent(
            name="research-agent",
            profile=PROFILE,
            authority=signed_root(),
            approval=approval,  # type: ignore[arg-type]
        )
        child = await parent.delegate(
            name="records-child",
            authority=base_authority(),
            signer=child_signer,  # type: ignore[arg-type]
        )
        await client.aclose()
        await client.aclose()
        await child.aclose()
        assert parent.closed
        assert child.closed
        assert parent_signer.close_calls == 1
        assert child_signer.close_calls == 1

    asyncio.run(scenario())


def test_native_transaction_is_single_use_across_approval_and_signature() -> None:
    unsigned = parse_unsigned_object(
        "grant", (VECTORS / "authoring.proposed-grant.cbor").read_bytes()
    )
    principal = PrincipalDescriptor(PARENT, "raw-key-v1", PARENT.value, "ed25519-v1")
    provider = ApprovalDouble()
    approval = Approval.grant_only("approval.default", provider)
    transaction = native.prepare_signing_transaction(
        unsigned,
        principal,
        approval.policy.reference,
        200,
    )
    assert transaction.accept_approval(
        transaction.request_id,
        transaction.transaction_digest,
        transaction.policy,
        "approved",
        100,
    )
    with pytest.raises(RuntimeError, match="not awaiting approval"):
        transaction.accept_approval(
            transaction.request_id,
            transaction.transaction_digest,
            transaction.policy,
            "approved",
            100,
        )
    signed = transaction.complete_response(
        transaction.request_id,
        principal,
        transaction.transaction_digest,
        bytes([9]) * 64,
        100,
    )
    assert signed.kind == "grant"
    assert transaction.phase == "terminal"
    with pytest.raises(RuntimeError, match="not awaiting a signature"):
        transaction.complete_response(
            "grant:reused",
            principal,
            bytes(32),
            bytes([9]) * 64,
            100,
        )


def test_wrong_native_response_consumes_the_transaction() -> None:
    unsigned = parse_unsigned_object(
        "grant", (VECTORS / "authoring.proposed-grant.cbor").read_bytes()
    )
    principal = PrincipalDescriptor(PARENT, "raw-key-v1", PARENT.value, "ed25519-v1")
    approval = Approval.grant_only("approval.default", ApprovalDouble())
    transaction = native.prepare_signing_transaction(
        unsigned,
        principal,
        approval.policy.reference,
        200,
    )
    with pytest.raises(ValueError, match="exact transaction"):
        transaction.accept_approval(
            transaction.request_id,
            bytes(32),
            transaction.policy,
            "approved",
            100,
        )
    assert transaction.phase == "terminal"
    with pytest.raises(RuntimeError):
        transaction.accept_approval(
            "reused",
            bytes(32),
            transaction.policy,
            "approved",
            100,
        )


def test_expired_native_transaction_is_terminal_before_provider_completion() -> None:
    unsigned = parse_unsigned_object(
        "grant", (VECTORS / "authoring.proposed-grant.cbor").read_bytes()
    )
    principal = PrincipalDescriptor(PARENT, "raw-key-v1", PARENT.value, "ed25519-v1")
    approval = Approval.grant_only("approval.default", ApprovalDouble())
    transaction = native.prepare_signing_transaction(
        unsigned,
        principal,
        approval.policy.reference,
        99,
    )
    with pytest.raises(RuntimeError, match="expired"):
        transaction.accept_approval(
            transaction.request_id,
            transaction.transaction_digest,
            transaction.policy,
            "approved",
            100,
        )
    assert transaction.phase == "terminal"
    with pytest.raises(RuntimeError):
        transaction.accept_approval(
            "reused",
            bytes(32),
            transaction.policy,
            "approved",
            100,
        )


def test_profile_and_extensions_are_not_caller_selectable_during_delegation() -> None:
    request = base_authority()
    with pytest.raises(TypeError, match="unexpected keyword"):
        DelegatedAuthority(
            permissions=request.permissions,
            validity=request.validity,
            audiences=request.audiences,
            remaining_depth=request.remaining_depth,
            profile=Profile("auths.http", 1),  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError, match="unexpected keyword"):
        DelegatedAuthority(
            permissions=request.permissions,
            validity=request.validity,
            audiences=request.audiences,
            remaining_depth=request.remaining_depth,
            critical_extensions=(),  # type: ignore[call-arg]
        )


def test_provider_failure_kinds_survive_without_arbitrary_causes() -> None:
    provider = ApprovalDouble()

    async def unavailable(_request: ApprovalRequest) -> ApprovalResponse:
        raise ProviderOperationError("unavailable")

    provider.approve = unavailable  # type: ignore[assignment]

    async def scenario() -> None:
        client, _, child_signer, _, approval = workflow_fixture(
            approval_provider=provider
        )
        async with client:
            parent = await client.attach_agent(
                name="research-agent",
                profile=PROFILE,
                authority=signed_root(),
                approval=approval,  # type: ignore[arg-type]
            )
            with pytest.raises(AuthsWorkflowError) as raised:
                await parent.delegate(
                    name="records-child",
                    authority=base_authority(),
                    signer=child_signer,  # type: ignore[arg-type]
                )
            assert raised.value.code == "approval-failed"

    asyncio.run(scenario())
