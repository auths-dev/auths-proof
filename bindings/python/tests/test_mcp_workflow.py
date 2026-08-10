from __future__ import annotations

import asyncio
import copy
import json
import pickle
from pathlib import Path
from typing import Optional
import pytest

from auths import (
    Approval,
    ApprovalRequest,
    ApprovalResponse,
    AttachedAgent,
    AuthorizationRequest,
    AuthsClient,
    AuthsWorkflowError,
    BudgetCeiling,
    ControlEvidence,
    DelegatedAuthority,
    ExpiryOnly,
    McpAuthorized,
    McpAuthorizationResult,
    McpDenied,
    McpGatewayCall,
    McpIndeterminate,
    McpPlanAuthorized,
    McpPlanDenied,
    McpProfile,
    Permission,
    Principal,
    PrincipalDescriptor,
    SignedGrantMaterial,
    SigningRequest,
    SigningResponse,
    TrustedAuthority,
    Validity,
    mcp,
    native,
)
from auths import _native as native_abi
from auths.advanced import (
    create_diagnostic_verifier,
    inspect_decision,
    parse_signed_object,
    parse_trusted_context_bytes,
)


VECTORS = Path(__file__).parents[3] / "target" / "binding-vectors"
ROOT = Principal("key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs")
ACTOR = Principal("key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E")


class ApprovalDouble:
    def __init__(self) -> None:
        self.calls = 0

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        self.calls += 1
        return ApprovalResponse(
            request.request_id,
            request.transaction_digest,
            request.policy,
            "approved",
        )


class ActionSigner:
    kind = "test-action"
    lifecycle = "durable"

    def __init__(
        self,
        signature_file: str,
        *,
        evidence: bool = True,
        principal: Principal = ACTOR,
        evidence_file: str = "mcp.actor-evidence.bin",
        grant_signature_file: Optional[str] = None,
        lifecycle: str = "durable",
    ) -> None:
        self._signature = (VECTORS / signature_file).read_bytes()
        self._grant_signature = (
            None
            if grant_signature_file is None
            else (VECTORS / grant_signature_file).read_bytes()
        )
        self._evidence = evidence
        self._principal = principal
        self._evidence_file = evidence_file
        self.lifecycle = lifecycle
        self.closed = False
        self.signatures = 0

    async def public_identity(self) -> PrincipalDescriptor:
        return PrincipalDescriptor(
            self._principal,
            "raw-key-v1",
            self._principal.value,
            "ed25519-v1",
        )

    async def sign(self, request: SigningRequest) -> SigningResponse:
        self.signatures += 1
        evidence = (
            (
                ControlEvidence(
                    "raw-key-v1",
                    "application/vnd.auths.raw-key.v1",
                    (VECTORS / self._evidence_file).read_bytes(),
                ),
            )
            if self._evidence
            else ()
        )
        return SigningResponse(
            request.request_id,
            request.principal,
            request.transaction_digest,
            (
                self._grant_signature
                if request.object_kind == "grant" and self._grant_signature is not None
                else self._signature
            ),
            evidence,
        )

    async def aclose(self) -> None:
        self.closed = True


class SequenceSigner(ActionSigner):
    def __init__(self, signature_files: tuple[str, ...]) -> None:
        super().__init__(signature_files[0])
        self._signatures = tuple(
            (VECTORS / signature_file).read_bytes()
            for signature_file in signature_files
        )

    async def sign(self, request: SigningRequest) -> SigningResponse:
        index = self.signatures
        self._signature = self._signatures[index]
        return await super().sign(request)


def context() -> native.TrustedContext:
    return parse_trusted_context_bytes((VECTORS / "mcp.context.cbor").read_bytes())


def root_material() -> SignedGrantMaterial:
    return SignedGrantMaterial(
        parse_signed_object(
            "grant", (VECTORS / "mcp.signed-root-grant.cbor").read_bytes()
        ),
        (
            ControlEvidence(
                "raw-key-v1",
                "application/vnd.auths.raw-key.v1",
                (VECTORS / "mcp.root-evidence.bin").read_bytes(),
            ),
        ),
    )


async def authorize(
    signature_file: str = "mcp.action-signature.bin", *, evidence: bool = True
) -> tuple[AuthsClient, McpProfile, AttachedAgent, McpAuthorizationResult]:
    signer = ActionSigner(signature_file, evidence=evidence)
    approval = Approval.every_action("approval.mcp", ApprovalDouble())
    profile = mcp.profile(service="reports")
    client = AuthsClient(
        signer=signer,
        trusted_authority=TrustedAuthority(
            "local.mcp-root",
            ROOT,
            context(),
            approval.policy.reference,
        ),
    )
    await client.open()
    agent = await client.attach_agent(
        name="reports-agent",
        profile=profile,
        authority=root_material(),
        approval=approval,
    )
    action = profile.call("update_demo_record", {"value": "reviewed"})
    result = await agent.authorize(
        action,
        request=AuthorizationRequest(bytes([0x22]) * 32, 50),
    )
    return client, profile, agent, result


@pytest.mark.asyncio
async def test_installed_workflow_authorizes_and_executes_one_native_command() -> None:
    client, profile, _, result = await authorize()
    assert isinstance(result, McpAuthorized)
    calls: list[McpGatewayCall] = []

    async def execute(call: McpGatewayCall) -> str:
        calls.append(call)
        return "updated"

    gateway = profile.gateway(execute)
    assert await gateway.execute(result.command) == "updated"
    assert calls == [
        McpGatewayCall("reports", "update_demo_record", b'{"value":"reviewed"}')
    ]
    with pytest.raises(RuntimeError, match="consumed"):
        await gateway.execute(result.command)
    await client.aclose()


@pytest.mark.asyncio
async def test_installed_workflow_delegates_authorizes_and_executes() -> None:
    child_principal = Principal(
        (VECTORS / "mcp.child-principal.txt").read_text().strip()
    )
    parent_signer = ActionSigner(
        "mcp.action-signature.bin",
        grant_signature_file="mcp.child-grant-signature.bin",
    )
    child_signer = ActionSigner(
        "mcp.child-action-signature.bin",
        principal=child_principal,
        evidence_file="mcp.child-evidence.bin",
        lifecycle="ephemeral",
    )
    approval = Approval.every_action("approval.mcp", ApprovalDouble())
    profile = mcp.profile(service="reports")
    client = AuthsClient(
        signer=parent_signer,
        trusted_authority=TrustedAuthority(
            "local.mcp-root", ROOT, context(), approval.policy.reference
        ),
    )
    calls: list[McpGatewayCall] = []

    async def execute(call: McpGatewayCall) -> str:
        calls.append(call)
        return "delegated-update"

    async with client:
        parent = await client.attach_agent(
            name="reports-agent",
            profile=profile,
            authority=root_material(),
            approval=approval,
        )
        async with await parent.delegate(
            name="reports-child",
            authority=DelegatedAuthority(
                permissions=(
                    Permission("tools/call", "mcp://reports/tools/update_demo_record"),
                ),
                validity=Validity(30, 70),
                audiences=("mcp://reports",),
                remaining_depth=0,
                budget=BudgetCeiling("numeric-ceiling-v1", 10),
                status=ExpiryOnly(),
            ),
            signer=child_signer,
        ) as child:
            result = await child.authorize(
                profile.call("update_demo_record", {"value": "reviewed"}),
                request=AuthorizationRequest(bytes([0x22]) * 32, 50),
            )
            assert isinstance(result, McpAuthorized)
            assert (
                await profile.gateway(execute).execute(result.command)
                == "delegated-update"
            )
    assert child_signer.closed
    assert calls == [
        McpGatewayCall("reports", "update_demo_record", b'{"value":"reviewed"}')
    ]


@pytest.mark.asyncio
async def test_denied_and_indeterminate_results_cannot_reach_the_gateway() -> None:
    signer = ActionSigner("mcp.denied-action-signature.bin")
    approval = Approval.every_action("approval.mcp", ApprovalDouble())
    profile = mcp.profile(service="reports")
    client = AuthsClient(
        signer=signer,
        trusted_authority=TrustedAuthority(
            "local.mcp-root", ROOT, context(), approval.policy.reference
        ),
    )
    async with client:
        agent = await client.attach_agent(
            name="reports-agent",
            profile=profile,
            authority=root_material(),
            approval=approval,
        )
        denied = await agent.authorize(
            profile.call("delete_demo_record", {"value": "reviewed"}),
            request=AuthorizationRequest(bytes([0x22]) * 32, 50),
        )
        assert isinstance(denied, McpDenied)
        assert not hasattr(denied, "command")
    indeterminate_client, _, _, indeterminate = await authorize(evidence=False)
    assert isinstance(indeterminate, McpIndeterminate)
    assert not hasattr(indeterminate, "command")
    await indeterminate_client.aclose()


@pytest.mark.asyncio
async def test_gateway_rejects_wrong_profile_without_consuming_command() -> None:
    client, profile, _, result = await authorize()
    assert isinstance(result, McpAuthorized)
    calls = 0

    async def execute(_call: McpGatewayCall) -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(TypeError, match="native MCP command"):
        await profile.gateway(execute).execute(b"forged")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="does not belong"):
        await mcp.profile(service="billing").gateway(execute).execute(result.command)
    assert calls == 0
    await profile.gateway(execute).execute(result.command)
    assert calls == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_native_command_cannot_be_forged_copied_or_serialized() -> None:
    client, _, _, result = await authorize()
    assert isinstance(result, McpAuthorized)
    with pytest.raises(TypeError):
        type(result.command)()
    with pytest.raises(TypeError):
        type("ForgedMcpCommand", (type(result.command),), {})
    with pytest.raises(AttributeError):
        result.command.name = "substituted"  # type: ignore[misc]
    with pytest.raises(TypeError):
        memoryview(result.command)
    for operation in (
        lambda: copy.copy(result.command),
        lambda: copy.deepcopy(result.command),
        lambda: pickle.dumps(result.command),
    ):
        with pytest.raises(TypeError, match="non-copyable"):
            operation()
    await client.aclose()


@pytest.mark.asyncio
async def test_duplicate_native_command_handle_fails_without_consumption() -> None:
    client, profile, _, result = await authorize()
    assert isinstance(result, McpAuthorized)
    action = profile.call("update_demo_record", {"value": "reviewed"})
    plan = profile.plan((action, action))

    with pytest.raises(ValueError, match="duplicate command handle"):
        native_abi.seal_mcp_plan_command(
            [result.command, result.command],
            "reports",
            plan.commitment,
        )

    calls = 0

    async def execute(_call: McpGatewayCall) -> None:
        nonlocal calls
        calls += 1

    await profile.gateway(execute).execute(result.command)
    assert calls == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_profile_mismatch_and_gateway_failure_are_closed() -> None:
    client, profile, agent, result = await authorize()
    assert isinstance(result, McpAuthorized)
    other = mcp.profile(service="reports")
    with pytest.raises(AuthsWorkflowError, match="different profile instance"):
        await agent.authorize(
            other.call("update_demo_record", {"value": "reviewed"}),
            request=AuthorizationRequest(bytes([0x22]) * 32, 50),
        )

    async def fail(_call: McpGatewayCall) -> None:
        raise RuntimeError("secret endpoint detail")

    with pytest.raises(AuthsWorkflowError) as failure:
        await profile.gateway(fail).execute(result.command)
    assert failure.value.code == "gateway-failed"
    assert "secret endpoint detail" not in str(failure.value)
    with pytest.raises(RuntimeError, match="consumed"):
        await profile.gateway(fail).execute(result.command)
    await client.aclose()


async def plan_fixture(
    signer: ActionSigner, approval_provider: ApprovalDouble
) -> tuple[AuthsClient, McpProfile, AttachedAgent]:
    approval = Approval.plan_once("approval.mcp-plan", approval_provider, max_uses=2)
    profile = mcp.profile(service="reports")
    client = AuthsClient(
        signer=signer,
        trusted_authority=TrustedAuthority(
            "local.mcp-root", ROOT, context(), approval.policy.reference
        ),
    )
    await client.open()
    agent = await client.attach_agent(
        name="reports-plan-agent",
        profile=profile,
        authority=root_material(),
        approval=approval,
    )
    return client, profile, agent


@pytest.mark.asyncio
async def test_ordered_plan_prompts_once_and_releases_one_native_plan_command() -> None:
    signer = SequenceSigner(("mcp.action-signature.bin", "mcp.action-signature.bin"))
    provider = ApprovalDouble()
    client, profile, agent = await plan_fixture(signer, provider)
    first = profile.call("update_demo_record", {"value": "reviewed"})
    second = profile.call("update_demo_record", {"value": "reviewed"})
    plan = profile.plan((first, second))
    requests = (
        AuthorizationRequest(bytes([0x22]) * 32, 50),
        AuthorizationRequest(bytes([0x22]) * 32, 50),
    )

    result = await agent.authorize_plan(plan, requests=requests)

    assert isinstance(result, McpPlanAuthorized)
    assert result.command.count == 2
    assert result.command.plan_commitment == plan.commitment
    assert len(result.results) == 2
    assert all(not hasattr(member, "command") for member in result.results)
    assert provider.calls == 1
    assert signer.signatures == 2
    assert plan.length == 2
    assert plan.authority.resource_namespaces == ("mcp://reports",)

    for operation in (
        lambda: copy.copy(result.command),
        lambda: copy.deepcopy(result.command),
        lambda: pickle.dumps(result.command),
    ):
        with pytest.raises(TypeError, match="native capability"):
            operation()
    with pytest.raises(TypeError):
        type(result.command)()
    with pytest.raises(TypeError):
        type("ForgedMcpPlanCommand", (type(result.command),), {})
    with pytest.raises(AttributeError):
        result.command.plan_commitment = bytes(32)  # type: ignore[misc]
    with pytest.raises(TypeError):
        memoryview(result.command)

    calls: list[McpGatewayCall] = []

    async def execute(call: McpGatewayCall) -> str:
        calls.append(call)
        return call.name

    gateway = profile.gateway(execute)
    assert await gateway.execute_plan(result.command) == (
        "update_demo_record",
        "update_demo_record",
    )
    assert len(calls) == 2
    with pytest.raises(RuntimeError, match="consumed"):
        await gateway.execute_plan(result.command)
    await client.aclose()


def test_mcp_plan_commitment_binds_order_and_exact_membership() -> None:
    profile = mcp.profile(service="reports")
    first = profile.call("update_demo_record", {"value": "first"})
    second = profile.call("update_demo_record", {"value": "second"})

    ordered = profile.plan((first, second))
    reordered = profile.plan((second, first))
    duplicated = profile.plan((first, first))

    assert ordered.commitment != reordered.commitment
    assert ordered.commitment != duplicated.commitment


@pytest.mark.asyncio
async def test_plan_approval_response_substitution_fails_before_signing() -> None:
    class SubstitutingApproval(ApprovalDouble):
        async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
            response = await super().approve(request)
            return ApprovalResponse(
                response.request_id,
                bytes(32),
                response.policy,
                response.decision,
            )

    signer = SequenceSigner(("mcp.action-signature.bin", "mcp.action-signature.bin"))
    provider = SubstitutingApproval()
    client, profile, agent = await plan_fixture(signer, provider)
    plan = profile.plan(
        (
            profile.call("update_demo_record", {"value": "reviewed"}),
            profile.call("update_demo_record", {"value": "reviewed"}),
        )
    )

    with pytest.raises(AuthsWorkflowError) as failure:
        await agent.authorize_plan(
            plan,
            requests=(
                AuthorizationRequest(bytes([0x22]) * 32, 50),
                AuthorizationRequest(bytes([0x22]) * 32, 50),
            ),
        )
    assert failure.value.code == "approval-rejected"
    assert signer.signatures == 0
    assert provider.calls == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_plan_cancellation_exposes_no_partial_command() -> None:
    class BlockingSecondSigner(SequenceSigner):
        def __init__(self) -> None:
            super().__init__(("mcp.action-signature.bin", "mcp.action-signature.bin"))
            self.started = asyncio.Event()

        async def sign(self, request: SigningRequest) -> SigningResponse:
            if self.signatures == 1:
                self.started.set()
                await asyncio.Event().wait()
            return await super().sign(request)

    signer = BlockingSecondSigner()
    provider = ApprovalDouble()
    client, profile, agent = await plan_fixture(signer, provider)
    action = profile.call("update_demo_record", {"value": "reviewed"})
    operation = asyncio.create_task(
        agent.authorize_plan(
            profile.plan((action, action)),
            requests=(
                AuthorizationRequest(bytes([0x22]) * 32, 50),
                AuthorizationRequest(bytes([0x22]) * 32, 50),
            ),
        )
    )

    await signer.started.wait()
    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation
    assert provider.calls == 1
    assert signer.signatures == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_ordered_plan_failure_exposes_no_partial_command() -> None:
    signer = SequenceSigner(
        ("mcp.action-signature.bin", "mcp.denied-action-signature.bin")
    )
    provider = ApprovalDouble()
    client, profile, agent = await plan_fixture(signer, provider)
    plan = profile.plan(
        (
            profile.call("update_demo_record", {"value": "reviewed"}),
            profile.call("delete_demo_record", {"value": "reviewed"}),
        )
    )

    result = await agent.authorize_plan(
        plan,
        requests=(
            AuthorizationRequest(bytes([0x22]) * 32, 50),
            AuthorizationRequest(bytes([0x22]) * 32, 50),
        ),
    )

    assert isinstance(result, McpPlanDenied)
    assert result.failed_index == 1
    assert len(result.results) == 2
    assert all(not hasattr(member, "command") for member in result.results)
    assert not hasattr(result, "command")
    assert provider.calls == 1
    assert signer.signatures == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_plan_mutation_after_approval_fails_before_the_next_signature() -> None:
    signer = SequenceSigner(("mcp.action-signature.bin", "mcp.action-signature.bin"))
    provider = ApprovalDouble()
    client, profile, agent = await plan_fixture(signer, provider)
    first = profile.call("update_demo_record", {"value": "reviewed"})
    second = profile.call("delete_demo_record", {"value": "reviewed"})
    plan = profile.plan((first, second))
    original_approve = provider.approve

    async def mutate(request: ApprovalRequest) -> ApprovalResponse:
        second._call = first._call
        return await original_approve(request)

    provider.approve = mutate  # type: ignore[method-assign]

    with pytest.raises(AuthsWorkflowError, match="membership changed"):
        await agent.authorize_plan(
            plan,
            requests=(
                AuthorizationRequest(bytes([0x22]) * 32, 50),
                AuthorizationRequest(bytes([0x22]) * 32, 50),
            ),
        )
    assert provider.calls == 1
    assert signer.signatures == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_decision_inspection_and_diagnostic_verification_stay_inert() -> None:
    client, profile, _, result = await authorize()
    assert isinstance(result, McpAuthorized)

    inspection = inspect_decision(result)
    assert inspection.decision.kind == "authorized"
    assert inspection.kernel.code == "authorized"
    assert inspection.commitments.action == result.action_commitment
    assert len(inspection.commitments.result) == 32
    assert set(inspection.safe_to_log) == {"kind", "stage", "code", "retryable"}
    assert not hasattr(inspection, "command")

    class Engine:
        def verify_v1(
            self, proof_cbor: bytes, action_cbor: bytes, context_cbor: bytes
        ) -> bytes:
            assert proof_cbor == b"proof"
            assert action_cbor == b"action"
            assert context_cbor == b"context"
            return result.result_cbor

    diagnostic = create_diagnostic_verifier(Engine()).verify(
        b"proof", b"action", b"context"
    )
    assert diagnostic.kind == "authorized"
    assert diagnostic.effect_capable is False
    assert diagnostic.submitted_action_cbor == b"action"
    assert not hasattr(diagnostic, "action")
    assert not hasattr(diagnostic, "command")

    async def execute(_call: McpGatewayCall) -> None:
        return None

    gateway = profile.gateway(execute)
    with pytest.raises(TypeError):
        await gateway.execute(inspection)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        await gateway.execute(diagnostic)  # type: ignore[arg-type]
    await client.aclose()


def test_shared_full_workflow_projection_matches_native_python() -> None:
    projection = json.loads((VECTORS / "workflow.projection.json").read_text())
    result = native_abi.verify_v1(
        (VECTORS / "workflow.proof.cbor").read_bytes(),
        (VECTORS / "workflow.action.cbor").read_bytes(),
        (VECTORS / "workflow.context.cbor").read_bytes(),
    )

    assert projection["schema"] == "auths.full-workflow-projection/1"
    assert (result.kind, result.stage, result.code) == (
        projection["verdict"],
        projection["stage"],
        projection["code"],
    )
    assert list(result.metrics) == list(projection["metrics"].values())
    assert bytes(result.result_cbor) == (VECTORS / "workflow.result.cbor").read_bytes()
    assert (
        native_abi.commit_canonical_v1(
            "auths.canonical-action.v1",
            (VECTORS / "workflow.action.cbor").read_bytes(),
        ).hex()
        == projection["commitments"]["action"]
    )
    assert (
        native_abi.commit_canonical_v1(
            "auths.verification-result.v1", bytes(result.result_cbor)
        ).hex()
        == projection["commitments"]["result"]
    )
    assert (
        native_abi.commit_canonical_v1(
            "auths.verifier-configuration.v1", bytes(result.local_configuration)
        ).hex()
        == projection["commitments"]["localConfiguration"]
    )

    call = native_abi.mcp_call(
        projection["command"]["service"],
        projection["command"]["name"],
        projection["command"]["argumentsJson"].encode(),
    )
    plan = native_abi.commit_mcp_plan([call, call])
    assert bytes(plan.commitment).hex() == projection["commitments"]["plan"]
    assert [bytes(member).hex() for member in plan.members] == projection[
        "commitments"
    ]["planMembers"]
    assert (
        plan.permissions
        == [("tools/call", "mcp://reports/tools/update_demo_record")] * 2
    )
    assert plan.resource_namespaces == ["mcp://reports"]
    assert plan.audiences == ["mcp://reports"]
    assert (
        native_abi.commit_plan_approval(
            bytes(plan.commitment), bytes([7]) * 32, 2, 350
        ).hex()
        == projection["commitments"]["planApproval"]
    )

    parent = parse_signed_object(
        "grant", (VECTORS / "mcp.signed-root-grant.cbor").read_bytes()
    )
    proposed = parse_signed_object(
        "grant", (VECTORS / "mcp.signed-child-grant.cbor").read_bytes()
    )
    diff = native_abi.plan_child_statement(
        native_abi.unsigned_from_signed(parent),
        native_abi.grant_request_from_statement(
            native_abi.unsigned_from_signed(proposed)
        ),
    ).diff
    assert {
        "removedPermissions": diff.removed_permissions,
        "removedAudiences": diff.removed_audiences,
        "validityShortened": diff.validity_shortened,
        "actionNarrowed": diff.action_narrowed,
        "budgetNarrowed": diff.budget_narrowed,
        "statusNarrowed": diff.status_narrowed,
        "delegationDepth": list(diff.delegation_depth),
    } == projection["authorityDiff"]
