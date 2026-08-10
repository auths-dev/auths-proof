from __future__ import annotations

import copy
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
from auths.advanced import parse_signed_object, parse_trusted_context_bytes


VECTORS = Path(__file__).parents[3] / "target" / "binding-vectors"
ROOT = Principal("key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs")
ACTOR = Principal("key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E")


class ApprovalDouble:
    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
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

    async def public_identity(self) -> PrincipalDescriptor:
        return PrincipalDescriptor(
            self._principal,
            "raw-key-v1",
            self._principal.value,
            "ed25519-v1",
        )

    async def sign(self, request: SigningRequest) -> SigningResponse:
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
