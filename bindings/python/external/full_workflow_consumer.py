from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from auths import (
    Approval,
    ApprovalRequest,
    ApprovalResponse,
    AttachedAgent,
    AuthorizationRequest,
    AuthsClient,
    ControlEvidence,
    McpGatewayCall,
    McpPlanAuthorized,
    Principal,
    PrincipalDescriptor,
    SignedGrantMaterial,
    SigningRequest,
    SigningResponse,
    TrustedAuthority,
    mcp,
)
from auths.advanced import (
    inspect_decision,
    parse_signed_object,
    parse_trusted_context_bytes,
)


class ApprovalProvider:
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


class FixtureSigner:
    kind = "external-consumer-fixture"
    lifecycle = "ephemeral"

    def __init__(self, vectors: Path, principal: Principal) -> None:
        self._vectors = vectors
        self._principal = principal
        self.calls = 0
        self.closed = False

    async def public_identity(self) -> PrincipalDescriptor:
        return PrincipalDescriptor(
            self._principal,
            "raw-key-v1",
            self._principal.value,
            "ed25519-v1",
        )

    async def sign(self, request: SigningRequest) -> SigningResponse:
        self.calls += 1
        return SigningResponse(
            request.request_id,
            request.principal,
            request.transaction_digest,
            (self._vectors / "mcp.action-signature.bin").read_bytes(),
            (
                ControlEvidence(
                    "raw-key-v1",
                    "application/vnd.auths.raw-key.v1",
                    (self._vectors / "mcp.actor-evidence.bin").read_bytes(),
                ),
            ),
        )

    async def aclose(self) -> None:
        self.closed = True


async def run(vectors: Path) -> None:
    root = Principal("key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs")
    actor = Principal("key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E")
    signer = FixtureSigner(vectors, actor)
    approval_provider = ApprovalProvider()
    approval = Approval.plan_once(
        "approval.external-plan",
        approval_provider,
        max_uses=2,
    )
    trusted = TrustedAuthority(
        "external.root",
        root,
        parse_trusted_context_bytes((vectors / "mcp.context.cbor").read_bytes()),
        approval.policy.reference,
    )
    root_grant = SignedGrantMaterial(
        parse_signed_object(
            "grant", (vectors / "mcp.signed-root-grant.cbor").read_bytes()
        ),
        (
            ControlEvidence(
                "raw-key-v1",
                "application/vnd.auths.raw-key.v1",
                (vectors / "mcp.root-evidence.bin").read_bytes(),
            ),
        ),
    )
    profile = mcp.profile(service="reports")
    executed: list[McpGatewayCall] = []

    async def execute(call: McpGatewayCall) -> str:
        executed.append(call)
        return call.name

    async with AuthsClient(signer=signer, trusted_authority=trusted) as client:
        agent: AttachedAgent = await client.attach_agent(
            name="external-plan-agent",
            profile=profile,
            authority=root_grant,
            approval=approval,
        )
        plan = profile.plan(
            (
                profile.call("update_demo_record", {"value": "reviewed"}),
                profile.call("update_demo_record", {"value": "reviewed"}),
            )
        )
        result = await agent.authorize_plan(
            plan,
            requests=(
                AuthorizationRequest(bytes([0x22]) * 32, 50),
                AuthorizationRequest(bytes([0x22]) * 32, 50),
            ),
        )
        if not isinstance(result, McpPlanAuthorized):
            raise RuntimeError("installed wheel did not authorize the shared plan")
        if any(
            inspect_decision(member).decision.kind != "authorized"
            for member in result.results
        ):
            raise RuntimeError("installed wheel did not preserve plan member decisions")
        responses = await profile.gateway(execute).execute_plan(result.command)
        if responses != ("update_demo_record", "update_demo_record"):
            raise RuntimeError("installed wheel changed ordered gateway results")
    if approval_provider.calls != 1 or signer.calls != 2 or not signer.closed:
        raise RuntimeError("installed wheel changed provider lifecycle semantics")
    if len(executed) != 2:
        raise RuntimeError("installed wheel changed exact plan execution")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: full_workflow_consumer.py <binding-vectors>")
    asyncio.run(run(Path(sys.argv[1]).resolve()))
