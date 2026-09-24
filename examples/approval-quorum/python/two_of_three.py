"""Two of three managers approve one exact action before the agent submits it.

Run from the repository root:

    python examples/approval-quorum/python/two_of_three.py

The managers' keys are the public test vectors of
``bindings/fixtures/gateway/approval-quorum.json``; production approvers sign
through their own custody adapters. The operator's trust template anchors the
three managers and requires two authorized approvals from two distinct actors.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from auths import _native
from auths.adapters.custody import (
    CustodyDescriptor,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodySignatureDescriptor,
    CustodySigned,
    PublicControlEvidence,
    SigningRequest,
    SigningResponse,
)
from auths.authoring import AuthoringUnsuccessful, QuorumApprover, author_mcp_quorum_proof
from auths.self_hosted import EnumField, ExactMcpTool, StringField

DEFAULT_FIXTURE = (
    Path(__file__).resolve().parents[3] / "bindings/fixtures/gateway/approval-quorum.json"
)


@dataclass(frozen=True)
class SetStatus:
    operation_id: str
    operator_namespace: Literal["airtable-demo"]
    recipe_digest: str
    record_id: str
    replacement: Literal["Approved", "Pending"]


TOOL = ExactMcpTool(
    service="airtable-gateway-demo",
    name="set_demo_status_v1",
    command_type=SetStatus,
    fields={
        "operation_id": StringField(min_length=1, max_length=128),
        "operator_namespace": EnumField(("airtable-demo",)),
        "recipe_digest": StringField(min_length=64, max_length=64),
        "record_id": StringField(min_length=17, max_length=43),
        "replacement": EnumField(("Approved", "Pending")),
    },
)


def b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Manager:
    """A manager's signer. The seed is a public test vector, never a secret."""

    def __init__(self, member: dict[str, Any]) -> None:
        self.key = _native.DevelopmentEd25519Key.from_seed(bytes([member["seed_byte"]]) * 32)
        self.evidence = PublicControlEvidence(
            "raw-key-v1", "application/vnd.auths.raw-key.v1", b64(member["evidence_b64"])
        )
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "example.manager",
            member["principal"],
            CustodySignatureDescriptor("raw-key-v1", member["principal"], "ed25519-v1"),
            "example-key-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned:
        return CustodySigned(
            "signed",
            SigningResponse(
                request.request_id,
                request.object_id,
                self.descriptor.principal,
                self.descriptor.signature,
                self.descriptor.key_version,
                request.transaction_digest,
                self.key.sign(request.signing_preimage),
                (self.evidence,),
            ),
        )

    async def aclose(self) -> None:
        return None


async def main(fixture_path: Path) -> None:
    fixture = json.loads(fixture_path.read_text())
    managers = {member["name"]: Manager(member) for member in fixture["members"]}
    case = next(item for item in fixture["cases"] if item["id"] == "two-of-three-managers")
    command = TOOL.validate_arguments(json.loads(case["arguments_json"]))

    async def author(names: list[str], required: int) -> Any:
        return await author_mcp_quorum_proof(
            contract=TOOL,
            command=command,
            required=required,
            approvers=[QuorumApprover(managers[name]) for name in names],
            trusted_context_template=b64(fixture["sdk_trusted_context_b64"]),
            challenge=bytes.fromhex(fixture["challenge_hex"]),
            evaluation_time=fixture["authored_at"],
        )

    authored = await author(["manager-a", "manager-b"], 2)
    try:
        await author(["manager-a"], 1)
        single = "authorized"
    except AuthoringUnsuccessful as refused:
        single = refused.code
    print(
        json.dumps(
            {
                "example": "approval-quorum",
                "outcome": "authorized",
                "approvals": len(authored.plan.approvers),
                "members": sum(1 for member in fixture["members"] if member["member"]),
                "plan_id": authored.plan.plan_id.hex(),
                "matches_gateway_vector": authored.proof == b64(case["proof_b64"]),
                "single_approval": single,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FIXTURE))
