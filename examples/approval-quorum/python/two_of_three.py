"""Any two of three managers approve the agent's exact action before it is
submitted. Whoever answers counts: every pair works, and the third manager
need not answer.

Run from the repository root:

    python examples/approval-quorum/python/two_of_three.py

The keys are the public test vectors of
``bindings/fixtures/gateway/approval-quorum.json``; production signers use
their own custody adapters. The operator's trust template anchors the agent
for one tool, names the three managers as approvers, and requires approvals
from any two of them. The agent signs the action; each approving manager signs
an approval of that exact action. The agent's own approval never counts.
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
from auths.authoring import AuthoringUnsuccessful, author_mcp_quorum_proof
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


class Signer:
    """A test signer. The seed is a public test vector, never a secret."""

    def __init__(self, member: dict[str, Any]) -> None:
        self.key = _native.DevelopmentEd25519Key.from_seed(bytes([member["seed_byte"]]) * 32)
        self.evidence = PublicControlEvidence(
            "raw-key-v1", "application/vnd.auths.raw-key.v1", b64(member["evidence_b64"])
        )
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "example.test-vector",
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
    signers = {member["name"]: Signer(member) for member in fixture["members"]}
    cases = {case["id"]: case for case in fixture["cases"]}
    managers = [signers[name].descriptor.principal for name in fixture["approvers"]]

    async def author(case_id: str, names: list[str], required: int) -> Any:
        case = cases[case_id]
        return await author_mcp_quorum_proof(
            contract=TOOL,
            command=TOOL.validate_arguments(json.loads(case["arguments_json"])),
            actor=signers[fixture["actor"]],
            required=required,
            approvers=managers,
            signers=[signers[name] for name in names],
            trusted_context_template=b64(fixture["sdk_trusted_context_b64"]),
            challenge=bytes.fromhex(fixture["challenge_hex"]),
            evaluation_time=fixture["authored_at"],
        )

    pairs: dict[str, str] = {}
    matches = True
    requirement = None
    for case_id, names in (
        ("managers-a-and-b", ["manager-a", "manager-b"]),
        ("managers-a-and-c", ["manager-a", "manager-c"]),
        ("managers-b-and-c", ["manager-b", "manager-c"]),
    ):
        authored = await author(case_id, names, 2)
        pairs["+".join(names)] = "authorized"
        matches = matches and authored.proof == b64(cases[case_id]["proof_b64"])
        requirement = authored.requirement
    try:
        await author("approvals-for-a-lowered-threshold", ["manager-a"], 1)
        single = "authorized"
    except AuthoringUnsuccessful as refused:
        single = refused.code
    assert requirement is not None
    print(
        json.dumps(
            {
                "example": "approval-quorum",
                "outcome": "authorized",
                "required": requirement.required,
                "approvers": len(requirement.approvers),
                "requirement_id": requirement.requirement_id.hex(),
                "pairs": pairs,
                "matches_gateway_vector": matches,
                "single_approval": single,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FIXTURE))
