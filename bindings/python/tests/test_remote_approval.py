"""Remote approval: Python replays the native corpus byte for byte."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import pytest

from auths import _native
from auths.adapters.custody import (
    CustodyDescriptor,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodySignatureDescriptor,
    CustodySigned,
    PublicControlEvidence,
    SigningObjectKind,
    SigningRequest,
    SigningResponse,
)
from auths.authoring import (
    ApprovalAction,
    ApprovalProposal,
    ApprovalRefused,
    GrantEvidence,
    approval_requests,
    approve,
    collect_approvals,
    decline,
    open_approval_request,
    propose_mcp_approval,
    sign_approval_action,
)
from auths.self_hosted import ExactMcpTool, IntegerField, StringField

FIXTURE: dict[str, Any] = json.loads(
    (
        Path(__file__).resolve().parents[2] / "fixtures/approval/remote-approval.json"
    ).read_text()
)
MEMBERS = {member["name"]: member for member in FIXTURE["members"]}
RESPONSES = {response["name"]: response for response in FIXTURE["responses"]}


def _b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class Refund:
    amount: int
    payment_intent: str


TOOL = ExactMcpTool(
    service=FIXTURE["service"],
    name=FIXTURE["tool"],
    command_type=Refund,
    fields={
        "amount": IntegerField(1, 10_000_000),
        "payment_intent": StringField(min_length=1, max_length=64),
    },
)


class SeededSigner:
    def __init__(self, name: str) -> None:
        self.key = _native.DevelopmentEd25519Key.from_seed(
            bytes([MEMBERS[name]["seed_byte"]]) * 32
        )
        assert self.key.principal == MEMBERS[name]["principal"]
        self.requests: list[SigningRequest] = []
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "test.seeded-approver",
            self.key.principal,
            CustodySignatureDescriptor(
                self.key.principal_method, self.key.verification_method, self.key.suite
            ),
            "test-key-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned:
        self.requests.append(request)
        return CustodySigned(
            "signed",
            SigningResponse(
                request.request_id,
                request.object_id,
                self.key.principal,
                self.descriptor.signature,
                self.descriptor.key_version,
                request.transaction_digest,
                self.key.sign(request.signing_preimage),
                (
                    PublicControlEvidence(
                        self.key.evidence_type, self.key.media_type, self.key.evidence
                    ),
                ),
            ),
        )

    async def aclose(self) -> None:
        return None


def _agent_grants() -> tuple[GrantEvidence, ...]:
    grant = FIXTURE["agent_grant"]
    return (
        GrantEvidence(
            _b64(grant["signed_grant_b64"]),
            tuple(
                PublicControlEvidence(
                    item["evidence_type"],
                    item["evidence_media_type"],
                    _b64(item["evidence_b64"]),
                )
                for item in grant["evidence"]
            ),
        ),
    )


def _proposal(arguments: Optional[dict[str, Any]] = None) -> ApprovalProposal[Refund]:
    values = arguments or FIXTURE["arguments"]
    return propose_mcp_approval(
        contract=TOOL,
        command=Refund(**values),
        required=FIXTURE["required"],
        approvers=[MEMBERS[name]["principal"] for name in FIXTURE["approvers"]],
        actor=MEMBERS[FIXTURE["requester"]]["principal"],
        actor_grant=_agent_grants()[0].signed_grant,
        challenge=bytes.fromhex(FIXTURE["challenge_hex"]),
        evaluation_time=FIXTURE["evaluation_time"],
    )


async def _action(proposal: ApprovalProposal[Refund]) -> ApprovalAction:
    return await sign_approval_action(
        proposal, SeededSigner(FIXTURE["requester"]), grants=_agent_grants()
    )


def test_python_issues_the_native_requests() -> None:
    proposal = _proposal()
    assert proposal.requirement.required == FIXTURE["required"]
    assert proposal.requirement.requirement_id.hex() == FIXTURE["requirement_id_hex"]
    assert proposal.requirement.approvers == tuple(
        MEMBERS[name]["principal"] for name in FIXTURE["approvers"]
    )
    issued = approval_requests(proposal)
    assert len(issued) == len(FIXTURE["requests"])
    for request, expected in zip(issued, FIXTURE["requests"]):
        assert request.approver == MEMBERS[expected["approver"]]["principal"]
        assert request.data == _b64(expected["request_b64"])
        assert request.text == expected["request_text"]
        assert request.request_id.hex() == expected["request_id_hex"]


def test_an_actor_listed_as_approver_is_refused_before_any_request() -> None:
    with pytest.raises(ValueError):
        propose_mcp_approval(
            contract=TOOL,
            command=Refund(**FIXTURE["arguments"]),
            required=FIXTURE["required"],
            approvers=[
                MEMBERS[name]["principal"] for name in (*FIXTURE["approvers"], "agent")
            ],
            actor=MEMBERS["agent"]["principal"],
            actor_grant=None,
            challenge=bytes.fromhex(FIXTURE["challenge_hex"]),
            evaluation_time=FIXTURE["evaluation_time"],
        )


@pytest.mark.asyncio
async def test_the_actor_signs_the_native_action() -> None:
    proposal = _proposal()
    signer = SeededSigner(FIXTURE["requester"])
    action = await sign_approval_action(proposal, signer, grants=_agent_grants())
    assert action.actor == proposal.actor
    (request,) = signer.requests
    assert request.object_kind == SigningObjectKind.ACTION
    assert request.expires_at_unix_seconds == proposal.requirement.valid_until
    expected = _native.parse_signed("action", _b64(FIXTURE["agent_action"]["signed_action_b64"]))
    assert bytes(request.signing_preimage) == bytes(
        _native.prepare_signing(
            _native.unsigned_from_signed(expected),
            request.descriptor.signature.principal_method,
            request.descriptor.signature.verification_method,
            request.descriptor.signature.suite,
        ).signing_preimage
    )
    with pytest.raises(ValueError):
        await sign_approval_action(proposal, SeededSigner("manager-a"))


@pytest.mark.parametrize("case", FIXTURE["open"], ids=lambda case: case["name"])
def test_python_opens_every_request_vector(case: dict[str, Any]) -> None:
    if case["profiles"] != "mcp":
        pytest.skip("the SDK registers exactly the profiles it ships")
    data: Union[bytes, str] = (
        case["input_text"] if "input_text" in case else _b64(case["input_b64"])
    )
    if case["expect"] is None:
        reviewed = open_approval_request(data, now=case["now"])
        review = case["review"]
        assert reviewed.title == review["title"]
        assert [list(item) for item in reviewed.fields] == review["fields"]
        assert reviewed.display_digest_hex == review["display_digest_hex"]
        assert reviewed.requester == review["requester"]
        assert list(reviewed.approvers) == review["approvers"]
        assert reviewed.required == review["required"]
        assert reviewed.approver == review["approver"]
        assert [reviewed.valid_from, reviewed.valid_until] == review["window"]
        assert reviewed.request_id.hex() == review["request_id_hex"]
    else:
        with pytest.raises(ApprovalRefused) as refused:
            open_approval_request(data, now=case["now"])
        assert refused.value.code == case["expect"]


def _reviewed(approver: str) -> Any:
    request = next(
        item for item in FIXTURE["requests"] if item["approver"] == approver
    )
    return open_approval_request(request["request_text"], now=FIXTURE["opened_at"])


@pytest.mark.asyncio
async def test_python_approves_and_declines_to_the_native_bytes() -> None:
    for name, approver in (
        ("approve-manager-a", "manager-a"),
        ("approve-manager-b", "manager-b"),
        ("approve-manager-c", "manager-c"),
    ):
        reviewed = _reviewed(approver)
        signer = SeededSigner(approver)
        response = await approve(reviewed, signer)
        assert response.decision == "approve"
        assert response.data == _b64(RESPONSES[name]["response_b64"])
        assert response.text.startswith("auths-as2-")
        (request,) = signer.requests
        assert request.object_kind == SigningObjectKind.APPROVAL
        assert request.request_id.startswith("approval:")
        assert tuple((field.label, field.value) for field in request.display) == reviewed.fields
        assert request.expires_at_unix_seconds == reviewed.valid_until

    for name, approver in (
        ("decline-manager-b", "manager-b"),
        ("decline-manager-c", "manager-c"),
    ):
        reviewed = _reviewed(approver)
        signer = SeededSigner(approver)
        response = await decline(reviewed, signer, now=FIXTURE["decided_at"])
        assert response.decision == "decline"
        assert response.data == _b64(RESPONSES[name]["response_b64"])
        (request,) = signer.requests
        assert request.object_kind == SigningObjectKind.APPROVAL_DECLINE
        assert request.request_id.startswith("approval-decline:")
        assert request.expires_at_unix_seconds == reviewed.valid_until


@pytest.mark.asyncio
async def test_only_the_addressed_approver_can_answer() -> None:
    reviewed = _reviewed("manager-a")
    for answer in (
        approve(reviewed, SeededSigner("outsider")),
        approve(reviewed, SeededSigner("agent")),
        decline(reviewed, SeededSigner("manager-b"), now=FIXTURE["decided_at"]),
    ):
        with pytest.raises(ApprovalRefused) as refused:
            await answer
        assert refused.value.code == "approval.not-addressed"


def test_every_stable_code_is_exercised() -> None:
    seen = {case["expect"] for case in FIXTURE["open"] if case["expect"]}
    for case in FIXTURE["collect"]:
        seen.update(status.get("code") for status in case["statuses"] if "code" in status)
        seen.update(code for _, code in case["unattributed"])
        if "assemble_code" in case:
            seen.add(case["assemble_code"])
    assert seen == set(FIXTURE["codes"])


@pytest.mark.asyncio
@pytest.mark.parametrize("case", FIXTURE["collect"], ids=lambda case: case["name"])
async def test_python_collects_every_vector(case: dict[str, Any]) -> None:
    collection = collect_approvals(
        _proposal(), [_b64(item) for item in case["responses_b64"]]
    )
    statuses = []
    for status in collection.statuses:
        entry: dict[str, Any] = {
            "approver": next(
                name
                for name, member in MEMBERS.items()
                if member["principal"] == status.approver
            ),
            "status": status.status,
        }
        if status.code is not None:
            entry["code"] = status.code
        if status.decided_at is not None:
            entry["decided_at"] = status.decided_at
        statuses.append(entry)
    assert statuses == case["statuses"]
    assert [list(item) for item in collection.unattributed] == case["unattributed"]
    assert (collection.approved, collection.required) == (case["approved"], FIXTURE["required"])
    proposal = (
        _proposal(FIXTURE["attacker_arguments"]) if case.get("action") == "attacker" else _proposal()
    )
    action = await _action(proposal)
    if "proof_b64" in case:
        assert collection.assemble(action) == _b64(case["proof_b64"])
    else:
        with pytest.raises(ApprovalRefused) as refused:
            collection.assemble(action)
        assert refused.value.code == case["assemble_code"]
