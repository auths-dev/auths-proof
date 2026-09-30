"""Any two of three managers approve the agent's action: Python authors the
gateway's quorum bytes and decides every gateway vector identically."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import pytest

from auths import _native
from auths.adapters.custody import (
    CustodyDescriptor,
    CustodyFailure,
    CustodyKeyState,
    CustodyKind,
    CustodyLifecycle,
    CustodyRejected,
    CustodySignatureDescriptor,
    CustodySigned,
    PublicControlEvidence,
    SigningRequest,
    SigningResponse,
)
from auths.adapters.custody import SigningObjectKind
from auths.authoring import (
    AuthoringUnsuccessful,
    approval_requests,
    approve,
    author_mcp_quorum_proof,
    collect_approvals,
    open_approval_request,
    propose_mcp_approval,
    sign_approval_action,
)
from auths.self_hosted import EnumField, ExactMcpTool, StringField

FIXTURE: dict[str, Any] = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "fixtures/gateway/approval-quorum.json"
    ).read_text()
)
MEMBERS = {member["name"]: member for member in FIXTURE["members"]}
MANAGERS = [MEMBERS[name]["principal"] for name in FIXTURE["approvers"]]
CASES = {case["id"]: case for case in FIXTURE["cases"]}
CHALLENGE = bytes.fromhex(FIXTURE["challenge_hex"])


@dataclass(frozen=True)
class SetStatus:
    operation_id: str
    operator_namespace: Literal["airtable-demo"]
    recipe_digest: str
    record_id: str
    replacement: Literal["Approved", "Pending"]


TOOL = ExactMcpTool(
    service=FIXTURE["service"],
    name=FIXTURE["tool"],
    command_type=SetStatus,
    fields={
        "operation_id": StringField(min_length=1, max_length=128),
        "operator_namespace": EnumField(("airtable-demo",)),
        "recipe_digest": StringField(min_length=64, max_length=64),
        "record_id": StringField(min_length=17, max_length=43),
        "replacement": EnumField(("Approved", "Pending")),
    },
)


class SeededSigner:
    def __init__(self, name: str, *, reject: bool = False) -> None:
        self.key = _native.DevelopmentEd25519Key.from_seed(
            bytes([MEMBERS[name]["seed_byte"]]) * 32
        )
        assert self.key.principal == MEMBERS[name]["principal"]
        self.reject = reject
        self.requests: list[SigningRequest] = []
        self.descriptor = CustodyDescriptor(
            "signer-custody/2",
            CustodyKind.WORKLOAD,
            "test.seeded-manager",
            self.key.principal,
            CustodySignatureDescriptor(
                self.key.principal_method, self.key.verification_method, self.key.suite
            ),
            "test-key-1",
            CustodyKeyState.ACTIVE_CURRENT,
            CustodyLifecycle.EPHEMERAL,
        )

    async def sign(self, request: SigningRequest) -> CustodySigned | CustodyRejected:
        self.requests.append(request)
        if self.reject:
            return CustodyRejected("rejected", CustodyFailure.DENIED)
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


def _template() -> bytes:
    now = FIXTURE["evaluation_time"]
    audience = f"mcp://{FIXTURE['service']}"
    resource = f"{audience}/tools/{FIXTURE['tool']}"
    agent = MEMBERS[FIXTURE["actor"]]
    context = _native.compile_trusted_context(
        _native.self_contained_configuration(),
        None,
        1,
        1,
        1,
        [
            _native.TrustAnchor(
                agent["name"],
                _native.Principal(agent["principal"]),
                ["raw-key-v1"],
                [("auths.mcp", 2)],
                [("tools/call", resource)],
                [audience],
                [audience],
                now - 86_400,
                now + 86_400,
                None,
                0,
                "approval-quorum-test-v1",
                None,
            )
        ],
        _native.AssurancePolicy(
            "approval-quorum-test-v1",
            [
                ("root", "every", "self-certifying-identifier", None),
                ("actor", "every", "self-certifying-identifier", None),
                ("actor", "every", "offline-verifiable", None),
            ],
        ),
        None,
        None,
        "none-v1",
        ["raw-key-v1"],
        [],
        [
            _native.ApproverAnchor(
                _native.Principal(principal),
                ["raw-key-v1"],
                now - 86_400,
                now + 86_400,
                None,
            )
            for principal in MANAGERS
        ],
        [(MANAGERS, FIXTURE["required"])],
    )
    return bytes(_native.inspect_trusted_context(context))


def _command(case: dict[str, Any]) -> SetStatus:
    return TOOL.validate_arguments(json.loads(case["arguments_json"]))


def _b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


async def _author(
    case_id: str,
    names: list[str],
    required: int,
    *,
    approvers: list[str] = MANAGERS,
    validity: Any = None,
    actor: Any = None,
) -> Any:
    return await author_mcp_quorum_proof(
        contract=TOOL,
        command=_command(CASES[case_id]),
        actor=actor or SeededSigner(FIXTURE["actor"]),
        required=required,
        approvers=approvers,
        signers=[SeededSigner(name) for name in names],
        trusted_context_template=_template(),
        challenge=CHALLENGE,
        evaluation_time=FIXTURE["authored_at"],
        validity_seconds=validity,
    )


async def _remote(case_id: str, names: list[str], required: int) -> bytes:
    """The same quorum through requests the managers open on their own."""
    proposal = propose_mcp_approval(
        contract=TOOL,
        command=_command(CASES[case_id]),
        required=required,
        approvers=MANAGERS,
        actor=MEMBERS[FIXTURE["actor"]]["principal"],
        actor_grant=None,
        challenge=CHALLENGE,
        evaluation_time=FIXTURE["authored_at"],
    )
    responses = []
    answering = {MEMBERS[name]["principal"]: name for name in names}
    for request in approval_requests(proposal):
        name = answering.get(request.approver)
        if name is None:
            continue
        reviewed = open_approval_request(request.text, now=FIXTURE["authored_at"] + 60)
        responses.append((await approve(reviewed, SeededSigner(name))).text)
    action = await sign_approval_action(proposal, SeededSigner(FIXTURE["actor"]))
    return collect_approvals(proposal, responses).assemble(action)


SDK_CASES = [case for case in FIXTURE["cases"] if case["authoring"] == "sdk"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_id",
    [case["id"] for case in SDK_CASES if case["decision"] == "authorized"],
)
async def test_python_authors_the_exact_gateway_quorum_bytes(case_id: str) -> None:
    case = CASES[case_id]
    authored = await _author(case_id, case["approvers"], case["required"])
    assert authored.proof == _b64(case["proof_b64"])
    assert authored.action == _b64(case["action_b64"])
    assert authored.command == _command(case)
    assert authored.requirement.required == case["required"]
    assert authored.requirement.approvers == tuple(sorted(MANAGERS))
    assert len(authored.requirement.requirement_id) == 32
    assert (authored.requirement.valid_from, authored.requirement.valid_until) == (
        FIXTURE["authored_at"],
        FIXTURE["authored_at"] + FIXTURE["validity_seconds"],
    )
    assert await _remote(case_id, case["approvers"], case["required"]) == authored.proof


@pytest.mark.asyncio
async def test_a_lowered_threshold_is_authored_but_never_authorized() -> None:
    case = CASES["approvals-for-a-lowered-threshold"]
    assert case["authoring"] == "sdk" and case["required"] == 1
    assert await _remote(case["id"], case["approvers"], case["required"]) == _b64(
        case["proof_b64"]
    )
    with pytest.raises(AuthoringUnsuccessful) as lowered:
        await _author(case["id"], case["approvers"], case["required"])
    assert (lowered.value.kind, lowered.value.code) == ("rejected", case["code"])


@pytest.mark.asyncio
async def test_quorum_window_defaults_to_a_day_and_is_configurable() -> None:
    case = CASES["managers-a-and-b"]
    assert FIXTURE["validity_seconds"] == 86_400
    explicit = await _author(
        case["id"], case["approvers"], 2, validity=FIXTURE["validity_seconds"]
    )
    assert explicit.proof == _b64(case["proof_b64"])
    shorter = await _author(case["id"], case["approvers"], 2, validity=3_600)
    assert shorter.requirement.valid_until == FIXTURE["authored_at"] + 3_600
    assert shorter.proof != explicit.proof
    # A week passes the native bound; the one-day trust anchor then refuses it.
    with pytest.raises(AuthoringUnsuccessful) as week:
        await _author(case["id"], case["approvers"], 2, validity=604_800)
    assert (week.value.kind, week.value.code) == ("rejected", "action-outside-validity")
    for invalid in (0, 604_801):
        with pytest.raises(ValueError):
            await _author(case["id"], case["approvers"], 2, validity=invalid)


@pytest.mark.asyncio
async def test_the_actor_and_every_approver_review_the_same_action() -> None:
    actor = SeededSigner(FIXTURE["actor"])
    signers = [SeededSigner(name) for name in FIXTURE["approvers"]]
    await author_mcp_quorum_proof(
        contract=TOOL,
        command=_command(CASES["three-of-three-managers"]),
        actor=actor,
        required=2,
        approvers=MANAGERS,
        signers=signers,
        trusted_context_template=_template(),
        challenge=CHALLENGE,
        evaluation_time=FIXTURE["authored_at"],
    )
    requests = [actor.requests[0]] + [signer.requests[0] for signer in signers]
    displays = {request.display for request in requests}
    assert len(displays) == 1
    fields = dict((field.label, field.value) for field in displays.pop())
    assert fields["Approvals required"] == "any 2 of 3"
    assert actor.requests[0].object_kind == SigningObjectKind.ACTION
    assert all(signer.requests[0].object_kind == SigningObjectKind.APPROVAL for signer in signers)
    assert all(signer.requests[0].request_id.startswith("approval:") for signer in signers)
    assert len({request.object_id for request in requests}) == 4
    assert all(
        request.expires_at_unix_seconds
        == FIXTURE["authored_at"] + FIXTURE["validity_seconds"]
        for request in requests
    )


def test_python_compiles_the_same_quorum_trust_template() -> None:
    assert _template() == _b64(FIXTURE["sdk_trusted_context_b64"])


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["id"])
def test_python_verifier_decides_every_gateway_vector_identically(
    case: dict[str, Any],
) -> None:
    template = _native.parse_trusted_context(_template())
    context = template.bind_request(
        f"mcp://{FIXTURE['service']}", CHALLENGE, FIXTURE["evaluation_time"]
    )
    verdict = _native.verify_v1(
        _b64(case["proof_b64"]),
        _b64(case["action_b64"]),
        bytes(_native.inspect_trusted_context(context)),
    )
    assert verdict.kind == case["decision"]
    if case["decision"] != "authorized":
        assert verdict.code == case["code"]


@pytest.mark.asyncio
async def test_an_unlisted_signer_self_approval_or_too_few_signers_are_refused() -> None:
    case_id = "managers-a-and-b"
    for names in (["manager-a", "outsider"], ["manager-a"], ["manager-a", "manager-a"]):
        with pytest.raises(ValueError):
            await _author(case_id, names, 2)
    agent = MEMBERS[FIXTURE["actor"]]["principal"]
    with pytest.raises(ValueError):
        await _author(case_id, ["manager-a", "manager-b"], 2, approvers=MANAGERS + [agent])


@pytest.mark.asyncio
async def test_duplicate_approver_and_impossible_threshold_are_refused() -> None:
    for approvers, required in (
        ([MANAGERS[0], MANAGERS[0], MANAGERS[1]], 2),
        (MANAGERS, 4),
        (MANAGERS, 0),
    ):
        with pytest.raises(ValueError):
            await _author("managers-a-and-b", ["manager-a", "manager-b"], required, approvers=approvers)


@pytest.mark.asyncio
async def test_a_declining_custody_signer_stops_the_quorum() -> None:
    case = CASES["managers-a-and-b"]
    with pytest.raises(AuthoringUnsuccessful) as declined:
        await author_mcp_quorum_proof(
            contract=TOOL,
            command=_command(case),
            actor=SeededSigner(FIXTURE["actor"]),
            required=2,
            approvers=MANAGERS,
            signers=[SeededSigner("manager-a"), SeededSigner("manager-b", reject=True)],
            trusted_context_template=_template(),
            challenge=CHALLENGE,
            evaluation_time=FIXTURE["authored_at"],
        )
    assert declined.value.kind == "rejected"


def test_runnable_example_authors_the_gateway_quorum() -> None:
    example = (
        Path(__file__).resolve().parents[3]
        / "examples/approval-quorum/python/two_of_three.py"
    )
    output = subprocess.run(
        [sys.executable, str(example)], check=True, capture_output=True, text=True
    ).stdout
    report = json.loads(output.strip().splitlines()[-1])
    assert report["outcome"] == "authorized"
    assert (report["required"], report["approvers"]) == (2, 3)
    assert report["pairs"] == {
        "manager-a+manager-b": "authorized",
        "manager-a+manager-c": "authorized",
        "manager-b+manager-c": "authorized",
    }
    assert report["matches_gateway_vector"] is True
    assert report["single_approval"] == CASES["one-of-three-managers"]["code"]
